<?php
/*
 * Overview: Admin Records
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

requireAdminAuth();

$admin_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
$can_manage = canManageElection($admin_role);

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $action = sanitize($_POST['action'] ?? '');
    $admin_actions = ['update_voter', 'force_reject_voter', 'update_candidate', 'mark_candidate_deceased'];

    if ($error === '' && in_array($action, $admin_actions, true) && !$can_manage) {
        $error = 'Your role does not have permission to perform this action.';
        logAuditEvent('admin', (int)($_SESSION['admin_id'] ?? 0), 'admin_action_forbidden', ['action' => $action, 'role' => $admin_role]);
    }

    if ($error === '' && $action === 'update_voter') {
        $voter_id = (int)($_POST['voter_id'] ?? 0);
        $full_name = sanitize($_POST['full_name'] ?? '');
        $email = sanitize($_POST['email'] ?? '');
        $phone = sanitize($_POST['phone'] ?? '');
        $status = sanitize($_POST['status'] ?? 'active');

        if ($voter_id <= 0 || $full_name === '' || $email === '' || $phone === '') {
            $error = 'Voter id, name, email, and phone are required for update.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please provide a valid voter email address.';
        } elseif (isVoterEmailOrPhoneTaken($voter_id, $email, $phone)) {
            $error = 'Another voter already uses that email or phone number.';
        } elseif (updateVoterAdminRecord($voter_id, $full_name, $email, $phone, $status)) {
            $message = 'Voter record updated successfully.';
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_record_updated_from_records_page', [
                'voter_id' => $voter_id,
                'status' => $status
            ]);
        } else {
            $error = 'Failed to update voter record.';
        }
    } elseif ($error === '' && $action === 'force_reject_voter') {
        $voter_id = (int)($_POST['voter_id'] ?? 0);
        $rejection_reason = sanitize($_POST['rejection_reason'] ?? 'Rejected by admin after review.');

        if ($voter_id <= 0) {
            $error = 'Invalid voter selected for rejection.';
        } elseif (forceRejectVoter($voter_id, (int)$_SESSION['admin_id'], $rejection_reason)) {
            $message = 'Voter rejected successfully.';
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_force_rejected_from_records_page', [
                'voter_id' => $voter_id,
                'rejection_reason' => $rejection_reason
            ]);
        } else {
            $error = 'Failed to reject voter.';
        }
    } elseif ($error === '' && $action === 'update_candidate') {
        $candidate_id = (int)($_POST['candidate_id'] ?? 0);
        $position_id = (int)($_POST['position_id'] ?? 0);
        $full_name = sanitize($_POST['full_name'] ?? '');
        $party_name = sanitize($_POST['party_name'] ?? '');
        $status = sanitize($_POST['status'] ?? 'active');
        $force_apply_changes = !empty($_POST['force_apply_changes']);

        $county_id = (int)($_POST['county_id'] ?? 0);
        $constituency_id = (int)($_POST['constituency_id'] ?? 0);
        $ward_id = (int)($_POST['ward_id'] ?? 0);

        if ($candidate_id <= 0 || $position_id <= 0 || $full_name === '' || $party_name === '') {
            $error = 'Candidate details are incomplete for update.';
        } else {
            $update_result = updateCandidateAdminRecord(
                $candidate_id,
                $position_id,
                $full_name,
                $party_name,
                $county_id > 0 ? $county_id : null,
                $constituency_id > 0 ? $constituency_id : null,
                $ward_id > 0 ? $ward_id : null,
                $status,
                $force_apply_changes
            );

            if (!empty($update_result['ok'])) {
                $message = (string)($update_result['message'] ?? 'Candidate updated successfully.');
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'candidate_updated_from_records_page', [
                    'candidate_id' => $candidate_id,
                    'status' => $status,
                    'force_apply_changes' => $force_apply_changes ? 1 : 0
                ]);
            } else {
                $error = (string)($update_result['message'] ?? 'Failed to update candidate.');
            }
        }
    } elseif ($error === '' && $action === 'mark_candidate_deceased') {
        $candidate_id = (int)($_POST['candidate_id'] ?? 0);
        $deceased_reason = sanitize($_POST['deceased_reason'] ?? 'Candidate died while in office.');

        $deceased_result = markCandidateDeceasedAndDraftByElection($candidate_id, (int)$_SESSION['admin_id'], $deceased_reason);
        if (!empty($deceased_result['ok'])) {
            $message = (string)$deceased_result['message'];
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'candidate_marked_deceased_from_records_page', [
                'candidate_id' => $candidate_id,
                'deceased_reason' => $deceased_reason,
                'by_election_id' => (int)($deceased_result['by_election_id'] ?? 0)
            ]);
        } else {
            $error = (string)($deceased_result['message'] ?? 'Failed to mark candidate deceased.');
        }
    }
}

$type = sanitize($_GET['type'] ?? 'voters');
$allowed_types = ['voters', 'candidates', 'pending'];
if (!in_array($type, $allowed_types, true)) {
    $type = 'voters';
}

$query = sanitize($_GET['q'] ?? '');
$query_lc = strtolower($query);

$rows = [];
$title = 'All Registered Voters';

if ($type === 'candidates') {
    $title = 'Configured Candidates';
    $positions = getAllPositions();
    foreach ($positions as $position) {
        $items = getCandidatesForPosition((int)$position['position_id']);
        foreach ($items as $item) {
            $rows[] = $item;
        }
    }
} elseif ($type === 'pending') {
    $title = 'Pending Verification';
    $rows = getPendingVerifications();
} else {
    $rows = getAllRegisteredVoters();
}

if ($query_lc !== '') {
    $rows = array_values(array_filter($rows, function ($row) use ($query_lc, $type) {
        if (!is_array($row)) {
            return false;
        }

        if ($type === 'candidates') {
            $haystack = strtolower(
                (string)($row['full_name'] ?? '') . ' ' .
                (string)($row['party_name'] ?? '') . ' ' .
                (string)($row['position_name'] ?? '') . ' ' .
                (string)($row['scope'] ?? '')
            );
            return strpos($haystack, $query_lc) !== false;
        }

        if ($type === 'pending') {
            $haystack = strtolower(
                (string)($row['full_name'] ?? '') . ' ' .
                (string)($row['national_id'] ?? '') . ' ' .
                (string)($row['email'] ?? '') . ' ' .
                (string)($row['county_name'] ?? '') . ' ' .
                (string)($row['constituency_name'] ?? '') . ' ' .
                (string)($row['ward_name'] ?? '')
            );
            return strpos($haystack, $query_lc) !== false;
        }

        $haystack = strtolower(
            (string)($row['full_name'] ?? '') . ' ' .
            (string)($row['national_id'] ?? '') . ' ' .
            (string)($row['email'] ?? '') . ' ' .
            (string)($row['phone'] ?? '') . ' ' .
            (string)($row['status'] ?? '') . ' ' .
            (string)($row['verification_status'] ?? '')
        );
        return strpos($haystack, $query_lc) !== false;
    }));
}

$csrf_token = getCsrfToken();

require_once 'views/admin_records.view.html';