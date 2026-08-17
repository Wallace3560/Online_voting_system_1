<?php
/*
 * Module: Admin Voter Records Management Controller
 * Responsibility: Enforce admin access, process voter/profile actions,
 * and load filtered voter datasets for the management view.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

/* Section: Admin authentication and capability checks. */
requireAdminAuth();
$admin_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
$can_manage = canManageElection($admin_role);
$can_verify_voters = canVerifyVoters($admin_role);

$message = '';
$error = '';

$location_status_filter = sanitize($_GET['location_status'] ?? 'all');
$allowed_location_status_filters = ['all', 'pending', 'approved', 'rejected'];
if (!in_array($location_status_filter, $allowed_location_status_filters, true)) {
    $location_status_filter = 'all';
}

$new_user_search = sanitize($_GET['new_user_search'] ?? '');
$location_search = sanitize($_GET['location_search'] ?? '');

/* Section: Action dispatcher for voter/profile management operations. */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $action = sanitize($_POST['action'] ?? '');
    $allowed_actions = ['update_voter', 'force_reject_voter', 'approve_profile_change', 'reject_profile_change', 'approve_voter', 'request_voter_corrections'];

    if ($error === '' && (!in_array($action, $allowed_actions, true) || !$can_manage)) {
        $error = 'Your role does not have permission to perform this action.';
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
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_record_updated', [
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
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_force_rejected', [
                'voter_id' => $voter_id,
                'rejection_reason' => $rejection_reason
            ]);
        } else {
            $error = 'Failed to reject voter.';
        }
    } elseif ($error === '' && $action === 'approve_voter') {
        if (!$can_verify_voters) {
            $error = 'Only super-admin and sub-admin roles can verify voters.';
        } else {
            $voter_id = (int)($_POST['voter_id'] ?? 0);
            if ($voter_id <= 0) {
                $error = 'Invalid voter selected for approval.';
            } elseif (verifyVoter($voter_id, (int)$_SESSION['admin_id'], 'approve', null)) {
                $message = 'Voter approved successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_approved_from_manage_voters', [
                    'voter_id' => $voter_id
                ]);
            } else {
                $error = 'Failed to approve voter.';
            }
        }
    } elseif ($error === '' && $action === 'request_voter_corrections') {
        if (!$can_verify_voters) {
            $error = 'Only super-admin and sub-admin roles can request voter corrections.';
        } else {
            $voter_id = (int)($_POST['voter_id'] ?? 0);
            $request_note = sanitize($_POST['request_note'] ?? 'Please correct your submitted details and upload clear ID photos.');
            if ($voter_id <= 0) {
                $error = 'Invalid voter selected for correction request.';
            } else {
                $correction_result = requestVoterVerificationCorrections($voter_id, (int)$_SESSION['admin_id'], $request_note);
                if (!empty($correction_result['ok'])) {
                    $message = (string)$correction_result['message'];
                    logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_correction_requested_from_manage_voters', [
                        'voter_id' => $voter_id,
                        'request_note' => $request_note,
                        'email_sent' => !empty($correction_result['email_sent']) ? 1 : 0
                    ]);
                } else {
                    $error = (string)($correction_result['message'] ?? 'Failed to request corrections from voter.');
                }
            }
        }
    } elseif ($error === '' && $action === 'approve_profile_change') {
        $request_id = (int)($_POST['request_id'] ?? 0);
        $decision_note = sanitize($_POST['decision_note'] ?? 'Approved');
        if ($request_id <= 0) {
            $error = 'Invalid profile change request.';
        } else {
            $result = approveVoterProfileChangeRequest($request_id, (int)$_SESSION['admin_id'], $decision_note);
            if (!empty($result['ok'])) {
                $message = (string)$result['message'];
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'profile_change_request_approved', [
                    'request_id' => $request_id,
                    'decision_note' => $decision_note
                ]);
            } else {
                $error = (string)($result['message'] ?? 'Could not approve profile change request.');
            }
        }
    } elseif ($error === '' && $action === 'reject_profile_change') {
        $request_id = (int)($_POST['request_id'] ?? 0);
        $decision_note = sanitize($_POST['decision_note'] ?? 'Rejected');
        if ($request_id <= 0) {
            $error = 'Invalid profile change request.';
        } else {
            $result = rejectVoterProfileChangeRequest($request_id, (int)$_SESSION['admin_id'], $decision_note);
            if (!empty($result['ok'])) {
                $message = (string)$result['message'];
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'profile_change_request_rejected', [
                    'request_id' => $request_id,
                    'decision_note' => $decision_note
                ]);
            } else {
                $error = (string)($result['message'] ?? 'Could not reject profile change request.');
            }
        }
    }
}

/* Section: Read-model assembly for screen tables and filters. */
$all_voters = getAllRegisteredVoters();
$pending_profile_requests = getVoterProfileChangeRequests('pending');
$pending_profile_requests = filterRowsByVoterName($pending_profile_requests, $location_search, 'voter_name');
$profile_request_history = $location_status_filter === 'all'
    ? getVoterProfileChangeRequests()
    : getVoterProfileChangeRequests($location_status_filter);
$profile_request_history = filterRowsByVoterName($profile_request_history, $location_search, 'voter_name');
$all_voters = filterRowsByVoterName($all_voters, $new_user_search, 'full_name');
$csrf_token = getCsrfToken();

/* Section: Render view. */
require_once 'views/admin_manage_voters.view.html';