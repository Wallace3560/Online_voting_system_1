<?php
/*
 * Overview: Admin Manage Voters
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
    $allowed_actions = ['update_voter', 'force_reject_voter', 'approve_profile_change', 'reject_profile_change'];

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
        } else {
            if (updateVoterAdminRecord($voter_id, $full_name, $email, $phone, $status)) {
                $message = 'Voter record updated successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_record_updated', [
                    'voter_id' => $voter_id,
                    'status' => $status
                ]);
            } else {
                $error = 'Failed to update voter record.';
            }
        }
    } elseif ($error === '' && $action === 'force_reject_voter') {
        $voter_id = (int)($_POST['voter_id'] ?? 0);
        $rejection_reason = sanitize($_POST['rejection_reason'] ?? 'Rejected by admin after review.');

        if ($voter_id <= 0) {
            $error = 'Invalid voter selected for rejection.';
        } else {
            if (forceRejectVoter($voter_id, (int)$_SESSION['admin_id'], $rejection_reason)) {
                $message = 'Voter rejected successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_force_rejected', [
                    'voter_id' => $voter_id,
                    'rejection_reason' => $rejection_reason
                ]);
            } else {
                $error = 'Failed to reject voter.';
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

$all_voters = getAllRegisteredVoters();
$pending_profile_requests = getVoterProfileChangeRequests('pending');
$profile_request_history = getVoterProfileChangeRequests();
$csrf_token = getCsrfToken();

require_once 'views/admin_manage_voters.view.html';