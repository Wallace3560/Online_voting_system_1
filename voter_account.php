<?php
/*
 * Overview: Voter Account
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

if (!isset($_SESSION['voter_id'])) {
    header('Location: login.php');
    exit();
}

$voter_id = (int)$_SESSION['voter_id'];
$voter = getVoterById($voter_id);
if (!$voter || !canLogin($voter_id)) {
    session_destroy();
    header('Location: login.php');
    exit();
}

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request_profile_update') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } else {
        $reason = sanitize($_POST['update_reason'] ?? '');
        $request_payload = [
            'full_name' => sanitize($_POST['full_name'] ?? ''),
            'email' => sanitize($_POST['email'] ?? ''),
            'phone' => sanitize($_POST['phone'] ?? ''),
            'date_of_birth' => sanitize($_POST['date_of_birth'] ?? ''),
            'county_id' => (int)($_POST['county_id'] ?? 0),
            'constituency_id' => (int)($_POST['constituency_id'] ?? 0),
            'ward_id' => (int)($_POST['ward_id'] ?? 0)
        ];

        $result = createVoterProfileChangeRequest($voter_id, $request_payload, $reason);
        if (!empty($result['ok'])) {
            $message = (string)$result['message'];
            logAuditEvent('voter', $voter_id, 'profile_change_requested', [
                'reason' => $reason,
                'requested_fields' => array_keys($request_payload)
            ]);
        } else {
            $error = (string)($result['message'] ?? 'Could not submit profile update request.');
        }
    }
}

$voter = getVoterById($voter_id);
$counties = getCounties();
$current_constituencies = getConstituenciesByCounty((int)($voter['county_id'] ?? 0));
$current_wards = getWardsByConstituency((int)($voter['constituency_id'] ?? 0));
$change_requests = getVoterProfileChangeRequestsByVoter($voter_id);
$csrf_token = getCsrfToken();

require_once 'views/voter_account.view.html';