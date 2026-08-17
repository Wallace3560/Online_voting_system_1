<?php
/*
 * Module: Voter Location Change Controller
 * Responsibility: Validate voter relocation requests and submit them
 * for admin review and approval.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

/* Section: Voter authentication and access gate. */
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
$location_change_eligibility = getVoterLocationChangeEligibility();

/* Section: Location change request submission flow. */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'request_location_change') {
    if (empty($location_change_eligibility['allowed'])) {
        $error = (string)($location_change_eligibility['message'] ?? 'Location change is not allowed at this time.');
    } elseif (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } else {
        $county_id = (int)($_POST['county_id'] ?? 0);
        $constituency_id = (int)($_POST['constituency_id'] ?? 0);
        $ward_id = (int)($_POST['ward_id'] ?? 0);
        $reason = sanitize($_POST['relocation_reason'] ?? '');

        $result = createVoterRelocationRequest($voter_id, $county_id, $constituency_id, $ward_id, $reason);
        if (!empty($result['ok'])) {
            $message = (string)$result['message'];
            logAuditEvent('voter', $voter_id, 'location_change_requested', [
                'county_id' => $county_id,
                'constituency_id' => $constituency_id,
                'ward_id' => $ward_id
            ]);
        } else {
            $error = (string)($result['message'] ?? 'Could not submit location change request.');
        }
    }
}

/* Section: Refresh page data and render view. */
$voter = getVoterById($voter_id);
$counties = getCounties();
$current_constituencies = getConstituenciesByCounty((int)($voter['county_id'] ?? 0));
$current_wards = getWardsByConstituency((int)($voter['constituency_id'] ?? 0));
$change_requests = getVoterProfileChangeRequestsByVoter($voter_id);
$location_change_eligibility = getVoterLocationChangeEligibility();
$csrf_token = getCsrfToken();

require_once 'views/change_location.view.html';
