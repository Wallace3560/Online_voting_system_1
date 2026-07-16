<?php
/*
 * Overview: Voter Account
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$correction_token = sanitize($_GET['correction_token'] ?? ($_POST['correction_token'] ?? ''));
$can_use_correction_token = $correction_token !== '';
$is_token_flow = false;

$voter = null;
$voter_id = 0;

if ($can_use_correction_token) {
    $voter = getVoterByProfileCorrectionToken($correction_token);
    if ($voter) {
        $is_token_flow = true;
        $voter_id = (int)($voter['voter_id'] ?? 0);
    }
}

if (!$voter) {
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
}

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request_profile_update') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } else {
        $front_upload = null;
        $back_upload = null;
        $front_path = '';
        $back_path = '';

        $front_error = (int)($_FILES['national_id_front']['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($front_error !== UPLOAD_ERR_NO_FILE) {
            $front_upload = saveNationalIdPhotoUpload($_FILES['national_id_front'] ?? null, 'front');
            if (empty($front_upload['ok'])) {
                $error = (string)($front_upload['message'] ?? 'Failed to upload National ID front photo.');
            } else {
                $front_path = (string)($front_upload['path'] ?? '');
            }
        }

        if ($error === '') {
            $back_error = (int)($_FILES['national_id_back']['error'] ?? UPLOAD_ERR_NO_FILE);
            if ($back_error !== UPLOAD_ERR_NO_FILE) {
                $back_upload = saveNationalIdPhotoUpload($_FILES['national_id_back'] ?? null, 'back');
                if (empty($back_upload['ok'])) {
                    $error = (string)($back_upload['message'] ?? 'Failed to upload National ID back photo.');
                    if ($front_path !== '') {
                        $front_file = __DIR__ . '/' . ltrim($front_path, '/');
                        if (is_file($front_file)) {
                            @unlink($front_file);
                        }
                    }
                } else {
                    $back_path = (string)($back_upload['path'] ?? '');
                }
            }
        }

        $reason = sanitize($_POST['update_reason'] ?? '');
        if ($reason === '' && $is_token_flow) {
            $reason = 'Details correction requested by admin.';
        }

        $request_payload = [
            'full_name' => sanitize($_POST['full_name'] ?? ''),
            'email' => sanitize($_POST['email'] ?? ''),
            'phone' => sanitize($_POST['phone'] ?? ''),
            'date_of_birth' => sanitize($_POST['date_of_birth'] ?? ''),
            'county_id' => (int)($_POST['county_id'] ?? 0),
            'constituency_id' => (int)($_POST['constituency_id'] ?? 0),
            'ward_id' => (int)($_POST['ward_id'] ?? 0),
            'national_id_front_path' => $front_path,
            'national_id_back_path' => $back_path
        ];

        if ($error === '') {
            $result = createVoterProfileChangeRequest($voter_id, $request_payload, $reason);
            if (!empty($result['ok'])) {
                if ($is_token_flow) {
                    clearVoterProfileCorrectionToken($voter_id);
                }
                $message = (string)$result['message'];
                logAuditEvent('voter', $voter_id, 'profile_change_requested', [
                    'reason' => $reason,
                    'requested_fields' => array_keys($request_payload),
                    'token_flow' => $is_token_flow ? 1 : 0
                ]);
            } else {
                if ($front_path !== '') {
                    $front_file = __DIR__ . '/' . ltrim($front_path, '/');
                    if (is_file($front_file)) {
                        @unlink($front_file);
                    }
                }
                if ($back_path !== '') {
                    $back_file = __DIR__ . '/' . ltrim($back_path, '/');
                    if (is_file($back_file)) {
                        @unlink($back_file);
                    }
                }
                $error = (string)($result['message'] ?? 'Could not submit profile update request.');
            }
        } else {
            if ($front_path !== '') {
                $front_file = __DIR__ . '/' . ltrim($front_path, '/');
                if (is_file($front_file)) {
                    @unlink($front_file);
                }
            }
            if ($back_path !== '') {
                $back_file = __DIR__ . '/' . ltrim($back_path, '/');
                if (is_file($back_file)) {
                    @unlink($back_file);
                }
            }
        }
    }
}

$voter = getVoterById($voter_id);
$counties = getCounties();
$current_constituencies = getConstituenciesByCounty((int)($voter['county_id'] ?? 0));
$current_wards = getWardsByConstituency((int)($voter['constituency_id'] ?? 0));
$change_requests = getVoterProfileChangeRequestsByVoter($voter_id);
$csrf_token = getCsrfToken();

if ($can_use_correction_token && !$is_token_flow) {
    $error = 'This correction link is invalid or has expired. Please contact support or request a new link.';
}

require_once 'views/voter_account.view.html';