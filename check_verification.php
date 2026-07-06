<?php
/*
 * Overview: Check Verification
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$error = '';
$status_info = null;

if (!$conn) {
    $error = 'Database connection failed. Check DB settings in includes/db_connect.php or environment variables.';
}

if ($conn && $_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $identifier = sanitize($_POST['identifier'] ?? '');
    
    if ($error === '') {
        $query = "SELECT voter_id, full_name, email, national_id, email_verified, admin_verified, verification_status, rejection_reason
                  FROM voters WHERE national_id = ? OR email = ?";
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            $error = 'System error. Please try again later.';
            logAuditEvent('system', null, 'check_verification_prepare_failed');
        }

        if ($error === '') {
            mysqli_stmt_bind_param($stmt, "ss", $identifier, $identifier);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if ($voter = mysqli_fetch_assoc($result)) {
                $status_info = $voter;
            } else {
                $error = "No voter found with the provided National ID or Email!";
            }
        }
    }
}

$csrf_token = getCsrfToken();

require_once 'views/check_verification.view.html';