<?php
/*
 * Overview: Resend Verification
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$message = '';
$error = '';
$email = '';

if (!$conn) {
    $error = 'Database connection failed. Check DB settings in includes/db_connect.php or environment variables.';
}

if ($conn && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $email = sanitize($_POST['email'] ?? '');

    if ($error === '' && isRateLimited('resend_verification', strtolower($email ?: getClientIpAddress()), 5, 30)) {
        $error = 'Too many requests. Please try again later.';
    }

    if ($error === '' && $email !== '') {
        $voter = getVoterByEmail($email);

        if ($voter && $voter['email_verified'] == 0) {
            $token = generateVerificationToken();
            $token_expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));

            $query = "UPDATE voters SET verification_token = ?, verification_token_expires_at = ? WHERE voter_id = ?";
            $stmt = mysqli_prepare($conn, $query);
            if (!$stmt) {
                $error = 'System error. Please try again later.';
                logAuditEvent('system', null, 'resend_verification_prepare_failed', ['email' => $email]);
            }

            if ($error === '') {
                mysqli_stmt_bind_param($stmt, "ssi", $token, $token_expiry, $voter['voter_id']);
                mysqli_stmt_execute($stmt);
            }

            if ($error === '') {
                sendVerificationEmail($email, $token);
                recordRateLimitEvent('resend_verification', strtolower($email), true);
                logAuditEvent('system', null, 'verification_resent', ['email' => $email]);
                $message = 'If your account exists and is pending email verification, a verification email has been sent.';
            }
        } else {
            recordRateLimitEvent('resend_verification', strtolower($email), false);
            $message = 'If your account exists and is pending email verification, a verification email has been sent.';
        }
    }
}

$csrf_token = getCsrfToken();

require_once 'views/resend_verification.view.html';