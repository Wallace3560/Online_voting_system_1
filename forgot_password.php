<?php
/*
 * Overview: Forgot Password
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

    $email = strtolower(sanitize($_POST['email'] ?? ''));

    if ($error === '' && isRateLimited('forgot_password', $email ?: getClientIpAddress(), 5, 30)) {
        $error = 'Too many reset requests. Please try again later.';
    }

    if ($error === '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    }

    if ($error === '') {
        $voter = getVoterByEmail($email);

        if ($voter && ($voter['status'] ?? 'active') === 'active') {
            $token = generateVerificationToken();
            $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));

            if (savePasswordResetToken((int)$voter['voter_id'], $token, $expires_at)) {
                sendPasswordResetEmail($email, $token);
                recordRateLimitEvent('forgot_password', $email, true);
                logAuditEvent('system', null, 'password_reset_requested', ['voter_id' => (int)$voter['voter_id']]);
            } else {
                recordRateLimitEvent('forgot_password', $email, false);
                logAuditEvent('system', null, 'password_reset_request_failed', ['email' => $email]);
            }
        } else {
            recordRateLimitEvent('forgot_password', $email, false);
        }

        // Use a generic message to avoid leaking account existence.
        $message = 'If your account exists, a password reset link has been sent to your email.';
    }
}

$csrf_token = getCsrfToken();

require_once 'views/forgot_password.view.html';