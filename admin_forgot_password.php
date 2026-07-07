<?php
/*
 * Overview: Admin Forgot Password
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

    if ($error === '' && isRateLimited('admin_forgot_password', $email ?: getClientIpAddress(), 5, 30)) {
        $error = 'Too many reset requests. Please try again later.';
    }

    if ($error === '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    }

    if ($error === '') {
        $admin = getAdminByEmail($email);

        if ($admin && ($admin['status'] ?? 'active') === 'active') {
            $token = generateVerificationToken();
            $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours'));

            if (saveAdminPasswordResetToken((int)$admin['admin_id'], $token, $expires_at)) {
                sendAdminPasswordResetEmail($email, $token);
                recordRateLimitEvent('admin_forgot_password', $email, true);
                logAuditEvent('system', null, 'admin_password_reset_requested', ['admin_id' => (int)$admin['admin_id']]);
            } else {
                recordRateLimitEvent('admin_forgot_password', $email, false);
                logAuditEvent('system', null, 'admin_password_reset_request_failed', ['email' => $email]);
            }
        } else {
            recordRateLimitEvent('admin_forgot_password', $email, false);
        }

        $message = 'If your admin account exists, a password reset link has been sent to your email.';
    }
}

$csrf_token = getCsrfToken();
require_once 'views/admin_forgot_password.view.html';