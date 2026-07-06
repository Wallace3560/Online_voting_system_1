<?php
/*
 * Overview: Reset Password
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$message = '';
$error = '';
$token = sanitize($_GET['token'] ?? $_POST['token'] ?? '');
$token_valid = false;

if (!$conn) {
    $error = 'Database connection failed. Check DB settings in includes/db_connect.php or environment variables.';
}

$voter = null;
if ($conn && $token !== '') {
    $voter = getVoterByPasswordResetToken($token);
    $token_valid = $voter !== null;
}

if ($conn && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $new_password = (string)($_POST['new_password'] ?? '');
    $confirm_password = (string)($_POST['confirm_password'] ?? '');

    if ($error === '' && !$token_valid) {
        $error = 'This reset link is invalid or has expired. Please request a new one.';
    }

    if ($error === '' && strlen($new_password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    }

    if ($error === '' && !hash_equals($new_password, $confirm_password)) {
        $error = 'Passwords do not match.';
    }

    if ($error === '' && $voter) {
        $updated = updateVoterPassword((int)$voter['voter_id'], $new_password);
        if ($updated) {
            clearPasswordResetToken((int)$voter['voter_id']);
            logAuditEvent('voter', (int)$voter['voter_id'], 'password_reset_success');
            header('Location: login.php?reset=success');
            exit();
        }

        $error = 'Unable to reset password right now. Please try again.';
    }
}

require_once 'views/reset_password.view.html';