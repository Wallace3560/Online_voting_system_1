<?php
/*
 * Overview: Login
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$error = '';
$message = '';

if (($_GET['reset'] ?? '') === 'success') {
    $message = 'Password reset successful. Please login with your new password.';
}

if (($_GET['logout'] ?? '') === 'success' && $message === '') {
    $message = 'You have logged out successfully.';
}

if (!$conn) {
    $error = 'Database connection failed. Check DB settings in includes/db_connect.php or environment variables.';
}

if ($conn && $_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $identifier = sanitize($_POST['identifier'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if ($error === '' && isRateLimited('voter_login', strtolower($identifier), 5, 15)) {
        $error = 'Too many failed login attempts. Please try again later.';
    }
    
    if ($error === '') {
        $query = "SELECT * FROM voters WHERE (national_id = ? OR email = ?) AND status = 'active'";
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            $error = 'System error. Please try again later.';
            logAuditEvent('system', null, 'voter_login_prepare_failed');
        }

        if ($error === '') {
            mysqli_stmt_bind_param($stmt, "ss", $identifier, $identifier);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if ($voter = mysqli_fetch_assoc($result)) {
                if (!canLogin($voter['voter_id'])) {
                    $status = getVerificationStatus($voter['voter_id']);

                    if ($status['email_verified'] == 0) {
                        $error = "Please verify your email before logging in. <a href='resend_verification.php'>Resend verification email</a>";
                    } elseif ($status['verification_status'] == 'rejected') {
                        $error = "Your application has been rejected. Reason: " . htmlspecialchars($status['rejection_reason'] ?? 'Not specified');
                    } else {
                        $error = "Your account is pending admin approval. Please check back later.";
                    }
                } else {
                    $stored_password = (string)($voter['password'] ?? '');
                    $password_meta = password_get_info($stored_password);
                    $is_hashed_password = (int)($password_meta['algo'] ?? 0) !== 0;
                    $is_valid_password = $is_hashed_password
                        ? password_verify($password, $stored_password)
                        : hash_equals($stored_password, (string)$password);

                    // One-time migration: upgrade legacy plaintext passwords to secure hashes.
                    if ($is_valid_password && !$is_hashed_password) {
                        $new_hash = password_hash($password, PASSWORD_DEFAULT);
                        $upgrade_query = "UPDATE voters SET password = ? WHERE voter_id = ? LIMIT 1";
                        $upgrade_stmt = mysqli_prepare($conn, $upgrade_query);
                        if ($upgrade_stmt) {
                            $voter_id = (int)$voter['voter_id'];
                            mysqli_stmt_bind_param($upgrade_stmt, "si", $new_hash, $voter_id);
                            mysqli_stmt_execute($upgrade_stmt);
                        }
                    }

                    if ($is_valid_password) {
                    session_regenerate_id(true);
                    $_SESSION['voter_id'] = $voter['voter_id'];
                    $_SESSION['voter_name'] = $voter['full_name'];
                    $_SESSION['national_id'] = $voter['national_id'];
                    $_SESSION['county_id'] = $voter['county_id'];
                    $_SESSION['constituency_id'] = $voter['constituency_id'];
                    $_SESSION['ward_id'] = $voter['ward_id'];
                    recordRateLimitEvent('voter_login', strtolower($identifier), true);
                    logAuditEvent('voter', (int)$voter['voter_id'], 'voter_login_success');
                    header("Location: ballot.php");
                    exit();
                    }

                    $error = "Invalid credentials!";
                    recordRateLimitEvent('voter_login', strtolower($identifier), false);
                    logAuditEvent('system', null, 'voter_login_failure', ['identifier' => $identifier]);
                }
            } else {
                $error = "Voter not found!";
                recordRateLimitEvent('voter_login', strtolower($identifier), false);
                logAuditEvent('system', null, 'voter_login_failure', ['identifier' => $identifier]);
            }
        }
    }
}

$csrf_token = getCsrfToken();

require_once 'views/login.view.html';