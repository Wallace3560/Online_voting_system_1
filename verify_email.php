<?php
/*
 * Overview: Verify Email
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$message = '';
$error = '';
$token = $_GET['token'] ?? '';

if (!$token) {
    header("Location: login.php");
    exit();
}

$voter = getVoterByToken($token);

if ($voter) {
    if ($voter['email_verified'] == 1) {
        $message = "Your email is already verified! Please wait for admin approval.";
    } else {
        if (verifyEmailToken($token)) {
            $message = "Email verified successfully! Your account is now pending admin approval.<br>
                       You will be able to login once an admin verifies your details.";
        } else {
            $error = "Verification failed. Please contact support.";
        }
    }
} else {
    $error = "Invalid verification token!";
}

require_once 'views/verify_email.view.html';