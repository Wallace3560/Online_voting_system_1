<?php
/*
 * Module: Email Verification Controller
 * Responsibility: Validate verification tokens and activate voter email status.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$message = '';
$error = '';
$token = $_GET['token'] ?? '';

/* Section: Token presence and verification outcome handling. */
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

/* Section: Render view. */
require_once 'views/verify_email.view.html';