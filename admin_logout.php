<?php
/*
 * Overview: Admin Logout
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$admin_id = $_SESSION['admin_id'] ?? null;
if ($admin_id !== null) {
    logAuditEvent('admin', (int)$admin_id, 'admin_logout');
}

unset(
    $_SESSION['admin_id'],
    $_SESSION['admin_name'],
    $_SESSION['admin_email'],
    $_SESSION['admin_role'],
    $_SESSION['admin_preauth_id'],
    $_SESSION['admin_preauth_name'],
    $_SESSION['admin_preauth_email'],
    $_SESSION['admin_preauth_role'],
    $_SESSION['admin_preauth_time'],
    $_SESSION['admin_mfa_setup_secret']
);
session_regenerate_id(true);

header('Location: admin_login.php?logout=success');
exit();