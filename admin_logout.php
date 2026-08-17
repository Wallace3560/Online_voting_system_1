<?php
/*
 * Module: Admin Logout Controller
 * Responsibility: Audit logout, clear privileged session state,
 * and redirect to admin login confirmation.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

/* Section: Audit logout event for active admin identity. */
$admin_id = $_SESSION['admin_id'] ?? null;
if ($admin_id !== null) {
    logAuditEvent('admin', (int)$admin_id, 'admin_logout');
}

/* Section: Destroy admin session attributes and rotate session id. */
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

/* Section: Redirect. */
header('Location: admin_login.php?logout=success');
exit();