<?php
/*
 * Overview: Admin Login
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

function getAdminLandingPageByRole($role) {
    $role = (string)$role;
    if ($role === 'sub_admin') {
        return 'sub_admin_dashboard.php';
    }
    if ($role === 'election_officer') {
        return 'election_officer_dashboard.php';
    }
    return 'admin_verify_voters.php';
}

if (isset($_SESSION['admin_id'])) {
    $existing_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
    header('Location: ' . getAdminLandingPageByRole($existing_role));
    exit();
}

function clearAdminPreAuthState() {
    unset(
        $_SESSION['admin_preauth_id'],
        $_SESSION['admin_preauth_name'],
        $_SESSION['admin_preauth_email'],
        $_SESSION['admin_preauth_role'],
        $_SESSION['admin_preauth_time'],
        $_SESSION['admin_mfa_setup_secret']
    );
}

$error = '';
$message = '';
$identifier = getClientIpAddress();
$step = 'login';
$mfa_qr_url = '';
$mfa_secret = '';
$pending_admin_name = '';

if (($_GET['logout'] ?? '') === 'success') {
    $message = 'You have logged out successfully.';
}

if (($_GET['reset'] ?? '') === 'success') {
    $message = 'Admin password reset successful. Please login with your new password.';
}

$pending_admin = null;
$preauth_admin_id = (int)($_SESSION['admin_preauth_id'] ?? 0);
$preauth_time = (int)($_SESSION['admin_preauth_time'] ?? 0);
if ($preauth_admin_id > 0 && $preauth_time > 0 && (time() - $preauth_time) <= 600) {
    $pending_admin = getAdminById($preauth_admin_id);
} else {
    clearAdminPreAuthState();
}

if ($pending_admin) {
    $requested_step = sanitize($_GET['step'] ?? '');
    if ($requested_step === 'mfa' && (int)$pending_admin['mfa_enabled'] === 1) {
        $step = 'mfa';
    } elseif ($requested_step === 'setup' && (int)$pending_admin['mfa_enabled'] !== 1) {
        $step = 'setup';
    }

    $pending_admin_name = $pending_admin['full_name'];
    if ($step === 'setup') {
        if (empty($_SESSION['admin_mfa_setup_secret'])) {
            $_SESSION['admin_mfa_setup_secret'] = generateTotpSecret(32);
        }
        $mfa_secret = (string)$_SESSION['admin_mfa_setup_secret'];
        $provision_uri = getTotpProvisioningUri($pending_admin['email'], $mfa_secret);
        $mfa_qr_url = getTotpQrCodeUrl($provision_uri);
    } elseif ($step === 'mfa') {
        $mfa_secret = (string)($pending_admin['mfa_secret'] ?? '');
        if ($mfa_secret !== '') {
            $provision_uri = getTotpProvisioningUri($pending_admin['email'], $mfa_secret);
            $mfa_qr_url = getTotpQrCodeUrl($provision_uri);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = sanitize($_POST['action'] ?? 'admin_login_submit');

    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } elseif ($action === 'admin_login_submit') {
        if (isRateLimited('admin_login', $identifier, 5, 15)) {
            $error = 'Too many failed attempts. Please try again later.';
        }

        if ($error === '') {
            $email = sanitize($_POST['email'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $admin = getAdminByEmail($email);

            if ($admin && password_verify($password, $admin['password'])) {
                $_SESSION['admin_preauth_id'] = (int)$admin['admin_id'];
                $_SESSION['admin_preauth_name'] = $admin['full_name'];
                $_SESSION['admin_preauth_email'] = $admin['email'];
                $_SESSION['admin_preauth_role'] = $admin['admin_role'] ?? 'super_admin';
                $_SESSION['admin_preauth_time'] = time();

                recordRateLimitEvent('admin_login', $identifier, true);

                if ((int)($admin['mfa_enabled'] ?? 0) === 1) {
                    logAuditEvent('admin', (int)$admin['admin_id'], 'admin_password_verified_mfa_required');
                    header('Location: admin_login.php?step=mfa');
                    exit();
                }

                $_SESSION['admin_mfa_setup_secret'] = generateTotpSecret(32);
                logAuditEvent('admin', (int)$admin['admin_id'], 'admin_mfa_setup_required');
                header('Location: admin_login.php?step=setup');
                exit();
            }

            recordRateLimitEvent('admin_login', $identifier, false);
            logAuditEvent('system', null, 'admin_login_failure', ['email' => $email]);
            $error = 'Invalid admin credentials.';
        }
    } elseif ($action === 'setup_mfa_confirm') {
        if (!$pending_admin || (int)($pending_admin['mfa_enabled'] ?? 0) === 1) {
            clearAdminPreAuthState();
            $error = 'MFA setup session expired. Please login again.';
            $step = 'login';
        } else {
            $mfa_secret = (string)($_SESSION['admin_mfa_setup_secret'] ?? '');
            $mfa_code = sanitize($_POST['mfa_code'] ?? '');
            $step = 'setup';

            if ($mfa_secret === '' || !verifyTotpCode($mfa_secret, $mfa_code, 1)) {
                recordRateLimitEvent('admin_mfa_setup', (string)$pending_admin['admin_id'], false);
                $error = 'Invalid authenticator code. Please try again.';
            } else {
                $update_query = "UPDATE admins
                                 SET mfa_enabled = 1,
                                     mfa_secret = ?,
                                     mfa_enabled_at = NOW(),
                                     last_mfa_at = NOW(),
                                     last_login_at = NOW()
                                 WHERE admin_id = ? LIMIT 1";
                $update_stmt = mysqli_prepare($conn, $update_query);

                if (!$update_stmt) {
                    $error = 'Unable to save MFA setup right now.';
                } else {
                    $admin_id = (int)$pending_admin['admin_id'];
                    mysqli_stmt_bind_param($update_stmt, 'si', $mfa_secret, $admin_id);
                    if (!mysqli_stmt_execute($update_stmt)) {
                        $error = 'Unable to save MFA setup right now.';
                    } else {
                        session_regenerate_id(true);
                        $_SESSION['admin_id'] = $admin_id;
                        $_SESSION['admin_name'] = $_SESSION['admin_preauth_name'] ?? $pending_admin['full_name'];
                        $_SESSION['admin_email'] = $_SESSION['admin_preauth_email'] ?? $pending_admin['email'];
                        $_SESSION['admin_role'] = $_SESSION['admin_preauth_role'] ?? ($pending_admin['admin_role'] ?? 'super_admin');

                        clearAdminPreAuthState();
                        recordRateLimitEvent('admin_mfa_setup', (string)$admin_id, true);
                        logAuditEvent('admin', $admin_id, 'admin_login_success_mfa_initialized');

                        $target_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
                        header('Location: ' . getAdminLandingPageByRole($target_role));
                        exit();
                    }
                }
            }
        }
    } elseif ($action === 'verify_mfa') {
        if (!$pending_admin || (int)($pending_admin['mfa_enabled'] ?? 0) !== 1) {
            clearAdminPreAuthState();
            $error = 'MFA verification session expired. Please login again.';
            $step = 'login';
        } else {
            $step = 'mfa';
            $mfa_identifier = 'admin-' . (string)$pending_admin['admin_id'];
            if (isRateLimited('admin_mfa_verify', $mfa_identifier, 5, 10)) {
                $error = 'Too many invalid authenticator attempts. Please login again later.';
            } else {
                $mfa_code = sanitize($_POST['mfa_code'] ?? '');
                $secret = (string)($pending_admin['mfa_secret'] ?? '');
                if (!verifyTotpCode($secret, $mfa_code, 1)) {
                    recordRateLimitEvent('admin_mfa_verify', $mfa_identifier, false);
                    logAuditEvent('admin', (int)$pending_admin['admin_id'], 'admin_mfa_failure');
                    $error = 'Invalid authenticator code.';
                } else {
                    $admin_id = (int)$pending_admin['admin_id'];
                    $update_query = "UPDATE admins SET last_mfa_at = NOW(), last_login_at = NOW() WHERE admin_id = ? LIMIT 1";
                    $update_stmt = mysqli_prepare($conn, $update_query);
                    if ($update_stmt) {
                        mysqli_stmt_bind_param($update_stmt, 'i', $admin_id);
                        mysqli_stmt_execute($update_stmt);
                    }

                    session_regenerate_id(true);
                    $_SESSION['admin_id'] = $admin_id;
                    $_SESSION['admin_name'] = $_SESSION['admin_preauth_name'] ?? $pending_admin['full_name'];
                    $_SESSION['admin_email'] = $_SESSION['admin_preauth_email'] ?? $pending_admin['email'];
                    $_SESSION['admin_role'] = $_SESSION['admin_preauth_role'] ?? ($pending_admin['admin_role'] ?? 'super_admin');

                    clearAdminPreAuthState();
                    recordRateLimitEvent('admin_mfa_verify', $mfa_identifier, true);
                    logAuditEvent('admin', $admin_id, 'admin_login_success_mfa_verified');

                    $target_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
                    header('Location: ' . getAdminLandingPageByRole($target_role));
                    exit();
                }
            }
        }
    } else {
        $error = 'Unsupported login action.';
        $step = 'login';
    }

    // Refresh step-bound values after failed submit.
    $pending_admin = null;
    $preauth_admin_id = (int)($_SESSION['admin_preauth_id'] ?? 0);
    $preauth_time = (int)($_SESSION['admin_preauth_time'] ?? 0);
    if ($preauth_admin_id > 0 && $preauth_time > 0 && (time() - $preauth_time) <= 600) {
        $pending_admin = getAdminById($preauth_admin_id);
    }

    if ($pending_admin) {
        $pending_admin_name = $pending_admin['full_name'];
        if ($step === 'setup') {
            $mfa_secret = (string)($_SESSION['admin_mfa_setup_secret'] ?? '');
            if ($mfa_secret === '') {
                $mfa_secret = generateTotpSecret(32);
                $_SESSION['admin_mfa_setup_secret'] = $mfa_secret;
            }
            $provision_uri = getTotpProvisioningUri($pending_admin['email'], $mfa_secret);
            $mfa_qr_url = getTotpQrCodeUrl($provision_uri);
        } elseif ($step === 'mfa') {
            $mfa_secret = (string)($pending_admin['mfa_secret'] ?? '');
            if ($mfa_secret !== '') {
                $provision_uri = getTotpProvisioningUri($pending_admin['email'], $mfa_secret);
                $mfa_qr_url = getTotpQrCodeUrl($provision_uri);
            }
        }
    } else {
        $step = 'login';
    }
}

$csrf_token = getCsrfToken();
require_once 'views/admin_login.view.html';