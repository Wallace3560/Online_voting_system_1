<?php
/*
 * Module: Voter Logout Controller
 * Responsibility: Audit voter sign-out, clear voter session state,
 * and redirect to login confirmation.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

/* Section: Audit active logout event. */
$voter_id = $_SESSION['voter_id'] ?? null;
if ($voter_id !== null) {
    logAuditEvent('voter', (int)$voter_id, 'voter_logout');
}

unset(
    $_SESSION['voter_id'],
    $_SESSION['voter_name'],
    $_SESSION['national_id'],
    $_SESSION['county_id'],
    $_SESSION['constituency_id'],
    $_SESSION['ward_id']
);

/* Section: Rotate session and redirect. */
session_regenerate_id(true);

header('Location: login.php?logout=success');
exit();