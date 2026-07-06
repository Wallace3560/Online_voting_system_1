<?php
/*
 * Overview: Voter Logout
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

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

session_regenerate_id(true);

header('Location: login.php?logout=success');
exit();