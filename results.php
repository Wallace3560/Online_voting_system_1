<?php
/*
 * Overview: Results
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$results_published = areResultsPublished();
$admin_view = isset($_SESSION['admin_id']);
$voter_view = isset($_SESSION['voter_id']);
$results = ($results_published || $admin_view) ? getElectionResultsData() : [];
$turnout = getTurnoutStats();
$election_open = isElectionOpen();

require_once 'views/results.view.html';