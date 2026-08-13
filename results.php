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
$voter_can_view_results = false;
$can_view_results = false;
$counties = getCounties();
$constituencies = [];
$wards = [];
$selected_county_id = isset($_GET['county_id']) ? (int)$_GET['county_id'] : 0;
$selected_constituency_id = isset($_GET['constituency_id']) ? (int)$_GET['constituency_id'] : 0;
$selected_ward_id = isset($_GET['ward_id']) ? (int)$_GET['ward_id'] : 0;
$selected_area_filters = [];
$selected_area_turnout = null;
$selected_area_label = 'Country (National)';
$selected_location_path = 'Country (National)';

if ($selected_county_id > 0) {
	$constituencies = getConstituenciesByCounty($selected_county_id);
	$valid_constituency_ids = array_map(function ($row) {
		return (int)($row['constituency_id'] ?? 0);
	}, $constituencies);

	if (!in_array($selected_constituency_id, $valid_constituency_ids, true)) {
		$selected_constituency_id = 0;
		$selected_ward_id = 0;
	}
}

if ($selected_constituency_id > 0) {
	$wards = getWardsByConstituency($selected_constituency_id);
	$valid_ward_ids = array_map(function ($row) {
		return (int)($row['ward_id'] ?? 0);
	}, $wards);

	if (!in_array($selected_ward_id, $valid_ward_ids, true)) {
		$selected_ward_id = 0;
	}
}

if ($selected_county_id > 0) {
	$selected_area_filters['county_id'] = $selected_county_id;
	$selected_area_label = 'Selected County';
}
if ($selected_constituency_id > 0) {
	$selected_area_filters['constituency_id'] = $selected_constituency_id;
	$selected_area_label = 'Selected Constituency';
}
if ($selected_ward_id > 0) {
	$selected_area_filters['ward_id'] = $selected_ward_id;
	$selected_area_label = 'Selected Ward';
}

$selected_county_name = '';
foreach ($counties as $county_row) {
	if ((int)($county_row['county_id'] ?? 0) === $selected_county_id) {
		$selected_county_name = (string)($county_row['county_name'] ?? '');
		break;
	}
}

$selected_constituency_name = '';
foreach ($constituencies as $constituency_row) {
	if ((int)($constituency_row['constituency_id'] ?? 0) === $selected_constituency_id) {
		$selected_constituency_name = (string)($constituency_row['constituency_name'] ?? '');
		break;
	}
}

$selected_ward_name = '';
foreach ($wards as $ward_row) {
	if ((int)($ward_row['ward_id'] ?? 0) === $selected_ward_id) {
		$selected_ward_name = (string)($ward_row['ward_name'] ?? '');
		break;
	}
}

$location_parts = ['Country (National)'];
if ($selected_county_name !== '') {
	$location_parts[] = $selected_county_name;
}
if ($selected_constituency_name !== '') {
	$location_parts[] = $selected_constituency_name;
}
if ($selected_ward_name !== '') {
	$location_parts[] = $selected_ward_name;
}

$selected_location_path = implode(' > ', $location_parts);
if (!empty($selected_area_filters)) {
	$selected_area_label = $selected_location_path;
}

if ($voter_view) {
	$voter_can_view_results = true;
}

$can_view_results = ($results_published || $admin_view || $voter_can_view_results);
$results = $can_view_results ? getElectionResultsData($selected_area_filters) : [];
$turnout = getTurnoutStats();
$voter_turnout_comparison = [];
$election_open = isElectionOpen();
$flash_message = '';

if (!empty($selected_area_filters)) {
	$selected_area_turnout = buildTurnoutSummaryForScope($selected_area_filters, $selected_area_label);
}

if ($voter_view) {
	$voter_turnout_comparison = getVoterTurnoutComparisonStats((int)$_SESSION['voter_id']);
}

if (!empty($_SESSION['results_flash_message'])) {
	$flash_message = (string)$_SESSION['results_flash_message'];
	unset($_SESSION['results_flash_message']);
}

require_once 'views/results.view.html';