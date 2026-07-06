<?php
/*
 * Overview: Sub Admin Dashboard
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

requireAdminRole(['sub_admin']);

$admin_role = (string)($_SESSION['admin_role'] ?? 'sub_admin');
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
	if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
		$error = 'Invalid request token. Please refresh and try again.';
	} else {
		$action = sanitize($_POST['action']);

		if ($action === 'submit_manual_vote_batch') {
			$batch_title = sanitize($_POST['batch_title'] ?? '');
			$position_id = (int)($_POST['manual_position_id'] ?? 0);
			$county_id = (int)($_POST['manual_county_id'] ?? 0);
			$constituency_id = (int)($_POST['manual_constituency_id'] ?? 0);
			$ward_id = (int)($_POST['manual_ward_id'] ?? 0);
			$proposed_votes = (int)($_POST['proposed_votes'] ?? 0);
			$source_note = sanitize($_POST['source_note'] ?? '');

			$manual_batch_result = submitManualVoteBatch(
				$batch_title,
				$position_id,
				$county_id,
				$constituency_id,
				$ward_id,
				$proposed_votes,
				$source_note,
				(int)$_SESSION['admin_id']
			);

			if (!empty($manual_batch_result['ok'])) {
				$message = (string)$manual_batch_result['message'];
			} else {
				$error = (string)($manual_batch_result['message'] ?? 'Failed to submit manual vote batch.');
			}
		} else {
			$error = 'Unsupported action for sub admin.';
		}
	}
}

$stats = getVerificationStats();
$positions = getAllPositions();
$counties = getCounties();
$all_constituencies = getAllConstituencies();
$all_wards = getAllWards();
$pending_manual_batches = getPendingManualVoteBatches();
$csrf_token = getCsrfToken();

require_once 'views/sub_admin_dashboard.view.html';