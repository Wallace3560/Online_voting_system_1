<?php
/*
 * Overview: Election Officer Dashboard
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

requireAdminRole(['election_officer']);

$admin_role = (string)($_SESSION['admin_role'] ?? 'election_officer');
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
	if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
		$error = 'Invalid request token. Please refresh and try again.';
	} else {
		$action = sanitize($_POST['action']);

		if ($action === 'approve' || $action === 'reject') {
			$voter_id = (int)($_POST['voter_id'] ?? 0);
			$rejection_reason = sanitize($_POST['rejection_reason'] ?? 'Rejected by election officer.');
			if ($voter_id <= 0) {
				$error = 'Invalid voter selected.';
			} elseif (verifyVoter($voter_id, (int)$_SESSION['admin_id'], $action, $rejection_reason)) {
				$message = 'Voter ' . ($action === 'approve' ? 'approved' : 'rejected') . ' successfully.';
			} else {
				$error = 'Failed to update voter verification.';
			}
		} elseif ($action === 'add_candidate') {
			$position_id = (int)($_POST['position_id'] ?? 0);
			$full_name = sanitize($_POST['full_name'] ?? '');
			$party_name = sanitize($_POST['party_name'] ?? '');
			$county_id = (int)($_POST['county_id'] ?? 0);
			$constituency_id = (int)($_POST['constituency_id'] ?? 0);
			$ward_id = (int)($_POST['ward_id'] ?? 0);

			$positions = getAllPositions();
			$selected_position = null;
			foreach ($positions as $position) {
				if ((int)$position['position_id'] === $position_id) {
					$selected_position = $position;
					break;
				}
			}

			if (!$selected_position || $full_name === '' || $party_name === '') {
				$error = 'Position, candidate name, and party are required.';
			} else {
				$scope = $selected_position['scope'];
				$county_value = null;
				$constituency_value = null;
				$ward_value = null;

				if ($scope === 'county') {
					$county_value = $county_id > 0 ? $county_id : null;
					if ($county_value === null) {
						$error = 'County is required for county positions.';
					}
				} elseif ($scope === 'constituency') {
					$constituency_value = $constituency_id > 0 ? $constituency_id : null;
					if ($constituency_value === null) {
						$error = 'Constituency is required for constituency positions.';
					}
				} elseif ($scope === 'ward') {
					$ward_value = $ward_id > 0 ? $ward_id : null;
					if ($ward_value === null) {
						$error = 'Ward is required for ward positions.';
					}
				}

				if ($error === '') {
					$photo_upload = saveCandidatePhotoUpload($_FILES['candidate_photo'] ?? null);
					if (!$photo_upload['ok']) {
						$error = $photo_upload['message'];
					} elseif (addCandidate($position_id, $full_name, $party_name, $photo_upload['path'], $county_value, $constituency_value, $ward_value)) {
						$message = 'Candidate added successfully.';
					} else {
						$error = 'Failed to add candidate.';
					}
				}
			}
		} elseif ($action === 'submit_manual_vote_batch') {
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
			$error = 'Unsupported action for election officer.';
		}
	}
}

$stats = getVerificationStats();
$pending_voters = getPendingVerifications();
$positions = getAllPositions();
$counties = getCounties();
$all_constituencies = getAllConstituencies();
$all_wards = getAllWards();
$pending_manual_batches = getPendingManualVoteBatches();
$csrf_token = getCsrfToken();

require_once 'views/election_officer_dashboard.view.html';