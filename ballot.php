<?php
/*
 * Overview: Ballot
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

if (!isset($_SESSION['voter_id'])) {
    header('Location: login.php');
    exit();
}

$voter_id = (int)$_SESSION['voter_id'];
$voter = getVoterById($voter_id);

if (!$voter || !canLogin($voter_id)) {
    session_destroy();
    header('Location: login.php');
    exit();
}

$message = '';
$error = '';
$is_finalized = voterHasFinalizedVote($voter_id);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'submit_ballot') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } elseif ($is_finalized) {
        $error = 'Your ballot has already been finalized. You cannot vote again.';
    } else {
        $votes = $_POST['votes'] ?? [];
        $vote_result = submitFinalBallot($voter_id, $votes);
        if ($vote_result['ok']) {
            $message = $vote_result['message'];
            $is_finalized = true;
        } else {
            $error = $vote_result['message'];
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'submit_by_election_vote') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    } else {
        $by_election_id = (int)($_POST['by_election_id'] ?? 0);
        $candidate_id = (int)($_POST['by_election_candidate_id'] ?? 0);
        $by_vote_result = submitByElectionVote($voter_id, $by_election_id, $candidate_id);
        if (!empty($by_vote_result['ok'])) {
            $message = (string)$by_vote_result['message'];
        } else {
            $error = (string)($by_vote_result['message'] ?? 'Failed to submit by-election vote.');
        }
    }
}

$ballot = sortBallotByRequiredElectionOrder(getScopedBallot($voter_id));
$by_elections = getActiveByElectionsForVoter($voter_id);
$step_tracker = [];
$step_numbers = [];
$step_total = 0;

foreach ($ballot as $position) {
    if (empty($position['candidates'])) {
        continue;
    }

    $step_total++;
    $position_id = (int)$position['position_id'];
    $step_numbers[$position_id] = $step_total;
    $step_tracker[] = [
        'position_id' => $position_id,
        'position_name' => (string)$position['position_name'],
        'completed' => !empty($position['selected_candidate_id']),
        'state' => 'pending'
    ];
}

$current_step_index = null;
if (!$is_finalized) {
    foreach ($step_tracker as $index => $step) {
        if (empty($step['completed'])) {
            $current_step_index = $index;
            break;
        }
    }
}

foreach ($step_tracker as $index => $step) {
    if (!empty($step['completed']) || $is_finalized) {
        $step_tracker[$index]['state'] = 'completed';
    } elseif ($current_step_index !== null && $index === $current_step_index) {
        $step_tracker[$index]['state'] = 'current';
    } else {
        $step_tracker[$index]['state'] = 'pending';
    }
}

$progress = getBallotProgress($voter_id);
$election_open = isElectionOpen();
$csrf_token = getCsrfToken();

require_once 'views/ballot.view.html';