<?php
/*
 * Overview: Admin Verify Voters
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

requireAdminAuth();
$admin_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
$can_manage = canManageElection($admin_role);
$can_create_sub_admins = canCreateSubAdmins($admin_role);
$can_submit_manual_votes = canSubmitManualVotes($admin_role);
$can_review_manual_votes = canReviewManualVotes($admin_role);

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $action = sanitize($_POST['action']);
    $admin_actions = ['approve', 'reject', 'set_election_schedule', 'publish_results', 'hide_results', 'add_candidate', 'update_voter', 'force_reject_voter', 'update_candidate', 'archive_reset_election', 'download_archived_results', 'create_by_election', 'add_by_election_candidate', 'close_by_election', 'mark_candidate_deceased', 'create_sub_admin', 'submit_manual_vote_batch', 'review_manual_vote_batch'];

    $sensitive_actions = ['set_election_schedule', 'publish_results', 'hide_results', 'archive_reset_election', 'download_archived_results'];
    if ($error === '' && in_array($action, $admin_actions, true) && !$can_manage) {
        $error = 'Your role does not have permission to perform this action.';
        logAuditEvent('admin', (int)($_SESSION['admin_id'] ?? 0), 'admin_action_forbidden', ['action' => $action, 'role' => $admin_role]);
    } elseif ($error === '' && $admin_role === 'sub_admin' && in_array($action, $sensitive_actions, true)) {
        $error = 'Sub-admin role cannot perform this sensitive action.';
        logAuditEvent('admin', (int)($_SESSION['admin_id'] ?? 0), 'sub_admin_sensitive_action_blocked', ['action' => $action]);
    }

    if ($error === '' && ($action === 'approve' || $action === 'reject') && isset($_POST['voter_id'])) {
        $voter_id = (int)$_POST['voter_id'];
        $rejection_reason = isset($_POST['rejection_reason']) ? sanitize($_POST['rejection_reason']) : null;

        if (verifyVoter($voter_id, $_SESSION['admin_id'], $action, $rejection_reason)) {
            $message = 'Voter ' . ($action === 'approve' ? 'approved' : 'rejected') . ' successfully.';
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_verification_' . $action, [
                'voter_id' => $voter_id,
                'rejection_reason' => $rejection_reason
            ]);
        } else {
            $error = 'Failed to process voter verification.';
        }
    } elseif ($error === '' && $action === 'set_election_schedule') {
        $start_input = sanitize($_POST['election_start_at'] ?? '');
        $end_input = sanitize($_POST['election_end_at'] ?? '');
        $start_ts = $start_input !== '' ? strtotime($start_input) : false;
        $end_ts = $end_input !== '' ? strtotime($end_input) : false;

        if ($start_input === '' || $end_input === '') {
            $error = 'Start and end date/time are required.';
        } elseif ($start_ts === false || $end_ts === false) {
            $error = 'Please provide valid start and end date/time values.';
        } elseif ($end_ts <= $start_ts) {
            $error = 'End date/time must be later than start date/time.';
        } else {
            $normalized_start = date('Y-m-d H:i:s', $start_ts);
            $normalized_end = date('Y-m-d H:i:s', $end_ts);

            $saved_start = setElectionSetting('election_start_at', $normalized_start);
            $saved_end = setElectionSetting('election_end_at', $normalized_end);

            if ($saved_start && $saved_end) {
                setElectionSetting('election_status', 'scheduled');
                $message = 'Election schedule saved successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'election_schedule_updated', [
                    'start_at' => $normalized_start,
                    'end_at' => $normalized_end
                ]);
            } else {
                $error = 'Failed to save election schedule.';
            }
        }
    } elseif ($error === '' && $action === 'publish_results') {
        setElectionSetting('results_published', '1');
        $message = 'Results published for public viewing.';
        logAuditEvent('admin', (int)$_SESSION['admin_id'], 'results_published');
    } elseif ($error === '' && $action === 'hide_results') {
        setElectionSetting('results_published', '0');
        $message = 'Results hidden from public view.';
        logAuditEvent('admin', (int)$_SESSION['admin_id'], 'results_hidden');
    } elseif ($error === '' && $action === 'add_candidate') {
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
                    $error = 'County is required for county-wide positions.';
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
                }
            }

            if ($error === '') {
                $candidate_photo = $photo_upload['path'];
                if (addCandidate($position_id, $full_name, $party_name, $candidate_photo, $county_value, $constituency_value, $ward_value)) {
                    $message = 'Candidate added successfully.';
                    logAuditEvent('admin', (int)$_SESSION['admin_id'], 'candidate_added', [
                        'position_id' => $position_id,
                        'full_name' => $full_name,
                        'party_name' => $party_name,
                        'candidate_photo' => $candidate_photo,
                        'county_id' => $county_value,
                        'constituency_id' => $constituency_value,
                        'ward_id' => $ward_value
                    ]);
                } else {
                    $error = 'Failed to add candidate.';
                }
            }
        }
    } elseif ($error === '' && $action === 'update_voter') {
        $voter_id = (int)($_POST['voter_id'] ?? 0);
        $full_name = sanitize($_POST['full_name'] ?? '');
        $email = sanitize($_POST['email'] ?? '');
        $phone = sanitize($_POST['phone'] ?? '');
        $status = sanitize($_POST['status'] ?? 'active');

        if ($voter_id <= 0 || $full_name === '' || $email === '' || $phone === '') {
            $error = 'Voter id, name, email, and phone are required for update.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please provide a valid voter email address.';
        } elseif (isVoterEmailOrPhoneTaken($voter_id, $email, $phone)) {
            $error = 'Another voter already uses that email or phone number.';
        } else {
            if (updateVoterAdminRecord($voter_id, $full_name, $email, $phone, $status)) {
                $message = 'Voter record updated successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_record_updated', [
                    'voter_id' => $voter_id,
                    'status' => $status
                ]);
            } else {
                $error = 'Failed to update voter record.';
            }
        }
    } elseif ($error === '' && $action === 'force_reject_voter') {
        $voter_id = (int)($_POST['voter_id'] ?? 0);
        $rejection_reason = sanitize($_POST['rejection_reason'] ?? 'Rejected by admin after review.');

        if ($voter_id <= 0) {
            $error = 'Invalid voter selected for rejection.';
        } else {
            if (forceRejectVoter($voter_id, (int)$_SESSION['admin_id'], $rejection_reason)) {
                $message = 'Voter rejected successfully.';
                logAuditEvent('admin', (int)$_SESSION['admin_id'], 'voter_force_rejected', [
                    'voter_id' => $voter_id,
                    'rejection_reason' => $rejection_reason
                ]);
            } else {
                $error = 'Failed to reject voter.';
            }
        }
    } elseif ($error === '' && $action === 'update_candidate') {
        $candidate_id = (int)($_POST['candidate_id'] ?? 0);
        $position_id = (int)($_POST['position_id'] ?? 0);
        $full_name = sanitize($_POST['full_name'] ?? '');
        $party_name = sanitize($_POST['party_name'] ?? '');
        $status = sanitize($_POST['status'] ?? 'active');
        $force_apply_changes = !empty($_POST['force_apply_changes']);

        $county_id = (int)($_POST['county_id'] ?? 0);
        $constituency_id = (int)($_POST['constituency_id'] ?? 0);
        $ward_id = (int)($_POST['ward_id'] ?? 0);

        $selected_position = null;
        $positions = getAllPositions();
        foreach ($positions as $position) {
            if ((int)$position['position_id'] === $position_id) {
                $selected_position = $position;
                break;
            }
        }

        if ($candidate_id <= 0 || !$selected_position || $full_name === '' || $party_name === '') {
            $error = 'Candidate id, position, candidate name, and party are required.';
        } else {
            $scope = $selected_position['scope'];
            $county_value = null;
            $constituency_value = null;
            $ward_value = null;

            if ($scope === 'county') {
                $county_value = $county_id > 0 ? $county_id : null;
                if ($county_value === null) {
                    $error = 'County is required for county-wide positions.';
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
                $update_result = updateCandidateAdminRecord(
                    $candidate_id,
                    $position_id,
                    $full_name,
                    $party_name,
                    $county_value,
                    $constituency_value,
                    $ward_value,
                    $status,
                    $force_apply_changes
                );

                if (!empty($update_result['ok'])) {
                    $message = (string)($update_result['message'] ?? 'Candidate updated successfully.');
                    logAuditEvent('admin', (int)$_SESSION['admin_id'], 'candidate_updated', [
                        'candidate_id' => $candidate_id,
                        'position_id' => $position_id,
                        'status' => $status,
                        'force_apply_changes' => $force_apply_changes ? 1 : 0,
                        'county_id' => $county_value,
                        'constituency_id' => $constituency_value,
                        'ward_id' => $ward_value
                    ]);
                } else {
                    $error = (string)($update_result['message'] ?? 'Failed to update candidate.');
                }
            }
        }
    } elseif ($error === '' && $action === 'archive_reset_election') {
        $archive_year = (int)($_POST['archive_year'] ?? 0);
        $archive_note = sanitize($_POST['archive_note'] ?? '');

        $archive_result = archiveAndResetElectionData($archive_year, (int)$_SESSION['admin_id'], $archive_note);
        if (!empty($archive_result['ok'])) {
            $message = (string)$archive_result['message'];
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'election_archived_and_reset', [
                'archive_year' => $archive_year,
                'archive_note' => $archive_note
            ]);
        } else {
            $error = (string)($archive_result['message'] ?? 'Failed to archive and reset election data.');
        }
    } elseif ($error === '' && $action === 'download_archived_results') {
        $download_year = (int)($_POST['download_year'] ?? 0);
        $rows = getArchivedElectionResultsByYear($download_year);

        if ($download_year <= 0) {
            $error = 'Select a valid year to download archived results.';
        } elseif (empty($rows)) {
            $error = 'No archived results found for the selected year.';
        } else {
            $filename = 'election_results_' . $download_year . '.csv';
            header('Content-Type: text/csv; charset=UTF-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');

            $output = fopen('php://output', 'w');
            if ($output !== false) {
                fputcsv($output, [
                    'Archive Batch',
                    'Election Year',
                    'Position',
                    'Candidate',
                    'Party',
                    'Votes',
                    'Percentage',
                    'Leading',
                    'Position Total Votes',
                    'Registered Voters',
                    'Votes Cast',
                    'Turnout %',
                    'Archived At'
                ]);

                foreach ($rows as $row) {
                    fputcsv($output, [
                        (int)($row['run_id'] ?? 0),
                        (int)($row['election_year'] ?? 0),
                        (string)($row['position_name'] ?? ''),
                        (string)($row['candidate_name'] ?? ''),
                        (string)($row['party_name'] ?? ''),
                        (int)($row['votes'] ?? 0),
                        (float)($row['percentage'] ?? 0),
                        !empty($row['is_leading']) ? 'Yes' : 'No',
                        (int)($row['total_votes_position'] ?? 0),
                        (int)($row['registered_voters'] ?? 0),
                        (int)($row['votes_cast'] ?? 0),
                        (float)($row['turnout_percentage'] ?? 0),
                        (string)($row['run_archived_at'] ?? $row['archived_at'] ?? '')
                    ]);
                }
                fclose($output);
            }

            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'archived_results_downloaded', [
                'download_year' => $download_year,
                'rows' => count($rows)
            ]);
            exit();
        }
    } elseif ($error === '' && $action === 'create_by_election') {
        $position_id = (int)($_POST['by_position_id'] ?? 0);
        $election_title = sanitize($_POST['by_election_title'] ?? '');
        $affected_candidate_name = sanitize($_POST['affected_candidate_name'] ?? '');
        $reason = sanitize($_POST['by_reason'] ?? '');
        $county_id = (int)($_POST['by_county_id'] ?? 0);
        $constituency_id = (int)($_POST['by_constituency_id'] ?? 0);
        $ward_id = (int)($_POST['by_ward_id'] ?? 0);

        $create_result = createByElection(
            $position_id,
            $election_title,
            $affected_candidate_name,
            $reason,
            $county_id,
            $constituency_id,
            $ward_id,
            (int)$_SESSION['admin_id']
        );

        if (!empty($create_result['ok'])) {
            $message = (string)$create_result['message'];
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'by_election_created', [
                'by_election_id' => (int)($create_result['by_election_id'] ?? 0),
                'position_id' => $position_id,
                'county_id' => $county_id,
                'constituency_id' => $constituency_id,
                'ward_id' => $ward_id
            ]);
        } else {
            $error = (string)($create_result['message'] ?? 'Failed to create by-election.');
        }
    } elseif ($error === '' && $action === 'add_by_election_candidate') {
        $by_election_id = (int)($_POST['by_election_id'] ?? 0);
        $full_name = sanitize($_POST['full_name'] ?? '');
        $party_name = sanitize($_POST['party_name'] ?? '');

        if ($by_election_id <= 0 || $full_name === '' || $party_name === '') {
            $error = 'By-election, candidate name, and party are required.';
        } else {
            $photo_upload = saveOptionalCandidatePhotoUpload($_FILES['candidate_photo'] ?? null);
            if (!$photo_upload['ok']) {
                $error = $photo_upload['message'];
            } else {
                $candidate_photo = $photo_upload['path'];
                if (addByElectionCandidate($by_election_id, $full_name, $party_name, $candidate_photo)) {
                    $message = 'By-election candidate added successfully.';
                    logAuditEvent('admin', (int)$_SESSION['admin_id'], 'by_election_candidate_added', [
                        'by_election_id' => $by_election_id,
                        'full_name' => $full_name,
                        'party_name' => $party_name
                    ]);
                } else {
                    $error = 'Failed to add by-election candidate.';
                }
            }
        }
    } elseif ($error === '' && $action === 'close_by_election') {
        $by_election_id = (int)($_POST['by_election_id'] ?? 0);
        if ($by_election_id <= 0) {
            $error = 'Invalid by-election selected.';
        } elseif (closeByElection($by_election_id)) {
            $message = 'By-election closed successfully.';
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'by_election_closed', [
                'by_election_id' => $by_election_id
            ]);
        } else {
            $error = 'Failed to close by-election.';
        }
    } elseif ($error === '' && $action === 'mark_candidate_deceased') {
        $candidate_id = (int)($_POST['candidate_id'] ?? 0);
        $deceased_reason = sanitize($_POST['deceased_reason'] ?? 'Candidate died while in office.');

        $deceased_result = markCandidateDeceasedAndDraftByElection($candidate_id, (int)$_SESSION['admin_id'], $deceased_reason);
        if (!empty($deceased_result['ok'])) {
            $message = (string)$deceased_result['message'];
            logAuditEvent('admin', (int)$_SESSION['admin_id'], 'candidate_marked_deceased', [
                'candidate_id' => $candidate_id,
                'deceased_reason' => $deceased_reason,
                'by_election_id' => (int)($deceased_result['by_election_id'] ?? 0)
            ]);
        } else {
            $error = (string)($deceased_result['message'] ?? 'Failed to mark candidate deceased.');
        }
    } elseif ($error === '' && $action === 'create_sub_admin') {
        if (!$can_create_sub_admins) {
            $error = 'Your role cannot create sub-admins.';
        } else {
            $full_name = sanitize($_POST['full_name'] ?? '');
            $email = sanitize($_POST['email'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $new_role = sanitize($_POST['new_admin_role'] ?? 'sub_admin');

            $create_admin_result = createSubAdmin($full_name, $email, $password, (int)$_SESSION['admin_id'], $new_role);
            if (!empty($create_admin_result['ok'])) {
                $message = (string)$create_admin_result['message'];
            } else {
                $error = (string)($create_admin_result['message'] ?? 'Failed to create sub-admin.');
            }
        }
    } elseif ($error === '' && $action === 'submit_manual_vote_batch') {
        if (!$can_submit_manual_votes) {
            $error = 'Your role cannot submit manual votes.';
        } else {
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
        }
    } elseif ($error === '' && $action === 'review_manual_vote_batch') {
        if (!$can_review_manual_votes) {
            $error = 'Only super-admins can review manual vote batches.';
        } else {
            $batch_id = (int)($_POST['batch_id'] ?? 0);
            $candidate_id = (int)($_POST['candidate_id'] ?? 0);
            $approved_votes = (int)($_POST['approved_votes'] ?? 0);
            $decision = sanitize($_POST['decision'] ?? 'approved');
            $decision_note = sanitize($_POST['decision_note'] ?? '');

            $review_result = reviewManualVoteBatch(
                $batch_id,
                $candidate_id,
                $approved_votes,
                $decision,
                $decision_note,
                (int)$_SESSION['admin_id']
            );

            if (!empty($review_result['ok'])) {
                $message = (string)$review_result['message'];
            } else {
                $error = (string)($review_result['message'] ?? 'Failed to review manual vote batch.');
            }
        }
    }
}

$pending_voters = getPendingVerifications();
$verified_voters = getVerifiedVoters();
$rejected_voters = getRejectedVoters();
$all_voters = getAllRegisteredVoters();
$stats = getVerificationStats();
$positions = getAllPositions();
$counties = getCounties();
$election_open = isElectionOpen();
$results_published = areResultsPublished();
$election_window = getElectionScheduleWindow();
$election_start_at = is_array($election_window) ? (string)$election_window['start_at'] : '';
$election_end_at = is_array($election_window) ? (string)$election_window['end_at'] : '';
$election_start_input = $election_start_at !== '' ? date('Y-m-d\TH:i', strtotime($election_start_at)) : '';
$election_end_input = $election_end_at !== '' ? date('Y-m-d\TH:i', strtotime($election_end_at)) : '';

$election_timeline_label = 'NOT SCHEDULED';
if (is_array($election_window)) {
    $now_ts = time();
    if ($now_ts < (int)$election_window['start_ts']) {
        $election_timeline_label = 'SCHEDULED';
    } elseif ($now_ts <= (int)$election_window['end_ts']) {
        $election_timeline_label = 'LIVE';
    } else {
        $election_timeline_label = 'ENDED';
    }
}

$archived_years = getArchivedElectionYears();
$all_constituencies = getAllConstituencies();
$all_wards = getAllWards();
$by_elections = getByElectionsForAdmin();
$pending_manual_batches = getPendingManualVoteBatches();

$candidate_rows = [];
foreach ($positions as $position) {
    $items = getCandidatesForPosition((int)$position['position_id']);
    foreach ($items as $item) {
        $candidate_rows[] = $item;
    }
}

$csrf_token = getCsrfToken();

require_once 'views/admin_verify_voters.view.html';