<?php
/*
 * Overview: Admin Candidate Change History
 * Purpose: Displays auditable candidate change history with filters and CSV export.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

requireAdminAuth();
requireAdminRole(['super_admin', 'sub_admin']);

$admin_role = (string)($_SESSION['admin_role'] ?? 'super_admin');
$error = '';

$candidate_id = (int)($_GET['candidate_id'] ?? 0);
$admin_id = (int)($_GET['admin_id'] ?? 0);
$change_type = sanitize($_GET['change_type'] ?? '');
$date_from = sanitize($_GET['date_from'] ?? '');
$date_to = sanitize($_GET['date_to'] ?? '');
$export = sanitize($_GET['export'] ?? '');

$filters = [
    'candidate_id' => $candidate_id,
    'admin_id' => $admin_id,
    'change_type' => $change_type,
    'date_from' => $date_from,
    'date_to' => $date_to
];

$candidate_filter_options = [];
$admin_filter_options = [];
$change_type_options = getCandidateChangeTypes();

$candidate_rows = getCandidateChangeHistory([], 0);
if (!empty($candidate_rows)) {
    $seen = [];
    foreach ($candidate_rows as $row) {
        $cid = (int)($row['candidate_id'] ?? 0);
        if ($cid <= 0 || isset($seen[$cid])) {
            continue;
        }
        $candidate_filter_options[] = [
            'candidate_id' => $cid,
            'candidate_name' => (string)($row['candidate_name'] ?? 'Candidate #' . $cid),
            'party_name' => (string)($row['party_name'] ?? ''),
            'position_name' => (string)($row['position_name'] ?? '')
        ];
        $seen[$cid] = true;
    }
}

$admins_result = mysqli_query($conn, "SELECT admin_id, full_name, admin_role FROM admins WHERE status = 'active' ORDER BY full_name ASC");
$admin_filter_options = $admins_result ? mysqli_fetch_all($admins_result, MYSQLI_ASSOC) : [];

if ($export === 'csv') {
    $rows = getCandidateChangeHistory($filters, 0);
    $filename = 'candidate_change_history_' . date('Ymd_His') . '.csv';

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    $output = fopen('php://output', 'w');
    if ($output !== false) {
        fputcsv($output, ['Change ID', 'Date Time', 'Candidate', 'Party', 'Position', 'Changed By', 'Admin Role', 'Change Type', 'Reason']);
        foreach ($rows as $row) {
            fputcsv($output, [
                (int)($row['change_id'] ?? 0),
                (string)($row['created_at'] ?? ''),
                (string)($row['candidate_name'] ?? ''),
                (string)($row['party_name'] ?? ''),
                (string)($row['position_name'] ?? ''),
                (string)($row['admin_name'] ?? 'Admin'),
                (string)($row['admin_role'] ?? ''),
                (string)($row['change_type'] ?? ''),
                (string)($row['change_reason'] ?? '')
            ]);
        }
        fclose($output);
    }

    logAuditEvent('admin', (int)($_SESSION['admin_id'] ?? 0), 'candidate_change_history_csv_exported', $filters);
    exit();
}

$history_rows = getCandidateChangeHistory($filters, 500);
$csrf_token = getCsrfToken();

require_once 'views/admin_candidate_change_history.view.html';
