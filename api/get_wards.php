<?php
/*
 * Overview: Get Wards
 * Purpose: Handles server-side logic for this feature.
 */
require_once __DIR__ . '/../includes/functions.php';
header('Content-Type: application/json; charset=utf-8');

$constituency_id = isset($_GET['constituency_id']) ? (int)$_GET['constituency_id'] : 0;
if ($constituency_id <= 0) {
    echo json_encode([]);
    exit;
}

echo json_encode(getWardsByConstituency($constituency_id));
?>
?>