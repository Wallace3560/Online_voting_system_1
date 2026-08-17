<?php
/*
 * Module: Wards Lookup API
 * Responsibility: Return ward list for a provided constituency id.
 */
require_once __DIR__ . '/../includes/functions.php';
header('Content-Type: application/json; charset=utf-8');

/* Section: Validate required input. */
$constituency_id = isset($_GET['constituency_id']) ? (int)$_GET['constituency_id'] : 0;
if ($constituency_id <= 0) {
    echo json_encode([]);
    exit;
}

/* Section: Return DB-backed JSON payload. */
echo json_encode(getWardsByConstituency($constituency_id));
?>