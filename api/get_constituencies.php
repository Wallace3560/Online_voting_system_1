<?php
/*
 * Module: Constituencies Lookup API
 * Responsibility: Return constituency list for a provided county id.
 */
require_once __DIR__ . '/../includes/functions.php';
header('Content-Type: application/json; charset=utf-8');

/* Section: Validate required input. */
$county_id = isset($_GET['county_id']) ? (int)$_GET['county_id'] : 0;
if ($county_id <= 0) {
    echo json_encode([]);
    exit;
}

/* Section: Return DB-backed JSON payload. */
echo json_encode(getConstituenciesByCounty($county_id));
?>