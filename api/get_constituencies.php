<?php
/*
 * Overview: Get Constituencies
 * Purpose: Handles server-side logic for this feature.
 */
require_once __DIR__ . '/../includes/functions.php';
header('Content-Type: application/json; charset=utf-8');

$county_id = isset($_GET['county_id']) ? (int)$_GET['county_id'] : 0;
if ($county_id <= 0) {
    echo json_encode([]);
    exit;
}

echo json_encode(getConstituenciesByCounty($county_id));
?>