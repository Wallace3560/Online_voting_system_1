<?php
/*
 * Module: Shared Include Wrappers and Lightweight Helpers
 * Responsibility: Load core function library, apply security headers,
 * and provide minimal compatibility helpers when needed.
 */

/* Section: Load runtime dependencies. */
require_once __DIR__ . '/db_connect.php';
require_once __DIR__ . '/../function.php';

/* Section: Apply global HTTP security policy when available. */
if (function_exists('sendSecurityHeaders')) {
    sendSecurityHeaders();
}

/* Section: Compatibility helper fallbacks. */
if (!function_exists('sanitize')) {
    function sanitize($value) {
        return trim((string)$value);
    }
}

if (!function_exists('getCounties')) {
    function getCounties() {
        global $conn;
        if (!$conn) {
            return [];
        }
        $result = mysqli_query($conn, 'SELECT county_id, county_name FROM counties ORDER BY county_name ASC');
        return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
    }
}

if (!function_exists('getConstituenciesByCounty')) {
    function getConstituenciesByCounty($county_id) {
        global $conn;
        if (!$conn) {
            return [];
        }
        $query = 'SELECT constituency_id, constituency_name FROM constituencies WHERE county_id = ? ORDER BY constituency_name ASC';
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            return [];
        }
        mysqli_stmt_bind_param($stmt, 'i', $county_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
    }
}

if (!function_exists('getWardsByConstituency')) {
    function getWardsByConstituency($constituency_id) {
        global $conn;
        if (!$conn) {
            return [];
        }
        $query = 'SELECT ward_id, ward_name FROM wards WHERE constituency_id = ? ORDER BY ward_name ASC';
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            return [];
        }
        mysqli_stmt_bind_param($stmt, 'i', $constituency_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
    }
}

if (!function_exists('getVoterByEmail')) {
    function getVoterByEmail($email) {
        global $conn;
        if (!$conn) {
            return null;
        }
        $query = 'SELECT * FROM voters WHERE email = ? LIMIT 1';
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            return null;
        }
        mysqli_stmt_bind_param($stmt, 's', $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return $result ? mysqli_fetch_assoc($result) : null;
    }
}
?>