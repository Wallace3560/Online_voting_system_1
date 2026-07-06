<?php
/*
 * Overview: Db Connect
 * Purpose: Handles server-side logic for this feature.
 */
if (session_status() === PHP_SESSION_NONE) {
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
    ini_set('session.cookie_lifetime', '0');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $is_https,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_start();
}

$db_host = getenv('DB_HOST') ?: '';
$db_user = getenv('DB_USER') ?: '';
$db_pass = getenv('DB_PASS');
$db_name = getenv('DB_NAME') ?: '';
$db_port = (int)(getenv('DB_PORT') ?: 3306);

if ($db_port <= 0) {
    $db_port = 3306;
}

$conn = null;

$hosts_to_try = array_values(array_unique(array_filter([
    $db_host,
    '127.0.0.1',
    'localhost'
])));

$users_to_try = array_values(array_unique(array_filter([
    $db_user,
    'root'
])));

$passes_to_try = [];
if ($db_pass !== false && $db_pass !== null) {
    $passes_to_try[] = $db_pass;
}
$passes_to_try[] = '';
$passes_to_try = array_values(array_unique($passes_to_try));

$db_names_to_try = array_values(array_unique(array_filter([
    $db_name,
    'online_voting_system'
])));

foreach ($hosts_to_try as $host) {
    foreach ($users_to_try as $user) {
        foreach ($passes_to_try as $pass) {
            foreach ($db_names_to_try as $name) {
                $conn = @mysqli_connect($host, $user, $pass, $name, $db_port);
                if ($conn) {
                    mysqli_set_charset($conn, 'utf8mb4');
                    break 4;
                }

                $server_conn = @mysqli_connect($host, $user, $pass, null, $db_port);
                if ($server_conn) {
                    $safe_name = mysqli_real_escape_string($server_conn, $name);
                    @mysqli_query($server_conn, "CREATE DATABASE IF NOT EXISTS `{$safe_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    @mysqli_close($server_conn);

                    $conn = @mysqli_connect($host, $user, $pass, $name, $db_port);
                    if ($conn) {
                        mysqli_set_charset($conn, 'utf8mb4');
                        break 4;
                    }
                }
            }
        }
    }
}
?>
?>