<?php
/*
 * Overview: Function
 * Purpose: Handles server-side logic for this feature.
 */
function hasDbConnection() {
    global $conn;
    return ($conn instanceof mysqli);
}

function sendSecurityHeaders() {
    if (headers_sent()) {
        return;
    }

    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    header('X-XSS-Protection: 0');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
    if ($is_https) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    $csp = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        . "img-src 'self' data: https:; "
        . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        . "font-src 'self' https://fonts.gstatic.com data:; "
        . "script-src 'self' 'unsafe-inline'; connect-src 'self';";
    header('Content-Security-Policy: ' . $csp);
}

function generateVerificationToken() {
    return bin2hex(random_bytes(32));
}

function getMailConfigFileValues() {
    $config_path = __DIR__ . '/includes/mail_config.php';
    if (!is_file($config_path)) {
        return [];
    }

    $loaded = require $config_path;
    return is_array($loaded) ? $loaded : [];
}

function getSystemEmailConfig() {
    $file_cfg = getMailConfigFileValues();

    $from_email = getenv('MAIL_FROM_ADDRESS') ?: (string)($file_cfg['MAIL_FROM_ADDRESS'] ?? 'iebconlinevotingsystem@gmail.com');
    $from_name = getenv('MAIL_FROM_NAME') ?: (string)($file_cfg['MAIL_FROM_NAME'] ?? 'Online Voting System');
    $smtp_host = getenv('MAIL_SMTP_HOST') ?: (string)($file_cfg['MAIL_SMTP_HOST'] ?? '');
    $smtp_port = (int)(getenv('MAIL_SMTP_PORT') ?: (string)($file_cfg['MAIL_SMTP_PORT'] ?? 0));
    $smtp_username = getenv('MAIL_SMTP_USERNAME') ?: (string)($file_cfg['MAIL_SMTP_USERNAME'] ?? '');
    $smtp_password = getenv('MAIL_SMTP_PASSWORD') ?: (string)($file_cfg['MAIL_SMTP_PASSWORD'] ?? '');
    $smtp_encryption = strtolower((string)(getenv('MAIL_SMTP_ENCRYPTION') ?: (string)($file_cfg['MAIL_SMTP_ENCRYPTION'] ?? 'tls')));
    $smtp_timeout = (int)(getenv('MAIL_SMTP_TIMEOUT') ?: (string)($file_cfg['MAIL_SMTP_TIMEOUT'] ?? 15));

    if (!in_array($smtp_encryption, ['tls', 'ssl', 'none'], true)) {
        $smtp_encryption = 'tls';
    }

    if ($smtp_timeout <= 0) {
        $smtp_timeout = 15;
    }

    return [
        'from_email' => $from_email,
        'from_name' => $from_name,
        'smtp_host' => $smtp_host,
        'smtp_port' => $smtp_port > 0 ? $smtp_port : 587,
        'smtp_username' => $smtp_username,
        'smtp_password' => $smtp_password,
        'smtp_encryption' => $smtp_encryption,
        'smtp_timeout' => $smtp_timeout
    ];
}

function smtpReadResponse($socket) {
    $response = '';
    while (!feof($socket)) {
        $line = fgets($socket, 515);
        if ($line === false) {
            break;
        }
        $response .= $line;
        if (strlen($line) >= 4 && $line[3] === ' ') {
            break;
        }
    }
    return $response;
}

function smtpCommand($socket, $command, $expected_codes) {
    if ($command !== '') {
        fwrite($socket, $command . "\r\n");
    }

    $response = smtpReadResponse($socket);
    if ($response === '' || strlen($response) < 3) {
        return [false, $response];
    }

    $code = (int)substr($response, 0, 3);
    $expected = is_array($expected_codes) ? $expected_codes : [$expected_codes];
    return [in_array($code, $expected, true), $response];
}

function sendSystemEmailViaSmtp($cfg, $to_email, $subject, $message_text) {
    $host = (string)$cfg['smtp_host'];
    $port = (int)$cfg['smtp_port'];
    $username = (string)$cfg['smtp_username'];
    $password = (string)$cfg['smtp_password'];
    $encryption = (string)$cfg['smtp_encryption'];
    $timeout = (int)$cfg['smtp_timeout'];
    $from_email = (string)$cfg['from_email'];
    $from_name = str_replace(["\r", "\n"], '', (string)$cfg['from_name']);

    if ($host === '' || $username === '' || $password === '') {
        return false;
    }

    $remote = ($encryption === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false
        ]
    ]);

    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
    if (!$socket) {
        error_log('SMTP connect failed: ' . $errstr . ' (' . $errno . ')');
        return false;
    }

    stream_set_timeout($socket, $timeout);

    [$ok, $resp] = smtpCommand($socket, '', [220]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP greeting failed: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, 'EHLO localhost', [250]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP EHLO failed: ' . trim($resp));
        return false;
    }

    if ($encryption === 'tls') {
        [$ok, $resp] = smtpCommand($socket, 'STARTTLS', [220]);
        if (!$ok) {
            fclose($socket);
            error_log('SMTP STARTTLS failed: ' . trim($resp));
            return false;
        }

        $crypto_ok = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($crypto_ok !== true) {
            fclose($socket);
            error_log('SMTP TLS negotiation failed.');
            return false;
        }

        [$ok, $resp] = smtpCommand($socket, 'EHLO localhost', [250]);
        if (!$ok) {
            fclose($socket);
            error_log('SMTP EHLO after TLS failed: ' . trim($resp));
            return false;
        }
    }

    [$ok, $resp] = smtpCommand($socket, 'AUTH LOGIN', [334]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP AUTH LOGIN failed: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, base64_encode($username), [334]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP username rejected: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, base64_encode($password), [235]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP password rejected: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, 'MAIL FROM:<' . $from_email . '>', [250]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP MAIL FROM failed: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, 'RCPT TO:<' . $to_email . '>', [250, 251]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP RCPT TO failed: ' . trim($resp));
        return false;
    }

    [$ok, $resp] = smtpCommand($socket, 'DATA', [354]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP DATA failed: ' . trim($resp));
        return false;
    }

    $safe_subject = str_replace(["\r", "\n"], '', (string)$subject);
    $body = preg_replace("/(\r\n|\r|\n)/", "\r\n", (string)$message_text);
    $body = preg_replace('/^\./m', '..', $body);
    $data = '';
    $data .= 'Date: ' . date('r') . "\r\n";
    $data .= 'From: ' . $from_name . ' <' . $from_email . '>' . "\r\n";
    $data .= 'To: <' . $to_email . '>' . "\r\n";
    $data .= 'Subject: ' . $safe_subject . "\r\n";
    $data .= "MIME-Version: 1.0\r\n";
    $data .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $data .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
    $data .= $body . "\r\n.\r\n";
    fwrite($socket, $data);

    [$ok, $resp] = smtpCommand($socket, '', [250]);
    if (!$ok) {
        fclose($socket);
        error_log('SMTP message send failed: ' . trim($resp));
        return false;
    }

    smtpCommand($socket, 'QUIT', [221]);
    fclose($socket);
    return true;
}

function sendSystemEmail($to_email, $subject, $message_text) {
    $cfg = getSystemEmailConfig();

    if (sendSystemEmailViaSmtp($cfg, $to_email, $subject, $message_text)) {
        return true;
    }

    // Fallback to local mail transport when SMTP is unavailable.
    $from_email = (string)$cfg['from_email'];
    @ini_set('sendmail_from', $from_email);

    $safe_from_name = str_replace(["\r", "\n"], '', (string)$cfg['from_name']);
    $safe_from_email = str_replace(["\r", "\n"], '', $from_email);
    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'From: ' . $safe_from_name . ' <' . $safe_from_email . '>',
        'Reply-To: ' . $safe_from_email,
        'X-Mailer: PHP/' . phpversion()
    ];

    return @mail((string)$to_email, (string)$subject, (string)$message_text, implode("\r\n", $headers));
}

function sendVerificationEmail($email, $token) {
    $verification_link = getAppBaseUrl() . '/verify_email.php?token=' . urlencode($token);
    $subject = 'Verify Your Email - Online Voting System';
    $message = "Hello,\n\n"
        . "Thank you for registering.\n\n"
        . "Verify your email address using the link below:\n"
        . $verification_link . "\n\n"
        . "This verification link expires in 24 hours.\n\n"
        . "Online Voting System";

    $sent = sendSystemEmail($email, $subject, $message);
    if (!$sent) {
        error_log('Verification email delivery failed for ' . $email . '. Verification link: ' . $verification_link);
    }

    return $sent;
}

function getAppBaseUrl() {
    $file_cfg = getMailConfigFileValues();
    $configured_base = getenv('APP_BASE_URL') ?: (string)($file_cfg['APP_BASE_URL'] ?? '');
    if ($configured_base !== '') {
        return rtrim($configured_base, '/');
    }

    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
    $scheme = $is_https ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? '127.0.0.1';
    $path = str_replace('\\', '/', dirname($_SERVER['PHP_SELF'] ?? '/'));
    $path = rtrim($path, '/');
    return $scheme . $host . $path;
}

function sendPasswordResetEmail($email, $token) {
    $reset_link = getAppBaseUrl() . '/reset_password.php?token=' . urlencode($token);
    $subject = 'Password Reset Request - Online Voting System';
    $message = "Hello,\n\n"
        . "We received a request to reset your password.\n\n"
        . "Use the link below to reset your password:\n"
        . $reset_link . "\n\n"
        . "This link expires in 1 hour.\n"
        . "If you did not request this, you can ignore this email.\n\n"
        . "Online Voting System";

    $sent = sendSystemEmail($email, $subject, $message);

    // Fallback trace for local/dev environments where mail() is not configured.
    if (!$sent) {
        error_log('Password reset email delivery failed for ' . $email . '. Reset link: ' . $reset_link);
    }

    return $sent;
}

function sendAdminPasswordResetEmail($email, $token) {
    $reset_link = getAppBaseUrl() . '/admin_reset_password.php?token=' . urlencode($token);
    $subject = 'Admin Password Reset Request - Online Voting System';
    $message = "Hello,\n\n"
        . "We received a request to reset your admin password.\n\n"
        . "Use the link below to reset your password:\n"
        . $reset_link . "\n\n"
        . "This link expires in 1 hour.\n"
        . "If you did not request this, you can ignore this email.\n\n"
        . "Online Voting System";

    $sent = sendSystemEmail($email, $subject, $message);
    if (!$sent) {
        error_log('Admin password reset email delivery failed for ' . $email . '. Reset link: ' . $reset_link);
    }

    return $sent;
}

function getActiveAdminEmails() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT email FROM admins WHERE status = 'active' AND email <> '' ORDER BY admin_id ASC";
    $result = mysqli_query($conn, $query);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    $emails = [];
    foreach ($rows as $row) {
        $email = trim((string)($row['email'] ?? ''));
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $emails[strtolower($email)] = $email;
        }
    }

    return array_values($emails);
}

function sendProfileChangeRequestNotificationsToAdmins($voter, $reason, $requested_data) {
    $admin_emails = getActiveAdminEmails();
    if (empty($admin_emails)) {
        return false;
    }

    $subject = 'New Voter Profile Change Request';
    $message = "A voter has requested profile changes and requires admin approval.\n\n"
        . "Voter Name: " . (string)($voter['full_name'] ?? '') . "\n"
        . "National ID: " . (string)($voter['national_id'] ?? '') . "\n"
        . "Current Email: " . (string)($voter['email'] ?? '') . "\n"
        . "Reason: " . (string)$reason . "\n\n"
        . "Requested Details:\n"
        . "- Full Name: " . (string)($requested_data['full_name'] ?? '') . "\n"
        . "- Email: " . (string)($requested_data['email'] ?? '') . "\n"
        . "- Phone: " . (string)($requested_data['phone'] ?? '') . "\n"
        . "- Date of Birth: " . (string)($requested_data['date_of_birth'] ?? '') . "\n"
        . "- County ID: " . (string)($requested_data['county_id'] ?? '') . "\n"
        . "- Constituency ID: " . (string)($requested_data['constituency_id'] ?? '') . "\n"
        . "- Ward ID: " . (string)($requested_data['ward_id'] ?? '') . "\n\n"
        . "Review in admin panel: " . getAppBaseUrl() . "/admin_manage_voters.php\n\n"
        . "Online Voting System";

    $any_sent = false;
    foreach ($admin_emails as $admin_email) {
        if (sendSystemEmail($admin_email, $subject, $message)) {
            $any_sent = true;
        }
    }

    return $any_sent;
}

function sendProfileChangeDecisionEmailToVoter($email, $decision, $decision_note = '') {
    $normalized_decision = strtolower(trim((string)$decision));
    if ($normalized_decision !== 'approved' && $normalized_decision !== 'rejected') {
        return false;
    }

    $subject = $normalized_decision === 'approved'
        ? 'Profile Update Request Approved'
        : 'Profile Update Request Rejected';

    $message = "Hello,\n\n";
    if ($normalized_decision === 'approved') {
        $message .= "Your profile update request has been approved and your account details were updated successfully.\n\n";
    } else {
        $message .= "Your profile update request has been reviewed and rejected by an administrator.\n\n";
    }

    if ($decision_note !== '') {
        $message .= "Admin Note: " . $decision_note . "\n\n";
    }

    $message .= "You can sign in and view request status here:\n"
        . getAppBaseUrl() . "/voter_account.php\n\n"
        . "Online Voting System";

    return sendSystemEmail((string)$email, $subject, $message);
}

function hashResetToken($token) {
    return hash('sha256', (string)$token);
}

function getVoterByPasswordResetToken($token) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }

    $token_hash = hashResetToken($token);
    $query = "SELECT * FROM voters
              WHERE password_reset_token_hash = ?
                AND password_reset_expires_at IS NOT NULL
                AND password_reset_expires_at >= NOW()
                AND status = 'active'
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, 's', $token_hash);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function getAdminByPasswordResetToken($token) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }

    $token_hash = hashResetToken($token);
    $query = "SELECT * FROM admins
              WHERE admin_password_reset_token_hash = ?
                AND admin_password_reset_expires_at IS NOT NULL
                AND admin_password_reset_expires_at >= NOW()
                AND status = 'active'
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, 's', $token_hash);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function savePasswordResetToken($voter_id, $raw_token, $expires_at) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $token_hash = hashResetToken($raw_token);
    $query = "UPDATE voters
              SET password_reset_token_hash = ?,
                  password_reset_expires_at = ?,
                  password_reset_requested_at = NOW()
              WHERE voter_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'ssi', $token_hash, $expires_at, $voter_id);
    return mysqli_stmt_execute($stmt);
}

function saveAdminPasswordResetToken($admin_id, $raw_token, $expires_at) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $token_hash = hashResetToken($raw_token);
    $query = "UPDATE admins
              SET admin_password_reset_token_hash = ?,
                  admin_password_reset_expires_at = ?,
                  admin_password_reset_requested_at = NOW()
              WHERE admin_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'ssi', $token_hash, $expires_at, $admin_id);
    return mysqli_stmt_execute($stmt);
}

function clearPasswordResetToken($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "UPDATE voters
              SET password_reset_token_hash = NULL,
                  password_reset_expires_at = NULL,
                  password_reset_requested_at = NULL
              WHERE voter_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'i', $voter_id);
    return mysqli_stmt_execute($stmt);
}

function clearAdminPasswordResetToken($admin_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "UPDATE admins
              SET admin_password_reset_token_hash = NULL,
                  admin_password_reset_expires_at = NULL,
                  admin_password_reset_requested_at = NULL
              WHERE admin_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'i', $admin_id);
    return mysqli_stmt_execute($stmt);
}

function updateVoterPassword($voter_id, $plain_password) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $password_hash = password_hash($plain_password, PASSWORD_DEFAULT);
    $query = "UPDATE voters SET password = ? WHERE voter_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'si', $password_hash, $voter_id);
    return mysqli_stmt_execute($stmt);
}

function updateAdminPassword($admin_id, $plain_password) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $password_hash = password_hash($plain_password, PASSWORD_DEFAULT);
    $query = "UPDATE admins SET password = ? WHERE admin_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, 'si', $password_hash, $admin_id);
    return mysqli_stmt_execute($stmt);
}

function verifyEmailToken($token) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "UPDATE voters
              SET email_verified = 1, verification_token = NULL, verification_token_expires_at = NULL
              WHERE verification_token = ?
                AND email_verified = 0
                AND (verification_token_expires_at IS NULL OR verification_token_expires_at >= NOW())";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "s", $token);
    return mysqli_stmt_execute($stmt);
}

function getPendingVerifications() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT v.*, co.county_name, cn.constituency_name, w.ward_name
              FROM voters v
              JOIN counties co ON v.county_id = co.county_id
              JOIN constituencies cn ON v.constituency_id = cn.constituency_id
              JOIN wards w ON v.ward_id = w.ward_id
              WHERE v.verification_status = 'pending' AND v.email_verified = 1
              ORDER BY v.registration_date ASC";
    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getVerifiedVoters() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT v.*, co.county_name, cn.constituency_name, w.ward_name, a.full_name as verified_by_name
              FROM voters v
              JOIN counties co ON v.county_id = co.county_id
              JOIN constituencies cn ON v.constituency_id = cn.constituency_id
              JOIN wards w ON v.ward_id = w.ward_id
              LEFT JOIN admins a ON v.verified_by = a.admin_id
              WHERE v.verification_status = 'verified'
              ORDER BY v.verified_at DESC";
    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getRejectedVoters() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT v.*, co.county_name, cn.constituency_name, w.ward_name, a.full_name as verified_by_name
              FROM voters v
              JOIN counties co ON v.county_id = co.county_id
              JOIN constituencies cn ON v.constituency_id = cn.constituency_id
              JOIN wards w ON v.ward_id = w.ward_id
              LEFT JOIN admins a ON v.verified_by = a.admin_id
              WHERE v.verification_status = 'rejected'
              ORDER BY v.verified_at DESC";
    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getAllRegisteredVoters() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT v.*, co.county_name, cn.constituency_name, w.ward_name,
                     a.full_name as verified_by_name,
                     (SELECT COUNT(*) FROM votes x WHERE x.voter_id = v.voter_id) AS votes_count
              FROM voters v
              LEFT JOIN counties co ON v.county_id = co.county_id
              LEFT JOIN constituencies cn ON v.constituency_id = cn.constituency_id
              LEFT JOIN wards w ON v.ward_id = w.ward_id
              LEFT JOIN admins a ON v.verified_by = a.admin_id
              WHERE v.status = 'active'
              ORDER BY v.registration_date DESC, v.voter_id DESC";
    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function updateVoterAdminRecord($voter_id, $full_name, $email, $phone, $status = 'active') {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $status = in_array($status, ['active', 'inactive'], true) ? $status : 'active';
    // National ID is intentionally immutable after registration.
    $query = "UPDATE voters
              SET full_name = ?, email = ?, phone = ?, status = ?
              WHERE voter_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "ssssi", $full_name, $email, $phone, $status, $voter_id);
    return mysqli_stmt_execute($stmt);
}

function isVoterEmailOrPhoneTaken($voter_id, $email, $phone) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "SELECT 1 FROM voters WHERE (email = ? OR phone = ?) AND voter_id <> ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "ssi", $email, $phone, $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result && mysqli_num_rows($result) > 0;
}

function findDuplicateRegistration($national_id, $email, $phone, $full_name, $dob, $county_id, $constituency_id, $ward_id) {
    global $conn;
    if (!hasDbConnection()) {
        return ['has_duplicate' => false, 'reason' => ''];
    }

    $query = "SELECT voter_id,
                     national_id,
                     email,
                     phone,
                     full_name,
                     date_of_birth,
                     county_id,
                     constituency_id,
                     ward_id
              FROM voters
              WHERE national_id = ?
                 OR email = ?
                 OR phone = ?
                 OR (
                    full_name = ?
                    AND date_of_birth = ?
                    AND county_id = ?
                    AND constituency_id = ?
                    AND ward_id = ?
                 )
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['has_duplicate' => false, 'reason' => ''];
    }

    mysqli_stmt_bind_param(
        $stmt,
        "sssssiii",
        $national_id,
        $email,
        $phone,
        $full_name,
        $dob,
        $county_id,
        $constituency_id,
        $ward_id
    );
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result ? mysqli_fetch_assoc($result) : null;

    if (!$row) {
        return ['has_duplicate' => false, 'reason' => ''];
    }

    if ((string)$row['national_id'] === (string)$national_id) {
        return ['has_duplicate' => true, 'reason' => 'National ID already registered.'];
    }
    if (strcasecmp((string)$row['email'], (string)$email) === 0) {
        return ['has_duplicate' => true, 'reason' => 'Email already registered.'];
    }
    if ((string)$row['phone'] === (string)$phone) {
        return ['has_duplicate' => true, 'reason' => 'Phone number already registered.'];
    }

    return ['has_duplicate' => true, 'reason' => 'These registration details already exist in the system.'];
}

function forceRejectVoter($voter_id, $admin_id, $rejection_reason = null) {
    return verifyVoter($voter_id, $admin_id, 'reject', $rejection_reason);
}

function verifyVoter($voter_id, $admin_id, $action, $rejection_reason = null) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $status = ($action === 'approve') ? 'verified' : 'rejected';
    $verified_at = date('Y-m-d H:i:s');
    $admin_verified = ($action === 'approve') ? 1 : 0;

    $query = "UPDATE voters
              SET admin_verified = ?, verification_status = ?, verified_by = ?, verified_at = ?, rejection_reason = ?
              WHERE voter_id = ?";

    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "isissi", $admin_verified, $status, $admin_id, $verified_at, $rejection_reason, $voter_id);
    return mysqli_stmt_execute($stmt);
}

function canLogin($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "SELECT email_verified, admin_verified, verification_status FROM voters WHERE voter_id = ?";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $voter = mysqli_fetch_assoc($result);

    if ($voter) {
        return ((int)$voter['email_verified'] === 1 && (int)$voter['admin_verified'] === 1 && $voter['verification_status'] === 'verified');
    }
    return false;
}

function getVerificationStatus($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
    $query = "SELECT email_verified, admin_verified, verification_status, rejection_reason FROM voters WHERE voter_id = ?";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_assoc($result);
}

function getVoterByToken($token) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
        $query = "SELECT * FROM voters
                            WHERE verification_token = ?
                                AND (verification_token_expires_at IS NULL OR verification_token_expires_at >= NOW())";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "s", $token);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_assoc($result);
}

function getVoterById($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
    $query = "SELECT * FROM voters WHERE voter_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function hasPendingVoterProfileChangeRequest($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "SELECT 1 FROM voter_profile_change_requests WHERE voter_id = ? AND status = 'pending' LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result && mysqli_num_rows($result) > 0;
}

function createVoterProfileChangeRequest($voter_id, $requested_data, $reason) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    if (hasPendingVoterProfileChangeRequest($voter_id)) {
        return ['ok' => false, 'message' => 'You already have a pending profile update request.'];
    }

    $current = getVoterById($voter_id);
    if (!$current) {
        return ['ok' => false, 'message' => 'Voter account not found.'];
    }

    $full_name = sanitize($requested_data['full_name'] ?? '');
    $email = sanitize($requested_data['email'] ?? '');
    $phone = sanitize($requested_data['phone'] ?? '');
    $date_of_birth = sanitize($requested_data['date_of_birth'] ?? '');
    $county_id = (int)($requested_data['county_id'] ?? 0);
    $constituency_id = (int)($requested_data['constituency_id'] ?? 0);
    $ward_id = (int)($requested_data['ward_id'] ?? 0);

    if ($full_name === '' || $email === '' || $phone === '' || $date_of_birth === '' || $county_id <= 0 || $constituency_id <= 0 || $ward_id <= 0) {
        return ['ok' => false, 'message' => 'All profile fields are required.'];
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['ok' => false, 'message' => 'Please provide a valid email address.'];
    }

    if (!preg_match('/^\+?[0-9]{9,15}$/', $phone)) {
        return ['ok' => false, 'message' => 'Phone number must contain 9 to 15 digits (optional + at start).'];
    }

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date_of_birth) || strtotime($date_of_birth) === false || strtotime($date_of_birth) > time()) {
        return ['ok' => false, 'message' => 'Please provide a valid date of birth.'];
    }

    if ($reason === '') {
        return ['ok' => false, 'message' => 'Please provide a reason for your profile update request.'];
    }

    if (isVoterEmailOrPhoneTaken($voter_id, $email, $phone)) {
        return ['ok' => false, 'message' => 'Another voter already uses that email or phone number.'];
    }

    $payload = [
        'full_name' => $full_name,
        'email' => $email,
        'phone' => $phone,
        'date_of_birth' => $date_of_birth,
        'county_id' => $county_id,
        'constituency_id' => $constituency_id,
        'ward_id' => $ward_id
    ];
    $requested_json = json_encode($payload);
    if (!is_string($requested_json) || $requested_json === '') {
        return ['ok' => false, 'message' => 'Could not prepare update request payload.'];
    }

    $query = "INSERT INTO voter_profile_change_requests
              (voter_id, reason, requested_data)
              VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Could not create update request.'];
    }
    mysqli_stmt_bind_param($stmt, "iss", $voter_id, $reason, $requested_json);
    if (!mysqli_stmt_execute($stmt)) {
        return ['ok' => false, 'message' => 'Could not save update request.'];
    }

    $request_id = (int)mysqli_insert_id($conn);
    $admin_notified = sendProfileChangeRequestNotificationsToAdmins($current, $reason, $payload);

    if ($request_id > 0) {
        $notify_query = "UPDATE voter_profile_change_requests
                         SET admin_notification_sent = ?, admin_notification_last_at = NOW()
                         WHERE request_id = ?
                         LIMIT 1";
        $notify_stmt = mysqli_prepare($conn, $notify_query);
        if ($notify_stmt) {
            $admin_sent = $admin_notified ? 1 : 0;
            mysqli_stmt_bind_param($notify_stmt, "ii", $admin_sent, $request_id);
            mysqli_stmt_execute($notify_stmt);
        }
    }

    return ['ok' => true, 'message' => 'Profile update request submitted for admin approval.'];
}

function getVoterProfileChangeRequestsByVoter($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT r.*, a.full_name AS reviewed_by_name
              FROM voter_profile_change_requests r
              LEFT JOIN admins a ON r.reviewed_by = a.admin_id
              WHERE r.voter_id = ?
              ORDER BY r.created_at DESC, r.request_id DESC";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    foreach ($rows as $index => $row) {
        $decoded = json_decode((string)($row['requested_data'] ?? ''), true);
        $rows[$index]['requested_data_parsed'] = is_array($decoded) ? $decoded : [];
    }

    return $rows;
}

function getVoterProfileChangeRequests($status = null) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT r.*, v.full_name AS voter_name, v.national_id, v.email AS current_email, v.phone AS current_phone,
                     a.full_name AS reviewed_by_name
              FROM voter_profile_change_requests r
              JOIN voters v ON r.voter_id = v.voter_id
              LEFT JOIN admins a ON r.reviewed_by = a.admin_id";

    $use_status = is_string($status) && $status !== '';
    if ($use_status) {
        $query .= " WHERE r.status = ?";
    }
    $query .= " ORDER BY r.created_at DESC, r.request_id DESC";

    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    if ($use_status) {
        mysqli_stmt_bind_param($stmt, "s", $status);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    foreach ($rows as $index => $row) {
        $decoded = json_decode((string)($row['requested_data'] ?? ''), true);
        $rows[$index]['requested_data_parsed'] = is_array($decoded) ? $decoded : [];
    }

    return $rows;
}

function approveVoterProfileChangeRequest($request_id, $admin_id, $decision_note = '') {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $query = "SELECT * FROM voter_profile_change_requests WHERE request_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Could not load request.'];
    }
    mysqli_stmt_bind_param($stmt, "i", $request_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $request = $result ? mysqli_fetch_assoc($result) : null;

    if (!$request) {
        return ['ok' => false, 'message' => 'Request not found.'];
    }
    if (($request['status'] ?? '') !== 'pending') {
        return ['ok' => false, 'message' => 'This request has already been reviewed.'];
    }

    $voter_id = (int)$request['voter_id'];
    $voter = getVoterById($voter_id);
    if (!$voter) {
        return ['ok' => false, 'message' => 'Voter account not found.'];
    }

    $requested = json_decode((string)($request['requested_data'] ?? ''), true);
    if (!is_array($requested)) {
        return ['ok' => false, 'message' => 'Request payload is invalid.'];
    }

    $full_name = sanitize($requested['full_name'] ?? '');
    $email = sanitize($requested['email'] ?? '');
    $phone = sanitize($requested['phone'] ?? '');
    $date_of_birth = sanitize($requested['date_of_birth'] ?? '');
    $county_id = (int)($requested['county_id'] ?? 0);
    $constituency_id = (int)($requested['constituency_id'] ?? 0);
    $ward_id = (int)($requested['ward_id'] ?? 0);

    if ($full_name === '' || $email === '' || $phone === '' || $date_of_birth === '' || $county_id <= 0 || $constituency_id <= 0 || $ward_id <= 0) {
        return ['ok' => false, 'message' => 'Requested details are incomplete.'];
    }

    if (isVoterEmailOrPhoneTaken($voter_id, $email, $phone)) {
        return ['ok' => false, 'message' => 'Another voter already uses that email or phone number.'];
    }

    mysqli_begin_transaction($conn);
    try {
        $archive_query = "INSERT INTO previuos_user_data
            (voter_id, national_id, full_name, email, phone, county_id, constituency_id, ward_id, date_of_birth, archived_by_admin_id, change_request_id, archive_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $archive_stmt = mysqli_prepare($conn, $archive_query);
        if (!$archive_stmt) {
            throw new Exception('Could not archive previous voter data.');
        }

        $old_national_id = (string)($voter['national_id'] ?? '');
        $old_full_name = (string)($voter['full_name'] ?? '');
        $old_email = (string)($voter['email'] ?? '');
        $old_phone = (string)($voter['phone'] ?? '');
        $old_county_id = (int)($voter['county_id'] ?? 0);
        $old_constituency_id = (int)($voter['constituency_id'] ?? 0);
        $old_ward_id = (int)($voter['ward_id'] ?? 0);
        $old_dob = (string)($voter['date_of_birth'] ?? '');
        $archive_reason = 'Approved profile change request';

        mysqli_stmt_bind_param(
            $archive_stmt,
            "issssiiisiis",
            $voter_id,
            $old_national_id,
            $old_full_name,
            $old_email,
            $old_phone,
            $old_county_id,
            $old_constituency_id,
            $old_ward_id,
            $old_dob,
            $admin_id,
            $request_id,
            $archive_reason
        );
        if (!mysqli_stmt_execute($archive_stmt)) {
            throw new Exception('Could not archive previous voter data.');
        }

        $update_query = "UPDATE voters
                         SET full_name = ?, email = ?, phone = ?, county_id = ?, constituency_id = ?, ward_id = ?, date_of_birth = ?
                         WHERE voter_id = ?
                         LIMIT 1";
        $update_stmt = mysqli_prepare($conn, $update_query);
        if (!$update_stmt) {
            throw new Exception('Could not update voter details.');
        }
        mysqli_stmt_bind_param($update_stmt, "sssiiisi", $full_name, $email, $phone, $county_id, $constituency_id, $ward_id, $date_of_birth, $voter_id);
        if (!mysqli_stmt_execute($update_stmt)) {
            throw new Exception('Could not update voter details.');
        }

        $reviewed_at = date('Y-m-d H:i:s');
        $status = 'approved';
        $review_query = "UPDATE voter_profile_change_requests
                         SET status = ?, reviewed_by = ?, reviewed_at = ?, decision_note = ?
                         WHERE request_id = ?
                         LIMIT 1";
        $review_stmt = mysqli_prepare($conn, $review_query);
        if (!$review_stmt) {
            throw new Exception('Could not mark request as approved.');
        }
        mysqli_stmt_bind_param($review_stmt, "sissi", $status, $admin_id, $reviewed_at, $decision_note, $request_id);
        if (!mysqli_stmt_execute($review_stmt)) {
            throw new Exception('Could not mark request as approved.');
        }

        mysqli_commit($conn);
        $voter_notified = sendProfileChangeDecisionEmailToVoter((string)($voter['email'] ?? ''), 'approved', (string)$decision_note);
        $notify_query = "UPDATE voter_profile_change_requests
                         SET voter_notification_sent = ?, voter_notification_last_at = NOW()
                         WHERE request_id = ?
                         LIMIT 1";
        $notify_stmt = mysqli_prepare($conn, $notify_query);
        if ($notify_stmt) {
            $voter_sent = $voter_notified ? 1 : 0;
            mysqli_stmt_bind_param($notify_stmt, "ii", $voter_sent, $request_id);
            mysqli_stmt_execute($notify_stmt);
        }
        return ['ok' => true, 'message' => 'Profile change request approved and voter details updated.'];
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function rejectVoterProfileChangeRequest($request_id, $admin_id, $decision_note = '') {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $status = 'rejected';
    $reviewed_at = date('Y-m-d H:i:s');
    $query = "UPDATE voter_profile_change_requests
              SET status = ?, reviewed_by = ?, reviewed_at = ?, decision_note = ?
              WHERE request_id = ? AND status = 'pending'
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Could not process request.'];
    }
    mysqli_stmt_bind_param($stmt, "sissi", $status, $admin_id, $reviewed_at, $decision_note, $request_id);
    if (!mysqli_stmt_execute($stmt)) {
        return ['ok' => false, 'message' => 'Could not process request.'];
    }

    if (mysqli_stmt_affected_rows($stmt) < 1) {
        return ['ok' => false, 'message' => 'Request is not pending or does not exist.'];
    }

    $request_query = "SELECT v.email
                      FROM voter_profile_change_requests r
                      JOIN voters v ON r.voter_id = v.voter_id
                      WHERE r.request_id = ?
                      LIMIT 1";
    $request_stmt = mysqli_prepare($conn, $request_query);
    $voter_notified = false;
    if ($request_stmt) {
        mysqli_stmt_bind_param($request_stmt, "i", $request_id);
        mysqli_stmt_execute($request_stmt);
        $request_result = mysqli_stmt_get_result($request_stmt);
        $request_row = $request_result ? mysqli_fetch_assoc($request_result) : null;
        if ($request_row && !empty($request_row['email'])) {
            $voter_notified = sendProfileChangeDecisionEmailToVoter((string)$request_row['email'], 'rejected', (string)$decision_note);
        }
    }

    $notify_query = "UPDATE voter_profile_change_requests
                     SET voter_notification_sent = ?, voter_notification_last_at = NOW()
                     WHERE request_id = ?
                     LIMIT 1";
    $notify_stmt = mysqli_prepare($conn, $notify_query);
    if ($notify_stmt) {
        $voter_sent = $voter_notified ? 1 : 0;
        mysqli_stmt_bind_param($notify_stmt, "ii", $voter_sent, $request_id);
        mysqli_stmt_execute($notify_stmt);
    }

    return ['ok' => true, 'message' => 'Profile change request rejected.'];
}

function getVerificationStats() {
    global $conn;
    if (!hasDbConnection()) {
        return [
            'total' => 0,
            'pending' => 0,
            'verified' => 0,
            'rejected' => 0,
            'email_pending' => 0
        ];
    }
    $stats = [];

    $query = "SELECT COUNT(*) as total FROM voters WHERE status = 'active'";
    $result = mysqli_query($conn, $query);
    $stats['total'] = $result ? (int)mysqli_fetch_assoc($result)['total'] : 0;

    $query = "SELECT COUNT(*) as pending FROM voters WHERE verification_status = 'pending' AND email_verified = 1";
    $result = mysqli_query($conn, $query);
    $stats['pending'] = $result ? (int)mysqli_fetch_assoc($result)['pending'] : 0;

    $query = "SELECT COUNT(*) as verified FROM voters WHERE verification_status = 'verified'";
    $result = mysqli_query($conn, $query);
    $stats['verified'] = $result ? (int)mysqli_fetch_assoc($result)['verified'] : 0;

    $query = "SELECT COUNT(*) as rejected FROM voters WHERE verification_status = 'rejected'";
    $result = mysqli_query($conn, $query);
    $stats['rejected'] = $result ? (int)mysqli_fetch_assoc($result)['rejected'] : 0;

    $query = "SELECT COUNT(*) as email_pending FROM voters WHERE email_verified = 0";
    $result = mysqli_query($conn, $query);
    $stats['email_pending'] = $result ? (int)mysqli_fetch_assoc($result)['email_pending'] : 0;

    return $stats;
}

function getTotalRegisteredVoters() {
    global $conn;
    if (!hasDbConnection()) {
        return 0;
    }
    $query = "SELECT COUNT(*) as total FROM voters WHERE status = 'active' AND verification_status = 'verified'";
    $result = mysqli_query($conn, $query);
    $row = $result ? mysqli_fetch_assoc($result) : ['total' => 0];
    return (int)$row['total'];
}

function getTotalVotesCast() {
    global $conn;
    if (!hasDbConnection()) {
        return 0;
    }
    $query = "SELECT COUNT(*) as total FROM votes";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        return 0;
    }
    $row = mysqli_fetch_assoc($result);
    return (int)$row['total'];
}

function ensureElectionSchema() {
    global $conn;
    if (!$conn) {
        return;
    }

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS election_settings (
        setting_key VARCHAR(64) PRIMARY KEY,
        setting_value VARCHAR(255) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS positions (
        position_id INT AUTO_INCREMENT PRIMARY KEY,
        position_name VARCHAR(120) NOT NULL,
        scope ENUM('national','county','constituency','ward') NOT NULL,
        display_order INT NOT NULL DEFAULT 0,
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS candidates (
        candidate_id INT AUTO_INCREMENT PRIMARY KEY,
        position_id INT NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        party_name VARCHAR(150) NOT NULL,
        candidate_photo VARCHAR(255) NULL,
        county_id INT NULL,
        constituency_id INT NULL,
        ward_id INT NULL,
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_candidates_position (position_id),
        INDEX idx_candidates_county (county_id),
        INDEX idx_candidates_constituency (constituency_id),
        INDEX idx_candidates_ward (ward_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS votes (
        vote_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        voter_id INT NOT NULL,
        position_id INT NOT NULL,
        candidate_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_voter_position (voter_id, position_id),
        INDEX idx_votes_candidate (candidate_id),
        INDEX idx_votes_position (position_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS election_archive_runs (
        run_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        election_year INT NOT NULL,
        archived_by_admin_id INT NULL,
        candidates_count INT NOT NULL DEFAULT 0,
        votes_count INT NOT NULL DEFAULT 0,
        archive_note VARCHAR(255) NULL,
        archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_archive_runs_year (election_year),
        INDEX idx_archive_runs_archived_at (archived_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS election_results_archive (
        archive_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        run_id BIGINT NOT NULL,
        election_year INT NOT NULL,
        position_id INT NULL,
        position_name VARCHAR(120) NOT NULL,
        candidate_id INT NULL,
        candidate_name VARCHAR(150) NOT NULL,
        party_name VARCHAR(150) NOT NULL,
        votes INT NOT NULL DEFAULT 0,
        percentage DECIMAL(6,2) NOT NULL DEFAULT 0.00,
        is_leading TINYINT(1) NOT NULL DEFAULT 0,
        total_votes_position INT NOT NULL DEFAULT 0,
        registered_voters INT NOT NULL DEFAULT 0,
        votes_cast INT NOT NULL DEFAULT 0,
        turnout_percentage DECIMAL(6,2) NOT NULL DEFAULT 0.00,
        archived_by_admin_id INT NULL,
        archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_archive_year (election_year),
        INDEX idx_archive_run (run_id),
        INDEX idx_archive_position (position_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS by_elections (
        by_election_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        position_id INT NOT NULL,
        election_title VARCHAR(180) NOT NULL,
        affected_candidate_name VARCHAR(150) NULL,
        reason TEXT NOT NULL,
        scope ENUM('national','county','constituency','ward') NOT NULL,
        county_id INT NULL,
        constituency_id INT NULL,
        ward_id INT NULL,
        status ENUM('active','closed') NOT NULL DEFAULT 'active',
        created_by_admin_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at DATETIME NULL,
        INDEX idx_byelection_status (status),
        INDEX idx_byelection_position (position_id),
        INDEX idx_byelection_scope_county (scope, county_id),
        INDEX idx_byelection_scope_constituency (scope, constituency_id),
        INDEX idx_byelection_scope_ward (scope, ward_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS by_election_candidates (
        by_election_candidate_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        by_election_id BIGINT NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        party_name VARCHAR(150) NOT NULL,
        candidate_photo VARCHAR(255) NULL,
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_bec_by_election (by_election_id),
        INDEX idx_bec_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS by_election_votes (
        by_election_vote_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        by_election_id BIGINT NOT NULL,
        by_election_candidate_id BIGINT NOT NULL,
        voter_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_byelection_voter (by_election_id, voter_id),
        INDEX idx_bev_candidate (by_election_candidate_id),
        INDEX idx_bev_voter (voter_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS manual_vote_batches (
        batch_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        batch_title VARCHAR(180) NOT NULL,
        position_id INT NOT NULL,
        county_id INT NULL,
        constituency_id INT NULL,
        ward_id INT NULL,
        proposed_votes INT NOT NULL DEFAULT 0,
        source_note TEXT NULL,
        submitted_by_admin_id INT NOT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        approved_votes INT NOT NULL DEFAULT 0,
        approved_candidate_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at DATETIME NULL,
        INDEX idx_manual_batch_status (status),
        INDEX idx_manual_batch_position (position_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS manual_vote_approvals (
        approval_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        batch_id BIGINT NOT NULL,
        admin_id INT NOT NULL,
        decision ENUM('approved','rejected') NOT NULL,
        decision_note VARCHAR(255) NULL,
        decided_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_batch_admin_decision (batch_id, admin_id),
        INDEX idx_manual_approvals_batch (batch_id),
        INDEX idx_manual_approvals_admin (admin_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Backward-compatible migration for legacy election_settings schema.
    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM election_settings LIKE 'setting_key'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE election_settings ADD COLUMN setting_key VARCHAR(64) NULL");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM election_settings LIKE 'setting_value'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE election_settings ADD COLUMN setting_value VARCHAR(255) NULL");
    }

    $index_check = mysqli_query($conn, "SHOW INDEX FROM election_settings WHERE Key_name = 'uniq_setting_key'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        mysqli_query($conn, "ALTER TABLE election_settings ADD UNIQUE KEY uniq_setting_key (setting_key)");
    }

    $legacy_settings = mysqli_query($conn, "SELECT voting_status FROM election_settings ORDER BY setting_id DESC LIMIT 1");
    if ($legacy_settings && mysqli_num_rows($legacy_settings) > 0) {
        $legacy = mysqli_fetch_assoc($legacy_settings);
        $legacy_status = ($legacy['voting_status'] ?? 'closed') === 'open' ? 'open' : 'closed';
        mysqli_query($conn, "INSERT INTO election_settings (setting_key, setting_value)
            VALUES ('election_status', '" . mysqli_real_escape_string($conn, $legacy_status) . "')
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
    }

    // Backward-compatible migration for legacy candidates schema.
    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM candidates LIKE 'position_id'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE candidates ADD COLUMN position_id INT NULL AFTER candidate_id");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM candidates LIKE 'party_name'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE candidates ADD COLUMN party_name VARCHAR(150) NULL AFTER full_name");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM candidates LIKE 'candidate_photo'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE candidates ADD COLUMN candidate_photo VARCHAR(255) NULL AFTER party_name");
    }

    mysqli_query($conn, "UPDATE candidates SET party_name = COALESCE(NULLIF(party, ''), 'Independent')
        WHERE party_name IS NULL OR party_name = ''");

    mysqli_query($conn, "UPDATE candidates c
        LEFT JOIN positions p ON p.position_name =
            CASE c.position
                WHEN 'President' THEN 'President'
                WHEN 'Governor' THEN 'Governor'
                WHEN 'Senator' THEN 'Senator'
                WHEN 'Women Representative' THEN 'Woman Representative'
                WHEN 'Member of Parliament' THEN 'Member of National Assembly'
                WHEN 'Ward Representative' THEN 'Member of County Assembly'
                ELSE NULL
            END
        SET c.position_id = p.position_id
        WHERE c.position_id IS NULL OR c.position_id = 0");

    $index_check = mysqli_query($conn, "SHOW INDEX FROM candidates WHERE Key_name = 'idx_candidates_position'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        mysqli_query($conn, "ALTER TABLE candidates ADD INDEX idx_candidates_position (position_id)");
    }

    // Backward-compatible migration for legacy votes schema.
    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM votes LIKE 'position_id'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE votes ADD COLUMN position_id INT NULL AFTER voter_id");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM votes LIKE 'created_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE votes ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP");
        mysqli_query($conn, "UPDATE votes SET created_at = vote_timestamp WHERE created_at IS NULL");
    }

    mysqli_query($conn, "UPDATE votes v
        JOIN candidates c ON c.candidate_id = v.candidate_id
        SET v.position_id = c.position_id
        WHERE v.position_id IS NULL OR v.position_id = 0");

    $index_check = mysqli_query($conn, "SHOW INDEX FROM votes WHERE Key_name = 'idx_votes_position'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        mysqli_query($conn, "ALTER TABLE votes ADD INDEX idx_votes_position (position_id)");
    }

    mysqli_query($conn, "INSERT INTO election_settings (setting_key, setting_value)
        VALUES ('election_status', 'closed')
        ON DUPLICATE KEY UPDATE setting_key = setting_key");

    mysqli_query($conn, "INSERT INTO election_settings (setting_key, setting_value)
        VALUES ('results_published', '0')
        ON DUPLICATE KEY UPDATE setting_key = setting_key");

    $count_result = mysqli_query($conn, "SELECT COUNT(*) AS total FROM positions");
    $position_count = $count_result ? (int)mysqli_fetch_assoc($count_result)['total'] : 0;

    if ($position_count === 0) {
        mysqli_query($conn, "INSERT INTO positions (position_name, scope, display_order) VALUES
            ('President', 'national', 1),
            ('Governor', 'county', 2),
            ('Senator', 'county', 3),
            ('Woman Representative', 'county', 4),
            ('Member of National Assembly', 'constituency', 5),
            ('Member of County Assembly', 'ward', 6)");
    }
}

function ensureSecuritySchema() {
    global $conn;
    if (!$conn) {
        return;
    }

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS admins (
        admin_id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(150) NOT NULL,
        email VARCHAR(190) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        admin_role VARCHAR(40) NOT NULL DEFAULT 'super_admin',
        mfa_enabled TINYINT(1) NOT NULL DEFAULT 0,
        mfa_secret VARCHAR(64) NULL,
        mfa_enabled_at DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME NULL,
        last_mfa_at DATETIME NULL,
        admin_password_reset_token_hash VARCHAR(64) NULL,
        admin_password_reset_expires_at DATETIME NULL,
        admin_password_reset_requested_at DATETIME NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'admin_role'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN admin_role VARCHAR(40) NOT NULL DEFAULT 'super_admin' AFTER status");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'mfa_enabled'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN mfa_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER admin_role");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'mfa_secret'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN mfa_secret VARCHAR(64) NULL AFTER mfa_enabled");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'mfa_enabled_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN mfa_enabled_at DATETIME NULL AFTER mfa_secret");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'last_mfa_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN last_mfa_at DATETIME NULL AFTER last_login_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'admin_password_reset_token_hash'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN admin_password_reset_token_hash VARCHAR(64) NULL AFTER last_mfa_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'admin_password_reset_expires_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN admin_password_reset_expires_at DATETIME NULL AFTER admin_password_reset_token_hash");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM admins LIKE 'admin_password_reset_requested_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE admins ADD COLUMN admin_password_reset_requested_at DATETIME NULL AFTER admin_password_reset_expires_at");
    }

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS rate_limit_events (
        event_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        endpoint VARCHAR(80) NOT NULL,
        identifier VARCHAR(190) NOT NULL,
        ip_address VARCHAR(64) NOT NULL,
        was_successful TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_rate_endpoint (endpoint),
        INDEX idx_rate_identifier (identifier),
        INDEX idx_rate_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS audit_logs (
        log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        actor_type VARCHAR(50) NOT NULL,
        actor_id INT NULL,
        action VARCHAR(100) NOT NULL,
        details TEXT NULL,
        ip_address VARCHAR(64) NOT NULL,
        user_agent VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_audit_created (created_at),
        INDEX idx_audit_action (action)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS voter_profile_change_requests (
        request_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        voter_id INT NOT NULL,
        reason TEXT NOT NULL,
        requested_data LONGTEXT NOT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        admin_notification_sent TINYINT(1) NOT NULL DEFAULT 0,
        admin_notification_last_at DATETIME NULL,
        voter_notification_sent TINYINT(1) NOT NULL DEFAULT 0,
        voter_notification_last_at DATETIME NULL,
        reviewed_by INT NULL,
        reviewed_at DATETIME NULL,
        decision_note TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_profile_change_voter (voter_id),
        INDEX idx_profile_change_status (status),
        INDEX idx_profile_change_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voter_profile_change_requests LIKE 'admin_notification_sent'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voter_profile_change_requests ADD COLUMN admin_notification_sent TINYINT(1) NOT NULL DEFAULT 0 AFTER status");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voter_profile_change_requests LIKE 'admin_notification_last_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voter_profile_change_requests ADD COLUMN admin_notification_last_at DATETIME NULL AFTER admin_notification_sent");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voter_profile_change_requests LIKE 'voter_notification_sent'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voter_profile_change_requests ADD COLUMN voter_notification_sent TINYINT(1) NOT NULL DEFAULT 0 AFTER admin_notification_last_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voter_profile_change_requests LIKE 'voter_notification_last_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voter_profile_change_requests ADD COLUMN voter_notification_last_at DATETIME NULL AFTER voter_notification_sent");
    }

    mysqli_query($conn, "CREATE TABLE IF NOT EXISTS previuos_user_data (
        archive_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        voter_id INT NOT NULL,
        national_id VARCHAR(20) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        county_id INT NULL,
        constituency_id INT NULL,
        ward_id INT NULL,
        date_of_birth DATE NULL,
        archived_by_admin_id INT NULL,
        change_request_id BIGINT NULL,
        archive_reason TEXT NULL,
        archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_prev_voter (voter_id),
        INDEX idx_prev_archived_at (archived_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $default_password = getenv('ADMIN_DEFAULT_PASSWORD') ?: 'ChangeMe!123';
    $default_hash = password_hash($default_password, PASSWORD_DEFAULT);

    // Auto-correct legacy seeded admin email typo when the corrected email is free.
    $legacy_check = mysqli_query($conn, "SELECT admin_id FROM admins WHERE email = 'admin254@gamil.com' LIMIT 1");
    $correct_check = mysqli_query($conn, "SELECT admin_id FROM admins WHERE email = 'admin254@gmail.com' LIMIT 1");
    if ($legacy_check && mysqli_num_rows($legacy_check) > 0 && (!$correct_check || mysqli_num_rows($correct_check) === 0)) {
        mysqli_query($conn, "UPDATE admins SET email = 'admin254@gmail.com' WHERE email = 'admin254@gamil.com'");
    }

    $insert_admin = "INSERT INTO admins (full_name, email, password, status, admin_role)
                     SELECT 'System Administrator', 'admin254@gmail.com', ?, 'active', 'super_admin'
                     WHERE NOT EXISTS (SELECT 1 FROM admins)";
    $stmt = mysqli_prepare($conn, $insert_admin);
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $default_hash);
        mysqli_stmt_execute($stmt);
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'verification_token_expires_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN verification_token_expires_at DATETIME NULL AFTER verification_token");
    }

    $index_check = mysqli_query($conn, "SHOW INDEX FROM voters WHERE Key_name = 'uniq_voters_national_id'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        @mysqli_query($conn, "ALTER TABLE voters ADD UNIQUE KEY uniq_voters_national_id (national_id)");
    }

    $index_check = mysqli_query($conn, "SHOW INDEX FROM voters WHERE Key_name = 'uniq_voters_email'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        @mysqli_query($conn, "ALTER TABLE voters ADD UNIQUE KEY uniq_voters_email (email)");
    }

    $index_check = mysqli_query($conn, "SHOW INDEX FROM voters WHERE Key_name = 'uniq_voters_phone'");
    if ($index_check && mysqli_num_rows($index_check) === 0) {
        @mysqli_query($conn, "ALTER TABLE voters ADD UNIQUE KEY uniq_voters_phone (phone)");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'password_reset_token_hash'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN password_reset_token_hash VARCHAR(64) NULL AFTER verification_token_expires_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'password_reset_expires_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN password_reset_expires_at DATETIME NULL AFTER password_reset_token_hash");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'password_reset_requested_at'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN password_reset_requested_at DATETIME NULL AFTER password_reset_expires_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'has_voted_final'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN has_voted_final TINYINT(1) NOT NULL DEFAULT 0 AFTER password_reset_requested_at");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'national_id_front_path'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN national_id_front_path VARCHAR(255) NULL AFTER date_of_birth");
    }

    $column_check = mysqli_query($conn, "SHOW COLUMNS FROM voters LIKE 'national_id_back_path'");
    if ($column_check && mysqli_num_rows($column_check) === 0) {
        mysqli_query($conn, "ALTER TABLE voters ADD COLUMN national_id_back_path VARCHAR(255) NULL AFTER national_id_front_path");
    }

    $trigger_check = mysqli_prepare($conn, "SELECT 1
        FROM information_schema.TRIGGERS
        WHERE TRIGGER_SCHEMA = DATABASE()
          AND TRIGGER_NAME = 'trg_voters_national_id_immutable'
        LIMIT 1");
    $trigger_exists = false;
    if ($trigger_check) {
        mysqli_stmt_execute($trigger_check);
        $trigger_result = mysqli_stmt_get_result($trigger_check);
        $trigger_exists = $trigger_result && mysqli_num_rows($trigger_result) > 0;
    }

    if (!$trigger_exists) {
        @mysqli_query($conn, "CREATE TRIGGER trg_voters_national_id_immutable
            BEFORE UPDATE ON voters
            FOR EACH ROW
            BEGIN
                IF NEW.national_id <> OLD.national_id THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'National ID cannot be changed after registration';
                END IF;
            END");
    }
}

function getClientIpAddress() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function getCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    $session_token = $_SESSION['csrf_token'] ?? '';
    return is_string($token) && $session_token !== '' && hash_equals($session_token, $token);
}

function recordRateLimitEvent($endpoint, $identifier, $was_successful) {
    global $conn;
    if (!hasDbConnection()) {
        return;
    }
    $ip_address = getClientIpAddress();
    $query = "INSERT INTO rate_limit_events (endpoint, identifier, ip_address, was_successful)
              VALUES (?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return;
    }
    $success_int = $was_successful ? 1 : 0;
    mysqli_stmt_bind_param($stmt, "sssi", $endpoint, $identifier, $ip_address, $success_int);
    mysqli_stmt_execute($stmt);
}

function isRateLimited($endpoint, $identifier, $max_attempts = 5, $window_minutes = 15) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $ip_address = getClientIpAddress();
    $query = "SELECT COUNT(*) AS total
              FROM rate_limit_events
              WHERE endpoint = ?
                AND was_successful = 0
                AND created_at >= (NOW() - INTERVAL ? MINUTE)
                AND (identifier = ? OR ip_address = ?)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "siss", $endpoint, $window_minutes, $identifier, $ip_address);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result ? mysqli_fetch_assoc($result) : ['total' => 0];
    return ((int)$row['total'] >= (int)$max_attempts);
}

function logAuditEvent($actor_type, $actor_id, $action, $details = null) {
    global $conn;
    if (!hasDbConnection()) {
        return;
    }
    $ip_address = getClientIpAddress();
    $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
    $details_text = is_array($details) ? json_encode($details) : (string)$details;

    $query = "INSERT INTO audit_logs (actor_type, actor_id, action, details, ip_address, user_agent)
              VALUES (?, ?, ?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return;
    }
    mysqli_stmt_bind_param($stmt, "sissss", $actor_type, $actor_id, $action, $details_text, $ip_address, $user_agent);
    mysqli_stmt_execute($stmt);
}

function getAdminByEmail($email) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
    $query = "SELECT * FROM admins WHERE email = ? AND status = 'active' LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function getAdminById($admin_id) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
    $query = "SELECT * FROM admins WHERE admin_id = ? AND status = 'active' LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "i", $admin_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function requireAdminAuth() {
    if (!isset($_SESSION['admin_id'])) {
        header('Location: admin_login.php');
        exit();
    }
}

function requireAdminRole($roles) {
    if (!isset($_SESSION['admin_id'])) {
        header('Location: admin_login.php');
        exit();
    }

    $roles = is_array($roles) ? $roles : [$roles];
    $current_role = (string)($_SESSION['admin_role'] ?? '');
    if (!in_array($current_role, $roles, true)) {
        http_response_code(403);
        exit('Forbidden: insufficient permissions.');
    }
}

function canManageElection($admin_role) {
    return in_array((string)$admin_role, ['super_admin', 'election_officer'], true);
}

function canCreateSubAdmins($admin_role) {
    return in_array((string)$admin_role, ['super_admin', 'election_officer'], true);
}

function canSubmitManualVotes($admin_role) {
    return in_array((string)$admin_role, ['super_admin', 'election_officer'], true);
}

function canReviewManualVotes($admin_role) {
    return (string)$admin_role === 'super_admin';
}

function createSubAdmin($full_name, $email, $password, $created_by_admin_id, $admin_role = 'sub_admin') {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database connection unavailable.'];
    }

    $full_name = sanitize($full_name);
    $email = sanitize($email);
    $admin_role = sanitize($admin_role);

    if ($full_name === '' || $email === '' || $password === '') {
        return ['ok' => false, 'message' => 'Name, email, and password are required.'];
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['ok' => false, 'message' => 'Provide a valid admin email.'];
    }

    if (!in_array($admin_role, ['sub_admin', 'election_officer'], true)) {
        return ['ok' => false, 'message' => 'Invalid admin role selected.'];
    }

    $check_stmt = mysqli_prepare($conn, "SELECT admin_id FROM admins WHERE email = ? LIMIT 1");
    if (!$check_stmt) {
        return ['ok' => false, 'message' => 'Unable to validate admin email.'];
    }
    mysqli_stmt_bind_param($check_stmt, 's', $email);
    mysqli_stmt_execute($check_stmt);
    $exists = mysqli_stmt_get_result($check_stmt);
    if ($exists && mysqli_num_rows($exists) > 0) {
        return ['ok' => false, 'message' => 'An admin already exists with that email.'];
    }

    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    $insert_stmt = mysqli_prepare($conn, "INSERT INTO admins (full_name, email, password, status, admin_role, mfa_enabled)
                                         VALUES (?, ?, ?, 'active', ?, 0)");
    if (!$insert_stmt) {
        return ['ok' => false, 'message' => 'Unable to create sub-admin.'];
    }
    mysqli_stmt_bind_param($insert_stmt, 'ssss', $full_name, $email, $password_hash, $admin_role);
    if (!mysqli_stmt_execute($insert_stmt)) {
        return ['ok' => false, 'message' => 'Unable to create sub-admin.'];
    }

    $new_admin_id = (int)mysqli_insert_id($conn);
    logAuditEvent('admin', (int)$created_by_admin_id, 'sub_admin_created', [
        'new_admin_id' => $new_admin_id,
        'email' => $email,
        'admin_role' => $admin_role
    ]);

    return ['ok' => true, 'message' => 'Sub-admin created successfully.', 'admin_id' => $new_admin_id];
}

function submitManualVoteBatch($batch_title, $position_id, $county_id, $constituency_id, $ward_id, $proposed_votes, $source_note, $submitted_by_admin_id) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database connection unavailable.'];
    }

    $batch_title = sanitize($batch_title);
    $source_note = sanitize($source_note);
    $position_id = (int)$position_id;
    $county_id = (int)$county_id;
    $constituency_id = (int)$constituency_id;
    $ward_id = (int)$ward_id;
    $proposed_votes = (int)$proposed_votes;

    if ($batch_title === '' || $position_id <= 0 || $proposed_votes <= 0) {
        return ['ok' => false, 'message' => 'Batch title, position, and proposed votes are required.'];
    }

    $insert_stmt = mysqli_prepare($conn, "INSERT INTO manual_vote_batches
        (batch_title, position_id, county_id, constituency_id, ward_id, proposed_votes, source_note, submitted_by_admin_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')");
    if (!$insert_stmt) {
        return ['ok' => false, 'message' => 'Unable to submit manual vote batch.'];
    }

    $county_val = $county_id > 0 ? $county_id : null;
    $constituency_val = $constituency_id > 0 ? $constituency_id : null;
    $ward_val = $ward_id > 0 ? $ward_id : null;
    $submitted_by = (int)$submitted_by_admin_id;
    mysqli_stmt_bind_param($insert_stmt, 'siiiiisi', $batch_title, $position_id, $county_val, $constituency_val, $ward_val, $proposed_votes, $source_note, $submitted_by);

    if (!mysqli_stmt_execute($insert_stmt)) {
        return ['ok' => false, 'message' => 'Unable to submit manual vote batch.'];
    }

    $batch_id = (int)mysqli_insert_id($conn);
    logAuditEvent('admin', $submitted_by, 'manual_vote_batch_submitted', [
        'batch_id' => $batch_id,
        'position_id' => $position_id,
        'proposed_votes' => $proposed_votes
    ]);

    return ['ok' => true, 'message' => 'Manual vote batch submitted for dual super-admin approval.', 'batch_id' => $batch_id];
}

function reviewManualVoteBatch($batch_id, $candidate_id, $approved_votes, $decision, $decision_note, $review_admin_id) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database connection unavailable.'];
    }

    $batch_id = (int)$batch_id;
    $candidate_id = (int)$candidate_id;
    $approved_votes = (int)$approved_votes;
    $decision = sanitize($decision);
    $decision_note = sanitize($decision_note);
    $review_admin_id = (int)$review_admin_id;

    if ($batch_id <= 0 || !in_array($decision, ['approved', 'rejected'], true)) {
        return ['ok' => false, 'message' => 'Invalid manual vote review request.'];
    }

    $batch_stmt = mysqli_prepare($conn, "SELECT * FROM manual_vote_batches WHERE batch_id = ? LIMIT 1");
    if (!$batch_stmt) {
        return ['ok' => false, 'message' => 'Unable to load manual vote batch.'];
    }
    mysqli_stmt_bind_param($batch_stmt, 'i', $batch_id);
    mysqli_stmt_execute($batch_stmt);
    $batch_result = mysqli_stmt_get_result($batch_stmt);
    $batch = $batch_result ? mysqli_fetch_assoc($batch_result) : null;

    if (!$batch) {
        return ['ok' => false, 'message' => 'Manual vote batch not found.'];
    }

    if (($batch['status'] ?? 'pending') !== 'pending') {
        return ['ok' => false, 'message' => 'This manual vote batch is already finalized.'];
    }

    if ($review_admin_id === (int)$batch['submitted_by_admin_id']) {
        return ['ok' => false, 'message' => 'Submitting admin cannot review their own manual vote batch.'];
    }

    if ($decision === 'approved' && ($candidate_id <= 0 || $approved_votes <= 0)) {
        return ['ok' => false, 'message' => 'Candidate and approved votes are required for approval.'];
    }

    mysqli_begin_transaction($conn);
    try {
        $insert_review = mysqli_prepare($conn, "INSERT INTO manual_vote_approvals (batch_id, admin_id, decision, decision_note)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE decision = VALUES(decision), decision_note = VALUES(decision_note), decided_at = CURRENT_TIMESTAMP");
        if (!$insert_review) {
            throw new Exception('Unable to store review decision.');
        }
        mysqli_stmt_bind_param($insert_review, 'iiss', $batch_id, $review_admin_id, $decision, $decision_note);
        if (!mysqli_stmt_execute($insert_review)) {
            throw new Exception('Unable to store review decision.');
        }

        $reject_check_stmt = mysqli_prepare($conn, "SELECT COUNT(*) AS total FROM manual_vote_approvals WHERE batch_id = ? AND decision = 'rejected'");
        mysqli_stmt_bind_param($reject_check_stmt, 'i', $batch_id);
        mysqli_stmt_execute($reject_check_stmt);
        $reject_row = mysqli_fetch_assoc(mysqli_stmt_get_result($reject_check_stmt));
        $rejected_count = (int)($reject_row['total'] ?? 0);

        if ($rejected_count > 0) {
            $update_batch_rejected = mysqli_prepare($conn, "UPDATE manual_vote_batches
                SET status = 'rejected', reviewed_at = NOW()
                WHERE batch_id = ? LIMIT 1");
            mysqli_stmt_bind_param($update_batch_rejected, 'i', $batch_id);
            mysqli_stmt_execute($update_batch_rejected);

            mysqli_commit($conn);
            return ['ok' => true, 'message' => 'Manual vote batch has been rejected.'];
        }

        $approval_check_stmt = mysqli_prepare($conn, "SELECT COUNT(DISTINCT admin_id) AS total
            FROM manual_vote_approvals
            WHERE batch_id = ? AND decision = 'approved'");
        mysqli_stmt_bind_param($approval_check_stmt, 'i', $batch_id);
        mysqli_stmt_execute($approval_check_stmt);
        $approval_row = mysqli_fetch_assoc(mysqli_stmt_get_result($approval_check_stmt));
        $approved_count = (int)($approval_row['total'] ?? 0);

        if ($approved_count >= 2) {
            $insert_vote_stmt = mysqli_prepare($conn, "INSERT INTO votes (voter_id, position_id, candidate_id)
                VALUES (?, ?, ?)");
            if (!$insert_vote_stmt) {
                throw new Exception('Unable to apply approved manual votes.');
            }

            $seed_stmt = mysqli_prepare($conn, "SELECT COALESCE(MIN(voter_id), 0) AS min_voter_id FROM votes WHERE voter_id < 0");
            if (!$seed_stmt) {
                throw new Exception('Unable to apply approved manual votes.');
            }
            if (!mysqli_stmt_execute($seed_stmt)) {
                throw new Exception('Unable to apply approved manual votes.');
            }
            $seed_row = mysqli_fetch_assoc(mysqli_stmt_get_result($seed_stmt));
            $next_manual_voter_id = min(0, (int)($seed_row['min_voter_id'] ?? 0)) - 1;

            for ($i = 0; $i < $approved_votes; $i++) {
                $position_id = (int)$batch['position_id'];
                mysqli_stmt_bind_param($insert_vote_stmt, 'iii', $next_manual_voter_id, $position_id, $candidate_id);
                if (!mysqli_stmt_execute($insert_vote_stmt)) {
                    throw new Exception('Unable to apply approved manual votes.');
                }
                $next_manual_voter_id--;
            }

            $update_batch_approved = mysqli_prepare($conn, "UPDATE manual_vote_batches
                SET status = 'approved', approved_votes = ?, approved_candidate_id = ?, reviewed_at = NOW()
                WHERE batch_id = ? LIMIT 1");
            mysqli_stmt_bind_param($update_batch_approved, 'iii', $approved_votes, $candidate_id, $batch_id);
            mysqli_stmt_execute($update_batch_approved);

            mysqli_commit($conn);
            return ['ok' => true, 'message' => 'Manual vote batch approved by two super admins and counted.'];
        }

        mysqli_commit($conn);
        return ['ok' => true, 'message' => 'First approval captured. Awaiting second super-admin approval.'];
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function getPendingManualVoteBatches() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT b.batch_id, b.batch_title, b.position_id, p.position_name,
                     b.county_id, b.constituency_id, b.ward_id,
                     co.county_name, cs.constituency_name, w.ward_name,
                     b.proposed_votes, b.source_note, b.submitted_by_admin_id,
                     a.full_name AS submitted_by_name,
                     b.status, b.created_at,
                     (SELECT COUNT(DISTINCT r.admin_id) FROM manual_vote_approvals r WHERE r.batch_id = b.batch_id AND r.decision = 'approved') AS approvals_count,
                     (SELECT COUNT(*) FROM manual_vote_approvals r WHERE r.batch_id = b.batch_id AND r.decision = 'rejected') AS rejects_count
              FROM manual_vote_batches b
              LEFT JOIN positions p ON p.position_id = b.position_id
              LEFT JOIN counties co ON co.county_id = b.county_id
              LEFT JOIN constituencies cs ON cs.constituency_id = b.constituency_id
              LEFT JOIN wards w ON w.ward_id = b.ward_id
              LEFT JOIN admins a ON a.admin_id = b.submitted_by_admin_id
              WHERE b.status = 'pending'
              ORDER BY b.created_at DESC";

    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function generateTotpSecret($length = 32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $max = strlen($alphabet) - 1;
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        try {
            $idx = random_int(0, $max);
        } catch (Exception $e) {
            $idx = mt_rand(0, $max);
        }
        $secret .= $alphabet[$idx];
    }
    return $secret;
}

function base32Decode($input) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $clean = strtoupper(preg_replace('/[^A-Z2-7]/', '', (string)$input));
    $bits = '';

    $len = strlen($clean);
    for ($i = 0; $i < $len; $i++) {
        $val = strpos($alphabet, $clean[$i]);
        if ($val === false) {
            return '';
        }
        $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
    }

    $bytes = '';
    $bits_len = strlen($bits);
    for ($i = 0; $i + 8 <= $bits_len; $i += 8) {
        $bytes .= chr(bindec(substr($bits, $i, 8)));
    }
    return $bytes;
}

function getTotpCode($secret, $time_slice = null) {
    $time_slice = $time_slice !== null ? (int)$time_slice : (int)floor(time() / 30);
    $binary_key = base32Decode($secret);
    if ($binary_key === '') {
        return null;
    }

    $binary_time = pack('N*', 0) . pack('N*', $time_slice);
    $hash = hash_hmac('sha1', $binary_time, $binary_key, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $segment = substr($hash, $offset, 4);
    $value = unpack('N', $segment);
    $value = $value ? ($value[1] & 0x7FFFFFFF) : 0;

    return str_pad((string)($value % 1000000), 6, '0', STR_PAD_LEFT);
}

function verifyTotpCode($secret, $code, $window = 1) {
    $normalized_code = preg_replace('/\D/', '', (string)$code);
    if (strlen($normalized_code) !== 6) {
        return false;
    }

    $current_slice = (int)floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        $calc = getTotpCode($secret, $current_slice + $i);
        if ($calc !== null && hash_equals($calc, $normalized_code)) {
            return true;
        }
    }
    return false;
}

function getTotpProvisioningUri($email, $secret, $issuer = 'Online Voting System') {
    $label = rawurlencode($issuer . ':' . $email);
    $issuer_q = rawurlencode($issuer);
    $secret_q = rawurlencode($secret);
    return "otpauth://totp/{$label}?secret={$secret_q}&issuer={$issuer_q}&algorithm=SHA1&digits=6&period=30";
}

function getTotpQrCodeUrl($otpauth_uri) {
    return 'https://quickchart.io/qr?size=220&text=' . rawurlencode($otpauth_uri);
}

function getElectionSetting($key, $default = null) {
    global $conn;
    if (!hasDbConnection()) {
        return $default;
    }
    $query = "SELECT setting_value FROM election_settings WHERE setting_key = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return $default;
    }
    mysqli_stmt_bind_param($stmt, "s", $key);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result ? mysqli_fetch_assoc($result) : null;
    return $row ? $row['setting_value'] : $default;
}

function setElectionSetting($key, $value) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "INSERT INTO election_settings (setting_key, setting_value)
              VALUES (?, ?)
              ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "ss", $key, $value);
    return mysqli_stmt_execute($stmt);
}

function isElectionOpen() {
    return getElectionSetting('election_status', 'closed') === 'open';
}

function areResultsPublished() {
    return getElectionSetting('results_published', '0') === '1';
}

function getAllPositions() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $result = mysqli_query($conn, "SELECT * FROM positions WHERE status = 'active' ORDER BY display_order ASC, position_name ASC");
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getCandidatesForPosition($position_id) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT c.*, p.position_name, p.scope
              FROM candidates c
              JOIN positions p ON c.position_id = p.position_id
              WHERE c.position_id = ?
              ORDER BY c.full_name ASC";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    mysqli_stmt_bind_param($stmt, "i", $position_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function updateCandidateAdminRecord($candidate_id, $position_id, $full_name, $party_name, $county_id = null, $constituency_id = null, $ward_id = null, $status = 'active', $force_apply = false) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $candidate_id = (int)$candidate_id;
    $position_id = (int)$position_id;
    $status = in_array($status, ['active', 'inactive'], true) ? $status : 'active';
    $county_id = $county_id !== null ? (int)$county_id : null;
    $constituency_id = $constituency_id !== null ? (int)$constituency_id : null;
    $ward_id = $ward_id !== null ? (int)$ward_id : null;
    $force_apply = !empty($force_apply);

    $candidate_query = "SELECT candidate_id, position_id FROM candidates WHERE candidate_id = ? LIMIT 1";
    $candidate_stmt = mysqli_prepare($conn, $candidate_query);
    if (!$candidate_stmt) {
        return ['ok' => false, 'message' => 'Unable to load candidate record.'];
    }
    mysqli_stmt_bind_param($candidate_stmt, "i", $candidate_id);
    mysqli_stmt_execute($candidate_stmt);
    $candidate_result = mysqli_stmt_get_result($candidate_stmt);
    $existing_candidate = $candidate_result ? mysqli_fetch_assoc($candidate_result) : null;

    if (!$existing_candidate) {
        return ['ok' => false, 'message' => 'Candidate not found.'];
    }

    $position_changed = (int)$existing_candidate['position_id'] !== $position_id;

    $votes_count = 0;
    if ($position_changed) {
        $votes_count_query = "SELECT COUNT(*) AS total FROM votes WHERE candidate_id = ?";
        $votes_count_stmt = mysqli_prepare($conn, $votes_count_query);
        if ($votes_count_stmt) {
            mysqli_stmt_bind_param($votes_count_stmt, "i", $candidate_id);
            mysqli_stmt_execute($votes_count_stmt);
            $votes_count_result = mysqli_stmt_get_result($votes_count_stmt);
            $votes_count_row = $votes_count_result ? mysqli_fetch_assoc($votes_count_result) : ['total' => 0];
            $votes_count = (int)($votes_count_row['total'] ?? 0);
        }
    }

    if ($position_changed && isElectionOpen() && $votes_count > 0 && !$force_apply) {
        return [
            'ok' => false,
            'message' => 'This candidate already has ' . $votes_count . ' vote(s). To change position during an open election, enable force apply. Existing votes for this candidate will be cleared and affected voters unlocked.',
            'requires_force' => true,
            'affected_votes' => $votes_count
        ];
    }

    mysqli_begin_transaction($conn);
    try {
        if ($position_changed && $votes_count > 0 && $force_apply) {
            $affected_voters = [];
            $affected_query = "SELECT DISTINCT voter_id FROM votes WHERE candidate_id = ?";
            $affected_stmt = mysqli_prepare($conn, $affected_query);
            if ($affected_stmt) {
                mysqli_stmt_bind_param($affected_stmt, "i", $candidate_id);
                mysqli_stmt_execute($affected_stmt);
                $affected_result = mysqli_stmt_get_result($affected_stmt);
                if ($affected_result) {
                    while ($row = mysqli_fetch_assoc($affected_result)) {
                        $affected_voters[] = (int)$row['voter_id'];
                    }
                }
            }

            $delete_votes_query = "DELETE FROM votes WHERE candidate_id = ?";
            $delete_votes_stmt = mysqli_prepare($conn, $delete_votes_query);
            if (!$delete_votes_stmt) {
                throw new Exception('Unable to clear candidate votes for forced position change.');
            }
            mysqli_stmt_bind_param($delete_votes_stmt, "i", $candidate_id);
            if (!mysqli_stmt_execute($delete_votes_stmt)) {
                throw new Exception('Unable to clear candidate votes for forced position change.');
            }

            if (!empty($affected_voters)) {
                $ids = implode(',', array_map('intval', $affected_voters));
                mysqli_query($conn, "UPDATE voters SET has_voted_final = 0 WHERE voter_id IN (" . $ids . ")");
            }
        }

        $query = "UPDATE candidates
                  SET position_id = ?,
                      full_name = ?,
                      party_name = ?,
                      county_id = ?,
                      constituency_id = ?,
                      ward_id = ?,
                      status = ?
                  WHERE candidate_id = ?
                  LIMIT 1";
        $stmt = mysqli_prepare($conn, $query);
        if (!$stmt) {
            throw new Exception('Failed to prepare candidate update.');
        }
        mysqli_stmt_bind_param($stmt, "issiiisi", $position_id, $full_name, $party_name, $county_id, $constituency_id, $ward_id, $status, $candidate_id);
        if (!mysqli_stmt_execute($stmt)) {
            throw new Exception('Failed to update candidate.');
        }

        mysqli_commit($conn);
        return [
            'ok' => true,
            'message' => ($position_changed && $votes_count > 0 && $force_apply)
                ? 'Candidate updated. Existing votes for this candidate were cleared and affected voters were unlocked to vote again.'
                : 'Candidate updated successfully.'
        ];
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function markCandidateDeceasedAndDraftByElection($candidate_id, $admin_id, $deceased_reason) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $candidate_id = (int)$candidate_id;
    $admin_id = (int)$admin_id;
    $deceased_reason = trim((string)$deceased_reason);

    if ($candidate_id <= 0) {
        return ['ok' => false, 'message' => 'Invalid candidate selected.'];
    }
    if ($deceased_reason === '') {
        return ['ok' => false, 'message' => 'Please provide a reason for this emergency change.'];
    }

    $query = "SELECT c.*, p.position_name, p.scope
              FROM candidates c
              JOIN positions p ON p.position_id = c.position_id
              WHERE c.candidate_id = ?
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Unable to load candidate details.'];
    }
    mysqli_stmt_bind_param($stmt, "i", $candidate_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $candidate = $result ? mysqli_fetch_assoc($result) : null;

    if (!$candidate) {
        return ['ok' => false, 'message' => 'Candidate not found.'];
    }

    mysqli_begin_transaction($conn);
    try {
        $update_query = "UPDATE candidates SET status = 'inactive' WHERE candidate_id = ? LIMIT 1";
        $update_stmt = mysqli_prepare($conn, $update_query);
        if (!$update_stmt) {
            throw new Exception('Unable to mark candidate inactive.');
        }
        mysqli_stmt_bind_param($update_stmt, "i", $candidate_id);
        if (!mysqli_stmt_execute($update_stmt)) {
            throw new Exception('Unable to mark candidate inactive.');
        }

        $title = 'By-Election: ' . (string)$candidate['position_name'] . ' Replacement (' . date('Y') . ')';
        $reason = 'Candidate death reported during election. ' . $deceased_reason;

        $by_result = createByElection(
            (int)$candidate['position_id'],
            $title,
            (string)$candidate['full_name'],
            $reason,
            (int)($candidate['county_id'] ?? 0),
            (int)($candidate['constituency_id'] ?? 0),
            (int)($candidate['ward_id'] ?? 0),
            $admin_id
        );

        if (!empty($by_result['ok'])) {
            mysqli_commit($conn);
            return [
                'ok' => true,
                'message' => 'Candidate marked inactive and by-election draft created successfully.',
                'by_election_id' => (int)($by_result['by_election_id'] ?? 0)
            ];
        }

        $error_message = (string)($by_result['message'] ?? 'Failed to create by-election draft.');
        if (stripos($error_message, 'already exists') !== false) {
            mysqli_commit($conn);
            return [
                'ok' => true,
                'message' => 'Candidate marked inactive. An active by-election for this area already exists.',
                'by_election_id' => 0
            ];
        }

        throw new Exception($error_message);
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function getScopedBallot($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $voter = getVoterById($voter_id);
    if (!$voter) {
        return [];
    }

    $query = "SELECT p.position_id, p.position_name, p.scope,
                     c.candidate_id, c.full_name, c.party_name, c.candidate_photo,
                     (SELECT candidate_id FROM votes v WHERE v.voter_id = ? AND v.position_id = p.position_id LIMIT 1) AS selected_candidate_id
              FROM positions p
              LEFT JOIN candidates c ON c.position_id = p.position_id AND c.status = 'active'
              WHERE p.status = 'active' AND (
                    p.scope = 'national'
                    OR (p.scope = 'county' AND c.county_id = ?)
                    OR (p.scope = 'constituency' AND c.constituency_id = ?)
                    OR (p.scope = 'ward' AND c.ward_id = ?)
              )
              ORDER BY p.display_order ASC, p.position_name ASC, c.full_name ASC";

    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    mysqli_stmt_bind_param($stmt, "iiii", $voter_id, $voter['county_id'], $voter['constituency_id'], $voter['ward_id']);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    $ballot = [];
    foreach ($rows as $row) {
        $position_id = (int)$row['position_id'];
        if (!isset($ballot[$position_id])) {
            $ballot[$position_id] = [
                'position_id' => $position_id,
                'position_name' => $row['position_name'],
                'scope' => $row['scope'],
                'selected_candidate_id' => $row['selected_candidate_id'] !== null ? (int)$row['selected_candidate_id'] : null,
                'candidates' => []
            ];
        }
        if (!empty($row['candidate_id'])) {
            $ballot[$position_id]['candidates'][] = [
                'candidate_id' => (int)$row['candidate_id'],
                'full_name' => $row['full_name'],
                'party_name' => $row['party_name'],
                'candidate_photo' => $row['candidate_photo']
            ];
        }
    }

    return array_values($ballot);
}

function voterHasVotedForPosition($voter_id, $position_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "SELECT 1 FROM votes WHERE voter_id = ? AND position_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "ii", $voter_id, $position_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result && mysqli_num_rows($result) > 0;
}

function voterHasFinalizedVote($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }
    $query = "SELECT has_voted_final FROM voters WHERE voter_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "i", $voter_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = $result ? mysqli_fetch_assoc($result) : null;
    return $row && isset($row['has_voted_final']) && (int)$row['has_voted_final'] === 1;
}

function sortBallotByRequiredElectionOrder($ballot) {
    if (!is_array($ballot)) {
        return [];
    }

    $priority = [
        'president' => 1,
        'governor' => 2,
        'senator' => 3,
        'woman representative' => 4,
        'member of national assembly' => 5,
        'member of county assembly' => 6
    ];

    foreach ($ballot as $index => $position) {
        $name = strtolower(trim((string)($position['position_name'] ?? '')));
        $ballot[$index]['_required_order'] = $priority[$name] ?? (100 + $index);
    }

    usort($ballot, function ($a, $b) {
        $a_order = (int)($a['_required_order'] ?? 999);
        $b_order = (int)($b['_required_order'] ?? 999);
        if ($a_order === $b_order) {
            return strcmp((string)($a['position_name'] ?? ''), (string)($b['position_name'] ?? ''));
        }
        return $a_order <=> $b_order;
    });

    foreach ($ballot as $index => $position) {
        unset($ballot[$index]['_required_order']);
    }

    return $ballot;
}

function submitFinalBallot($voter_id, $votes_by_position) {
    global $conn;

    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable. Please try again later.'];
    }
    if (!isElectionOpen()) {
        return ['ok' => false, 'message' => 'Election is currently closed.'];
    }
    if (!canLogin($voter_id)) {
        return ['ok' => false, 'message' => 'Only verified voters can vote.'];
    }
    if (voterHasFinalizedVote($voter_id)) {
        return ['ok' => false, 'message' => 'Your ballot is already finalized. You cannot vote again.'];
    }

    $ballot = sortBallotByRequiredElectionOrder(getScopedBallot($voter_id));
    $votable_positions = [];
    foreach ($ballot as $position) {
        if (!empty($position['candidates'])) {
            $votable_positions[] = $position;
        }
    }

    if (empty($votable_positions)) {
        return ['ok' => false, 'message' => 'No candidates are available for your ballot.'];
    }

    $votes_by_position = is_array($votes_by_position) ? $votes_by_position : [];
    $normalized_votes = [];
    foreach ($votes_by_position as $position_id => $candidate_id) {
        $position_id_int = (int)$position_id;
        $candidate_id_int = (int)$candidate_id;
        if ($position_id_int > 0 && $candidate_id_int > 0) {
            $normalized_votes[$position_id_int] = $candidate_id_int;
        }
    }

    $allowed_position_ids = [];
    foreach ($votable_positions as $position) {
        $allowed_position_ids[] = (int)$position['position_id'];
    }

    foreach ($normalized_votes as $position_id_int => $candidate_id_int) {
        if (!in_array($position_id_int, $allowed_position_ids, true)) {
            return ['ok' => false, 'message' => 'Invalid ballot data received. Please refresh and try again.'];
        }
    }

    $total_votable_positions = count($votable_positions);
    for ($i = 0; $i < $total_votable_positions; $i++) {
        $position = $votable_positions[$i];
        $position_id = (int)$position['position_id'];
        $position_name = (string)$position['position_name'];
        $existing_candidate_id = $position['selected_candidate_id'] !== null ? (int)$position['selected_candidate_id'] : null;
        $has_current_selection = ($existing_candidate_id !== null) || isset($normalized_votes[$position_id]);

        if ($has_current_selection) {
            continue;
        }

        for ($j = $i + 1; $j < $total_votable_positions; $j++) {
            $later_position = $votable_positions[$j];
            $later_position_id = (int)$later_position['position_id'];
            $later_existing = $later_position['selected_candidate_id'] !== null ? (int)$later_position['selected_candidate_id'] : null;
            $later_submitted = isset($normalized_votes[$later_position_id]);

            if ($later_existing === null && $later_submitted) {
                return ['ok' => false, 'message' => 'Complete ' . $position_name . ' before selecting later positions.'];
            }
        }
    }

    mysqli_begin_transaction($conn);
    try {
        foreach ($votable_positions as $position) {
            $position_id = (int)$position['position_id'];
            $existing_candidate_id = $position['selected_candidate_id'] !== null ? (int)$position['selected_candidate_id'] : null;

            if ($existing_candidate_id !== null) {
                continue;
            }

            if (!isset($normalized_votes[$position_id])) {
                throw new Exception('Please select a candidate for ' . (string)$position['position_name'] . '.');
            }

            $candidate_id = (int)$normalized_votes[$position_id];
            $allowed_candidate_ids = [];
            foreach ($position['candidates'] as $candidate) {
                $allowed_candidate_ids[] = (int)$candidate['candidate_id'];
            }

            if (!in_array($candidate_id, $allowed_candidate_ids, true)) {
                throw new Exception('Invalid candidate selection for ' . (string)$position['position_name'] . '.');
            }

            $insert_query = "INSERT INTO votes (voter_id, position_id, candidate_id) VALUES (?, ?, ?)";
            $insert_stmt = mysqli_prepare($conn, $insert_query);
            if (!$insert_stmt) {
                throw new Exception('Unable to save your vote right now.');
            }
            mysqli_stmt_bind_param($insert_stmt, "iii", $voter_id, $position_id, $candidate_id);
            if (!mysqli_stmt_execute($insert_stmt)) {
                throw new Exception('Failed to save vote for ' . (string)$position['position_name'] . '.');
            }
        }

        $finalize_query = "UPDATE voters SET has_voted_final = 1 WHERE voter_id = ? LIMIT 1";
        $finalize_stmt = mysqli_prepare($conn, $finalize_query);
        if (!$finalize_stmt) {
            throw new Exception('Could not finalize your ballot.');
        }
        mysqli_stmt_bind_param($finalize_stmt, "i", $voter_id);
        if (!mysqli_stmt_execute($finalize_stmt)) {
            throw new Exception('Could not finalize your ballot.');
        }

        logAuditEvent('voter', $voter_id, 'ballot_submitted_final', [
            'positions_total' => count($votable_positions)
        ]);

        mysqli_commit($conn);
        return ['ok' => true, 'message' => 'Ballot submitted successfully. Your voting session is now locked.'];
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function castVote($voter_id, $candidate_id) {
    global $conn;

    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable. Please try again later.'];
    }

    if (!isElectionOpen()) {
        return ['ok' => false, 'message' => 'Election is currently closed.'];
    }

    if (!canLogin($voter_id)) {
        return ['ok' => false, 'message' => 'Only verified voters can vote.'];
    }

    $voter = getVoterById($voter_id);
    if (!$voter) {
        return ['ok' => false, 'message' => 'Voter account not found.'];
    }

    if (voterHasFinalizedVote($voter_id)) {
        return ['ok' => false, 'message' => 'Your vote has already been finalized. You cannot vote again.'];
    }

    $candidate_query = "SELECT c.*, p.scope
                        FROM candidates c
                        JOIN positions p ON c.position_id = p.position_id
                        WHERE c.candidate_id = ? AND c.status = 'active'";
    $stmt = mysqli_prepare($conn, $candidate_query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Unable to process request right now.'];
    }
    mysqli_stmt_bind_param($stmt, "i", $candidate_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $candidate = $result ? mysqli_fetch_assoc($result) : null;

    if (!$candidate) {
        return ['ok' => false, 'message' => 'Candidate not found.'];
    }

    $scope = $candidate['scope'];
    if (($scope === 'county' && (int)$candidate['county_id'] !== (int)$voter['county_id'])
        || ($scope === 'constituency' && (int)$candidate['constituency_id'] !== (int)$voter['constituency_id'])
        || ($scope === 'ward' && (int)$candidate['ward_id'] !== (int)$voter['ward_id'])) {
        return ['ok' => false, 'message' => 'Selected candidate is outside your voting area.'];
    }

    $position_id = (int)$candidate['position_id'];
    if (voterHasVotedForPosition($voter_id, $position_id)) {
        return ['ok' => false, 'message' => 'You already voted for this position.'];
    }

    $insert_query = "INSERT INTO votes (voter_id, position_id, candidate_id) VALUES (?, ?, ?)";
    $insert_stmt = mysqli_prepare($conn, $insert_query);
    if (!$insert_stmt) {
        return ['ok' => false, 'message' => 'Unable to save vote right now.'];
    }
    mysqli_stmt_bind_param($insert_stmt, "iii", $voter_id, $position_id, $candidate_id);

    if (!mysqli_stmt_execute($insert_stmt)) {
        return ['ok' => false, 'message' => 'Failed to save your vote. Please try again.'];
    }

    logAuditEvent('voter', $voter_id, 'vote_cast', [
        'position_id' => $position_id,
        'candidate_id' => (int)$candidate_id
    ]);

    return ['ok' => true, 'message' => 'Vote submitted successfully.'];
}

function getBallotProgress($voter_id) {
    $ballot = getScopedBallot($voter_id);
    $total = count($ballot);
    $completed = 0;
    foreach ($ballot as $position) {
        if (!empty($position['selected_candidate_id'])) {
            $completed++;
        }
    }
    return ['total' => $total, 'completed' => $completed];
}

function saveCandidatePhotoUpload($file) {
    if (!is_array($file) || !isset($file['error'])) {
        return ['ok' => false, 'message' => 'Candidate photo is required.'];
    }

    if ((int)$file['error'] === UPLOAD_ERR_NO_FILE) {
        return ['ok' => false, 'message' => 'Candidate photo is required.'];
    }

    if ((int)$file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'message' => 'Failed to upload candidate photo.'];
    }

    $max_size = 5 * 1024 * 1024;
    if ((int)($file['size'] ?? 0) > $max_size) {
        return ['ok' => false, 'message' => 'Candidate photo must be 5MB or less.'];
    }

    $tmp_name = (string)($file['tmp_name'] ?? '');
    if ($tmp_name === '' || !is_uploaded_file($tmp_name)) {
        return ['ok' => false, 'message' => 'Invalid candidate photo upload.'];
    }

    $image_info = @getimagesize($tmp_name);
    if (!$image_info || empty($image_info['mime'])) {
        return ['ok' => false, 'message' => 'Candidate photo must be a valid image.'];
    }

    $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp'
    ];
    $mime = strtolower((string)$image_info['mime']);
    if (!isset($allowed_mimes[$mime])) {
        return ['ok' => false, 'message' => 'Candidate photo must be JPG, PNG, or WEBP.'];
    }

    $upload_dir = __DIR__ . '/assets/uploads/candidates';
    if (!is_dir($upload_dir) && !@mkdir($upload_dir, 0755, true)) {
        return ['ok' => false, 'message' => 'Unable to prepare candidate photo storage.'];
    }

    try {
        $random = bin2hex(random_bytes(6));
    } catch (Exception $e) {
        $random = (string)mt_rand(100000, 999999);
    }

    $filename = 'candidate_' . date('YmdHis') . '_' . $random . '.' . $allowed_mimes[$mime];
    $target_path = $upload_dir . '/' . $filename;

    $normalized_width = 400;
    $normalized_height = 400;

    $source_image = null;
    if ($mime === 'image/jpeg' && function_exists('imagecreatefromjpeg')) {
        $source_image = @imagecreatefromjpeg($tmp_name);
    } elseif ($mime === 'image/png' && function_exists('imagecreatefrompng')) {
        $source_image = @imagecreatefrompng($tmp_name);
    } elseif ($mime === 'image/webp' && function_exists('imagecreatefromwebp')) {
        $source_image = @imagecreatefromwebp($tmp_name);
    }

    $saved = false;
    if (is_resource($source_image) || (is_object($source_image) && get_class($source_image) === 'GdImage')) {
        $src_width = imagesx($source_image);
        $src_height = imagesy($source_image);

        if ($src_width > 0 && $src_height > 0 && function_exists('imagecreatetruecolor')) {
            $crop_size = min($src_width, $src_height);
            $src_x = (int)(($src_width - $crop_size) / 2);
            $src_y = (int)(($src_height - $crop_size) / 2);

            $normalized_image = imagecreatetruecolor($normalized_width, $normalized_height);

            if ($mime === 'image/png' || $mime === 'image/webp') {
                imagealphablending($normalized_image, false);
                imagesavealpha($normalized_image, true);
                $transparent = imagecolorallocatealpha($normalized_image, 0, 0, 0, 127);
                imagefilledrectangle($normalized_image, 0, 0, $normalized_width, $normalized_height, $transparent);
            }

            $copied = imagecopyresampled(
                $normalized_image,
                $source_image,
                0,
                0,
                $src_x,
                $src_y,
                $normalized_width,
                $normalized_height,
                $crop_size,
                $crop_size
            );

            if ($copied) {
                if ($mime === 'image/jpeg' && function_exists('imagejpeg')) {
                    $saved = imagejpeg($normalized_image, $target_path, 88);
                } elseif ($mime === 'image/png' && function_exists('imagepng')) {
                    $saved = imagepng($normalized_image, $target_path, 6);
                } elseif ($mime === 'image/webp' && function_exists('imagewebp')) {
                    $saved = imagewebp($normalized_image, $target_path, 88);
                }
            }

            imagedestroy($normalized_image);
        }

        imagedestroy($source_image);
    }

    // Fallback when GD image processing is unavailable.
    if (!$saved) {
        if (!move_uploaded_file($tmp_name, $target_path)) {
            return ['ok' => false, 'message' => 'Could not save candidate photo.'];
        }
    }

    return ['ok' => true, 'path' => 'assets/uploads/candidates/' . $filename];
}

function addCandidate($position_id, $full_name, $party_name, $candidate_photo = null, $county_id = null, $constituency_id = null, $ward_id = null) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "INSERT INTO candidates (position_id, full_name, party_name, candidate_photo, county_id, constituency_id, ward_id)
              VALUES (?, ?, ?, ?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "isssiii", $position_id, $full_name, $party_name, $candidate_photo, $county_id, $constituency_id, $ward_id);
    return mysqli_stmt_execute($stmt);
}

function saveOptionalCandidatePhotoUpload($file) {
    if (!is_array($file) || !isset($file['error']) || (int)$file['error'] === UPLOAD_ERR_NO_FILE) {
        return ['ok' => true, 'path' => null];
    }
    return saveCandidatePhotoUpload($file);
}

function saveNationalIdPhotoUpload($file, $side = 'front') {
    $normalized_side = strtolower(trim((string)$side)) === 'back' ? 'back' : 'front';
    $label = $normalized_side === 'back' ? 'National ID back photo' : 'National ID front photo';

    if (!is_array($file) || !isset($file['error'])) {
        return ['ok' => false, 'message' => $label . ' is required.'];
    }

    if ((int)$file['error'] === UPLOAD_ERR_NO_FILE) {
        return ['ok' => false, 'message' => $label . ' is required.'];
    }

    if ((int)$file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'message' => 'Failed to upload ' . strtolower($label) . '.'];
    }

    $max_size = 5 * 1024 * 1024;
    if ((int)($file['size'] ?? 0) > $max_size) {
        return ['ok' => false, 'message' => $label . ' must be 5MB or less.'];
    }

    $tmp_name = (string)($file['tmp_name'] ?? '');
    if ($tmp_name === '' || !is_uploaded_file($tmp_name)) {
        return ['ok' => false, 'message' => 'Invalid ' . strtolower($label) . ' upload.'];
    }

    $image_info = @getimagesize($tmp_name);
    if (!$image_info || empty($image_info['mime'])) {
        return ['ok' => false, 'message' => $label . ' must be a valid image.'];
    }

    $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp'
    ];
    $mime = strtolower((string)$image_info['mime']);
    if (!isset($allowed_mimes[$mime])) {
        return ['ok' => false, 'message' => $label . ' must be JPG, PNG, or WEBP.'];
    }

    $upload_dir = __DIR__ . '/assets/uploads/voter_ids';
    if (!is_dir($upload_dir) && !@mkdir($upload_dir, 0755, true)) {
        return ['ok' => false, 'message' => 'Unable to prepare National ID document storage.'];
    }

    try {
        $random = bin2hex(random_bytes(6));
    } catch (Exception $e) {
        $random = (string)mt_rand(100000, 999999);
    }

    $filename = 'national_id_' . $normalized_side . '_' . date('YmdHis') . '_' . $random . '.' . $allowed_mimes[$mime];
    $target_path = $upload_dir . '/' . $filename;

    if (!move_uploaded_file($tmp_name, $target_path)) {
        return ['ok' => false, 'message' => 'Could not save ' . strtolower($label) . '.'];
    }

    return ['ok' => true, 'path' => 'assets/uploads/voter_ids/' . $filename];
}

function getAllConstituencies() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $result = mysqli_query($conn, "SELECT constituency_id, county_id, constituency_name FROM constituencies ORDER BY constituency_name ASC");
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getAllWards() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $result = mysqli_query($conn, "SELECT ward_id, constituency_id, ward_name FROM wards ORDER BY ward_name ASC");
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getByElectionById($by_election_id) {
    global $conn;
    if (!hasDbConnection()) {
        return null;
    }
    $query = "SELECT * FROM by_elections WHERE by_election_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return null;
    }
    mysqli_stmt_bind_param($stmt, "i", $by_election_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_assoc($result) : null;
}

function createByElection($position_id, $election_title, $affected_candidate_name, $reason, $county_id, $constituency_id, $ward_id, $admin_id) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $position_id = (int)$position_id;
    $county_id = (int)$county_id;
    $constituency_id = (int)$constituency_id;
    $ward_id = (int)$ward_id;
    $admin_id = (int)$admin_id;
    $election_title = trim((string)$election_title);
    $affected_candidate_name = trim((string)$affected_candidate_name);
    $reason = trim((string)$reason);

    if ($position_id <= 0 || $reason === '') {
        return ['ok' => false, 'message' => 'Position and reason are required for a by-election.'];
    }

    $position_query = "SELECT position_id, position_name, scope FROM positions WHERE position_id = ? LIMIT 1";
    $position_stmt = mysqli_prepare($conn, $position_query);
    if (!$position_stmt) {
        return ['ok' => false, 'message' => 'Unable to validate by-election position.'];
    }
    mysqli_stmt_bind_param($position_stmt, "i", $position_id);
    mysqli_stmt_execute($position_stmt);
    $position_result = mysqli_stmt_get_result($position_stmt);
    $position = $position_result ? mysqli_fetch_assoc($position_result) : null;
    if (!$position) {
        return ['ok' => false, 'message' => 'Selected position does not exist.'];
    }

    $scope = (string)$position['scope'];
    $county_value = null;
    $constituency_value = null;
    $ward_value = null;

    if ($scope === 'county') {
        if ($county_id <= 0) {
            return ['ok' => false, 'message' => 'County is required for this by-election.'];
        }
        $county_value = $county_id;
    } elseif ($scope === 'constituency') {
        if ($constituency_id <= 0) {
            return ['ok' => false, 'message' => 'Constituency is required for this by-election.'];
        }
        $constituency_value = $constituency_id;
    } elseif ($scope === 'ward') {
        if ($ward_id <= 0) {
            return ['ok' => false, 'message' => 'Ward is required for this by-election.'];
        }
        $ward_value = $ward_id;
    }

    if ($election_title === '') {
        $election_title = 'By-Election: ' . (string)$position['position_name'] . ' (' . date('Y') . ')';
    }

    $existing_query = "SELECT by_election_id FROM by_elections
        WHERE status = 'active'
          AND position_id = ?
          AND ((scope = 'national')
            OR (scope = 'county' AND county_id <=> ?)
            OR (scope = 'constituency' AND constituency_id <=> ?)
            OR (scope = 'ward' AND ward_id <=> ?))
        LIMIT 1";
    $existing_stmt = mysqli_prepare($conn, $existing_query);
    if ($existing_stmt) {
        mysqli_stmt_bind_param($existing_stmt, "iiii", $position_id, $county_value, $constituency_value, $ward_value);
        mysqli_stmt_execute($existing_stmt);
        $existing_result = mysqli_stmt_get_result($existing_stmt);
        if ($existing_result && mysqli_num_rows($existing_result) > 0) {
            return ['ok' => false, 'message' => 'An active by-election for this position and area already exists.'];
        }
    }

    $insert_query = "INSERT INTO by_elections
        (position_id, election_title, affected_candidate_name, reason, scope, county_id, constituency_id, ward_id, status, created_by_admin_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)";
    $insert_stmt = mysqli_prepare($conn, $insert_query);
    if (!$insert_stmt) {
        return ['ok' => false, 'message' => 'Failed to create by-election.'];
    }
    mysqli_stmt_bind_param(
        $insert_stmt,
        "issssiiii",
        $position_id,
        $election_title,
        $affected_candidate_name,
        $reason,
        $scope,
        $county_value,
        $constituency_value,
        $ward_value,
        $admin_id
    );

    if (!mysqli_stmt_execute($insert_stmt)) {
        return ['ok' => false, 'message' => 'Failed to create by-election.'];
    }

    return ['ok' => true, 'message' => 'By-election created successfully.', 'by_election_id' => (int)mysqli_insert_id($conn)];
}

function addByElectionCandidate($by_election_id, $full_name, $party_name, $candidate_photo = null) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "INSERT INTO by_election_candidates (by_election_id, full_name, party_name, candidate_photo, status)
              VALUES (?, ?, ?, ?, 'active')";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "isss", $by_election_id, $full_name, $party_name, $candidate_photo);
    return mysqli_stmt_execute($stmt);
}

function closeByElection($by_election_id) {
    global $conn;
    if (!hasDbConnection()) {
        return false;
    }

    $query = "UPDATE by_elections SET status = 'closed', closed_at = NOW() WHERE by_election_id = ? LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return false;
    }
    mysqli_stmt_bind_param($stmt, "i", $by_election_id);
    return mysqli_stmt_execute($stmt);
}

function getByElectionsForAdmin() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT b.*, p.position_name,
                     co.county_name,
                     cn.constituency_name,
                     w.ward_name,
                     (SELECT COUNT(*) FROM by_election_candidates c WHERE c.by_election_id = b.by_election_id AND c.status = 'active') AS candidates_count,
                     (SELECT COUNT(*) FROM by_election_votes v WHERE v.by_election_id = b.by_election_id) AS votes_count
              FROM by_elections b
              JOIN positions p ON p.position_id = b.position_id
              LEFT JOIN counties co ON co.county_id = b.county_id
              LEFT JOIN constituencies cn ON cn.constituency_id = b.constituency_id
              LEFT JOIN wards w ON w.ward_id = b.ward_id
              ORDER BY FIELD(b.status, 'active', 'closed') ASC, b.created_at DESC";
    $result = mysqli_query($conn, $query);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getByElectionCandidates($by_election_id) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT c.*, (SELECT COUNT(*) FROM by_election_votes v WHERE v.by_election_candidate_id = c.by_election_candidate_id) AS votes_count
              FROM by_election_candidates c
              WHERE c.by_election_id = ?
              ORDER BY c.full_name ASC";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    mysqli_stmt_bind_param($stmt, "i", $by_election_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function getActiveByElectionsForVoter($voter_id) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $voter = getVoterById($voter_id);
    if (!$voter) {
        return [];
    }

    $query = "SELECT b.by_election_id, b.position_id, b.election_title, b.affected_candidate_name, b.reason,
                     b.scope, b.county_id, b.constituency_id, b.ward_id,
                     p.position_name,
                     (SELECT by_election_candidate_id FROM by_election_votes v
                        WHERE v.by_election_id = b.by_election_id AND v.voter_id = ? LIMIT 1) AS selected_candidate_id
              FROM by_elections b
              JOIN positions p ON p.position_id = b.position_id
              WHERE b.status = 'active'
                AND (
                    b.scope = 'national'
                    OR (b.scope = 'county' AND b.county_id = ?)
                    OR (b.scope = 'constituency' AND b.constituency_id = ?)
                    OR (b.scope = 'ward' AND b.ward_id = ?)
                )
              ORDER BY b.created_at DESC";

    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }
    mysqli_stmt_bind_param($stmt, "iiii", $voter_id, $voter['county_id'], $voter['constituency_id'], $voter['ward_id']);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    $list = [];
    foreach ($rows as $row) {
        $by_election_id = (int)$row['by_election_id'];
        $list[] = [
            'by_election_id' => $by_election_id,
            'position_id' => (int)$row['position_id'],
            'position_name' => (string)$row['position_name'],
            'election_title' => (string)$row['election_title'],
            'affected_candidate_name' => (string)($row['affected_candidate_name'] ?? ''),
            'reason' => (string)($row['reason'] ?? ''),
            'scope' => (string)$row['scope'],
            'selected_candidate_id' => $row['selected_candidate_id'] !== null ? (int)$row['selected_candidate_id'] : null,
            'candidates' => getByElectionCandidates($by_election_id)
        ];
    }

    return $list;
}

function submitByElectionVote($voter_id, $by_election_id, $by_election_candidate_id) {
    global $conn;
    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }
    if (!canLogin($voter_id)) {
        return ['ok' => false, 'message' => 'Only verified voters can vote.'];
    }

    $by_election_id = (int)$by_election_id;
    $by_election_candidate_id = (int)$by_election_candidate_id;
    if ($by_election_id <= 0 || $by_election_candidate_id <= 0) {
        return ['ok' => false, 'message' => 'Invalid by-election selection.'];
    }

    $voter = getVoterById($voter_id);
    if (!$voter) {
        return ['ok' => false, 'message' => 'Voter account not found.'];
    }

    $query = "SELECT b.*, c.by_election_candidate_id
              FROM by_elections b
              JOIN by_election_candidates c ON c.by_election_id = b.by_election_id
              WHERE b.by_election_id = ?
                AND c.by_election_candidate_id = ?
                AND b.status = 'active'
                AND c.status = 'active'
              LIMIT 1";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return ['ok' => false, 'message' => 'Unable to process by-election vote.'];
    }
    mysqli_stmt_bind_param($stmt, "ii", $by_election_id, $by_election_candidate_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $data = $result ? mysqli_fetch_assoc($result) : null;

    if (!$data) {
        return ['ok' => false, 'message' => 'By-election candidate not found.'];
    }

    $scope = (string)$data['scope'];
    if (($scope === 'county' && (int)$data['county_id'] !== (int)$voter['county_id'])
        || ($scope === 'constituency' && (int)$data['constituency_id'] !== (int)$voter['constituency_id'])
        || ($scope === 'ward' && (int)$data['ward_id'] !== (int)$voter['ward_id'])) {
        return ['ok' => false, 'message' => 'You are not eligible to vote in this by-election area.'];
    }

    $insert_query = "INSERT INTO by_election_votes (by_election_id, by_election_candidate_id, voter_id)
                     VALUES (?, ?, ?)";
    $insert_stmt = mysqli_prepare($conn, $insert_query);
    if (!$insert_stmt) {
        return ['ok' => false, 'message' => 'Unable to submit by-election vote.'];
    }
    mysqli_stmt_bind_param($insert_stmt, "iii", $by_election_id, $by_election_candidate_id, $voter_id);

    if (!mysqli_stmt_execute($insert_stmt)) {
        return ['ok' => false, 'message' => 'You already voted in this by-election.'];
    }

    logAuditEvent('voter', $voter_id, 'by_election_vote_cast', [
        'by_election_id' => $by_election_id,
        'by_election_candidate_id' => $by_election_candidate_id
    ]);

    return ['ok' => true, 'message' => 'By-election vote submitted successfully.'];
}

function getArchivedElectionYears() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $query = "SELECT DISTINCT election_year
              FROM election_archive_runs
              ORDER BY election_year DESC";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        return [];
    }

    $years = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $year = (int)($row['election_year'] ?? 0);
        if ($year > 0) {
            $years[] = $year;
        }
    }
    return $years;
}

function getArchivedElectionResultsByYear($year) {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }

    $year = (int)$year;
    if ($year <= 0) {
        return [];
    }

    $query = "SELECT a.*, r.archived_at AS run_archived_at
              FROM election_results_archive a
              JOIN election_archive_runs r ON r.run_id = a.run_id
              WHERE a.election_year = ?
              ORDER BY a.run_id ASC, a.position_name ASC, a.votes DESC, a.candidate_name ASC";
    $stmt = mysqli_prepare($conn, $query);
    if (!$stmt) {
        return [];
    }

    mysqli_stmt_bind_param($stmt, "i", $year);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];
}

function archiveAndResetElectionData($election_year, $admin_id, $archive_note = null) {
    global $conn;

    if (!hasDbConnection()) {
        return ['ok' => false, 'message' => 'Database is unavailable.'];
    }

    $election_year = (int)$election_year;
    if ($election_year < 2000 || $election_year > 2100) {
        return ['ok' => false, 'message' => 'Please provide a valid election year.'];
    }

    if (isElectionOpen()) {
        return ['ok' => false, 'message' => 'Close the election before archiving and resetting data.'];
    }

    $results = getElectionResultsData();
    if (empty($results)) {
        return ['ok' => false, 'message' => 'No election results found to archive.'];
    }

    $turnout = getTurnoutStats();
    $candidates_count_result = mysqli_query($conn, "SELECT COUNT(*) AS total FROM candidates");
    $candidates_count = $candidates_count_result ? (int)mysqli_fetch_assoc($candidates_count_result)['total'] : 0;
    $votes_count_result = mysqli_query($conn, "SELECT COUNT(*) AS total FROM votes");
    $votes_count = $votes_count_result ? (int)mysqli_fetch_assoc($votes_count_result)['total'] : 0;

    if ($candidates_count === 0) {
        return ['ok' => false, 'message' => 'No candidates found to reset.'];
    }

    mysqli_begin_transaction($conn);
    try {
        $run_query = "INSERT INTO election_archive_runs
            (election_year, archived_by_admin_id, candidates_count, votes_count, archive_note)
            VALUES (?, ?, ?, ?, ?)";
        $run_stmt = mysqli_prepare($conn, $run_query);
        if (!$run_stmt) {
            throw new Exception('Unable to create archive batch.');
        }

        $admin_id_int = (int)$admin_id;
        $archive_note = $archive_note !== null ? substr((string)$archive_note, 0, 255) : null;
        mysqli_stmt_bind_param($run_stmt, "iiiis", $election_year, $admin_id_int, $candidates_count, $votes_count, $archive_note);
        if (!mysqli_stmt_execute($run_stmt)) {
            throw new Exception('Failed to create archive batch.');
        }
        $run_id = (int)mysqli_insert_id($conn);
        if ($run_id <= 0) {
            throw new Exception('Failed to create archive batch.');
        }

        $archive_query = "INSERT INTO election_results_archive
            (run_id, election_year, position_id, position_name, candidate_id, candidate_name, party_name,
             votes, percentage, is_leading, total_votes_position,
             registered_voters, votes_cast, turnout_percentage, archived_by_admin_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $archive_stmt = mysqli_prepare($conn, $archive_query);
        if (!$archive_stmt) {
            throw new Exception('Unable to save archived election results.');
        }

        foreach ($results as $position) {
            $position_id = isset($position['position_id']) ? (int)$position['position_id'] : null;
            $position_name = (string)($position['position_name'] ?? 'Unknown Position');
            $total_votes_position = (int)($position['total_votes'] ?? 0);
            $candidates = $position['candidates'] ?? [];

            foreach ($candidates as $candidate) {
                $candidate_id = isset($candidate['candidate_id']) ? (int)$candidate['candidate_id'] : null;
                $candidate_name = (string)($candidate['full_name'] ?? 'Unknown Candidate');
                $party_name = (string)($candidate['party_name'] ?? 'Independent');
                $votes = (int)($candidate['votes'] ?? 0);
                $percentage = (float)($candidate['percentage'] ?? 0);
                $is_leading = !empty($candidate['is_leading']) ? 1 : 0;
                $registered_voters = (int)($turnout['registered_voters'] ?? 0);
                $votes_cast = (int)($turnout['votes_cast'] ?? 0);
                $turnout_percentage = (float)($turnout['turnout_percentage'] ?? 0);

                mysqli_stmt_bind_param(
                    $archive_stmt,
                    "iiisissidiiiidi",
                    $run_id,
                    $election_year,
                    $position_id,
                    $position_name,
                    $candidate_id,
                    $candidate_name,
                    $party_name,
                    $votes,
                    $percentage,
                    $is_leading,
                    $total_votes_position,
                    $registered_voters,
                    $votes_cast,
                    $turnout_percentage,
                    $admin_id_int
                );

                if (!mysqli_stmt_execute($archive_stmt)) {
                    throw new Exception('Failed to archive election results.');
                }
            }
        }

        mysqli_query($conn, "DELETE FROM votes");
        mysqli_query($conn, "DELETE FROM candidates");
        mysqli_query($conn, "UPDATE voters SET has_voted_final = 0");

        setElectionSetting('results_published', '0');
        setElectionSetting('election_status', 'closed');

        mysqli_commit($conn);

        return ['ok' => true, 'message' => 'Election data archived and reset successfully for year ' . $election_year . '.'];
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function getElectionResultsData() {
    global $conn;
    if (!hasDbConnection()) {
        return [];
    }
    $query = "SELECT p.position_id, p.position_name, c.candidate_id, c.full_name, c.party_name,
                     COUNT(v.vote_id) AS votes
              FROM positions p
              LEFT JOIN candidates c ON c.position_id = p.position_id AND c.status = 'active'
              LEFT JOIN votes v ON v.candidate_id = c.candidate_id
              WHERE p.status = 'active'
              GROUP BY p.position_id, p.position_name, c.candidate_id, c.full_name, c.party_name
              ORDER BY p.display_order ASC, votes DESC, c.full_name ASC";
    $result = mysqli_query($conn, $query);
    $rows = $result ? mysqli_fetch_all($result, MYSQLI_ASSOC) : [];

    $grouped = [];
    foreach ($rows as $row) {
        $position_id = (int)$row['position_id'];
        if (!isset($grouped[$position_id])) {
            $grouped[$position_id] = [
                'position_id' => $position_id,
                'position_name' => $row['position_name'],
                'total_votes' => 0,
                'candidates' => []
            ];
        }

        if (!empty($row['candidate_id'])) {
            $votes = (int)$row['votes'];
            $grouped[$position_id]['total_votes'] += $votes;
            $grouped[$position_id]['candidates'][] = [
                'candidate_id' => (int)$row['candidate_id'],
                'full_name' => $row['full_name'],
                'party_name' => $row['party_name'],
                'votes' => $votes
            ];
        }
    }

    foreach ($grouped as $position_id => $position) {
        $total_votes = $position['total_votes'];
        foreach ($position['candidates'] as $index => $candidate) {
            $pct = $total_votes > 0 ? round(($candidate['votes'] / $total_votes) * 100, 2) : 0;
            $grouped[$position_id]['candidates'][$index]['percentage'] = $pct;
            $grouped[$position_id]['candidates'][$index]['is_leading'] = ($index === 0 && $candidate['votes'] > 0);
        }
    }

    return array_values($grouped);
}

function getTurnoutStats() {
    $registered = getTotalRegisteredVoters();
    $votes_cast = getTotalVotesCast();
    $turnout = $registered > 0 ? round(($votes_cast / $registered) * 100, 2) : 0;

    return [
        'registered_voters' => $registered,
        'votes_cast' => $votes_cast,
        'turnout_percentage' => $turnout
    ];
}

ensureSecuritySchema();
ensureElectionSchema();
?>