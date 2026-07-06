<?php
/*
 * Overview: Register
 * Purpose: Handles server-side logic for this feature.
 */
require_once 'includes/db_connect.php';
require_once 'includes/functions.php';

$error = '';
$success = '';
$counties = getCounties();

if (!$conn) {
    $error = 'Database connection failed. Check DB settings in includes/db_connect.php or environment variables.';
}

if ($conn && $_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request token. Please refresh and try again.';
    }

    $national_id = sanitize($_POST['national_id'] ?? '');
    $full_name = sanitize($_POST['full_name'] ?? '');
    $email = sanitize($_POST['email'] ?? '');
    $phone = sanitize($_POST['phone'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $confirm_password = (string)($_POST['confirm_password'] ?? '');
    $county_id = (int)($_POST['county_id'] ?? 0);
    $constituency_id = (int)($_POST['constituency_id'] ?? 0);
    $ward_id = (int)($_POST['ward_id'] ?? 0);
    $dob = sanitize($_POST['dob'] ?? '');
    $national_id_front_path = '';
    $national_id_back_path = '';

    if ($error === '' && isRateLimited('register', getClientIpAddress(), 8, 30)) {
        $error = 'Too many registration attempts. Please try again later.';
    }
    
    if ($error === '' && ($national_id === '' || $full_name === '' || $email === '' || $phone === '' || $password === '' || $confirm_password === '' || $dob === '')) {
        $error = 'National ID, full name, email, phone, date of birth, and passwords are required.';
    } elseif ($error === '' && !preg_match('/^\d{8}$/', $national_id)) {
        $error = 'National ID must be exactly 8 digits.';
    } elseif ($error === '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please provide a valid email address.';
    } elseif ($error === '' && !preg_match('/^\+?[0-9]{9,15}$/', $phone)) {
        $error = 'Phone number must contain 9 to 15 digits (optional + at start).';
    } elseif ($error === '' && ($county_id <= 0 || $constituency_id <= 0 || $ward_id <= 0)) {
        $error = 'County, constituency, and ward are required.';
    } elseif ($error === '' && (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dob) || strtotime($dob) === false || strtotime($dob) > time() || strtotime($dob) < strtotime('1900-01-01'))) {
        $error = 'Please provide a valid date of birth.';
    } elseif ($error === '' && strtotime($dob) > strtotime('-18 years')) {
        $error = 'You must be at least 18 years old to register.';
    } elseif ($error === '' && $password !== $confirm_password) {
        $error = "Passwords do not match!";
    } elseif ($error === '' && strlen($password) < 6) {
        $error = "Password must be at least 6 characters!";
    } elseif ($error === '' && (((int)($_FILES['national_id_front']['error'] ?? UPLOAD_ERR_NO_FILE)) === UPLOAD_ERR_NO_FILE || ((int)($_FILES['national_id_back']['error'] ?? UPLOAD_ERR_NO_FILE)) === UPLOAD_ERR_NO_FILE)) {
        $error = 'Please upload both front and back photos of your National ID.';
    } elseif ($error === '') {
        $duplicate = findDuplicateRegistration(
            $national_id,
            $email,
            $phone,
            $full_name,
            $dob,
            $county_id,
            $constituency_id,
            $ward_id
        );

        if (!empty($duplicate['has_duplicate'])) {
            $error = (string)($duplicate['reason'] ?? 'Registration details already exist.');
        } else {
            $front_upload = saveNationalIdPhotoUpload($_FILES['national_id_front'] ?? null, 'front');
            if (empty($front_upload['ok'])) {
                $error = (string)($front_upload['message'] ?? 'Failed to upload National ID front photo.');
            } else {
                $national_id_front_path = (string)($front_upload['path'] ?? '');

                $back_upload = saveNationalIdPhotoUpload($_FILES['national_id_back'] ?? null, 'back');
                if (empty($back_upload['ok'])) {
                    $error = (string)($back_upload['message'] ?? 'Failed to upload National ID back photo.');

                    if ($national_id_front_path !== '') {
                        $front_file = __DIR__ . '/' . ltrim($national_id_front_path, '/');
                        if (is_file($front_file)) {
                            @unlink($front_file);
                        }
                    }
                } else {
                    $national_id_back_path = (string)($back_upload['path'] ?? '');
                }
            }
        }

        if ($error === '') {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $verification_token = generateVerificationToken();
            $token_expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
            
            $insert_query = "INSERT INTO voters (national_id, full_name, email, phone, password, county_id, constituency_id, ward_id, date_of_birth, national_id_front_path, national_id_back_path, verification_token, verification_token_expires_at, email_verified, admin_verified, verification_status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'pending')";
            $stmt = mysqli_prepare($conn, $insert_query);
            if (!$stmt) {
                $error = 'System error. Please try again later.';
                logAuditEvent('system', null, 'voter_register_prepare_failed');
            } else {
                mysqli_stmt_bind_param($stmt, "sssssiiisssss", $national_id, $full_name, $email, $phone, $hashed_password, $county_id, $constituency_id, $ward_id, $dob, $national_id_front_path, $national_id_back_path, $verification_token, $token_expiry);
            }
            
            if ($error === '' && mysqli_stmt_execute($stmt)) {
                sendVerificationEmail($email, $verification_token);
                recordRateLimitEvent('register', getClientIpAddress(), true);
                logAuditEvent('system', null, 'voter_registered', ['national_id' => $national_id]);
                
                $success = "Registration successful! Please check your email to verify your account.";
            } else {
                if ($national_id_front_path !== '') {
                    $front_file = __DIR__ . '/' . ltrim($national_id_front_path, '/');
                    if (is_file($front_file)) {
                        @unlink($front_file);
                    }
                }

                if ($national_id_back_path !== '') {
                    $back_file = __DIR__ . '/' . ltrim($national_id_back_path, '/');
                    if (is_file($back_file)) {
                        @unlink($back_file);
                    }
                }

                $db_error = (string)mysqli_error($conn);
                if (stripos($db_error, 'Duplicate entry') !== false) {
                    $error = 'This account cannot be created because one or more required details are already registered.';
                } else {
                    $error = "Registration failed. Please try again.";
                }
                recordRateLimitEvent('register', getClientIpAddress(), false);
            }
        }
    }
}

$csrf_token = getCsrfToken();

require_once 'views/register.view.html';