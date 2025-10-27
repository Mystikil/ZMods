<?php
if (!defined('INITIALIZED')) {
        die('Direct access not allowed.');
}

if (!defined('RECOVERY_KEY_GROUPS')) {
        define('RECOVERY_KEY_GROUPS', 5);
}
if (!defined('RECOVERY_KEY_GROUP_LEN')) {
        define('RECOVERY_KEY_GROUP_LEN', 5);
}
if (!defined('RECOVERY_KEY_ALPHABET')) {
        define('RECOVERY_KEY_ALPHABET', 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
}
if (!defined('RECOVERY_VERIFY_WINDOW_MIN')) {
        define('RECOVERY_VERIFY_WINDOW_MIN', 15);
}
if (!defined('RECOVERY_MAX_FAILS_PER_15M')) {
        define('RECOVERY_MAX_FAILS_PER_15M', 5);
}
if (!defined('RECOVERY_AUTO_REVOKE_AFTER_RESET')) {
        define('RECOVERY_AUTO_REVOKE_AFTER_RESET', false);
}

function rk_generate_plaintext() {
        $alphabet = RECOVERY_KEY_ALPHABET;
        $alphabetLength = strlen($alphabet);
        $groups = array();
        for ($i = 0; $i < RECOVERY_KEY_GROUPS; $i++) {
                $segment = '';
                for ($j = 0; $j < RECOVERY_KEY_GROUP_LEN; $j++) {
                        $index = random_int(0, $alphabetLength - 1);
                        $segment .= $alphabet[$index];
                }
                $groups[] = $segment;
        }
        return implode('-', $groups);
}

function rk_normalize($plain) {
        $plain = strtoupper($plain);
        return preg_replace('/[^A-Z0-9]/', '', $plain);
}

function rk_hash($plain) {
        $normalized = rk_normalize($plain);
        return password_hash($normalized, PASSWORD_BCRYPT, array('cost' => 12));
}

function rk_verify($plain, $hash) {
        $normalized = rk_normalize($plain);
        if (!$hash) {
                return false;
        }
        return password_verify($normalized, $hash);
}

function rk_hint_from_plain($plain) {
        $normalized = rk_normalize($plain);
        if (strlen($normalized) === 0) {
                return '';
        }
        $groupLength = RECOVERY_KEY_GROUP_LEN;
        $offset = strlen($normalized) - $groupLength;
        if ($offset < 0) {
                        $offset = 0;
        }
        return substr($normalized, $offset, $groupLength);
}

function rk_ip_to_binary($ip) {
        $packed = inet_pton($ip);
        if ($packed === false) {
                return null;
        }
        return $packed;
}

function rk_rate_limit_violation(PDO $db, $accountId, $ip) {
        $ipBinary = rk_ip_to_binary($ip);
        if ($ipBinary === null) {
                return false;
        }
        $windowStart = (new DateTimeImmutable('now'))->modify('-' . RECOVERY_VERIFY_WINDOW_MIN . ' minutes');
        $stmt = $db->prepare('SELECT COUNT(*) AS attempt_count FROM `znote_recovery_attempts` WHERE `ip` = :ip AND `created_at` >= :start');
        $stmt->bindValue(':ip', $ipBinary, PDO::PARAM_LOB);
        $stmt->bindValue(':start', $windowStart->format('Y-m-d H:i:s'));
        $stmt->execute();
        $count = (int) $stmt->fetchColumn();
        return $count >= RECOVERY_MAX_FAILS_PER_15M;
}

function rk_log_attempt(PDO $db, $accountId, $ip) {
        $ipBinary = rk_ip_to_binary($ip);
        $stmt = $db->prepare('INSERT INTO `znote_recovery_attempts` (`account_id`, `ip`, `created_at`) VALUES (:account_id, :ip, :created_at)');
        if ($accountId === null) {
                $stmt->bindValue(':account_id', null, PDO::PARAM_NULL);
        } else {
                $stmt->bindValue(':account_id', (int)$accountId, PDO::PARAM_INT);
        }
        if ($ipBinary === null) {
                $stmt->bindValue(':ip', null, PDO::PARAM_NULL);
        } else {
                $stmt->bindValue(':ip', $ipBinary, PDO::PARAM_LOB);
        }
        $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
        $stmt->execute();
}

function rk_audit(PDO $db, $accountId, $action, array $meta = array()) {
        $ipBinary = rk_ip_to_binary(getIP());
        $stmt = $db->prepare('INSERT INTO `znote_recovery_audit` (`account_id`, `action`, `meta`, `ip`, `created_at`) VALUES (:account_id, :action, :meta, :ip, :created_at)');
        $stmt->bindValue(':account_id', (int)$accountId, PDO::PARAM_INT);
        $stmt->bindValue(':action', $action);
        $stmt->bindValue(':meta', json_encode($meta, JSON_UNESCAPED_SLASHES));
        if ($ipBinary === null) {
                $stmt->bindValue(':ip', null, PDO::PARAM_NULL);
        } else {
                $stmt->bindValue(':ip', $ipBinary, PDO::PARAM_LOB);
        }
        $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
        $stmt->execute();
}

function rk_password_matches($inputPassword, $storedPassword, $salt = null) {
        if (!empty($storedPassword)) {
                $info = password_get_info($storedPassword);
                if (!empty($info['algo'])) {
                        return password_verify($inputPassword, $storedPassword);
                }
        }
        if (!empty($salt)) {
                return sha1($salt . $inputPassword) === $storedPassword;
        }
        return sha1($inputPassword) === $storedPassword;
}
