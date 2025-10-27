<?php
require_once '../engine/init.php';
include '../layout/overall/header.php';

if (!isset($db) || !($db instanceof PDO)) {
        echo '<h1>Recover Account</h1><p>Database connection unavailable.</p>';
        include '../layout/overall/footer.php';
        exit();
}

$errors = array();
$successMessage = '';
$identifier = '';
$newEmailValue = '';

if (!empty($_POST)) {
        if (!Token::isValid($_POST['token'])) {
                $errors[] = 'Token is invalid.';
        }
        $identifier = isset($_POST['name_or_email']) ? trim($_POST['name_or_email']) : '';
        $recoveryKey = isset($_POST['recovery_key']) ? trim($_POST['recovery_key']) : '';
        $newPassword = isset($_POST['new_password']) ? $_POST['new_password'] : '';
        $newPassword2 = isset($_POST['new_password2']) ? $_POST['new_password2'] : '';
        $newEmailValue = isset($_POST['new_email']) ? trim($_POST['new_email']) : '';

        if ($identifier === '') {
                $errors[] = 'Account name or email is required.';
        }
        if ($recoveryKey === '') {
                $errors[] = 'Recovery key is required.';
        }
        if (strlen($newPassword) < 8) {
                $errors[] = 'New password must be at least 8 characters long.';
        }
        if ($newPassword !== $newPassword2) {
                $errors[] = 'Passwords do not match.';
        }
        if (!empty($newEmailValue) && !filter_var($newEmailValue, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Please provide a valid email address.';
        }

        $accountRow = false;
        if (empty($errors)) {
                $fields = '`id`, `name`, `email`, `recovery_key_hash`, `recovery_key_created_at`, `recovery_key_revoked`, `recovery_key_hint`, `password`';
                if (config('salt') === true) {
                        $fields .= ', `salt`';
                }
                if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
                        $stmt = $db->prepare('SELECT ' . $fields . ' FROM `accounts` WHERE `email` = :identifier LIMIT 1');
                } else {
                        $stmt = $db->prepare('SELECT ' . $fields . ' FROM `accounts` WHERE `name` = :identifier LIMIT 1');
                }
                $stmt->bindValue(':identifier', $identifier);
                $stmt->execute();
                $accountRow = $stmt->fetch();
                if (!$accountRow) {
                        $errors[] = 'Account not found.';
                }
        }

        if ($accountRow && empty($errors)) {
                if (empty($accountRow['recovery_key_hash']) || (int)$accountRow['recovery_key_revoked'] === 1) {
                        $errors[] = 'No active recovery key is available for this account.';
                }
        }

        $ipAddress = getIP();
        if ($accountRow && empty($errors)) {
                if (rk_rate_limit_violation($db, (int)$accountRow['id'], $ipAddress)) {
                        $errors[] = 'Too many recovery attempts. Please wait before trying again.';
                }
        }

        if ($accountRow && empty($errors)) {
                if (!rk_verify($recoveryKey, $accountRow['recovery_key_hash'])) {
                        rk_log_attempt($db, (int)$accountRow['id'], $ipAddress);
                        rk_audit($db, (int)$accountRow['id'], 'VERIFY_FAIL', array('hint' => $accountRow['recovery_key_hint']));
                        $errors[] = 'Invalid recovery key.';
                }
        }

        if ($accountRow && empty($errors)) {
                rk_audit($db, (int)$accountRow['id'], 'VERIFY_SUCCESS', array('hint' => $accountRow['recovery_key_hint']));
                $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT, array('cost' => 12));
                $updateQuery = 'UPDATE `accounts` SET `password` = :password';
                if (config('salt') === true) {
                        $updateQuery .= ', `salt` = \'\'';
                }
                if (RECOVERY_AUTO_REVOKE_AFTER_RESET) {
                        $updateQuery .= ', `recovery_key_revoked` = 1';
                }
                $updateQuery .= ' WHERE `id` = :id';
                $updateStmt = $db->prepare($updateQuery);
                $updateStmt->bindValue(':password', $newPasswordHash);
                $updateStmt->bindValue(':id', (int)$accountRow['id'], PDO::PARAM_INT);
                $updateStmt->execute();
                rk_audit($db, (int)$accountRow['id'], 'RESET_PASSWORD');

                if (!empty($newEmailValue) && $newEmailValue !== $accountRow['email']) {
                        $emailStmt = $db->prepare('UPDATE `accounts` SET `email` = :email WHERE `id` = :id');
                        $emailStmt->bindValue(':email', $newEmailValue);
                        $emailStmt->bindValue(':id', (int)$accountRow['id'], PDO::PARAM_INT);
                        $emailStmt->execute();
                        rk_audit($db, (int)$accountRow['id'], 'RESET_EMAIL', array('email' => $newEmailValue));
                }

                $successMessage = 'Password updated, you can now log in.';
        }
}
?>
<h1>Recover Account</h1>
<?php
if (!empty($errors)) {
        echo '<div class="alert alert-danger">' . output_errors($errors) . '</div>';
}
if (!empty($successMessage)) {
        echo '<div class="alert alert-success">' . htmlspecialchars($successMessage) . '</div>';
}
?>
<form action="" method="post">
        <ul>
                <li>
                        Account name or email:<br>
                        <input type="text" name="name_or_email" value="<?php echo htmlspecialchars($identifier); ?>">
                </li>
                <li>
                        Recovery key:<br>
                        <input type="text" name="recovery_key">
                </li>
                <li>
                        New password:<br>
                        <input type="password" name="new_password">
                </li>
                <li>
                        Confirm new password:<br>
                        <input type="password" name="new_password2">
                </li>
                <li>
                        New email (optional):<br>
                        <input type="text" name="new_email" value="<?php echo htmlspecialchars($newEmailValue); ?>">
                </li>
                <?php Token::create(); ?>
                <li>
                        <input type="submit" value="Reset password">
                </li>
        </ul>
</form>
<?php
include '../layout/overall/footer.php';
