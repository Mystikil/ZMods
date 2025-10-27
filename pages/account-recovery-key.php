<?php
require_once '../engine/init.php';
protect_page();
include '../layout/overall/header.php';

if (!isset($db) || !($db instanceof PDO)) {
        echo '<h1>Recovery Key</h1><p>Database connection unavailable.</p>';
        include '../layout/overall/footer.php';
        exit();
}

$accountId = (int)$user_data['id'];
$errors = array();
$successMessage = '';
$oneTimeKey = '';

if (isset($_SESSION['one_time_recovery_key']) && !empty($_SESSION['one_time_recovery_key'])) {
        $oneTimeKey = htmlspecialchars($_SESSION['one_time_recovery_key']);
        unset($_SESSION['one_time_recovery_key']);
}

$stmt = $db->prepare('SELECT `recovery_key_hash`, `recovery_key_hint`, `recovery_key_created_at`, `recovery_key_revoked` FROM `accounts` WHERE `id` = :id');
$stmt->bindValue(':id', $accountId, PDO::PARAM_INT);
$stmt->execute();
$keyRow = $stmt->fetch();

if (!empty($_POST)) {
        if (!Token::isValid($_POST['token'])) {
                $errors[] = 'Token is invalid.';
        }
        $currentPassword = isset($_POST['current_password']) ? $_POST['current_password'] : '';
        if (empty($currentPassword)) {
                $errors[] = 'You must enter your current account password to rotate the recovery key.';
        }
        if (empty($errors)) {
                $passwordQuery = 'SELECT `password` FROM `accounts` WHERE `id` = :id';
                if (config('salt') === true) {
                        $passwordQuery = 'SELECT `password`, `salt` FROM `accounts` WHERE `id` = :id';
                }
                $passwordStmt = $db->prepare($passwordQuery);
                $passwordStmt->bindValue(':id', $accountId, PDO::PARAM_INT);
                $passwordStmt->execute();
                $passwordRow = $passwordStmt->fetch();
                $saltValue = (isset($passwordRow['salt'])) ? $passwordRow['salt'] : null;
                if (!$passwordRow || !rk_password_matches($currentPassword, $passwordRow['password'], $saltValue)) {
                        $errors[] = 'Incorrect password.';
                }
        }
        if (empty($errors)) {
                $newKey = rk_generate_plaintext();
                $hash = rk_hash($newKey);
                $hint = rk_hint_from_plain($newKey);
                $createdAt = date('Y-m-d H:i:s');
                $updateStmt = $db->prepare('UPDATE `accounts` SET `recovery_key_hash` = :hash, `recovery_key_created_at` = :created_at, `recovery_key_revoked` = 0, `recovery_key_hint` = :hint WHERE `id` = :id');
                $updateStmt->bindValue(':hash', $hash);
                $updateStmt->bindValue(':created_at', $createdAt);
                $updateStmt->bindValue(':hint', $hint);
                $updateStmt->bindValue(':id', $accountId, PDO::PARAM_INT);
                $updateStmt->execute();
                rk_audit($db, $accountId, 'ROTATE', array('hint' => $hint));
                $_SESSION['one_time_recovery_key'] = $newKey;
                header('Location: account-recovery-key.php?rotated=1');
                exit();
        }
}

if (isset($_GET['rotated']) && empty($_GET['rotated'])) {
        $successMessage = 'Recovery key rotated successfully. Your new key is shown below.';
}
?>
<h1>Recovery Key</h1>
<?php
if (!empty($errors)) {
        echo '<div class="alert alert-danger">' . output_errors($errors) . '</div>';
}
if (!empty($successMessage)) {
        echo '<div class="alert alert-success">' . htmlspecialchars($successMessage) . '</div>';
}
if (!empty($oneTimeKey)) {
        ?>
        <div class="alert alert-info">
                <h2>Your Recovery Key</h2>
                <p><strong><?php echo $oneTimeKey; ?></strong></p>
                <p>Store this key safely. It will not be displayed again.</p>
        </div>
        <?php
}
if ($keyRow) {
        $hintText = !empty($keyRow['recovery_key_hint']) ? htmlspecialchars($keyRow['recovery_key_hint']) : 'N/A';
        $createdText = !empty($keyRow['recovery_key_created_at']) ? htmlspecialchars($keyRow['recovery_key_created_at']) : 'Not generated yet';
        $statusText = (!empty($keyRow['recovery_key_hash']) && (int)$keyRow['recovery_key_revoked'] === 0) ? 'Active' : 'Revoked or not set';
        ?>
        <div class="recovery-key-status">
                <p><strong>Current key hint:</strong> <?php echo $hintText; ?></p>
                <p><strong>Created:</strong> <?php echo $createdText; ?></p>
                <p><strong>Status:</strong> <?php echo htmlspecialchars($statusText); ?></p>
        </div>
        <?php
}
?>
<h2>Rotate Recovery Key</h2>
<p>Generate a new recovery key after confirming your account password.</p>
<form action="" method="post">
        <ul>
                <li>
                        Current password:<br>
                        <input type="password" name="current_password">
                </li>
                <?php Token::create(); ?>
                <li>
                        <input type="submit" value="Generate new recovery key">
                </li>
        </ul>
</form>
<?php
include '../layout/overall/footer.php';
