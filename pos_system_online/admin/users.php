
<?php

require_once __DIR__ . "/../includes/auth.php";

require_role("admin");

$error = "";

// Create a new user
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    verify_csrf();

    $name = trim($_POST["name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";
    $role = $_POST["role"] ?? "cashier";

    // Validate user information
    if (
        $name == "" ||
        $username == "" ||
        strlen($password) < 8 ||
        !in_array($role, ["admin", "cashier"], true)
    ) {

        $error = "Complete all fields. Password must be at least 8 characters.";

    } else {

        try {

            // Encrypt password before saving
            $hashed_password = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            // Insert user into database
            $sql = "
                INSERT INTO users (name, username, password, role)
                VALUES (?, ?, ?, ?)
            ";

            $stmt = $pdo->prepare($sql);

            $stmt->execute([
                $name,
                $username,
                $hashed_password,
                $role
            ]);

            redirect_to("users.php");

        } catch (PDOException $e) {

            $error = "Could not add user. The username may already be taken.";

        }
    }
}

// Get all registered users
$sql = "
    SELECT id, name, username, role, created_at
    FROM users
    ORDER BY id DESC
";

$users = $pdo->query($sql)->fetchAll();

$page_title = "Users";
$asset_prefix = "../";

require __DIR__ . "/../includes/header.php";

?>

<h2 class="mb-3">User Management</h2>

<div class="row g-3">

    <!-- Add User Form -->
    <div class="col-lg-4">

        <div class="card p-3">

            <h5>Add User</h5>

            <?php if ($error != ""): ?>

                <div class="alert alert-danger">
                    <?= h($error) ?>
                </div>

            <?php endif; ?>

            <form method="post">

                <input
                    type="hidden"
                    name="csrf"
                    value="<?= h(csrf_token()) ?>"
                >

                <label class="form-label">Full Name</label>

                <input
                    type="text"
                    class="form-control mb-2"
                    name="name"
                    required
                >

                <label class="form-label">Username</label>

                <input
                    type="text"
                    class="form-control mb-2"
                    name="username"
                    required
                >

                <label class="form-label">Password (8+ characters)</label>

                <input
                    type="password"
                    class="form-control mb-2"
                    name="password"
                    minlength="8"
                    required
                >

                <label class="form-label">Role</label>

                <select
                    class="form-select mb-3"
                    name="role"
                    required
                >

                    <option value="cashier">Cashier</option>
                    <option value="admin">Admin</option>

                </select>

                <button type="submit" class="btn btn-primary">
                    Create User
                </button>

            </form>

        </div>

    </div>

    <!-- User List -->
    <div class="col-lg-8">

        <div class="card p-3">

            <h5>Registered Users</h5>

            <div class="table-responsive">

                <table class="table">

                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Date Created</th>
                        </tr>
                    </thead>

                    <tbody>

                        <?php foreach ($users as $user): ?>

                            <tr>

                                <td>
                                    <?= h($user["name"]) ?>
                                </td>

                                <td>
                                    <?= h($user["username"]) ?>
                                </td>

                                <td>
                                    <?= h(ucfirst($user["role"])) ?>
                                </td>

                                <td>
                                    <?= h($user["created_at"]) ?>
                                </td>

                            </tr>

                        <?php endforeach; ?>

                        <?php if (empty($users)): ?>

                            <tr>
                                <td colspan="4" class="text-center text-muted">
                                    No users registered yet.
                                </td>
                            </tr>

                        <?php endif; ?>

                    </tbody>

                </table>

            </div>

        </div>

    </div>

</div>

<?php

require __DIR__ . "/../includes/footer.php";

?>
