<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable PHP Application</title>
</head>
<body>
    <h1>Vulnerable PHP Application</h1>

    <!-- Form for SQL Injection -->
    <h2>Login (SQL Injection)</h2>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" name="login" value="Login">
    </form>

    <!-- Form for Local/Remote File Inclusion -->
    <h2>File Inclusion (LFI/RFI)</h2>
    <form method="get">
        Page: <input type="text" name="page"><br>
        <input type="submit" value="Load Page">
    </form>

    <!-- Form for Command Injection -->
    <h2>Command Execution (Command Injection)</h2>
    <form method="get">
        Command: <input type="text" name="cmd"><br>
        <input type="submit" value="Execute Command">
    </form>

    <!-- Form for Cross-Site Scripting (XSS) -->
    <h2>Greet User (XSS)</h2>
    <form method="get">
        Name: <input type="text" name="name"><br>
        <input type="submit" value="Greet">
    </form>

    <!-- Form for Code Injection -->
    <h2>Execute PHP Code (Code Injection)</h2>
    <form method="get">
        Code: <input type="text" name="code"><br>
        <input type="submit" value="Execute">
    </form>

    <?php
    $conn = new mysqli("localhost", "root", "", "test_db");

    // SQL Injection Vulnerability
    if (isset($_POST['login'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        $result = $conn->query($query);
        if ($result->num_rows > 0) {
            echo "Login successful";
        } else {
            echo "Invalid credentials";
        }
    }

    // Local/Remote File Inclusion Vulnerability
    if (isset($_GET['page'])) {
        $page = $_GET['page'];
        include($page);
    }

    // Command Injection Vulnerability
    if (isset($_GET['cmd'])) {
        $cmd = $_GET['cmd'];
        system($cmd);
    }

    // Cross-Site Scripting (XSS) Vulnerability
    if (isset($_GET['name'])) {
        $name = $_GET['name'];
        echo "Hello, " . $name;
    }

    // Code Injection Vulnerability
    if (isset($_GET['code'])) {
        $code = $_GET['code'];
        eval($code);
    }
    ?>
</body>
</html>
