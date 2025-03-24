<?php
// Vulnerable code for testing purposes

// Command Injection
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    system($cmd);
}

// SQL Injection
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    $conn = new mysqli("localhost", "username", "password", "database");
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    $sql = "SELECT * FROM users WHERE id = '$id'";
    $result = $conn->query($sql);
    while ($row = $result->fetch_assoc()) {
        echo "User: " . $row["username"];
    }
    $conn->close();
}

// Cross-Site Scripting (XSS)
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    echo "Search results for: " . $search;
}

// Remote File Inclusion (RFI)
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
}

// Local File Inclusion (LFI)
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page . ".php");
}
?>

<!-- HTML Form to test the vulnerabilities -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerable Web Application</title>
</head>
<body>
    <h1>Vulnerable Web Application</h1>

    <!-- Command Injection -->
    <form method="get">
        <label for="cmd">Command Injection:</label>
        <input type="text" name="cmd" id="cmd">
        <input type="submit" value="Execute">
    </form>

    <!-- SQL Injection -->
    <form method="get">
        <label for="id">SQL Injection:</label>
        <input type="text" name="id" id="id">
        <input type="submit" value="Search">
    </form>

    <!-- XSS -->
    <form method="get">
        <label for="search">XSS:</label>
        <input type="text" name="search" id="search">
        <input type="submit" value="Search">
    </form>

    <!-- RFI -->
    <form method="get">
        <label for="file">Remote File Inclusion:</label>
        <input type="text" name="file" id="file">
        <input type="submit" value="Include">
    </form>

    <!-- LFI -->
    <form method="get">
        <label for="page">Local File Inclusion:</label>
        <input type="text" name="page" id="page">
        <input type="submit" value="Include">
    </form>
</body>
</html>
