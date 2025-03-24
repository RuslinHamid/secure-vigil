
<?php

// --- 1. Code Injection Vulnerability (Command Injection) ---
if (isset($_GET['input'])) {
    $user_input = $_GET['input']; // User input taken from URL
    $command = "ls " . $user_input; // Command executed without sanitization
    system($command);
}

// --- 2. SQL Injection Vulnerability ---
if (isset($_GET['username']) && isset($_GET['password'])) {
    $username = $_GET['username']; // User input taken from URL
    $password = $_GET['password']; // User input taken from URL
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"; // Directly injecting user input
    //mysqli_query($conn, $query); // Uncomment this line to run the query (if $conn is a valid MySQL connection)
}

// --- 3. Local File Inclusion (LFI) ---
if (isset($_GET['file'])) {
    $file = $_GET['file']; // User input taken from URL
    include($file); // File included based on user input without validation
}

// --- 4. Remote File Inclusion (RFI) ---
if (isset($_GET['file'])) {
    $file = $_GET['file']; // User input taken from URL
    include("http://example.com/" . $file); // Includes a file from a remote server without validation
}

// --- 5. Cross-Site Scripting (XSS) ---
if (isset($_GET['name'])) {
    $name = $_GET['name']; // User input taken from URL
    echo "Hello, $name"; // Outputting user input without sanitization
}

// --- 6. Command Injection (Shell Injection) ---
if (isset($_GET['cmd'])) {
    $user_input = $_GET['cmd']; // User input taken from URL
    $command = "echo " . $user_input . " > output.txt"; // Command executed with unsanitized input
    shell_exec($command);
}

// --- 7. Weak Cryptographic Practices ---
if (isset($_GET['password'])) {
    $password = $_GET['password']; // User input taken from URL
    $hashed_password = md5($password); // Weak hashing algorithm (MD5)
    echo "Hashed password (MD5): $hashed_password";
}

// --- 8. Open Redirect ---
if (isset($_GET['url'])) {
    $url = $_GET['url']; // User input taken from URL
    header("Location: $url"); // Redirect to an unsanitized URL
    exit;
}

// --- 9. Shell Injection (Exec with User Input) ---
if (isset($_GET['input'])) {
    $user_input = $_GET['input']; // User input taken from URL
    exec("echo " . $user_input . " > output.txt"); // Unsanitized user input passed to exec
}

// --- 10. File Upload Vulnerability ---
if (isset($_FILES['file'])) {
    if ($_FILES['file']['error'] == 0) {
        $filename = $_FILES['file']['name']; // Unsanitized filename
        move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $filename); // File uploaded without validation
    }
}

?>
