<?php
// Vulnerable code to test command injection

// Accepting user input through GET parameter 'cmd'
if (isset($_GET['cmd'])) {
    $user_command = $_GET['cmd'];

    // Directly passing user input to system command
    $output = shell_exec($user_command);

    // Display the output of the command
    echo "<pre>$output</pre>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Command Injection Vulnerable Application</title>
</head>
<body>
    <h1>Test Command Injection Vulnerability</h1>

    <!-- Form to test command injection -->
    <form method="get">
        <label for="cmd">Enter Command:</label>
        <input type="text" name="cmd" id="cmd" placeholder="e.g., ls">
        <input type="submit" value="Execute">
    </form>
</body>
</html>
