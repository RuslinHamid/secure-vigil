<?php
// Security Configuration
ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();

// Security Headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// Constants for configuration
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('MAX_FAILED_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes
define('PASSWORD_MIN_LENGTH', 12);

// Enhanced Database Connection
function getDbConnection() {
    try {
        $config = parse_ini_file(__DIR__ . '/config.ini', true);
        if (!$config) {
            throw new Exception("Configuration file not found");
        }

        $pdo = new PDO(
            "mysql:host={$config['database']['host']};dbname={$config['database']['dbname']};charset=utf8mb4",
            $config['database']['username'],
            $config['database']['password'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
            ]
        );
        
        // Set additional security attributes
        $pdo->exec("SET SESSION sql_mode = 'STRICT_ALL_TABLES'");
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        throw new Exception("Database connection error");
    }
}

// Enhanced File Upload Security
function secureFileUpload($file) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        throw new Exception("Invalid file upload");
    }

    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        throw new Exception("File too large");
    }

    $allowed = ['jpg', 'jpeg', 'png', 'pdf'];
    $filename = $file['name'];
    $filetype = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Enhanced file type validation
    if (!in_array($filetype, $allowed)) {
        logSecurityEvent("Invalid file type attempted: {$filetype}");
        throw new Exception("Invalid file type");
    }
    
    // Generate secure filename with timestamp
    $newFilename = bin2hex(random_bytes(16)) . '_' . time() . '.' . $filetype;
    $uploadPath = __DIR__ . '/uploads/' . $newFilename;
    
    // Enhanced MIME type validation
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = [
        'image/jpeg' => ['jpg', 'jpeg'],
        'image/png' => ['png'],
        'application/pdf' => ['pdf']
    ];

    // Strict MIME type checking
    if (!isset($allowedMimes[$mimeType]) || !in_array($filetype, $allowedMimes[$mimeType])) {
        logSecurityEvent("Invalid MIME type attempted: {$mimeType}");
        throw new Exception("Invalid file type");
    }
    
    // Scan file for malware (example implementation)
    if (!scanFileForMalware($file['tmp_name'])) {
        logSecurityEvent("Potential malware detected in upload");
        throw new Exception("File security check failed");
    }
    
    // Create upload directory if it doesn't exist
    if (!file_exists(__DIR__ . '/uploads')) {
        mkdir(__DIR__ . '/uploads', 0750, true);
    }
    
    // Secure file permissions before and after upload
    umask(0077);
    if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
        throw new Exception("File upload failed");
    }
    chmod($uploadPath, 0640);
    
    // Log successful upload
    logSecurityEvent("File uploaded successfully: {$newFilename}");
    return $newFilename;
}

// Enhanced Command Execution Security
function secureCommand($command, $args = []) {
    $allowedCommands = [
        'ls' => ['--help', '-l', '-a'],
        'dir' => ['--help', '/w'],
        'pwd' => []
    ];
    
    // Validate command
    if (!array_key_exists($command, $allowedCommands)) {
        logSecurityEvent("Unauthorized command attempted: {$command}");
        throw new Exception("Command not allowed");
    }
    
    // Validate arguments
    foreach ($args as $arg) {
        if (!in_array($arg, $allowedCommands[$command])) {
            logSecurityEvent("Unauthorized command argument attempted: {$arg}");
            throw new Exception("Command argument not allowed");
        }
    }
    
    $command = escapeshellcmd($command);
    $args = array_map('escapeshellarg', $args);
    
    // Rate limiting
    if (!checkCommandRateLimit()) {
        throw new Exception("Too many command executions");
    }
    
    $output = [];
    $returnVar = 0;
    exec($command . ' ' . implode(' ', $args), $output, $returnVar);
    
    // Log command execution
    logSecurityEvent("Command executed: {$command}");
    return implode("\n", $output);
}

// Enhanced SQL Query Security
function secureQuery($pdo, $query, $params = [], $options = []) {
    try {
        // Query whitelisting
        $allowedQueries = [
            'SELECT' => true,
            'INSERT' => true,
            'UPDATE' => true,
            'DELETE' => false // Disabled by default
        ];
        
        $queryType = strtoupper(substr(trim($query), 0, 6));
        if (!isset($allowedQueries[$queryType]) || !$allowedQueries[$queryType]) {
            logSecurityEvent("Unauthorized query type attempted: {$queryType}");
            throw new Exception("Query type not allowed");
        }
        
        // Prepare and execute with timeout
        $stmt = $pdo->prepare($query);
        $stmt->setAttribute(PDO::ATTR_TIMEOUT, 5); // 5 seconds timeout
        
        // Parameter type binding
        foreach ($params as $key => $value) {
            $type = PDO::PARAM_STR;
            if (is_int($value)) $type = PDO::PARAM_INT;
            elseif (is_bool($value)) $type = PDO::PARAM_BOOL;
            elseif (is_null($value)) $type = PDO::PARAM_NULL;
            
            if (is_int($key)) $key++;  // 1-based indexing
            $stmt->bindValue($key, $value, $type);
        }
        
        $stmt->execute();
        return $stmt;
    } catch (PDOException $e) {
        logSecurityEvent("Query failed: " . $e->getMessage());
        throw new Exception("Database error occurred");
    }
}

// Enhanced XSS Prevention
function escapeOutput($data, $context = 'html') {
    if (is_array($data)) {
        return array_map(function($item) use ($context) {
            return escapeOutput($item, $context);
        }, $data);
    }
    
    switch ($context) {
        case 'html':
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        case 'js':
            return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        case 'url':
            return urlencode($data);
        case 'css':
            return preg_replace('/[^a-zA-Z0-9-_]/', '', $data);
        default:
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

// Enhanced File Inclusion Security
function secureInclude($file) {
    $allowedIncludes = [
        'header.php' => hash_file('sha256', __DIR__ . '/includes/header.php'),
        'footer.php' => hash_file('sha256', __DIR__ . '/includes/footer.php'),
        'config.php' => hash_file('sha256', __DIR__ . '/includes/config.php')
    ];
    
    $file = basename($file);
    if (!array_key_exists($file, $allowedIncludes)) {
        logSecurityEvent("Unauthorized file inclusion attempted: {$file}");
        throw new Exception("File inclusion not allowed");
    }
    
    $fullPath = __DIR__ . '/includes/' . $file;
    if (!file_exists($fullPath)) {
        throw new Exception("File not found");
    }
    
    // Verify file integrity
    $fileHash = hash_file('sha256', $fullPath);
    if ($fileHash !== $allowedIncludes[$file]) {
        logSecurityEvent("File integrity check failed: {$file}");
        throw new Exception("File integrity check failed");
    }
    
    return include $fullPath;
}

// Security Helper Functions
function logSecurityEvent($message) {
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[{$timestamp}] {$message}" . PHP_EOL;
    error_log($logEntry, 3, __DIR__ . '/security.log');
}

function checkCommandRateLimit() {
    $window = 60; // 1 minute
    $maxCommands = 10;
    
    if (!isset($_SESSION['command_history'])) {
        $_SESSION['command_history'] = [];
    }
    
    $now = time();
    $_SESSION['command_history'] = array_filter(
        $_SESSION['command_history'],
        function($time) use ($now, $window) {
            return $time > ($now - $window);
        }
    );
    
    if (count($_SESSION['command_history']) >= $maxCommands) {
        return false;
    }
    
    $_SESSION['command_history'][] = $now;
    return true;
}

function scanFileForMalware($filepath) {
    // Implement your malware scanning logic here
    // This is a placeholder implementation
    $suspicious_patterns = [
        '/\<\?php/i',
        '/shell_exec/i',
        '/base64_decode/i',
        '/eval\(/i'
    ];
    
    $content = file_get_contents($filepath);
    foreach ($suspicious_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return false;
        }
    }
    return true;
}

// Initialize Security Monitoring
function initializeSecurity() {
    // Set secure session parameters
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    
    // Regenerate session ID periodically
    if (!isset($_SESSION['last_regeneration'])) {
        $_SESSION['last_regeneration'] = time();
    } elseif (time() - $_SESSION['last_regeneration'] > 300) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

// Example usage with enhanced error handling
try {
    initializeSecurity();
    
    // Handle file upload
    if (isset($_FILES['file'])) {
        $filename = secureFileUpload($_FILES['file']);
        echo escapeOutput("File uploaded successfully: " . $filename);
    }
    
    // Handle database query
    if (isset($_POST['username']) && isset($_POST['password'])) {
        if (strlen($_POST['password']) < PASSWORD_MIN_LENGTH) {
            throw new Exception("Password too short");
        }
        
        $pdo = getDbConnection();
        $stmt = secureQuery(
            $pdo,
            "SELECT * FROM users WHERE username = ?",
            [$_POST['username']]
        );
        
        $user = $stmt->fetch();
        if ($user && password_verify($_POST['password'], $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            echo escapeOutput("Welcome " . $user['username']);
        } else {
            logSecurityEvent("Failed login attempt for user: {$_POST['username']}");
            throw new Exception("Invalid credentials");
        }
    }
    
    // Handle command execution
    if (isset($_POST['command'])) {
        $output = secureCommand($_POST['command']);
        echo escapeOutput($output);
    }
    
    // Handle file inclusion
    if (isset($_GET['page'])) {
        secureInclude($_GET['page']);
    }
    
} catch (Exception $e) {
    error_log("Error: " . $e->getMessage());
    http_response_code(400);
    echo escapeOutput("An error occurred. Please try again.");
}
?> 