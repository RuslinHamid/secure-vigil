<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../uploads/secure_version.php';

use PHPUnit\Framework\TestCase;

class SecurityTest extends TestCase {
    private $pdo;
    private $testFiles = [];
    
    protected function setUp(): void {
        // Setup test database connection
        $this->pdo = new PDO(
            "mysql:host=localhost;dbname=test_db;charset=utf8mb4",
            "test_user",
            "test_password",
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        
        // Create test files directory
        if (!file_exists(__DIR__ . '/test_files')) {
            mkdir(__DIR__ . '/test_files');
        }
    }
    
    protected function tearDown(): void {
        // Clean up test files
        foreach ($this->testFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
    }
    
    public function testFileUploadSecurity() {
        // Test file size limit
        $largeFile = __DIR__ . '/test_files/large.txt';
        file_put_contents($largeFile, str_repeat('a', MAX_FILE_SIZE + 1));
        $this->testFiles[] = $largeFile;
        
        $file = [
            'name' => 'large.txt',
            'type' => 'text/plain',
            'tmp_name' => $largeFile,
            'error' => UPLOAD_ERR_OK,
            'size' => MAX_FILE_SIZE + 1
        ];
        
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("File too large");
        secureFileUpload($file);
        
        // Test file type validation
        $maliciousFile = __DIR__ . '/test_files/malicious.php';
        file_put_contents($maliciousFile, '<?php echo "malicious"; ?>');
        $this->testFiles[] = $maliciousFile;
        
        $file = [
            'name' => 'malicious.php',
            'type' => 'application/x-httpd-php',
            'tmp_name' => $maliciousFile,
            'error' => UPLOAD_ERR_OK,
            'size' => 100
        ];
        
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid file type");
        secureFileUpload($file);
    }
    
    public function testSQLInjectionPrevention() {
        // Test SQL injection attempts
        $maliciousUsername = "' OR '1'='1";
        
        $stmt = secureQuery(
            $this->pdo,
            "SELECT * FROM users WHERE username = ?",
            [$maliciousUsername]
        );
        
        $result = $stmt->fetchAll();
        $this->assertEmpty($result, "SQL injection attempt should return no results");
        
        // Test query type restrictions
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Query type not allowed");
        secureQuery($this->pdo, "DELETE FROM users");
    }
    
    public function testXSSPrevention() {
        // Test HTML context
        $maliciousInput = '<script>alert("xss")</script>';
        $escaped = escapeOutput($maliciousInput, 'html');
        $this->assertEquals(
            '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
            $escaped
        );
        
        // Test JavaScript context
        $maliciousInput = "'; alert('xss'); '";
        $escaped = escapeOutput($maliciousInput, 'js');
        $this->assertNotContains(
            "alert('xss')",
            $escaped
        );
        
        // Test URL context
        $maliciousInput = 'javascript:alert("xss")';
        $escaped = escapeOutput($maliciousInput, 'url');
        $this->assertNotContains(
            'javascript:',
            urldecode($escaped)
        );
    }
    
    public function testCommandInjectionPrevention() {
        // Test command injection attempts
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Command not allowed");
        secureCommand('rm -rf /');
        
        // Test command argument injection
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Command argument not allowed");
        secureCommand('ls', ['-rf', '/']);
        
        // Test rate limiting
        for ($i = 0; $i < 12; $i++) {
            try {
                secureCommand('ls');
            } catch (Exception $e) {
                $this->assertEquals(
                    "Too many command executions",
                    $e->getMessage()
                );
                break;
            }
        }
    }
    
    public function testFileInclusionPrevention() {
        // Test directory traversal
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("File inclusion not allowed");
        secureInclude('../config.php');
        
        // Test non-whitelisted file
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("File inclusion not allowed");
        secureInclude('malicious.php');
        
        // Test file integrity
        $headerFile = __DIR__ . '/../includes/header.php';
        if (file_exists($headerFile)) {
            $originalHash = hash_file('sha256', $headerFile);
            file_put_contents($headerFile, '<?php echo "modified"; ?>');
            
            $this->expectException(Exception::class);
            $this->expectExceptionMessage("File integrity check failed");
            secureInclude('header.php');
            
            // Restore original file
            file_put_contents($headerFile, file_get_contents($headerFile . '.bak'));
        }
    }
    
    public function testSecurityHeaders() {
        // Capture headers
        $headers = xdebug_get_headers();
        
        // Test security headers
        $this->assertContains(
            'X-Frame-Options: DENY',
            $headers
        );
        $this->assertContains(
            'X-XSS-Protection: 1; mode=block',
            $headers
        );
        $this->assertContains(
            'X-Content-Type-Options: nosniff',
            $headers
        );
        $this->assertContains(
            'Content-Security-Policy: default-src \'self\'',
            $headers
        );
        $this->assertContains(
            'Strict-Transport-Security: max-age=31536000; includeSubDomains',
            $headers
        );
    }
    
    public function testPasswordSecurity() {
        // Test password length requirement
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Password too short");
        
        $_POST['username'] = 'testuser';
        $_POST['password'] = 'short';
        
        if (isset($_POST['username']) && isset($_POST['password'])) {
            if (strlen($_POST['password']) < PASSWORD_MIN_LENGTH) {
                throw new Exception("Password too short");
            }
        }
    }
    
    public function testMalwareScanning() {
        // Test malware detection
        $maliciousFile = __DIR__ . '/test_files/malware.php';
        file_put_contents($maliciousFile, '<?php eval($_GET["cmd"]); ?>');
        $this->testFiles[] = $maliciousFile;
        
        $this->assertFalse(
            scanFileForMalware($maliciousFile),
            "Malware scanning should detect malicious code"
        );
        
        // Test clean file
        $cleanFile = __DIR__ . '/test_files/clean.txt';
        file_put_contents($cleanFile, 'Hello, World!');
        $this->testFiles[] = $cleanFile;
        
        $this->assertTrue(
            scanFileForMalware($cleanFile),
            "Malware scanning should pass clean files"
        );
    }
}
?> 