import re

def find_command_injection_vulnerabilities(code):
    patterns = [
        # Look for common shell commands executed with user input
        r'(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        r'`.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?`',
        # Look for Python subprocess module with user input
        r'subprocess\.(call|run|Popen|check_output|check_call)\s*\(\s*\[?\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        r'subprocess\.(call|run|Popen|check_output|check_call)\s*\(\s*["\'].*?\$\(.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?\).*?["\']\s*\)',
        # Look for Perl backticks with user input
        r'`.*?\$\(.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?\)`',
        # Look for PowerShell execution with user input
        r'powershell\s*-\s*Command\s*".*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?"',
        # Look for Ruby system commands with user input
        r'`.*?#\{.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?\}`',
        r'system\s*\(.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\)',
        # Look for direct shell command execution in various languages
        r'(sh|bash|cmd|powershell)\s+-c\s*["\'].*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?["\']',
        # Look for unsafe usage of eval with user input
        r'eval\s*\(\s*.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\].*?\)',
        r'\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\s*;?\s*.*?\)\s*;?\s*\n?eval',
        # Look for unsafe usage of os.system in Python with user input
        r'os\.system\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        r'os\.popen\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        # Look for direct execution of user-supplied commands
        r'exec\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\)',
        r'passthru\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\)',
        r'popen\s*\(\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\)',
    ]

    vulnerabilities = []
    mitigation_advice = {
        "PHP": "Use escapeshellarg() and escapeshellcmd() to sanitize input before passing it to system commands.\n"
               "Example:\n"
               "$safe_input = escapeshellarg($_GET['cmd']);\n"
               "system($safe_input);",
        
        "Python": "Use subprocess.run() with controlled inputs instead of os.system().\n"
                  "Example:\n"
                  "import subprocess\n"
                  "safe_command = ['ls', '-l']\n"
                  "subprocess.run(safe_command, check=True)",
        
        "PowerShell": "Use validated input or restrict command execution with allowlists.\n"
                      "Example:\n"
                      "$allowed_commands = @('ls', 'dir')\n"
                      "if ($input -in $allowed_commands) { Invoke-Expression $input }",
        
        "General": "Validate and sanitize user inputs. Use allowlists instead of executing raw input commands."
    }

    for pattern in patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            detected_code = match.group()
            
            # Identify mitigation based on language
            if "subprocess" in detected_code or "os.system" in detected_code:
                mitigation = mitigation_advice["Python"]
            elif "system(" in detected_code or "exec(" in detected_code:
                mitigation = mitigation_advice["PHP"]
            elif "powershell" in detected_code:
                mitigation = mitigation_advice["PowerShell"]
            else:
                mitigation = mitigation_advice["General"]
            
            vulnerability = {
                'type': 'Command Injection',
                'pattern': detected_code,
                'line_number': code.count('\n', 0, match.start()) + 1,
                'mitigation': mitigation
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities
