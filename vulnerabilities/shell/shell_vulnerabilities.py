import re

def find_shell_vulnerabilities(code):
    patterns = [
        # PHP exec/system with user input
        r'(exec|shell_exec|system|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\s*\);',
        # Bash commands using unsanitized variables
        r'`.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?`',
        r'`.*?\$[a-zA-Z_][a-zA-Z0-9_]*.*?`',  # Unsanitized variables in backticks
        # Python os/system calls with user input
        r'os\.system\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'os\.popen\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'subprocess\.run\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'subprocess\.Popen\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'os\.exec.*?\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'subprocess\.(call|check_call|check_output)\s*\(.*?\)',
        # Ruby system commands with user input
        r'`.*?\#\{.*?params\[.*?\].*?\}.*?`',  # Backticks with interpolation
        r'system\s*\(.*?params\[.*?\]\)',
        r'IO\.popen\s*\(.*?params\[.*?\]\)',
        # Perl exec/system calls with user input
        r'system\s*\(.*?\$[a-zA-Z_][a-zA-Z0-9_]*.*?\)',
        r'`.*?\$[a-zA-Z_][a-zA-Z0-9_]*.*?`',
        # Java ProcessBuilder with concatenation
        r'new\s+ProcessBuilder\s*\(.*?\+.*?\)',
        r'Runtime\.getRuntime\(\)\.exec\s*\(.*?\+.*?\)',
        # Unsafe command execution in JavaScript
        r'child_process\.exec\s*\(.*?\)',
        r'child_process\.spawn\s*\(.*?\)',
        # Unsafe Shell Scripts
        r'\\$(\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?\))',
        r'\\$\(.*?\$[a-zA-Z_][a-zA-Z0-9_]*.*?\)',
        r'\`.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\`',
        # Unsafe use of eval (possible shell or code injection)
        r'eval\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\)',
        r'eval\s*\(.*?\$[a-zA-Z_][a-zA-Z0-9_]*.*?\)',
        # Unsafe use of command injection in Node.js
        r'child_process\.execSync\s*\(.*?\)',
        r'require\("child_process"\)\.exec\s*\(.*?\)',
        # Unsafe usage of exec in Bash scripts
        r'`.*?\$[A-Za-z_][A-Za-z0-9_]*.*?`',
        r'\\$(.*?\$[A-Za-z_][A-Za-z0-9_]*.*?\))',
        # Other command injection patterns
        r'Runtime\.getRuntime\(\)\.exec\s*\(".*?\$.*?"\)',  # Java dynamic command
        r'os\.exec.*?\(.*?\)',  # Generic Python unsafe execution
        r'\bsh\b\s+-c\s+["\'].*?\$.*?["\']',  # Generic shell execution
    ]
    
    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'Shell Injection Vulnerability',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities
