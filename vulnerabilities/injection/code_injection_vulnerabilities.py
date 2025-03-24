import re

def find_code_injection_vulnerabilities(code):
    patterns = [
        # JavaScript eval and setTimeout
        r'eval\([\s\S]*?\)',
        r'setTimeout\([\s\S]*?\)',
        r'setInterval\([\s\S]*?\)',

        # Python eval and exec
        r'eval\([\s\S]*?\)',
        r'exec\([\s\S]*?\)',

        # Python command execution
        r'os\.system\([\s\S]*?\)',
        r'subprocess\.call\([\s\S]*?,\s*shell=True\)',
        r'subprocess\.Popen\([\s\S]*?,\s*shell=True\)',
        r'subprocess\.run\([\s\S]*?,\s*shell=True\)',

        # PHP eval and backticks
        r'eval\([\s\S]*?\)',
        r'`\$[\s\S]*?`',
        r'`[\s\S]*?\$[\s\S]*?`',

        # General new Function usage
        r'new\s+Function\([\s\S]*?\)',

        # Shell command execution in various languages
        r'system\([\s\S]*?\)',
        r'exec\([\s\S]*?\)',
        r'popen\([\s\S]*?\)',

        # Perl and Ruby command execution
        r'`[\s\S]*?`',
        r'open\([\s\S]*?\)',
        r'qx\([\s\S]*?\)',

        # Web templates
        r'render_template_string\([\s\S]*?\)',
        r'template\.render\([\s\S]*?\)',
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'Code Injection',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities