import re

def find_lfi_vulnerabilities(code):
    patterns = [
        # Look for variations of include, require, include_once, or require_once with '../'
        r'(include|require|include_once|require_once)\s*[\'"]\.\./',
        # Look for variations of include, require, include_once, or require_once with base64 encoded '../'
        r'(include|require|include_once|require_once)\s*\(\s*base64_decode\s*\(\s*[\'"]/.*\s*\.\.\/',
        # Look for $_GET or $_POST being used directly in include, require, include_once, or require_once
        r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST)\[.*?\]\s*\)',
        # Look for file wrappers like data://, expect://, etc.
        r'(include|require|include_once|require_once)\s*[\'"](data|expect|php|file):\/\/',
        # Look for file wrappers with base64 encoded payloads
        r'(include|require|include_once|require_once)\s*\(\s*base64_decode\s*\(\s*[\'"]([a-zA-Z0-9+/=]+)\s*',
        # Look for file wrappers with URL encoded payloads
        r'(include|require|include_once|require_once)\s*\(\s*urldecode\s*\(\s*[\'"]([a-zA-Z0-9%]+)\s*',
        # Look for file wrappers with double encoding
        r'(include|require|include_once|require_once)\s*\(\s*urldecode\s*\(\s*urldecode\s*\(\s*[\'"]([a-zA-Z0-9%]+)\s*',
        # Look for generic file inclusion patterns using user input
        r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        # Look for file functions with user input
        r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        r'fopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\],\s*[\'"][rwb][\'"]\s*\)',
        r'readfile\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        r'file\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        r'scandir\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        r'opendir\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        # Look for patterns using eval with base64 decode
        r'eval\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)\s*\)',
    ]

    vulnerabilities = []
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            vulnerability = {
                'type': 'LFI (Local File Inclusion)',
                'pattern': match.group(),
                'line_number': code.count('\n', 0, match.start()) + 1
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities
