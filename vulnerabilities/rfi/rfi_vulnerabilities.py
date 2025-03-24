import re

def find_rfi_vulnerabilities(code):
    patterns = [
        # Look for variations of include, require, include_once, or require_once with a remote URL
        r'(include|require|include_once|require_once)\s*[\'"](http|https|ftp|ftps)://',
        # Look for file wrappers with remote URLs
        r'(include|require|include_once|require_once)\s*[\'"]data:(text|application)\/(x-)?php;base64',
        r'(include|require|include_once|require_once)\s*[\'"]expect://',
        r'(include|require|include_once|require_once)\s*[\'"]phar://',
        r'(include|require|include_once|require_once)\s*[\'"]gopher://',
        r'(include|require|include_once|require_once)\s*[\'"]dict://',
        r'(include|require|include_once|require_once)\s*[\'"]ldap://',
        r'(include|require|include_once|require_once)\s*[\'"]zlib://',
        r'(include|require|include_once|require_once)\s*[\'"]ssh2://',
        r'(include|require|include_once|require_once)\s*[\'"]compress.zlib://',
        # Look for file wrappers with base64 encoded payloads
        r'(include|require|include_once|require_once)\s*\(\s*base64_decode\s*\(\s*[\'"]([a-zA-Z0-9+/=]+)\s*',
        # Look for file wrappers with URL encoded payloads
        r'(include|require|include_once|require_once)\s*\(\s*urldecode\s*\(\s*[\'"]([a-zA-Z0-9%]+)\s*',
        # Look for file wrappers with double encoding
        r'(include|require|include_once|require_once)\s*\(\s*urldecode\s*\(\s*urldecode\s*\(\s*[\'"]([a-zA-Z0-9%]+)\s*',
        # Look for dynamic includes using variables
        r'(include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
        r'(include|require|include_once|require_once)\s*[\'"]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*[\'"]',
        # Look for $_GET or $_POST being used directly in include, require, include_once, or require_once
        r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        # Look for other potential dynamic includes with concatenation
        r'(include|require|include_once|require_once)\s*\(\s*[\'"].*[\'"]\s*\.\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\)',
        r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[.*?\]\s*\.\s*[\'"].*[\'"]\s*\)',
    ]

    vulnerabilities = []
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            vulnerability = {
                'type': 'RFI (Remote File Inclusion)',
                'pattern': match.group(),
                'line_number': code.count('\n', 0, match.start()) + 1
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities
