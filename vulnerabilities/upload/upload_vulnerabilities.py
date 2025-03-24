import re

def find_upload_vulnerabilities(code):
    patterns = [
        # PHP move_uploaded_file() without validation
        r'move_uploaded_file\s*\(\s*\$_FILES\[.*?\]\[\'tmp_name\'\]\s*,\s*.*?\);',
        # Unsanitized file name usage in PHP
        r'\$_FILES\[.*?\]\[\'name\'\]',
        r'\$_FILES\[.*?\]\[\'type\'\]',  # File type being used unsafely
        r'\$_FILES\[.*?\]\[\'size\'\]',  # File size being used unsafely
        r'\$_FILES\[.*?\]\[\'tmp_name\'\]',  # Temporary file being accessed directly
        # JavaScript handling file uploads without validation
        r'input\s*type=["\']file["\']',
        r'reader\.readAs.*?\(\s*document\.getElementById\([\'"].*?[\'"]\)\.files\[0\]',
        # Python file upload handling
        r'open\s*\(\s*request\.files\[.*?\]\)',
        r'request\.files\[.*?\]\.save\s*\(',
        r'request\.files\[.*?\]\.filename',
        r'request\.files\[.*?\]\.read\s*\(',
        # Ruby file upload handling
        r'params\[.*?\]\.path',
        r'params\[.*?\]\.original_filename',
        r'params\[.*?\]\.tempfile',
        # Java file upload handling
        r'new\s+File\s*\(\s*request\.getParameter\(".*?"\)',
        r'request\.getPart\s*\(\s*".*?"\)\.write\s*\(',
        r'request\.getPart\s*\(\s*".*?"\)\.getInputStream\s*\(',
        r'new\s+FileOutputStream\s*\(.*?\.getInputStream\(\)\)',
        # Node.js file upload handling
        r'req\.files\[.*?\]\.mv\s*\(',
        r'req\.files\[.*?\]\.name',
        r'req\.files\[.*?\]\.data',
        # Unsafe file path concatenation
        r'["\'].*?\$.*?\.[a-zA-Z]+["\']',  # Concatenation of file names/extensions
        r'os\.path\.join\s*\(.*?\$.*?\)',
        # Unsafe MIME type checking
        r'file\.mimetype\s*==\s*["\'].*?["\']',  # Checking MIME types in an unsafe way
        r'file\.content_type\s*==\s*["\'].*?["\']',
        # Unsafe file extension validation
        r'\.endswith\s*\(["\'].*?["\']\)',  # Checking extensions in Python
        r'matches\s*\(\s*["\'].*?\.[a-zA-Z]+["\']\s*\)',  # Checking extensions in Java
        # Lack of file size validation
        r'file\.size\s*<=?\s*\d+',  # Direct size comparison without safe handling
        r'$_FILES\[.*?\]\[\'size\'\]\s*<=?\s*\d+',  # PHP file size validation
        # Lack of directory traversal prevention
        r'(\.\.\/)+',  # Directory traversal pattern in file paths
        r'[\\"\'`].*?\.\./.*?[\\"\'`]',  # Embedded traversal sequences in quotes
    ]
    
    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'File Upload Vulnerability',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities
