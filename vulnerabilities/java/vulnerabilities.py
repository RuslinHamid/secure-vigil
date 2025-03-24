import re
from typing import List, Dict, Any

def find_java_vulnerabilities(code: str) -> List[Dict[str, Any]]:
    """
    Find security vulnerabilities in Java code.
    
    Args:
        code (str): The Java code to analyze
        
    Returns:
        List[Dict[str, Any]]: List of vulnerabilities found
    """
    vulnerabilities = []
    
    # SQL Injection
    sql_injection_patterns = [
        r'executeQuery\s*\([^)]*\+[^)]*\)',  # String concatenation in SQL
        r'executeUpdate\s*\([^)]*\+[^)]*\)',  # String concatenation in SQL
        r'Statement\.execute\s*\([^)]*\+[^)]*\)',  # String concatenation in SQL
        r'String\.format\s*\([^)]*\)',  # String formatting in SQL
        r'StringBuilder\.append\s*\([^)]*\)',  # StringBuilder in SQL
    ]
    
    for pattern in sql_injection_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'SQL Injection',
                'description': f'Potential SQL injection at line {line_number}. User input is being used directly in SQL queries.',
                'line': line_number,
                'severity': 'Critical',
                'mitigation': 'Use PreparedStatement with parameterized queries. Never use string concatenation for SQL queries.'
            })
    
    # Command Injection
    command_injection_patterns = [
        r'Runtime\.exec\s*\([^)]*\)',  # Runtime.exec()
        r'ProcessBuilder\s*\([^)]*\)',  # ProcessBuilder
        r'ProcessBuilder\.start\s*\([^)]*\)',  # ProcessBuilder.start()
    ]
    
    for pattern in command_injection_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Command Injection',
                'description': f'Potential command injection at line {line_number}. User input is being used in command execution.',
                'line': line_number,
                'severity': 'Critical',
                'mitigation': 'Use ProcessBuilder with a list of arguments instead of a single command string. Validate and sanitize all input.'
            })
    
    # Path Traversal
    path_traversal_patterns = [
        r'new File\s*\([^)]*\+[^)]*\)',  # String concatenation in file paths
        r'File\.getPath\s*\([^)]*\)',  # Unsafe path handling
        r'File\.getAbsolutePath\s*\([^)]*\)',  # Unsafe path handling
        r'File\.getCanonicalPath\s*\([^)]*\)',  # Unsafe path handling
    ]
    
    for pattern in path_traversal_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Path Traversal',
                'description': f'Potential path traversal at line {line_number}. User input is being used directly in file paths.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use File.getCanonicalPath() and validate against allowed directories. Use Path.normalize() to sanitize paths.'
            })
    
    # Insecure Deserialization
    deserialization_patterns = [
        r'ObjectInputStream\s*\([^)]*\)',  # ObjectInputStream
        r'readObject\s*\([^)]*\)',  # readObject()
        r'readUnshared\s*\([^)]*\)',  # readUnshared()
        r'readResolve\s*\([^)]*\)',  # readResolve()
    ]
    
    for pattern in deserialization_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Insecure Deserialization',
                'description': f'Potential insecure deserialization at line {line_number}. Untrusted data is being deserialized.',
                'line': line_number,
                'severity': 'Critical',
                'mitigation': 'Use ObjectInputFilter to restrict deserialization. Implement readObject() with proper validation.'
            })
    
    # Hardcoded Secrets
    secret_patterns = [
        r'password\s*=\s*["\'].*["\']',  # Hardcoded passwords
        r'secret\s*=\s*["\'].*["\']',  # Hardcoded secrets
        r'apiKey\s*=\s*["\'].*["\']',  # Hardcoded API keys
        r'token\s*=\s*["\'].*["\']',  # Hardcoded tokens
    ]
    
    for pattern in secret_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Hardcoded Secrets',
                'description': f'Potential hardcoded secret at line {line_number}. Sensitive information is stored in code.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use environment variables, configuration files, or secure secret management systems.'
            })
    
    # XSS (Cross-Site Scripting)
    xss_patterns = [
        r'response\.getWriter\s*\([^)]*\)\.write\s*\([^)]*\+[^)]*\)',  # Direct output
        r'response\.getOutputStream\s*\([^)]*\)\.write\s*\([^)]*\+[^)]*\)',  # Direct output
        r'out\.println\s*\([^)]*\+[^)]*\)',  # Direct output
        r'out\.print\s*\([^)]*\+[^)]*\)',  # Direct output
    ]
    
    for pattern in xss_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'description': f'Potential XSS vulnerability at line {line_number}. User input is being output directly to HTML.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use proper HTML escaping (e.g., StringEscapeUtils.escapeHtml4()) before outputting user input.'
            })
    
    return vulnerabilities 