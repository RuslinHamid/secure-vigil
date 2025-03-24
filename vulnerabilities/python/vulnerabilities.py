import re
from typing import List, Dict, Any

def find_python_vulnerabilities(code: str) -> List[Dict[str, Any]]:
    """
    Find security vulnerabilities in Python code.
    
    Args:
        code (str): The Python code to analyze
        
    Returns:
        List[Dict[str, Any]]: List of vulnerabilities found
    """
    vulnerabilities = []
    
    # SQL Injection Patterns
    sql_patterns = [
        (r'f["\']SELECT.*FROM.*WHERE.*{.*}', 'SQL injection through string formatting'),
        (r'execute\(["\']SELECT.*FROM.*WHERE.*%s.*["\']', 'SQL injection through string concatenation'),
        (r'cursor\.execute\([^?].*\+.*\)', 'SQL injection through string concatenation')
    ]
    
    # Command Injection Patterns
    command_patterns = [
        (r'os\.system\(f["\'].*{.*}["\']', 'Command injection through os.system'),
        (r'subprocess\..*\(.*shell\s*=\s*True', 'Command injection through subprocess with shell=True'),
        (r'eval\(.*\)', 'Command injection through eval')
    ]
    
    # Insecure Deserialization Patterns
    deserialization_patterns = [
        (r'pickle\.loads\(.*\)', 'Insecure deserialization using pickle'),
        (r'yaml\.load\(.*\)', 'Insecure deserialization using yaml.load'),
        (r'marshal\.loads\(.*\)', 'Insecure deserialization using marshal')
    ]
    
    # Hardcoded Secrets Patterns
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
        (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
        (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key')
    ]
    
    # Path Traversal Patterns
    path_patterns = [
        (r'open\([^,]+\)', 'Potential path traversal in file operations'),
        (r'file_get_contents\([^,]+\)', 'Potential path traversal in file reading'),
        (r'readfile\([^,]+\)', 'Potential path traversal in file reading')
    ]
    
    # Check each pattern against the code
    for pattern_group, patterns in [
        ('SQL Injection', sql_patterns),
        ('Command Injection', command_patterns),
        ('Insecure Deserialization', deserialization_patterns),
        ('Hardcoded Secrets', secret_patterns),
        ('Path Traversal', path_patterns)
    ]:
        for pattern, description in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # Calculate line number
                line_number = code.count('\n', 0, match.start()) + 1
                
                vulnerabilities.append({
                    'type': pattern_group,
                    'pattern': pattern,
                    'description': description,
                    'line_number': line_number,
                    'severity': 'High',
                    'code_snippet': match.group(0),
                    'mitigation': get_mitigation(pattern_group)
                })
    
    return vulnerabilities

def get_mitigation(vulnerability_type):
    mitigations = {
        'SQL Injection': '''
        - Use parameterized queries or prepared statements
        - Use an ORM (SQLAlchemy, Django ORM)
        - Validate and sanitize all user inputs
        - Use stored procedures
        - Implement proper input validation''',
        
        'Command Injection': '''
        - Use subprocess.run with shell=False
        - Validate and sanitize all command inputs
        - Use allowlists for permitted commands
        - Avoid os.system and shell=True
        - Use library functions instead of shell commands''',
        
        'Insecure Deserialization': '''
        - Use safe serialization formats (JSON, MessagePack)
        - Never deserialize untrusted data
        - Implement integrity checking
        - Use digital signatures
        - Consider using dill or jsonpickle instead of pickle''',
        
        'Hardcoded Secrets': '''
        - Use environment variables
        - Use secure secret management systems
        - Implement proper key rotation
        - Use configuration files outside version control
        - Use secret management services''',
        
        'Path Traversal': '''
        - Use os.path.abspath to get the canonical path
        - Validate file paths against a whitelist
        - Use secure file handling libraries
        - Implement proper access controls
        - Sanitize user input for file paths'''
    }
    
    return mitigations.get(vulnerability_type, 'No specific mitigation available') 