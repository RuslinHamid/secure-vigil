import re
from typing import List, Dict, Any

def find_javascript_vulnerabilities(code: str) -> List[Dict[str, Any]]:
    """
    Find security vulnerabilities in JavaScript code.
    
    Args:
        code (str): The JavaScript code to analyze
        
    Returns:
        List[Dict[str, Any]]: List of vulnerabilities found
    """
    vulnerabilities = []
    
    # XSS (Cross-Site Scripting)
    xss_patterns = [
        r'document\.write\s*\([^)]*\+[^)]*\)',  # document.write()
        r'innerHTML\s*=\s*[^;]*\+[^;]*',  # innerHTML assignment
        r'outerHTML\s*=\s*[^;]*\+[^;]*',  # outerHTML assignment
        r'insertAdjacentHTML\s*\([^)]*\+[^)]*\)',  # insertAdjacentHTML()
        r'jQuery\.html\s*\([^)]*\+[^)]*\)',  # jQuery.html()
        r'\$\([^)]*\)\.html\s*\([^)]*\+[^)]*\)',  # jQuery.html()
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
                'mitigation': 'Use textContent or innerText instead of innerHTML. Use DOMPurify or similar libraries to sanitize HTML.'
            })
    
    # DOM-based XSS
    dom_xss_patterns = [
        r'location\.hash\s*=',  # location.hash
        r'location\.search\s*=',  # location.search
        r'location\.href\s*=',  # location.href
        r'document\.URL\s*=',  # document.URL
        r'document\.documentURI\s*=',  # document.documentURI
        r'document\.baseURI\s*=',  # document.baseURI
        r'document\.cookie\s*=',  # document.cookie
    ]
    
    for pattern in dom_xss_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'DOM-based XSS',
                'description': f'Potential DOM-based XSS at line {line_number}. Unsafe DOM manipulation with user input.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Validate and sanitize all user input before using it in DOM operations. Use safe DOM manipulation methods.'
            })
    
    # Eval Injection
    eval_patterns = [
        r'eval\s*\([^)]*\+[^)]*\)',  # eval()
        r'Function\s*\([^)]*\+[^)]*\)',  # Function constructor
        r'setTimeout\s*\([^)]*\+[^)]*\)',  # setTimeout with string
        r'setInterval\s*\([^)]*\+[^)]*\)',  # setInterval with string
        r'new Function\s*\([^)]*\+[^)]*\)',  # new Function()
    ]
    
    for pattern in eval_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Eval Injection',
                'description': f'Potential eval injection at line {line_number}. User input is being used in eval() or similar functions.',
                'line': line_number,
                'severity': 'Critical',
                'mitigation': 'Avoid using eval() and similar functions. Use safer alternatives like JSON.parse() for data parsing.'
            })
    
    # Prototype Pollution
    prototype_pollution_patterns = [
        r'Object\.prototype\s*=',  # Object.prototype modification
        r'__proto__\s*=',  # __proto__ assignment
        r'prototype\s*=',  # prototype assignment
        r'Object\.create\s*\([^)]*\)',  # Object.create with untrusted input
        r'Object\.assign\s*\([^)]*\+[^)]*\)',  # Object.assign with untrusted input
    ]
    
    for pattern in prototype_pollution_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Prototype Pollution',
                'description': f'Potential prototype pollution at line {line_number}. Untrusted input is being used in object operations.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use Object.freeze() on prototypes. Validate and sanitize object properties before assignment.'
            })
    
    # Insecure Deserialization
    deserialization_patterns = [
        r'JSON\.parse\s*\([^)]*\+[^)]*\)',  # JSON.parse with untrusted input
        r'jQuery\.parseJSON\s*\([^)]*\+[^)]*\)',  # jQuery.parseJSON
        r'\.parse\s*\([^)]*\+[^)]*\)',  # General parse methods
    ]
    
    for pattern in deserialization_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Insecure Deserialization',
                'description': f'Potential insecure deserialization at line {line_number}. Untrusted data is being parsed.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Validate and sanitize all input before parsing. Use safe parsing methods with proper error handling.'
            })
    
    # Hardcoded Secrets
    secret_patterns = [
        r'apiKey\s*=\s*["\'].*["\']',  # Hardcoded API keys
        r'secret\s*=\s*["\'].*["\']',  # Hardcoded secrets
        r'password\s*=\s*["\'].*["\']',  # Hardcoded passwords
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
    
    return vulnerabilities 