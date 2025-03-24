import re

def find_sql_injection_vulnerabilities(code):
    patterns = [
        # Basic SQL keywords and suspicious patterns
        r'\bSELECT\b.*?\bFROM\b',
        r'\bUPDATE\b.*?\bSET\b',
        r'\bDELETE\b.*?\bFROM\b',
        r'\bINSERT\b.*?\bINTO\b',
        r'\bOR\b\s+["\']?\s*\d\s*=\s*\d',
        r'\bOR\b.*?=\s*["\'][^"\']*["\']',
        r'\bUNION\b.*?\bSELECT\b',
        r'\bDROP\b\s+\bTABLE\b',
        r'\bALTER\b\s+\bTABLE\b',
        r'\bEXEC\b\s+\bSP_EXECUTESQL\b',
        r'\bEXEC\b\s+["\']',
        r'\bEXECUTE\b\s+["\']',
        r'\bDECLARE\b\s+@',
        r'\bCAST\b\s*\(.*?\s+AS\s+',
        r'\bCONVERT\b\s*\(.*?\s*,\s*',
        r'\bCHAR\(\d+\)',
        r'\bWAITFOR\b\s+DELAY\b',
        r'\bINFORMATION_SCHEMA\b',
        r'\bSYSOBJECTS\b',
        r'\bXP_CMDSHELL\b',
        r'\bSP_OACREATE\b',
        r'\bSP_OAMETHOD\b',
        r'\bSP_ADDSERVER\b',
        r'\bOPENROWSET\b',
        r'\bOPENQUERY\b',
        r'\bOPENXML\b',
        r'\bWITH\b\s+RECOMPILE\b',
        
        # Look for PHP variables used in SQL queries without proper validation
        r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'].*\'.*\'.*["\']',
        
        # Look for concatenated SQL strings in PHP code
        r'\bquery\b\s*=\s*["\']\s*\.\s*\$',
        r'\bquery\b\s*=\s*\$',
        r'\bexec\b\s*\(\s*["\'].*?\$',
        
        # Patterns indicating user input directly in SQL statements
        r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*?\]',
        
        # Patterns indicating usage of common SQL functions in user input
        r'\bLENGTH\b\s*\(\s*\$_',
        r'\bORD\b\s*\(\s*\$_',
        r'\bSUBSTRING\b\s*\(\s*\$_',
        r'\bLOCATE\b\s*\(\s*\$_',
        r'\bPOSITION\b\s*\(\s*\$_',
        
        # JavaScript patterns for dynamic SQL queries
        r'"\s*\+\s*document\.',
        r'"\s*\+\s*window\.location',
        r'"\s*\+\s*window\.document',
        
        # ASP patterns for SQL concatenation
        r'Dim\s+\w+\s+:\s+\w+\s+=\s+".*\&\s*\w+\s*\&\s*".*',
        
        # C# patterns for SQL concatenation
        r'String\s+\w+\s+=\s*".*"\s*\+\s*\w+',
        r'"\s*\+\s*Request\.',
        
        # JSP patterns for SQL concatenation
        r'String\s+\w+\s*=\s*".*"\s*\+\s*request\.',
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'SQL Injection',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities
