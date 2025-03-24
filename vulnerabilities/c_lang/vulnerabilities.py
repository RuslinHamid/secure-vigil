import re
from typing import List, Dict, Any

def find_c_vulnerabilities(code: str) -> List[Dict[str, Any]]:
    """
    Find security vulnerabilities in C code.
    
    Args:
        code (str): The C code to analyze
        
    Returns:
        List[Dict[str, Any]]: List of vulnerabilities found
    """
    vulnerabilities = []
    
    # Buffer Overflow
    buffer_overflow_patterns = [
        r'gets\s*\(',  # Unsafe gets() function
        r'strcpy\s*\(',  # Unsafe strcpy
        r'strcat\s*\(',  # Unsafe strcat
        r'sprintf\s*\(',  # Unsafe sprintf
        r'scanf\s*\(',  # Unsafe scanf
        r'fscanf\s*\(',  # Unsafe fscanf
        r'vfscanf\s*\(',  # Unsafe vfscanf
        r'vscanf\s*\(',  # Unsafe vscanf
        r'vsscanf\s*\(',  # Unsafe vsscanf
        r'fgets\s*\(',  # Unsafe fgets without size check
    ]
    
    for pattern in buffer_overflow_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Buffer Overflow',
                'description': f'Use of unsafe function {match.group().strip()} at line {line_number}. This can lead to buffer overflow vulnerabilities.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use safer alternatives like gets_s(), strncpy(), strncat(), snprintf(), fgets() with proper size checks.'
            })
    
    # Format String Vulnerability
    format_string_patterns = [
        r'printf\s*\([^"]*%[^"]*\)',  # Unsafe printf
        r'fprintf\s*\([^"]*%[^"]*\)',  # Unsafe fprintf
        r'sprintf\s*\([^"]*%[^"]*\)',  # Unsafe sprintf
        r'snprintf\s*\([^"]*%[^"]*\)',  # Unsafe snprintf
        r'vprintf\s*\([^"]*%[^"]*\)',  # Unsafe vprintf
        r'vfprintf\s*\([^"]*%[^"]*\)',  # Unsafe vfprintf
        r'vsprintf\s*\([^"]*%[^"]*\)',  # Unsafe vsprintf
        r'vsnprintf\s*\([^"]*%[^"]*\)',  # Unsafe vsnprintf
    ]
    
    for pattern in format_string_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Format String Vulnerability',
                'description': f'Potential format string vulnerability at line {line_number}. User input is being used as a format string.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Always use format strings as the first argument and never use user input as a format string.'
            })
    
    # Integer Overflow
    integer_overflow_patterns = [
        r'malloc\s*\([^)]*\)',  # malloc without size check
        r'calloc\s*\([^)]*\)',  # calloc without size check
        r'realloc\s*\([^)]*\)',  # realloc without size check
        r'strlen\s*\([^)]*\)',  # strlen without size check
        r'atoi\s*\([^)]*\)',  # atoi without error checking
        r'atol\s*\([^)]*\)',  # atol without error checking
        r'atoll\s*\([^)]*\)',  # atoll without error checking
        r'strtol\s*\([^)]*\)',  # strtol without error checking
        r'strtoul\s*\([^)]*\)',  # strtoul without error checking
        r'strtoll\s*\([^)]*\)',  # strtoll without error checking
        r'strtoull\s*\([^)]*\)',  # strtoull without error checking
    ]
    
    for pattern in integer_overflow_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Integer Overflow',
                'description': f'Potential integer overflow at line {line_number}. Result of arithmetic operation may overflow.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use checked arithmetic operations or ensure proper bounds checking before arithmetic operations.'
            })
    
    # Memory Leak
    memory_leak_patterns = [
        r'malloc\s*\([^)]*\)',  # malloc without free
        r'calloc\s*\([^)]*\)',  # calloc without free
        r'strdup\s*\([^)]*\)',  # strdup without free
        r'strndup\s*\([^)]*\)',  # strndup without free
        r'asprintf\s*\([^)]*\)',  # asprintf without free
        r'vasprintf\s*\([^)]*\)',  # vasprintf without free
    ]
    
    for pattern in memory_leak_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Memory Leak',
                'description': f'Potential memory leak at line {line_number}. Allocated memory is not being freed.',
                'line': line_number,
                'severity': 'Medium',
                'mitigation': 'Ensure all allocated memory is properly freed when no longer needed.'
            })
    
    # Use After Free
    use_after_free_patterns = [
        r'free\s*\([^)]*\)',  # free without null check
        r'free\s*\([^)]*\)\s*[^;]*[^=]*[^;]*;',  # free followed by use
    ]
    
    for pattern in use_after_free_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Use After Free',
                'description': f'Potential use after free at line {line_number}. Memory is being accessed after being freed.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Set pointer to NULL after freeing and check for NULL before use.'
            })
    
    # Command Injection
    command_injection_patterns = [
        r'system\s*\([^)]*\)',  # system() function
        r'popen\s*\([^)]*\)',  # popen() function
        r'execl\s*\([^)]*\)',  # execl() function
        r'execle\s*\([^)]*\)',  # execle() function
        r'execlp\s*\([^)]*\)',  # execlp() function
        r'execv\s*\([^)]*\)',  # execv() function
        r'execve\s*\([^)]*\)',  # execve() function
        r'execvp\s*\([^)]*\)',  # execvp() function
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
                'mitigation': 'Avoid using command execution functions with user input. If necessary, properly sanitize and validate all input.'
            })
    
    # Race Condition
    race_condition_patterns = [
        r'access\s*\([^)]*\)',  # access() followed by open()
        r'stat\s*\([^)]*\)',  # stat() followed by open()
        r'lstat\s*\([^)]*\)',  # lstat() followed by open()
        r'fstat\s*\([^)]*\)',  # fstat() followed by open()
    ]
    
    for pattern in race_condition_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            vulnerabilities.append({
                'type': 'Race Condition',
                'description': f'Potential race condition at line {line_number}. Time of check to time of use (TOCTOU) vulnerability.',
                'line': line_number,
                'severity': 'High',
                'mitigation': 'Use atomic operations or proper file locking mechanisms to prevent race conditions.'
            })
    
    return vulnerabilities 