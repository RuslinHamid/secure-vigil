import re

def find_xss_vulnerabilities(code):
    patterns = [
        # Look for common HTML tags that might be used in XSS attacks
        r'<script.*?>.*?</script>',
        r'<img.*?src=.*?>',
        r'<iframe.*?>.*?</iframe>',
        r'<object.*?>.*?</object>',
        r'<embed.*?>.*?</embed>',
        r'<link.*?>',
        r'<style.*?>.*?</style>',
        r'<div.*?on.*?>.*?</div>',
        r'<span.*?on.*?>.*?</span>',
        # Look for common JavaScript events that might be used in XSS attacks
        r'on\w+\s*=\s*["\'].*?["\']',
        # Look for JavaScript injection patterns
        r'javascript\s*:\s*["\'].*?["\']',
        # Look for document.write and innerHTML
        r'document\.write\s*\(.*?\)',
        r'\.innerHTML\s*=\s*["\'].*?["\']',
        # Look for PHP echo/print with direct user input
        r'echo\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        r'print\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        r'\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\s*;?\s*',
        # Look for ASP.NET Response.Write with direct user input
        r'Response\.Write\s*\(.*?\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]\)',
        # Look for potential JSONP vulnerabilities
        r'\w+Callback\s*=\s*\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\[.*?\]',
        # Look for JavaScript URL patterns
        r'<a.*?href=["\']javascript:.*?["\']',
        r'<button.*?onclick=["\'].*?["\']',
        r'<form.*?action=["\'].*?["\']',
        # Look for attributes containing JavaScript
        r'<.*?href=["\']javascript:.*?["\'].*?>',
        r'<.*?src=["\']javascript:.*?["\'].*?>',
        r'<.*?data=["\']javascript:.*?["\'].*?>',
        # Look for XSS patterns in JSON
        r'"\s*:\s*".*?<.*?>.*?"',
        # Unsanitized input being rendered in HTML
        r'<.*?>.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?</.*?>',
        # Direct echoing of user input in PHP
        r'echo\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?\);',
        # JavaScript: document.write() with user input
        r'document\.write\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?\);',
        # JS: writing innerHTML with user input
        r'innerHTML\s*=\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\];',
        # AngularJS template injection
        r'ng-bind-html\s*=\s*".*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]"',
        # React dangerouslySetInnerHTML usage
        r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\s*\}'
    ]

    vulnerabilities = []
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            vulnerability = {
                'type': 'Cross-Site Scripting (XSS)',
                'pattern': match.group(),
                'line_number': code.count('\n', 0, match.start()) + 1
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities
