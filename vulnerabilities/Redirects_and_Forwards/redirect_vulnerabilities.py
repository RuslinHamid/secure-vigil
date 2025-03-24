import re

def find_redirect_vulnerabilities(code):
    patterns = [
        # PHP header() redirect using unsanitized user input
        r'header\s*\(\s*[\'"]Location:\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?[\'"]\s*\);',
        # JavaScript-based redirects using user-controlled input
        r'window\.location\.href\s*=\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\];',
        # HTTP meta-refresh using user input
        r'<meta\s+http-equiv=["\']refresh["\'].*?content=["\'].*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?>',
        # JavaScript dynamic redirects with string concatenation
        r'window\.location\.href\s*=\\s*.*?\+.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\];',
        r'document\.location\.href\s*=\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\];',
        # Server-side redirects in Java
        r'response\.sendRedirect\s*\(.*?\+.*?\);',
        r'request\.getRequestDispatcher\s*\(.*?\+.*?\)\.forward',
        # ASP.NET insecure redirects
        r'Response\.Redirect\s*\(.*?Request\.(QueryString|Form)\[.*?\]\)',
        r'Server\.Transfer\s*\(.*?Request\.(QueryString|Form)\[.*?\]\)',
        # Ruby on Rails unsafe redirects
        r'redirect_to\s*\(.*?params\[:.*?\]\)',
        r'redirect_to\s*\(.*?\+.*?params\[:.*?\]\)',
        # Django unsafe redirects
        r'return\s+HttpResponseRedirect\s*\(.*?\+.*?request\.GET\[".*?"\]\)',
        r'return\s+redirect\s*\(.*?\+.*?request\.GET\[".*?"\]\)',
        # Flask unsafe redirects
        r'return\s+redirect\s*\(.*?\+.*?request\.args\.get\(".*?"\)\)',
        r'return\s+redirect\s*\(.*?\+.*?request\.form\[".*?"\]\)',
        # JavaScript unsafe redirection with query parameters
        r'window\.location\s*=\s*.*?\+.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\];',
        r'location\.assign\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\);',
        r'location\.replace\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\);',
        # HTML links using unsanitized user input
        r'<a\s+href=["\'].*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?[\'"].*?>',
        # Unsafe redirect URLs from database or external sources
        r'redirect_to\s*\(.*?fetch_url_from_db\(.*?\)\)',
        r'response\.sendRedirect\s*\(.*?getURLFromSource\(.*?\)\)',
    ]
    
    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'Redirect/Forward Vulnerability',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities
