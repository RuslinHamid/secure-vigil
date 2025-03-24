import re

def find_crypto_vulnerabilities(code):
    patterns = [
        # Weak hashing algorithms
        r'\b(md5|sha1|md4|ripemd160|md2)\b\s*\(',

        # Insecure cipher modes
        r'(AES|DES|Blowfish|TripleDES)\s*\(.*?MODE_ECB',
        r'(AES|DES|Blowfish|TripleDES)\s*\(.*?(MODE_CBC|MODE_PCB|MODE_XTS)',
        r'\bMODE_(ECB|CBC)\b',

        # Hardcoded cryptographic keys
        r'\bkey\b\s*=\s*[\'"][A-Za-z0-9]{16,}[\'"]',
        r'(?i)\b(secret|api_key|password|crypt_key|private_key)\b\s*=\s*[\'"].*[\'"]',
        r'\bkey\b\s*=\s*\bbase64\.b64decode\b\(.*?\)',

        # Predictable Initialization Vectors (IV)
        r'\bIV\b\s*=\s*\b(Random\.new\b\(.*?\)|b?\'[A-Za-z0-9]{8,16}\')',
        r'\bIV\b\s*=\s*\bnew byte\[\]\b',

        # Weak random number generation
        r'\b(Random|SecureRandom)\b.*?\s*\.nextInt\(\d+\)',
        r'\bjava\.util\.Random\b',
        r'\brandom\.random\(\)',

        # Deprecated algorithms
        r'\bRC4\b',
        r'\bDES\b',
        r'\bTripleDES\b',

        # Lack of key stretching
        r'\b(PBKDF2|bcrypt|argon2)\b.*?\s*\(\s*\)',
        r'\bkey\s*=\\s*hashlib\.\w+\(.*?\)',

        # Lack of salting
        r'\bhashlib\.\w+\\s*\(.*?password\b.*?\)',
        r'\b(password_hash|crypt)\b\s*\(.*?[,|\)]',

        # Improper certificate validation
        r'\bssl\.wrap_socket\b\(.*?cert_reqs=ssl\.CERT_NONE',
        r'X509TrustManager\b.*?checkServerTrusted',

        # Insecure key management
        r'\b(private|public|secret)_key\b\s*=\s*[\'"][A-Za-z0-9+/=]{32,}[\'"]',
        r'\bkey\b\s*=\\s*\bopen\(',

        # Usage of broken protocols
        r'\bSSLv3\b',
        r'\bTLSv1\b',
        r'CipherSuite.*?(NULL|EXPORT)',

        # Plaintext secrets in memory or logs
        r'\bprint\b.*?(password|key|token)',
        r'\bLOG\.debug\b.*?(password|key|token)',

        # Unsalted cryptographic hash functions
        r'\b(hashlib|messageDigest)\b.*?\b(md5|sha1)\b.*?\)'
    ]

    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, code, re.IGNORECASE))

    vulnerabilities = []
    for match in matches:
        vulnerability = {
            'type': 'Cryptographic Vulnerability',
            'pattern': match.group(),
            'line_number': code.count('\n', 0, match.start()) + 1
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities


 