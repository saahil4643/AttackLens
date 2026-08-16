import re

SENSITIVE_KEYS = [
    'password', 'secret', 'passwd', 'api_key', 'apikey', 'access_token', 
    'token', 'private_key', 'cookie', 'authorization', 'bearer', 'pwd',
    'passphrase', 'secret_key', 'client_secret', 'jwt'
]

# Pattern for: key = value, key: value, "key": "value" (supports underscores)
KEY_VALUE_PATTERN = re.compile(
    rf'((?:{"|".join(SENSITIVE_KEYS)})[\s\w\"\'\-_]*[:=]\s*)(["\']?)([^\s"\',;}}]+)\2',
    re.IGNORECASE
)

# Case-insensitive pattern to detect Bearer tokens in Authorization headers
BEARER_PATTERN = re.compile(
    r'(Authorization\s*:\s*)(Bearer\s+)([^\s\r\n\t,;]+)',
    re.IGNORECASE
)

# Matches complete PEM format private keys
PEM_KEY_PATTERN = re.compile(
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]+-----END [A-Z ]*PRIVATE KEY-----',
    re.DOTALL
)

def redact_text(text: str) -> str:
    if not text:
        return text
    
    # 1. Redact complete PEM private keys
    text = PEM_KEY_PATTERN.sub('[REDACTED PRIVATE KEY]', text)
    
    # 2. Redact Bearer token header contents
    text = BEARER_PATTERN.sub(r'\1\2[REDACTED]', text)
    
    # 3. Redact key-value secrets
    def replace_secret(match):
        prefix = match.group(1)
        quote = match.group(2)
        val = match.group(3)
        # Avoid redacting already redacted placeholders
        if '[REDACTED]' in val:
            return match.group(0)
        return f"{prefix}{quote}[REDACTED]{quote}"
        
    text = KEY_VALUE_PATTERN.sub(replace_secret, text)
    return text

def redact_evidence(data):
    """
    Recursively redacts dictionary, list, or string structures representing finding evidence.
    """
    if isinstance(data, str):
        return redact_text(data)
    elif isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            kl = k.lower()
            if any(sk in kl for sk in SENSITIVE_KEYS):
                if isinstance(v, str):
                    redacted[k] = '[REDACTED]'
                else:
                    redacted[k] = redact_evidence(v)
            else:
                redacted[k] = redact_evidence(v)
        return redacted
    elif isinstance(data, list):
        return [redact_evidence(x) for x in data]
    return data
