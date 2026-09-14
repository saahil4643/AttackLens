"""
Secret Redaction Utility for AttackLens SAST

Ensures no raw API keys, passwords, database credentials, tokens, or private keys
are ever emitted in finding messages, code snippets, logs, or JSON responses.
"""

import re
from typing import Union, Dict, Any, List

REDACTED_TEXT = "[REDACTED]"

# Specific high-confidence secret patterns for selective inline replacement
SECRET_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'), REDACTED_TEXT),
    # AWS Secret Key
    (re.compile(r'(?i)(aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'), r'\1="[REDACTED]"'),
    # GitHub Tokens
    (re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b'), REDACTED_TEXT),
    (re.compile(r'\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b'), REDACTED_TEXT),
    # Slack Tokens
    (re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b'), REDACTED_TEXT),
    # Stripe API Keys
    (re.compile(r'\b[sr]k_live_[0-9a-zA-Z]{24,34}\b'), REDACTED_TEXT),
    # Private Key blocks
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----'),
    # Database URLs with passwords (e.g. postgres://user:password@host:5432/dbname)
    (re.compile(r'(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|oracle|amqp)://([^:]+):([^@\s/]+)@'), r'\1://\2:[REDACTED]@'),
    # Generic password / secret / token assignments in code (e.g., password = "...", api_key: "...")
    (re.compile(r'(?i)(["\']?(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key|secret_key|jwt_secret)["\']?\s*[:=]\s*["\'])([^"\']{4,})(["\'])'), r'\1[REDACTED]\3'),
    # Authorization: Bearer <token>
    (re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9_\-\.]{20,}'), r'\1[REDACTED]'),
    # Django SECRET_KEY = '...'
    (re.compile(r'(?i)(SECRET_KEY\s*=\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3')
]


def redact_secrets(text: str) -> str:
    """
    Scans a string and replaces all identifiable secrets with safe [REDACTED] placeholders.
    """
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        try:
            sanitized = pattern.sub(replacement, sanitized)
        except Exception:
            pass
    return sanitized


def sanitize_data_structure(data: Union[Dict, List, str, Any]) -> Any:
    """
    Recursively redacts secrets from dictionaries, lists, and strings before returning to UI/API.
    """
    if isinstance(data, str):
        return redact_secrets(data)
    elif isinstance(data, dict):
        return {k: sanitize_data_structure(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data_structure(elem) for elem in data]
    return data
