"""
Secret and Credential Detection Rules for AttackLens SAST

Detects hardcoded API keys, tokens, database credentials, AWS keys, and private keys.
Strictly redacts all values.
"""

import re
from typing import List, Dict, Any
from ..redactor import redact_secrets, REDACTED_TEXT


SECRET_RULE_PATTERNS = [
    {
        "id": "SEC-001",
        "title": "Hardcoded AWS Access Key ID",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.96,
        "pattern": re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'),
        "description": "An Amazon Web Services (AWS) Access Key ID was identified hardcoded in source code.",
        "recommendation": "Remove hardcoded AWS credentials immediately. Rotate the exposed key in the AWS IAM Console and load credentials via environment variables, AWS Secrets Manager, or IAM Roles."
    },
    {
        "id": "SEC-002",
        "title": "Hardcoded Private Key",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.98,
        "pattern": re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----'),
        "description": "An unencrypted private cryptographic key block was detected in the source repository.",
        "recommendation": "Never commit private keys to code repositories. Revoke and replace this key pair, and inject private keys at runtime using secure secret storage."
    },
    {
        "id": "SEC-003",
        "title": "Hardcoded GitHub Personal Access Token",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.97,
        "pattern": re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b'),
        "description": "A GitHub personal access token or OAuth token was found in the codebase.",
        "recommendation": "Revoke the token in GitHub Settings > Developer settings > Personal access tokens and store it securely in environment variables."
    },
    {
        "id": "SEC-004",
        "title": "Hardcoded Database Connection Credentials",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.92,
        "pattern": re.compile(r'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|oracle|amqp)://[^:\s]+:[^@\s/]{3,}@[a-zA-Z0-9_\-\.]+'),
        "description": "A database connection URI with embedded username and password was discovered.",
        "recommendation": "Extract database connection strings into environment variables (e.g. DATABASE_URL) and manage passwords via a secrets vault."
    },
    {
        "id": "SEC-005",
        "title": "Hardcoded JWT Secret / Signing Key",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.91,
        "pattern": re.compile(r'(?i)(?:jwt_secret|jwt_key|token_secret|signing_key)\s*[:=]\s*["\']([^"\']{6,})["\']'),
        "description": "A JSON Web Token (JWT) secret or signing key is hardcoded in application logic.",
        "recommendation": "Load JWT secret keys from secure environment variables or a key management service (KMS). Rotate existing secrets."
    },
    {
        "id": "SEC-006",
        "title": "Hardcoded API Key / Token Assignment",
        "severity": "medium",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.86,
        "pattern": re.compile(r'(?i)(?:api_key|apikey|secret_key|auth_token|client_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']'),
        "description": "A hardcoded API key or client secret assignment was identified.",
        "recommendation": "Store all third-party API keys and client credentials in environment variables or configuration vaults."
    },
    {
        "id": "SEC-007",
        "title": "Slack API / Bot Token",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.95,
        "pattern": re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b'),
        "description": "A Slack Bot or User API token was detected.",
        "recommendation": "Revoke the Slack token immediately through the Slack API management console and store credentials securely."
    },
    {
        "id": "SEC-008",
        "title": "Stripe Live API Key",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "confidence": 0.96,
        "pattern": re.compile(r'\b[sr]k_live_[0-9a-zA-Z]{24,34}\b'),
        "description": "A live production Stripe API Secret/Restricted Key was discovered.",
        "recommendation": "Roll this Stripe key in the Stripe Dashboard and load production keys through environment secrets."
    }
]


def scan_file_for_secrets(rel_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    """Scans content for secret and credential indicators and returns sanitized findings."""
    findings = []
    
    # Don't flag sample env documentation files (e.g. .env.example, .env.sample) unless they have real-looking keys
    is_example_file = any(rel_path.lower().endswith(suffix) for suffix in [".example", ".sample", ".template", ".default"])

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean_line = line.strip()
        if not clean_line:
            continue

        # Skip comment lines that are just docs
        if clean_line.startswith("#") and ("example" in clean_line.lower() or "placeholder" in clean_line.lower()):
            continue

        for rule in SECRET_RULE_PATTERNS:
            match = rule["pattern"].search(clean_line)
            if match:
                # Calculate context lines
                start_line = max(1, line_num - 2)
                end_line = min(len(lines), line_num + 2)
                context_snippet = "\n".join(lines[start_line - 1:end_line])
                
                # Sanitize evidence and context
                sanitized_context = redact_secrets(context_snippet)
                sanitized_line = redact_secrets(clean_line)

                # Lower confidence for template files
                conf = rule["confidence"]
                if is_example_file:
                    conf = max(0.50, conf - 0.25)

                findings.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": round(conf, 2),
                    "category": rule["category"],
                    "cwe": rule["cwe"],
                    "file": rel_path,
                    "line": line_num,
                    "code_context": {
                        "start_line": start_line,
                        "end_line": end_line,
                        "target_line": line_num,
                        "content": sanitized_context
                    },
                    "description": rule["description"],
                    "evidence": f"Secret pattern matched on line {line_num}: {sanitized_line}",
                    "recommendation": rule["recommendation"]
                })
                break  # match only one secret rule per line to avoid duplicates

    return findings
