"""
JavaScript and TypeScript Security Analysis Rules Engine for AttackLens SAST

Detects vulnerability patterns across Node.js, Express, React, Next.js, and browser JS:
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Server-Side Request Forgery (SSRF) (CWE-918)
- Cross-Site Scripting (XSS / DOM XSS) (CWE-79)
- Insecure JWT Configuration (CWE-345)
- Permissive CORS with Credentials (CWE-942)
- Insecure Cookie & Session Settings (CWE-614, CWE-1004)
- Insecure Deserialization (CWE-502)
- Weak Cryptographic Hashing (CWE-328)
"""

import re
from typing import List, Dict, Any
from ..redactor import redact_secrets


def get_js_code_context(lines: List[str], target_line: int, radius: int = 2) -> Dict[str, Any]:
    start = max(1, target_line - radius)
    end = min(len(lines), target_line + radius)
    content = "\n".join(lines[start - 1:end])
    return {
        "start_line": start,
        "end_line": end,
        "target_line": target_line,
        "content": redact_secrets(content)
    }


JS_RULE_DEFINITIONS = [
    # 1. SQL Injection: db.query / connection.query with concatenation or template literals
    {
        "id": "JS-SQLI-001",
        "title": "Potential SQL Injection in Dynamic Database Query",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.91,
        "pattern": re.compile(r'(?:connection\.query|db\.query|client\.query|pool\.query|sequelize\.query)\s*\(\s*(?:["\'].*?\+.*?["\']|`.*?\$\{.*?\}|req\.)', re.IGNORECASE),
        "description": "Database query executed with dynamically concatenated string or template literal, allowing SQL injection.",
        "recommendation": "Use parameterized queries with placeholder arrays (e.g. pool.query('SELECT * FROM users WHERE id = $1', [userId]))."
    },

    # 2. Command Injection: child_process.exec / execSync
    {
        "id": "JS-CMD-001",
        "title": "Command Injection via child_process.exec",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "injection",
        "confidence": 0.90,
        "pattern": re.compile(r'(?:child_process\.(?:exec|execSync)|\bexec\s*\(\s*(?:`|\$|["\'].*\+)|execSync\s*\()'),
        "description": "child_process.exec executes strings in a system shell. Untrusted input concatenated into shell commands enables arbitrary command execution.",
        "recommendation": "Use child_process.execFile() or child_process.spawn() with an array of arguments without invoking a shell."
    },

    # 3. Path Traversal: fs.readFile with request parameters
    {
        "id": "JS-PATH-001",
        "title": "Path Traversal in Filesystem Operations",
        "severity": "high",
        "cwe": "CWE-22",
        "category": "file_handling",
        "confidence": 0.88,
        "pattern": re.compile(r'fs\.(?:readFile|readFileSync|createReadStream|writeFile|unlink)\s*\(\s*(?:.*?req\.(?:query|params|body)|.*?path\.join\(.*?req\.)'),
        "description": "Filesystem operation constructed with user request parameters without canonical path validation, allowing Directory Traversal.",
        "recommendation": "Normalize paths using path.resolve() and verify the target path is strictly contained within the intended base directory."
    },

    # 4. SSRF: axios / fetch using user-controlled URL
    {
        "id": "JS-SSRF-001",
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "cwe": "CWE-918",
        "category": "ssrf",
        "confidence": 0.87,
        "pattern": re.compile(r'(?:axios\.(?:get|post|put|delete|request)|fetch|http\.get|https\.get)\s*\(\s*(?:req\.(?:query|params|body)|url|targetUrl)', re.IGNORECASE),
        "description": "Outbound HTTP request URL is derived from user input without hostname allowlisting.",
        "recommendation": "Validate destination URLs against an allowlist of trusted domains and disallow requests to internal IP addresses (RFC 1918, 127.0.0.1, 169.254.169.254)."
    },

    # 5. XSS: dangerouslySetInnerHTML or innerHTML
    {
        "id": "JS-XSS-001",
        "title": "DOM-based XSS via innerHTML / dangerouslySetInnerHTML",
        "severity": "medium",
        "cwe": "CWE-79",
        "category": "xss",
        "confidence": 0.89,
        "pattern": re.compile(r'(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|\.innerHTML\s*=|\.outerHTML\s*=)'),
        "description": "Direct injection of raw HTML into the DOM bypasses React/framework XSS protections.",
        "recommendation": "Sanitize HTML using DOMPurify (e.g. DOMPurify.sanitize(content)) before inserting into DOM, or use standard text elements."
    },

    # 6. Insecure JWT: algorithm 'none'
    {
        "id": "JS-JWT-001",
        "title": "Insecure JWT Signing Algorithm ('none')",
        "severity": "high",
        "cwe": "CWE-345",
        "category": "authentication",
        "confidence": 0.95,
        "pattern": re.compile(r'algorithm\s*:\s*["\']none["\']', re.IGNORECASE),
        "description": "JWT configured with algorithm 'none', allowing attackers to forge arbitrary tokens without a signature.",
        "recommendation": "Enforce strong asymmetric (RS256, ES256) or symmetric (HS256) algorithms and disallow 'none'."
    },

    # 7. Permissive CORS with Credentials
    {
        "id": "JS-CORS-001",
        "title": "Overly Permissive CORS with Credentials Allowed",
        "severity": "medium",
        "cwe": "CWE-942",
        "category": "configuration",
        "confidence": 0.88,
        "pattern": re.compile(r'cors\s*\(\s*\{[\s\S]*?origin\s*:\s*(?:true|["\']\*["\'])[\s\S]*?credentials\s*:\s*true', re.IGNORECASE),
        "description": "CORS configuration allows wildcard origins with credentials, exposing authenticated endpoints to unauthorized domains.",
        "recommendation": "Specify an explicit list of trusted origin domains rather than enabling wildcard reflection."
    },

    # 8. Insecure Cookie Flags
    {
        "id": "JS-COOKIE-001",
        "title": "Cookie Missing httpOnly or secure Flags",
        "severity": "low",
        "cwe": "CWE-1004",
        "category": "session",
        "confidence": 0.85,
        "pattern": re.compile(r'res\.cookie\s*\([^,]+,[^,]+,\s*\{[\s\S]*?httpOnly\s*:\s*false', re.IGNORECASE),
        "description": "Cookie explicitly created with httpOnly: false, allowing client-side scripts to access the cookie.",
        "recommendation": "Always set { httpOnly: true, secure: true, sameSite: 'lax' } for sensitive session and auth cookies."
    },

    # 9. Insecure Deserialization: node-serialize / funcster
    {
        "id": "JS-DESER-001",
        "title": "Insecure Deserialization in Node.js (node-serialize)",
        "severity": "high",
        "cwe": "CWE-502",
        "category": "deserialization",
        "confidence": 0.94,
        "pattern": re.compile(r'(?:serialize|node-serialize)\.unserialize\s*\('),
        "description": "node-serialize.unserialize() allows execution of Immediately Invoked Function Expressions (IIFE) leading to RCE.",
        "recommendation": "Do not use node-serialize. Parse standard structured JSON using JSON.parse()."
    },

    # 10. Weak Cryptographic Hashing: crypto.createHash('md5'/'sha1')
    {
        "id": "JS-CRYPTO-001",
        "title": "Weak Hash Algorithm (crypto.createHash)",
        "severity": "medium",
        "cwe": "CWE-328",
        "category": "cryptography",
        "confidence": 0.86,
        "pattern": re.compile(r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']\)', re.IGNORECASE),
        "description": "MD5 and SHA1 hash functions are vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 (crypto.createHash('sha256')) or SHA-512, and bcrypt/argon2 for password hashing."
    }
]


def scan_javascript_file(rel_path: str, content: str, lines: List[str], is_test: bool) -> List[Dict[str, Any]]:
    """Scans JavaScript / TypeScript files for vulnerability patterns."""
    findings: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean = line.strip()
        if not clean or clean.startswith("//") or clean.startswith("/*"):
            continue

        for rule in JS_RULE_DEFINITIONS:
            if rule["pattern"].search(clean):
                conf = rule["confidence"]
                if is_test:
                    conf = max(0.50, conf - 0.20)

                findings.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": round(conf, 2),
                    "category": rule["category"],
                    "cwe": rule["cwe"],
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_js_code_context(lines, line_num),
                    "description": rule["description"],
                    "evidence": f"Pattern matched on line {line_num}: {redact_secrets(clean)}",
                    "recommendation": rule["recommendation"]
                })

    return findings
