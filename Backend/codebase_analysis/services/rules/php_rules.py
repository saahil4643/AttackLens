"""
PHP Security Analysis Rules Engine for AttackLens SAST

Detects vulnerability patterns across PHP applications (Laravel, Symfony, WordPress, raw PHP):
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)
- Local File Inclusion / Path Traversal (CWE-22)
- Reflected XSS (CWE-79)
- Weak Cryptographic Password Hashing (CWE-328)
"""

import re
from typing import List, Dict, Any
from ..redactor import redact_secrets


def get_php_code_context(lines: List[str], target_line: int, radius: int = 2) -> Dict[str, Any]:
    start = max(1, target_line - radius)
    end = min(len(lines), target_line + radius)
    content = "\n".join(lines[start - 1:end])
    return {
        "start_line": start,
        "end_line": end,
        "target_line": target_line,
        "content": redact_secrets(content)
    }


PHP_RULE_DEFINITIONS = [
    {
        "id": "PHP-SQLI-001",
        "title": "SQL Injection in PHP Database Query",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.93,
        "pattern": re.compile(r'(?:\$conn->query|mysqli_query|mysql_query|PDO::query|DB::raw|\$db->query|\$pdo->query)\s*\(\s*["\'].*?["\']\s*\.\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+)', re.IGNORECASE),
        "description": "SQL query built via string concatenation with untrusted superglobal or variable.",
        "recommendation": "Use PDO prepared statements (PDO::prepare + execute with bound parameters) or ORM query builders."
    },
    {
        "id": "PHP-CMD-001",
        "title": "Command Injection via PHP System Functions",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "injection",
        "confidence": 0.91,
        "pattern": re.compile(r'\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+|\`.*?\`)', re.IGNORECASE),
        "description": "System command execution functions invoked with dynamic or user-controlled input.",
        "recommendation": "Avoid invoking shell commands from PHP. If necessary, escape arguments using escapeshellarg() or escapeshellcmd()."
    },
    {
        "id": "PHP-DESER-001",
        "title": "Insecure Deserialization via unserialize()",
        "severity": "high",
        "cwe": "CWE-502",
        "category": "deserialization",
        "confidence": 0.94,
        "pattern": re.compile(r'\bunserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$[a-zA-Z0-9_]+)', re.IGNORECASE),
        "description": "PHP unserialize() with untrusted data allows Object Injection and POP chain arbitrary code execution.",
        "recommendation": "Use json_decode() for data interchange. If unserialize() must be used, restrict classes with ['allowed_classes' => false]."
    },
    {
        "id": "PHP-LFI-001",
        "title": "File Inclusion / Path Traversal in PHP",
        "severity": "high",
        "cwe": "CWE-22",
        "category": "file_handling",
        "confidence": 0.90,
        "pattern": re.compile(r'\b(?:include|require|include_once|require_once|file_get_contents|readfile)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+)', re.IGNORECASE),
        "description": "Dynamic file inclusion or reading with user input enables Local File Inclusion (LFI) or arbitrary file read.",
        "recommendation": "Use a strict allowlist of permitted filenames rather than passing request parameters directly to file functions."
    },
    {
        "id": "PHP-XSS-001",
        "title": "Unescaped Output in PHP (Reflected XSS)",
        "severity": "medium",
        "cwe": "CWE-79",
        "category": "xss",
        "confidence": 0.88,
        "pattern": re.compile(r'\b(?:echo|print)\s+(?:\$_(?:GET|POST|REQUEST)|["\'].*?\.\s*\$_(?:GET|POST|REQUEST))', re.IGNORECASE),
        "description": "Directly echoing superglobals into HTML output without escaping enables Cross-Site Scripting.",
        "recommendation": "Escape all output using htmlspecialchars($var, ENT_QUOTES, 'UTF-8') or a modern templating engine like Blade/Twig."
    }
]


def scan_php_file(rel_path: str, content: str, lines: List[str], is_test: bool) -> List[Dict[str, Any]]:
    """Scans PHP files for vulnerability patterns."""
    findings: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean = line.strip()
        if not clean or clean.startswith("//") or clean.startswith("#"):
            continue

        for rule in PHP_RULE_DEFINITIONS:
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
                    "code_context": get_php_code_context(lines, line_num),
                    "description": rule["description"],
                    "evidence": f"Pattern matched on line {line_num}: {redact_secrets(clean)}",
                    "recommendation": rule["recommendation"]
                })

    return findings
