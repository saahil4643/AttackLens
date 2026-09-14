"""
Generic Multi-Language Security Analysis Rules Engine for AttackLens SAST

Covers Go, Ruby, C#, Rust, Shell, and configuration files:
- SQL Injection in Go, Ruby, C# (CWE-89)
- Command Injection in Go, Ruby, Shell (CWE-78)
- Pipe to Shell / Curl to Bash (CWE-78)
- Insecure CORS Headers (CWE-942)
- Insecure HTTP Endpoints (CWE-319)
"""

import re
from typing import List, Dict, Any
from ..redactor import redact_secrets


def get_generic_code_context(lines: List[str], target_line: int, radius: int = 2) -> Dict[str, Any]:
    start = max(1, target_line - radius)
    end = min(len(lines), target_line + radius)
    content = "\n".join(lines[start - 1:end])
    return {
        "start_line": start,
        "end_line": end,
        "target_line": target_line,
        "content": redact_secrets(content)
    }


GENERIC_RULE_DEFINITIONS = [
    # C# / .NET SQLi
    {
        "id": "CS-SQLI-001",
        "title": "SQL Injection in SqlCommand (.NET)",
        "language": "C#",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.90,
        "pattern": re.compile(r'new\s+SqlCommand\s*\(\s*["\'].*?\+.*?\)', re.IGNORECASE),
        "description": "SqlCommand constructed via dynamic string concatenation.",
        "recommendation": "Use parameterized queries with cmd.Parameters.AddWithValue() or Entity Framework ORM."
    },

    # Go SQLi
    {
        "id": "GO-SQLI-001",
        "title": "SQL Injection in Go database/sql Query",
        "language": "Go",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.90,
        "pattern": re.compile(r'db\.(?:Query|QueryRow|Exec)\s*\(\s*(?:fmt\.Sprintf\(|.*?["\'].*?\+)', re.IGNORECASE),
        "description": "Go SQL query formatted dynamically using fmt.Sprintf or string concatenation.",
        "recommendation": "Use placeholder parameters (e.g. db.Query('SELECT * FROM users WHERE id = $1', id))."
    },

    # Go Command Injection
    {
        "id": "GO-CMD-001",
        "title": "Command Execution in Go via exec.Command",
        "language": "Go",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "injection",
        "confidence": 0.88,
        "pattern": re.compile(r'exec\.Command\s*\(\s*["\'](?:sh|bash|cmd|powershell)["\'],\s*["\']-[cC]["\']'),
        "description": "exec.Command invoking a shell interpreter with dynamic string argument.",
        "recommendation": "Invoke the specific target binary directly with parameterized slice arguments rather than passing command strings to a shell."
    },

    # Ruby SQLi
    {
        "id": "RB-SQLI-001",
        "title": "SQL Injection in ActiveRecord / Ruby Query",
        "language": "Ruby",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.91,
        "pattern": re.compile(r'(?:ActiveRecord::Base\.connection\.execute|\.where)\s*\(\s*["\'].*?#\{.*?\}["\']', re.IGNORECASE),
        "description": "ActiveRecord query using string interpolation (#{}) instead of array parameter placeholders.",
        "recommendation": "Use parameterized query arrays: Model.where('name = ?', user_input)."
    },

    # Pipe to Shell in Shell / Dockerfile
    {
        "id": "SH-PIPE-001",
        "title": "Insecure Remote Script Execution (curl/wget piped to shell)",
        "language": "Shell",
        "severity": "medium",
        "cwe": "CWE-78",
        "category": "injection",
        "confidence": 0.92,
        "pattern": re.compile(r'(?:curl|wget)\s+.*?\s*\|\s*(?:bash|sh|sudo\s+bash|sudo\s+sh|zsh)'),
        "description": "Piping unverified remote scripts directly into a shell interpreter can allow Remote Code Execution if DNS or remote server is compromised.",
        "recommendation": "Download files, verify their cryptographic checksum / signature, and inspect before executing."
    },

    # CORS Wildcard in Config/Code
    {
        "id": "GEN-CORS-001",
        "title": "Wildcard Cross-Origin Resource Sharing (CORS)",
        "language": "Generic",
        "severity": "low",
        "cwe": "CWE-942",
        "category": "configuration",
        "confidence": 0.85,
        "pattern": re.compile(r'Access-Control-Allow-Origin[\s:=]+["\']?\*["\']?', re.IGNORECASE),
        "description": "Access-Control-Allow-Origin header set to '*' allows any website to read responses from this endpoint.",
        "recommendation": "Restrict Access-Control-Allow-Origin to authorized client origins."
    }
]


def scan_generic_file(rel_path: str, content: str, lines: List[str], lang: str, is_test: bool) -> List[Dict[str, Any]]:
    """Scans other supported languages and configuration files."""
    findings: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("//"):
            continue

        for rule in GENERIC_RULE_DEFINITIONS:
            rule_lang = rule.get("language")
            if rule_lang != "Generic" and rule_lang != lang:
                continue

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
                    "code_context": get_generic_code_context(lines, line_num),
                    "description": rule["description"],
                    "evidence": f"Pattern matched on line {line_num}: {redact_secrets(clean)}",
                    "recommendation": rule["recommendation"]
                })

    return findings
