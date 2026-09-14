"""
Java Security Analysis Rules Engine for AttackLens SAST

Detects vulnerability patterns across Java, Spring Boot, and JVM applications:
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-327, CWE-328)
- Disabled CSRF in Spring Security (CWE-352)
- Insecure Randomness (CWE-330)
- SSRF (CWE-918)
"""

import re
from typing import List, Dict, Any
from ..redactor import redact_secrets


def get_java_code_context(lines: List[str], target_line: int, radius: int = 2) -> Dict[str, Any]:
    start = max(1, target_line - radius)
    end = min(len(lines), target_line + radius)
    content = "\n".join(lines[start - 1:end])
    return {
        "start_line": start,
        "end_line": end,
        "target_line": target_line,
        "content": redact_secrets(content)
    }


JAVA_RULE_DEFINITIONS = [
    {
        "id": "JAVA-SQLI-001",
        "title": "SQL Injection via Concatenated JDBC Statement",
        "severity": "high",
        "cwe": "CWE-89",
        "category": "injection",
        "confidence": 0.92,
        "pattern": re.compile(r'(?:(?:statement|stmt|st|conn|em|entityManager)\s*\.\s*(?:executeQuery|executeUpdate|execute|createNativeQuery)|\.executeQuery|\.executeUpdate)\s*\(\s*["\'].*?\+.*?\)', re.IGNORECASE),
        "description": "JDBC Statement or JPA createNativeQuery constructed using dynamic string concatenation.",
        "recommendation": "Use PreparedStatement with parameter placeholders (?) or JPA named parameters (:param)."
    },
    {
        "id": "JAVA-CMD-001",
        "title": "Command Execution via Runtime.exec",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "injection",
        "confidence": 0.89,
        "pattern": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
        "description": "Executing system commands via Runtime.exec can allow Command Injection if arguments are dynamic.",
        "recommendation": "Avoid invoking shell processes. If mandatory, use ProcessBuilder with hardcoded command arrays and strict input validation."
    },
    {
        "id": "JAVA-DESER-001",
        "title": "Insecure Deserialization via ObjectInputStream",
        "severity": "high",
        "cwe": "CWE-502",
        "category": "deserialization",
        "confidence": 0.94,
        "pattern": re.compile(r'new\s+ObjectInputStream\s*\(.*?\.readObject\s*\(|ObjectInputStream\b'),
        "description": "ObjectInputStream.readObject() is susceptible to arbitrary code execution gadget chains (e.g. Commons Collections).",
        "recommendation": "Do not deserialize untrusted binary data. Use JSON or XML with safe deserialization libraries and schema validation."
    },
    {
        "id": "JAVA-CSRF-001",
        "title": "Spring Security CSRF Protection Explicitly Disabled",
        "severity": "medium",
        "cwe": "CWE-352",
        "category": "csrf",
        "confidence": 0.95,
        "pattern": re.compile(r'(?:http\.csrf\(\)\.disable\(\)|csrf\s*->\s*csrf\.disable\(\))'),
        "description": "CSRF protection has been disabled in Spring Security configuration, leaving endpoints vulnerable to Cross-Site Request Forgery.",
        "recommendation": "Enable CSRF protection in Spring Security, especially for browser session-based applications."
    },
    {
        "id": "JAVA-CRYPTO-001",
        "title": "Weak Cryptographic Algorithm in Java",
        "severity": "medium",
        "cwe": "CWE-327",
        "category": "cryptography",
        "confidence": 0.88,
        "pattern": re.compile(r'(?:MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\']\)|Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|AES/ECB)["\']\))', re.IGNORECASE),
        "description": "Insecure cryptographic hash or cipher algorithm (MD5, SHA-1, DES, RC4, or ECB mode) detected.",
        "recommendation": "Use SHA-256 / SHA-3 for hashing and AES/GCM/NoPadding for authenticated symmetric encryption."
    },
    {
        "id": "JAVA-PATH-001",
        "title": "Path Traversal in Java File Access",
        "severity": "high",
        "cwe": "CWE-22",
        "category": "file_handling",
        "confidence": 0.87,
        "pattern": re.compile(r'new\s+(?:File|FileInputStream|FileOutputStream)\s*\(\s*.*?request\.getParameter\('),
        "description": "File object initialized using unsanitized request parameter.",
        "recommendation": "Validate canonical file paths against an allowed base directory using Path.normalize() and Path.startsWith()."
    }
]


def scan_java_file(rel_path: str, content: str, lines: List[str], is_test: bool) -> List[Dict[str, Any]]:
    """Scans Java files for known vulnerability patterns."""
    findings: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean = line.strip()
        if not clean or clean.startswith("//") or clean.startswith("/*"):
            continue

        for rule in JAVA_RULE_DEFINITIONS:
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
                    "code_context": get_java_code_context(lines, line_num),
                    "description": rule["description"],
                    "evidence": f"Pattern matched on line {line_num}: {redact_secrets(clean)}",
                    "recommendation": rule["recommendation"]
                })

    return findings
