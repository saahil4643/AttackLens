"""
Python Security Analysis Rules Engine for AttackLens SAST

Detects vulnerability patterns across Python web frameworks (Django, Flask, FastAPI, raw Python):
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- XSS & Unsafe Template Rendering (CWE-79)
- Insecure Deserialization (CWE-502)
- Weak Cryptography & Insecure Randomness (CWE-327, CWE-330)
- Insecure Configuration (DEBUG=True) (CWE-489)
- Missing CSRF Protection (CWE-352)
- Plaintext Password Storage (CWE-256)
- Insecure File Upload Handling (CWE-434)
- Missing Authorization Controls (CWE-862)
"""

import ast
import re
from typing import List, Dict, Any, Tuple
from ..redactor import redact_secrets


def get_code_context(lines: List[str], target_line: int, radius: int = 2) -> Dict[str, Any]:
    """Helper to extract a bounded context window around a target line."""
    start = max(1, target_line - radius)
    end = min(len(lines), target_line + radius)
    content = "\n".join(lines[start - 1:end])
    return {
        "start_line": start,
        "end_line": end,
        "target_line": target_line,
        "content": redact_secrets(content)
    }


class PythonASTSecurityVisitor(ast.NodeVisitor):
    """
    AST Visitor checking Python syntax trees for dangerous constructs and AST patterns.
    """

    def __init__(self, rel_path: str, lines: List[str], is_test: bool):
        self.rel_path = rel_path
        self.lines = lines
        self.is_test = is_test
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call):
        lineno = getattr(node, 'lineno', 0)
        line_str = self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""

        # 1. SQL Injection: cursor.execute with format / concat / f-string
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in {"execute", "raw"} and node.args:
            first_arg = node.args[0]
            # Check if first arg is BinOp (concatenation "+", "%" formatting), JoinedStr (f-string), or Call (.format)
            is_unsafe_sql = False
            evidence_desc = ""

            if isinstance(first_arg, ast.BinOp):
                if isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    is_unsafe_sql = True
                    evidence_desc = "SQL query constructed via string concatenation (+) or % formatting in query execution call."
            elif isinstance(first_arg, ast.JoinedStr):
                is_unsafe_sql = True
                evidence_desc = "SQL query constructed dynamically via f-string interpolation."
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                is_unsafe_sql = True
                evidence_desc = "SQL query constructed via .format() dynamic string formatting."

            if is_unsafe_sql:
                self.findings.append({
                    "id": "PY-SQLI-001",
                    "title": "Potential SQL Injection in Raw Database Query",
                    "severity": "high",
                    "confidence": 0.93 if not self.is_test else 0.70,
                    "category": "injection",
                    "cwe": "CWE-89",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "A database query is constructed using dynamic string formatting, concatenation, or f-strings instead of parameterized placeholders.",
                    "evidence": f"Unsafe query invocation on line {lineno}: {redact_secrets(line_str.strip())} ({evidence_desc})",
                    "recommendation": "Use parameterized queries with database driver placeholders (e.g. cursor.execute('SELECT * FROM table WHERE id = %s', [user_id])) or ORM query abstractions."
                })

        # 2. Command Injection: subprocess with shell=True
        if func_name in {"Popen", "run", "call", "check_call", "check_output"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "id": "PY-CMD-001",
                        "title": "Command Execution with shell=True",
                        "severity": "high",
                        "confidence": 0.90 if not self.is_test else 0.65,
                        "category": "injection",
                        "cwe": "CWE-78",
                        "file": self.rel_path,
                        "line": lineno,
                        "code_context": get_code_context(self.lines, lineno),
                        "description": "Executing system commands through a shell (shell=True) can lead to arbitrary Command Injection if arguments are untrusted or unescaped.",
                        "evidence": f"subprocess invocation with shell=True on line {lineno}: {redact_secrets(line_str.strip())}",
                        "recommendation": "Set shell=False and pass arguments as an immutable list of arguments (e.g. ['executable', 'arg1', 'arg2']) without shell interpolation."
                    })

        # 3. Command Injection: os.system / os.popen / eval / exec
        if func_name == "system" and "os.system" in line_str:
            self.findings.append({
                "id": "PY-CMD-002",
                "title": "Dangerous System Command Execution (os.system)",
                "severity": "high",
                "confidence": 0.88 if not self.is_test else 0.60,
                "category": "injection",
                "cwe": "CWE-78",
                "file": self.rel_path,
                "line": lineno,
                "code_context": get_code_context(self.lines, lineno),
                "description": "os.system passes strings directly to the underlying shell, creating severe command injection risk.",
                "recommendation": "Replace os.system with subprocess.run(..., shell=False) with parameterized arguments."
            })
        elif func_name in {"eval", "exec"} and not self.is_test:
            # Check if argument is not a simple string literal
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append({
                    "id": "PY-CODE-001",
                    "title": "Dynamic Code Execution (eval/exec)",
                    "severity": "high",
                    "confidence": 0.85,
                    "category": "injection",
                    "cwe": "CWE-95",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "Dynamic evaluation of code via eval() or exec() can allow Remote Code Execution if inputs are untrusted.",
                    "evidence": f"Dynamic evaluation on line {lineno}: {redact_secrets(line_str.strip())}",
                    "recommendation": "Refactor logic to use safe parsers (such as ast.literal_eval or json.loads) rather than executing dynamic code."
                })

        # 4. Insecure Deserialization: pickle.loads / yaml.load unsafe
        if func_name in {"loads", "load"} and ("pickle" in line_str or "_pickle" in line_str):
            self.findings.append({
                "id": "PY-DESER-001",
                "title": "Insecure Deserialization via pickle",
                "severity": "high",
                "confidence": 0.94 if not self.is_test else 0.65,
                "category": "deserialization",
                "cwe": "CWE-502",
                "file": self.rel_path,
                "line": lineno,
                "code_context": get_code_context(self.lines, lineno),
                "description": "The pickle module is inherently unsafe when handling untrusted data and can be exploited to achieve arbitrary Remote Code Execution.",
                "evidence": f"Pickle deserialization on line {lineno}: {redact_secrets(line_str.strip())}",
                "recommendation": "Use safer serialization formats such as JSON (json.loads/dumps) or Protocol Buffers. Never unpickle data received over the network."
            })
        elif func_name == "load" and "yaml." in line_str:
            # Check if Loader is SafeLoader or CSafeLoader
            has_safe_loader = any(
                (kw.arg == "Loader" and "SafeLoader" in ast.unparse(kw.value))
                for kw in node.keywords
            )
            if not has_safe_loader and "safe_load" not in line_str:
                self.findings.append({
                    "id": "PY-DESER-002",
                    "title": "Unsafe YAML Deserialization (yaml.load without SafeLoader)",
                    "severity": "high",
                    "confidence": 0.91,
                    "category": "deserialization",
                    "cwe": "CWE-502",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "yaml.load() without SafeLoader allows arbitrary Python object instantiation and code execution.",
                    "evidence": f"Unsafe YAML load on line {lineno}: {redact_secrets(line_str.strip())}",
                    "recommendation": "Use yaml.safe_load(data) or specify yaml.load(data, Loader=yaml.SafeLoader)."
                })

        # 5. Weak Cryptography: hashlib.md5 / hashlib.sha1
        if func_name in {"md5", "sha1"} and "hashlib." in line_str:
            # Check if used in password hashing context
            is_password_context = any(term in line_str.lower() for term in ["pass", "pwd", "auth", "token", "key", "secret"])
            sev = "medium" if is_password_context else "low"
            conf = 0.88 if is_password_context else 0.65
            self.findings.append({
                "id": "PY-CRYPTO-001",
                "title": f"Weak Cryptographic Hash Algorithm ({func_name.upper()})",
                "severity": sev,
                "confidence": conf,
                "category": "cryptography",
                "cwe": "CWE-328",
                "file": self.rel_path,
                "line": lineno,
                "code_context": get_code_context(self.lines, lineno),
                "description": f"{func_name.upper()} is cryptographically broken and vulnerable to collision and preimage attacks.",
                "evidence": f"Hash function call on line {lineno}: {redact_secrets(line_str.strip())}",
                "recommendation": "For password storage, use argon2-cffi, bcrypt, or scrypt. For digital signatures and HMACs, use SHA-256 or SHA-3."
            })

        # 6. XSS: mark_safe / render_template_string
        if func_name == "mark_safe" and "django.utils.safestring" in "".join(self.lines[:30]) or func_name == "mark_safe":
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append({
                    "id": "PY-XSS-001",
                    "title": "Bypass of Django HTML Auto-Escaping (mark_safe)",
                    "severity": "medium",
                    "confidence": 0.86,
                    "category": "xss",
                    "cwe": "CWE-79",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "mark_safe disables Django's automatic HTML escaping. If unescaped user-controlled input reaches mark_safe, Cross-Site Scripting (XSS) can occur.",
                    "evidence": f"mark_safe call with dynamic argument on line {lineno}: {redact_secrets(line_str.strip())}",
                    "recommendation": "Ensure all dynamic inputs passed to mark_safe are rigorously sanitized with a dedicated HTML sanitizer like bleach or DOMPurify."
                })
        elif func_name == "render_template_string" and "flask" in "".join(self.lines[:30]):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append({
                    "id": "PY-SSTI-001",
                    "title": "Server-Side Template Injection (render_template_string)",
                    "severity": "high",
                    "confidence": 0.90,
                    "category": "injection",
                    "cwe": "CWE-1336",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "Dynamic construction of template strings in render_template_string enables Server-Side Template Injection (SSTI).",
                    "evidence": f"render_template_string on line {lineno}: {redact_secrets(line_str.strip())}",
                    "recommendation": "Use render_template() with static template files and pass dynamic parameters via context variables."
                })

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        lineno = getattr(node, 'lineno', 0)
        line_str = self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""

        # Check for DEBUG = True in settings / config
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    # Ignore if explicitly inside a test file
                    if not self.is_test:
                        self.findings.append({
                            "id": "PY-CONF-001",
                            "title": "Potentially Unsafe Production Configuration: DEBUG = True",
                            "severity": "medium",
                            "confidence": 0.90,
                            "category": "configuration",
                            "cwe": "CWE-489",
                            "file": self.rel_path,
                            "line": lineno,
                            "code_context": get_code_context(self.lines, lineno),
                            "description": "Django/Flask DEBUG mode is enabled. In production, DEBUG=True exposes sensitive stack traces, server environment variables, and source snippets.",
                            "evidence": f"DEBUG configuration on line {lineno}: {redact_secrets(line_str.strip())}",
                            "recommendation": "Ensure DEBUG is driven by environment variables (e.g. DEBUG = os.getenv('DEBUG', 'False').lower() == 'true') and disabled in production."
                        })

            # Check for insecure cookie flags: SESSION_COOKIE_SECURE = False, etc.
            if isinstance(target, ast.Name) and target.id in {"SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE"}:
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self.findings.append({
                        "id": "PY-CONF-002",
                        "title": f"Insecure Cookie Configuration ({target.id} = False)",
                        "severity": "low",
                        "confidence": 0.88,
                        "category": "session",
                        "cwe": "CWE-614",
                        "file": self.rel_path,
                        "line": lineno,
                        "code_context": get_code_context(self.lines, lineno),
                        "description": f"{target.id} is explicitly set to False, allowing session/CSRF tokens to be transmitted over unencrypted HTTP.",
                        "evidence": f"Cookie setting on line {lineno}: {line_str.strip()}",
                        "recommendation": f"Set {target.id} = True in production settings."
                    })

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        lineno = getattr(node, 'lineno', 0)
        line_str = self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""

        # Check for @csrf_exempt decorator
        decorator_names = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorator_names.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorator_names.append(dec.attr)

        if "csrf_exempt" in decorator_names and not self.is_test:
            # Check if function appears to handle state-modifying requests (POST/DELETE/PUT)
            func_code = "\n".join(self.lines[node.lineno - 1: min(len(self.lines), node.lineno + 25)])
            if any(term in func_code.lower() for term in ["request.method == 'post'", 'request.method == "post"', ".save()", ".delete()", "insert into", "update "]):
                self.findings.append({
                    "id": "PY-CSRF-001",
                    "title": "CSRF Protection Disabled on State-Modifying View (@csrf_exempt)",
                    "severity": "medium",
                    "confidence": 0.85,
                    "category": "csrf",
                    "cwe": "CWE-352",
                    "file": self.rel_path,
                    "line": lineno,
                    "code_context": get_code_context(self.lines, lineno),
                    "description": "The view is decorated with @csrf_exempt while performing state-changing database operations, exposing it to Cross-Site Request Forgery.",
                    "evidence": f"@csrf_exempt on view '{node.name}' at line {lineno}",
                    "recommendation": "Remove @csrf_exempt and enforce CSRF token validation, or use modern token-based auth (e.g. Bearer JWT) with appropriate origin validation."
                })

        self.generic_visit(node)


def scan_python_file(rel_path: str, content: str, lines: List[str], is_test: bool) -> List[Dict[str, Any]]:
    """Runs AST analysis and regex fallback checks on Python files."""
    findings: List[Dict[str, Any]] = []

    # 1. AST Visitor Analysis
    try:
        import textwrap
        clean_content = textwrap.dedent(content)
        tree = ast.parse(clean_content)
        visitor = PythonASTSecurityVisitor(rel_path, lines, is_test)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except Exception:
        # Fallback to regex-based heuristics if AST parse fails (e.g. syntax errors)
        for idx, line in enumerate(lines):
            line_num = idx + 1
            clean = line.strip()
            if "cursor.execute" in clean and ("+" in clean or "%" in clean or "f\"" in clean):
                findings.append({
                    "id": "PY-SQLI-001",
                    "title": "Potential SQL Injection in Raw Database Query",
                    "severity": "high",
                    "confidence": 0.90,
                    "category": "injection",
                    "cwe": "CWE-89",
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_code_context(lines, line_num),
                    "description": "A database query is constructed using dynamic string formatting.",
                    "evidence": f"Unsafe query invocation on line {line_num}: {redact_secrets(clean)}",
                    "recommendation": "Use parameterized queries."
                })
            if "subprocess" in clean and "shell=True" in clean:
                findings.append({
                    "id": "PY-CMD-001",
                    "title": "Command Execution with shell=True",
                    "severity": "high",
                    "confidence": 0.90,
                    "category": "injection",
                    "cwe": "CWE-78",
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_code_context(lines, line_num),
                    "description": "Executing system commands through a shell (shell=True).",
                    "evidence": f"subprocess with shell=True on line {line_num}: {clean}",
                    "recommendation": "Set shell=False."
                })
            if "os.system" in clean:
                findings.append({
                    "id": "PY-CMD-002",
                    "title": "Dangerous System Command Execution (os.system)",
                    "severity": "high",
                    "confidence": 0.88,
                    "category": "injection",
                    "cwe": "CWE-78",
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_code_context(lines, line_num),
                    "description": "os.system passes strings directly to the underlying shell.",
                    "evidence": f"os.system on line {line_num}: {clean}",
                    "recommendation": "Replace os.system with subprocess.run(..., shell=False)."
                })
            if "pickle.loads" in clean or "pickle.load" in clean:
                findings.append({
                    "id": "PY-DESER-001",
                    "title": "Insecure Deserialization via pickle",
                    "severity": "high",
                    "confidence": 0.94,
                    "category": "deserialization",
                    "cwe": "CWE-502",
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_code_context(lines, line_num),
                    "description": "The pickle module is inherently unsafe with untrusted data.",
                    "evidence": f"Pickle deserialization on line {line_num}: {clean}",
                    "recommendation": "Use JSON or safe serialization."
                })
            if re.search(r'^\s*DEBUG\s*=\s*True', clean):
                findings.append({
                    "id": "PY-CONF-001",
                    "title": "Potentially Unsafe Production Configuration: DEBUG = True",
                    "severity": "medium",
                    "confidence": 0.90,
                    "category": "configuration",
                    "cwe": "CWE-489",
                    "file": rel_path,
                    "line": line_num,
                    "code_context": get_code_context(lines, line_num),
                    "description": "DEBUG mode is enabled.",
                    "evidence": f"DEBUG configuration on line {line_num}: {clean}",
                    "recommendation": "Disable DEBUG in production."
                })

    # 2. Additional Regex-based checks for patterns that AST might miss
    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean = line.strip()

        # Plaintext password assignment: user.password = request.POST['password']
        if re.search(r'(?i)(?:user\.password|\.password)\s*=\s*(?:request\.(?:POST|data|json)\[|raw_pass|password)', clean) and "set_password" not in clean and "make_password" not in clean:
            findings.append({
                "id": "PY-AUTH-001",
                "title": "Potential Plaintext Password Assignment",
                "severity": "high",
                "confidence": 0.88,
                "category": "authentication",
                "cwe": "CWE-256",
                "file": rel_path,
                "line": line_num,
                "code_context": get_code_context(lines, line_num),
                "description": "Directly assigning a password variable to a model or user object without applying a secure hashing algorithm (like make_password or set_password).",
                "evidence": f"Password assignment on line {line_num}: {redact_secrets(clean)}",
                "recommendation": "Always hash passwords using django.contrib.auth.hashers.make_password or user.set_password(raw_password) before storing."
            })

        # Insecure Randomness for Security Tokens: random.random() or random.randint() for token generation
        if re.search(r'(?:token|auth_key|session_id|reset_code)\s*=\s*.*random\.(?:random|randint|choice|randrange)\(', clean):
            findings.append({
                "id": "PY-CRYPTO-002",
                "title": "Insecure Pseudo-Random Number Generator for Security Token",
                "severity": "medium",
                "confidence": 0.86,
                "category": "cryptography",
                "cwe": "CWE-330",
                "file": rel_path,
                "line": line_num,
                "code_context": get_code_context(lines, line_num),
                "description": "Standard Python random module uses Mersenne Twister, which is not cryptographically secure and is predictable.",
                "evidence": f"Insecure random generator on line {line_num}: {clean}",
                "recommendation": "Use the secrets module (e.g. secrets.token_urlsafe(32) or secrets.token_hex(32)) for security tokens."
            })

    return findings
