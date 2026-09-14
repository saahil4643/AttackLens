"""
Lightweight Taint Analysis Engine for AttackLens SAST

Tracks user-controlled untrusted input sources into sensitive execution sinks:
- Sources: HTTP query parameters, path params, form data, JSON bodies, headers, cookies, uploaded files
- Propagations: Variable assignments, string concatenations, format strings, f-strings
- Sinks: SQL query execution, command execution, filesystem access, outbound HTTP (SSRF), HTML output (XSS), deserialization

Constructs deterministic SOURCE -> FLOW -> SINK traces for high-fidelity reporting.
"""

import ast
import re
from typing import List, Dict, Any, Optional, Set, Tuple


# Regex patterns matching common untrusted input sources across languages
SOURCE_PATTERNS = [
    # Python / Django / Flask / FastAPI
    r'request\.(?:GET|POST|data|params|values|json|args|headers|COOKIES|FILES)(?:\[|\.get\()',
    r'request\.(?:query_params|body|form)(?:\[|\.get\()',
    r'(?:request_data|req_data|payload)\s*=\s*request\.',
    # Node / Express
    r'req\.(?:query|params|body|headers|cookies|files)(?:\.|\b|\[)',
    r'request\.(?:query|params|body|headers)(?:\.|\b|\[)',
    # Java Spring / Servlets
    r'@RequestParam\b',
    r'@PathVariable\b',
    r'@RequestBody\b',
    r'request\.getParameter\(',
    r'request\.getHeader\(',
    # PHP
    r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b',
    # C# ASP.NET
    r'\[FromQuery\]|\[FromBody\]|\[FromRoute\]|Request\.Query\[',
    # Go
    r'c\.(?:Query|Param|PostForm|GetHeader|BindJSON)\(',
    r'r\.URL\.Query\(\)'
]

SOURCE_REGEX = re.compile("|".join(SOURCE_PATTERNS), re.IGNORECASE)


class PythonTaintVisitor(ast.NodeVisitor):
    """
    AST-based Python taint flow tracker.
    Tracks variables assigned from request input and identifies if they reach known sinks.
    """

    def __init__(self, raw_lines: List[str]):
        self.raw_lines = raw_lines
        self.tainted_vars: Dict[str, Dict[str, Any]] = {}  # var_name -> source_info
        self.detected_flows: List[Dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign):
        # Check if right-hand-side expression uses request or an already tainted variable
        code_str = ""
        if hasattr(node, 'lineno') and node.lineno <= len(self.raw_lines):
            code_str = self.raw_lines[node.lineno - 1].strip()

        # 1. Direct source assignment: x = request.GET.get('id')
        if SOURCE_REGEX.search(code_str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = {
                        "source_line": node.lineno,
                        "source_code": code_str,
                        "source_var": target.id,
                        "history": [{"step": "SOURCE", "line": node.lineno, "code": code_str}]
                    }

        # 2. Propagation assignment: q = "SELECT * FROM users WHERE id=" + x
        else:
            for t_var, t_info in list(self.tainted_vars.items()):
                # Check if t_var is mentioned in assignment RHS
                if re.search(r'\b' + re.escape(t_var) + r'\b', code_str):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id != t_var:
                            new_history = list(t_info["history"])
                            new_history.append({
                                "step": "FLOW",
                                "line": node.lineno,
                                "code": code_str
                            })
                            self.tainted_vars[target.id] = {
                                "source_line": t_info["source_line"],
                                "source_code": t_info["source_code"],
                                "source_var": t_var,
                                "history": new_history
                            }

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check if call is a known sink receiving a tainted variable
        call_name = ""
        if isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            call_name = node.func.id

        lineno = getattr(node, 'lineno', 0)
        line_code = self.raw_lines[lineno - 1].strip() if lineno > 0 and lineno <= len(self.raw_lines) else ""

        # Check for arguments matching tainted vars
        for t_var, t_info in self.tainted_vars.items():
            if re.search(r'\b' + re.escape(t_var) + r'\b', line_code):
                # Identify sink type
                sink_type = None
                cwe = None
                category = "injection"

                # SQL Sinks: execute, raw, rawQuery, select
                if call_name in {"execute", "executemany", "raw"} or "cursor.execute" in line_code:
                    sink_type = "SQL Execution"
                    cwe = "CWE-89"
                    category = "injection"

                # Command execution Sinks: system, popen, run, call, check_output
                elif call_name in {"system", "popen", "run", "call", "check_output", "exec", "eval"} or "subprocess" in line_code or "os.system" in line_code:
                    sink_type = "Command Execution"
                    cwe = "CWE-78"
                    category = "injection"

                # Path traversal Sinks: open, read, send_file, FileResponse
                elif call_name in {"open", "send_file", "FileResponse", "read_file"} or "os.path.join" in line_code:
                    sink_type = "Filesystem Access"
                    cwe = "CWE-22"
                    category = "file_handling"

                # SSRF Sinks: get, post, put, request, urlopen
                elif call_name in {"get", "post", "put", "delete", "request", "urlopen"} and any(mod in line_code for mod in ["requests.", "urllib.", "http.client", "httpx."]):
                    sink_type = "Outbound HTTP Request (SSRF)"
                    cwe = "CWE-918"
                    category = "ssrf"

                # Deserialization Sinks: loads, load, yaml.load
                elif call_name in {"loads", "load"} and ("pickle" in line_code or "yaml" in line_code or "marshal" in line_code):
                    sink_type = "Insecure Deserialization"
                    cwe = "CWE-502"
                    category = "deserialization"

                if sink_type:
                    flow = list(t_info["history"])
                    flow.append({
                        "step": "SINK",
                        "line": lineno,
                        "code": line_code
                    })

                    self.detected_flows.append({
                        "sink_type": sink_type,
                        "sink_name": call_name,
                        "sink_line": lineno,
                        "sink_code": line_code,
                        "source_var": t_var,
                        "source_line": t_info["source_line"],
                        "source_code": t_info["source_code"],
                        "cwe": cwe,
                        "category": category,
                        "flow": flow
                    })

        self.generic_visit(node)


def analyze_python_taint(source_code: str) -> List[Dict[str, Any]]:
    """
    Parses Python source code with AST and executes taint tracking.
    """
    lines = source_code.splitlines()
    try:
        tree = ast.parse(source_code)
        visitor = PythonTaintVisitor(lines)
        visitor.visit(tree)
        return visitor.detected_flows
    except SyntaxError:
        # If file has python syntax error, fallback to regex flow tracing
        return trace_regex_taint(source_code, lines, lang="python")
    except Exception:
        return []


def trace_regex_taint(source_code: str, lines: List[str], lang: str = "generic") -> List[Dict[str, Any]]:
    """
    Lightweight heuristic taint tracer for JS, Java, PHP, Go, C# and fallback Python.
    """
    tainted_vars: Dict[str, Dict[str, Any]] = {}
    detected_flows: List[Dict[str, Any]] = []

    # Common assignment patterns across languages: const x = req.query.id; or $id = $_GET['id']; or String id = request.getParameter("id");
    assign_patterns = [
        # JS/TS: (const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(.*)
        re.compile(r'(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(.*)'),
        # PHP: \$([a-zA-Z0-9_]+)\s*=\s*(.*)
        re.compile(r'\$([a-zA-Z0-9_]+)\s*=\s*(.*)'),
        # Java / C#: (?:String|var|int|Object)\s+([a-zA-Z0-9_]+)\s*=\s*(.*)
        re.compile(r'(?:String|var|int|Object|auto)\s+([a-zA-Z0-9_]+)\s*=\s*(.*)'),
        # Generic: ([a-zA-Z0-9_]+)\s*=\s*(.*)
        re.compile(r'^\s*([a-zA-Z0-9_]+)\s*=\s*(.*)')
    ]

    for idx, line in enumerate(lines):
        line_num = idx + 1
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
            continue

        # 1. Check for untrusted source on this line
        if SOURCE_REGEX.search(clean_line):
            for ap in assign_patterns:
                m = ap.search(clean_line)
                if m:
                    var_name = m.group(1)
                    tainted_vars[var_name] = {
                        "source_line": line_num,
                        "source_code": clean_line,
                        "history": [{"step": "SOURCE", "line": line_num, "code": clean_line}]
                    }
                    break

        # 2. Check for propagation: new_var = "..." + tainted_var
        for t_var, t_info in list(tainted_vars.items()):
            if re.search(r'\b' + re.escape(t_var) + r'\b', clean_line):
                for ap in assign_patterns:
                    m = ap.search(clean_line)
                    if m and m.group(1) != t_var:
                        new_var = m.group(1)
                        new_hist = list(t_info["history"])
                        new_hist.append({"step": "FLOW", "line": line_num, "code": clean_line})
                        tainted_vars[new_var] = {
                            "source_line": t_info["source_line"],
                            "source_code": t_info["source_code"],
                            "history": new_hist
                        }

        # 3. Check for sinks
        for t_var, t_info in tainted_vars.items():
            if re.search(r'\b' + re.escape(t_var) + r'\b', clean_line):
                sink_type = None
                cwe = None
                category = "injection"

                # SQL Sink
                if re.search(r'(?:connection\.query|db\.query|statement\.executeQuery|stmt\.execute|\$conn->query|cursor\.execute|DB::raw)\(', clean_line, re.IGNORECASE):
                    sink_type = "SQL Execution"
                    cwe = "CWE-89"
                    category = "injection"

                # Command Injection Sink
                elif re.search(r'(?:child_process\.exec|execSync|Runtime\.getRuntime\(\)\.exec|shell_exec|system\(|passthru\(|exec\()\b', clean_line):
                    sink_type = "Command Execution"
                    cwe = "CWE-78"
                    category = "injection"

                # Path Traversal Sink
                elif re.search(r'(?:fs\.readFile|fs\.createReadStream|FileInputStream|file_get_contents|readfile)\(', clean_line):
                    sink_type = "Filesystem Access"
                    cwe = "CWE-22"
                    category = "file_handling"

                # SSRF Sink
                elif re.search(r'(?:axios\.(?:get|post)|fetch\(|HttpClient|curl_exec)\(', clean_line):
                    sink_type = "Outbound HTTP Request (SSRF)"
                    cwe = "CWE-918"
                    category = "ssrf"

                # XSS Sink
                elif re.search(r'(?:innerHTML|dangerouslySetInnerHTML|document\.write|res\.send\()', clean_line):
                    sink_type = "Unsafe HTML Output (XSS)"
                    cwe = "CWE-79"
                    category = "xss"

                if sink_type:
                    flow = list(t_info["history"])
                    flow.append({"step": "SINK", "line": line_num, "code": clean_line})
                    detected_flows.append({
                        "sink_type": sink_type,
                        "sink_name": sink_type,
                        "sink_line": line_num,
                        "sink_code": clean_line,
                        "source_var": t_var,
                        "source_line": t_info["source_line"],
                        "source_code": t_info["source_code"],
                        "cwe": cwe,
                        "category": category,
                        "flow": flow
                    })

    return detected_flows
