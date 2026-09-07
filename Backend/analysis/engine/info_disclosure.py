"""
Information Disclosure Headers Analyzer
"""
from typing import Dict, Any, List, Tuple
from .findings import Finding

DISCLOSURE_HEADERS = [
    ("server", "Server", "Web Server Banner"),
    ("x-powered-by", "X-Powered-By", "Framework / Platform Indicator"),
    ("x-aspnet-version", "X-AspNet-Version", "ASP.NET Runtime Version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version", "ASP.NET MVC Version"),
    ("x-generator", "X-Generator", "CMS / Tool Generator"),
    ("x-runtime", "X-Runtime", "Application Execution Runtime"),
    ("via", "Via", "Proxy / Gateway Header"),
    ("x-backend-server", "X-Backend-Server", "Internal Backend Identifier"),
]


def analyze_information_disclosure(
    headers: Dict[str, str]
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Checks for technology and version leakage in response headers.
    """
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-INF-{finding_counter:03d}"
        finding_counter += 1
        return fid

    norm_headers = {k.lower(): v.strip() for k, v in headers.items()}
    disclosed_headers: Dict[str, str] = {}

    for lower_key, canonical_name, desc in DISCLOSURE_HEADERS:
        if lower_key in norm_headers:
            val = norm_headers[lower_key]
            disclosed_headers[canonical_name] = val

            # Check if version number is disclosed
            has_version = any(char.isdigit() for char in val)
            severity = "low" if has_version else "info"

            findings.append(Finding(
                id=next_id(),
                title=f"Information Disclosure: '{canonical_name}' Header Exposed",
                category="information_disclosure",
                severity=severity,
                confidence=0.99,
                description=f"The server returns the '{canonical_name}' header with value '{val}'. This discloses {desc} details to prospective attackers.",
                evidence={
                    "header": canonical_name,
                    "observed_value": val,
                    "has_version_number": has_version
                },
                recommendation=f"Configure the web server / application gateway to suppress or obfuscate the '{canonical_name}' header."
            ))

    return disclosed_headers, findings
