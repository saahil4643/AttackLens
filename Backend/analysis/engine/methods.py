"""
Safe HTTP Methods Inspector
Uses non-destructive OPTIONS requests and Allow headers only.
"""
from typing import Dict, Any, List, Tuple
import requests
from .findings import Finding


def check_safe_http_methods(
    target_url: str,
    timeout: float = 4.0
) -> Tuple[List[str], Dict[str, Any], List[Finding]]:
    """
    Safely probes for supported HTTP methods using an OPTIONS request.
    Does NOT execute destructive methods (DELETE, PUT, PATCH).
    """
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-MTH-{finding_counter:03d}"
        finding_counter += 1
        return fid

    allowed_methods: List[str] = []
    raw_allow_header = None
    cors_methods_header = None

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens/1.0"
        })
        resp = session.options(target_url, timeout=timeout, allow_redirects=True, verify=False)
        
        # Check standard Allow header
        raw_allow_header = resp.headers.get("Allow") or resp.headers.get("allow")
        cors_methods_header = resp.headers.get("Access-Control-Allow-Methods")

        methods_set = set()
        if raw_allow_header:
            for m in raw_allow_header.split(","):
                m_clean = m.strip().upper()
                if m_clean:
                    methods_set.add(m_clean)

        if cors_methods_header:
            for m in cors_methods_header.split(","):
                m_clean = m.strip().upper()
                if m_clean:
                    methods_set.add(m_clean)

        allowed_methods = sorted(list(methods_set))

        # Check for potentially risky/unnecessary methods announced
        if "TRACE" in allowed_methods or "TRACK" in allowed_methods:
            findings.append(Finding(
                id=next_id(),
                title="HTTP TRACE / TRACK Method Enabled",
                category="http_methods",
                severity="low",
                confidence=0.95,
                description="The server reports support for HTTP TRACE or TRACK methods, which can be leveraged in Cross-Site Tracing (XST) attacks to steal cookies.",
                evidence={
                    "allowed_methods": allowed_methods,
                    "risky_methods": [m for m in allowed_methods if m in ("TRACE", "TRACK")]
                },
                recommendation="Disable HTTP TRACE and TRACK methods on the web server configuration."
            ))

        dav_methods = [m for m in allowed_methods if m in ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")]
        if dav_methods:
            findings.append(Finding(
                id=next_id(),
                title="WebDAV Methods Announced in Allow Header",
                category="http_methods",
                severity="low",
                confidence=0.90,
                description=f"The server announced WebDAV methods ({', '.join(dav_methods)}) in response to OPTIONS.",
                evidence={"webdav_methods": dav_methods},
                recommendation="Disable unused WebDAV extensions unless strictly required."
            ))

    except Exception:
        # OPTIONS request failed or blocked
        allowed_methods = ["GET", "HEAD"]  # Standard baseline assumptions

    methods_detail = {
        "methods": allowed_methods,
        "allow_header": raw_allow_header,
        "cors_methods_header": cors_methods_header
    }

    return allowed_methods, methods_detail, findings
