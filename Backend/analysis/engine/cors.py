"""
CORS & Cross-Origin Security Analyzer
"""
from typing import Dict, Any, List, Tuple
from .findings import Finding


def analyze_cors_configuration(
    headers: Dict[str, str]
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Analyzes CORS configuration from observed response headers safely.
    """
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-CORS-{finding_counter:03d}"
        finding_counter += 1
        return fid

    norm_headers = {k.lower(): v.strip() for k, v in headers.items()}

    allow_origin = norm_headers.get("access-control-allow-origin")
    allow_credentials = norm_headers.get("access-control-allow-credentials")
    allow_methods = norm_headers.get("access-control-allow-methods")
    allow_headers = norm_headers.get("access-control-allow-headers")
    expose_headers = norm_headers.get("access-control-expose-headers")
    max_age = norm_headers.get("access-control-max-age")

    is_credentials_true = allow_credentials is not None and allow_credentials.lower() == "true"

    cors_detail = {
        "configured": bool(allow_origin or allow_credentials or allow_methods),
        "allow_origin": allow_origin,
        "allow_credentials": is_credentials_true if allow_credentials else None,
        "allow_methods": [m.strip().upper() for m in allow_methods.split(",")] if allow_methods else [],
        "allow_headers": [h.strip() for h in allow_headers.split(",")] if allow_headers else [],
        "expose_headers": [h.strip() for h in expose_headers.split(",")] if expose_headers else [],
        "max_age": int(max_age) if max_age and max_age.isdigit() else None,
        "risk_level": "none"
    }

    if allow_origin:
        if allow_origin == "*" and is_credentials_true:
            # Dangerous CORS combination (invalid in spec and insecure if improperly reflected)
            cors_detail["risk_level"] = "high"
            findings.append(Finding(
                id=next_id(),
                title="Insecure CORS: Wildcard Origin With Credentials Allowed",
                category="cors",
                severity="high",
                confidence=0.99,
                description="Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true. This configuration permits arbitrary external websites to read authenticated responses if the browser allows it.",
                evidence={
                    "access_control_allow_origin": allow_origin,
                    "access_control_allow_credentials": allow_credentials
                },
                recommendation="Do not use wildcard '*' when credentials are enabled. Validate Origin headers against a strict whitelist of trusted domains."
            ))
        elif allow_origin == "null":
            cors_detail["risk_level"] = "medium"
            findings.append(Finding(
                id=next_id(),
                title="CORS Allows 'null' Origin",
                category="cors",
                severity="medium",
                confidence=0.95,
                description="Access-Control-Allow-Origin is set to 'null'. Sandboxed iframes and local file schemes execute with a 'null' origin and could access resource data.",
                evidence={
                    "access_control_allow_origin": "null"
                },
                recommendation="Remove 'null' from allowed origins and explicitly specify authorized domain names."
            ))
        elif allow_origin == "*":
            cors_detail["risk_level"] = "info"
            findings.append(Finding(
                id=next_id(),
                title="Wildcard CORS Origin Observed (Access-Control-Allow-Origin: *)",
                category="cors",
                severity="info",
                confidence=0.95,
                description="The resource permits cross-origin requests from any origin (*). This is typical for public APIs and assets, but ensure no sensitive or session-tied data is returned.",
                evidence={
                    "access_control_allow_origin": "*",
                    "credentials_allowed": is_credentials_true
                },
                recommendation="If this endpoint returns confidential user data, replace wildcard '*' with specific trusted origins."
            ))

    return cors_detail, findings
