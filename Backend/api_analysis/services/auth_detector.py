"""
Authentication Requirement Detector & Redaction Service
"""
import re
from typing import Dict, Any, List, Tuple
from .models import ApiAuthIndicator, ApiFinding


def analyze_auth_from_response(
    status_code: int,
    headers: Dict[str, str],
    endpoint_url: str
) -> Tuple[ApiAuthIndicator, List[ApiFinding]]:
    """
    Analyzes HTTP response headers and status codes for authentication requirements.
    """
    findings: List[ApiFinding] = []
    norm_headers = {k.lower(): v.strip() for k, v in headers.items()}
    
    required = False
    auth_type = "none"
    evidence_list: List[str] = []
    scheme_name = None

    # Check 1: 401 Unauthorized with WWW-Authenticate header
    if status_code == 401:
        required = True
        evidence_list.append("HTTP 401 Unauthorized challenge received")
        www_auth = norm_headers.get("www-authenticate", "")
        if www_auth:
            evidence_list.append(f"WWW-Authenticate: {www_auth.split()[0]}")
            www_lower = www_auth.lower()
            if "bearer" in www_lower:
                auth_type = "bearer"
                scheme_name = "Bearer JWT / Token"
            elif "basic" in www_lower:
                auth_type = "basic"
                scheme_name = "HTTP Basic Authentication"
            elif "digest" in www_lower:
                auth_type = "digest"
                scheme_name = "HTTP Digest Authentication"
            elif "apikey" in www_lower or "api_key" in www_lower:
                auth_type = "api_key"
                scheme_name = "API Key Scheme"
            else:
                auth_type = "custom"
                scheme_name = www_auth.split()[0]
        else:
            auth_type = "unknown"

    # Check 2: 403 Forbidden
    elif status_code == 403:
        required = True
        auth_type = "restricted"
        evidence_list.append("HTTP 403 Forbidden response (Access restricted or credentials required)")

    # Check 3: OAuth / OIDC Path Indicators
    url_lower = endpoint_url.lower()
    if any(p in url_lower for p in ("/oauth/token", "/oauth2/token", "/auth/login", "/api/auth/token")):
        auth_type = "oauth2"
        scheme_name = "OAuth 2.0 / Token Exchange"
        evidence_list.append("OAuth2 / Token Endpoint signature in URI path")

    indicator = ApiAuthIndicator(
        required=required,
        auth_type=auth_type,
        evidence=evidence_list,
        scheme_name=scheme_name
    )

    return indicator, findings
