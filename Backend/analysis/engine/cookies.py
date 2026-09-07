"""
Cookie Security Analyzer
Parses and checks cookie security flags without leaking sensitive values.
"""
import re
from http.cookies import SimpleCookie
from typing import Dict, Any, List, Tuple
from .findings import Finding

SESSION_COOKIE_PATTERNS = [
    r"^sess",
    r"session",
    r"sid$",
    r"phpsessid",
    r"jsessionid",
    r"aspsessionid",
    r"asp\.net_sessionid",
    r"connect\.sid",
    r"laravel_session",
    r"auth",
    r"jwt",
    r"token",
    r"csrftoken",
    r"xsrf-token",
    r"identity",
    r"user_id",
    r"remember_token",
    r"logged_in",
]


def is_session_cookie(cookie_name: str) -> bool:
    """Safely checks if cookie name corresponds to a probable session or security token."""
    name_lower = cookie_name.lower()
    for pattern in SESSION_COOKIE_PATTERNS:
        if re.search(pattern, name_lower):
            return True
    return False


def parse_raw_cookie_header(header_value: str) -> Dict[str, Any]:
    """
    Parses a single Set-Cookie string into metadata without exposing value.
    """
    # Set-Cookie format: name=val; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=...
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    if not parts:
        return {}

    first_part = parts[0]
    if "=" in first_part:
        name = first_part.split("=")[0].strip()
    else:
        name = first_part

    metadata: Dict[str, Any] = {
        "name": name,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "max_age": None,
        "expires": None,
        "is_session_indicator": is_session_cookie(name)
    }

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "secure":
            metadata["secure"] = True
        elif attr_lower == "httponly":
            metadata["httponly"] = True
        elif attr_lower.startswith("samesite="):
            metadata["samesite"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            metadata["domain"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            metadata["path"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            metadata["max_age"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("expires="):
            metadata["expires"] = attr.split("=", 1)[1].strip()

    return metadata


def analyze_cookies(
    raw_cookie_headers: List[str],
    is_https: bool = True
) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    """
    Analyzes cookies from Set-Cookie headers.
    """
    cookies_metadata: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-CK-{finding_counter:03d}"
        finding_counter += 1
        return fid

    for raw in raw_cookie_headers:
        if not raw:
            continue
        cookie_meta = parse_raw_cookie_header(raw)
        if not cookie_meta or not cookie_meta.get("name"):
            continue

        cookies_metadata.append(cookie_meta)
        c_name = cookie_meta["name"]
        is_session = cookie_meta["is_session_indicator"]

        # Check 1: Missing Secure on HTTPS
        if is_https and not cookie_meta["secure"]:
            severity = "medium" if is_session else "low"
            findings.append(Finding(
                id=next_id(),
                title=f"Cookie '{c_name}' Missing 'Secure' Attribute",
                category="cookies",
                severity=severity,
                confidence=0.99,
                description=f"The cookie '{c_name}' was set over HTTPS without the 'Secure' flag. It may be transmitted in plaintext if the user accesses an HTTP URL on the same domain.",
                evidence={
                    "cookie_name": c_name,
                    "secure": False,
                    "is_session_indicator": is_session
                },
                recommendation=f"Add the 'Secure' flag to the Set-Cookie header for '{c_name}'."
            ))

        # Check 2: Missing HttpOnly on Session/Auth cookie
        if not cookie_meta["httponly"] and is_session:
            findings.append(Finding(
                id=next_id(),
                title=f"Session Cookie '{c_name}' Missing 'HttpOnly' Attribute",
                category="cookies",
                severity="medium",
                confidence=0.90,
                description=f"The cookie '{c_name}' appears to be a session or authentication token, but lacks the 'HttpOnly' flag. It can be read by JavaScript via document.cookie, increasing risk in the event of XSS.",
                evidence={
                    "cookie_name": c_name,
                    "httponly": False,
                    "is_session_indicator": True
                },
                recommendation=f"Set 'HttpOnly' on '{c_name}' to prevent client-side script access."
            ))

        # Check 3: Missing or Insecure SameSite attribute
        samesite = cookie_meta.get("samesite")
        if not samesite:
            findings.append(Finding(
                id=next_id(),
                title=f"Cookie '{c_name}' Missing 'SameSite' Attribute",
                category="cookies",
                severity="low",
                confidence=0.95,
                description=f"The cookie '{c_name}' does not specify a 'SameSite' attribute. Setting SameSite=Lax or SameSite=Strict helps defend against Cross-Site Request Forgery (CSRF).",
                evidence={
                    "cookie_name": c_name,
                    "samesite": None
                },
                recommendation=f"Configure 'SameSite=Lax' (or 'SameSite=Strict') on cookie '{c_name}'."
            ))
        elif samesite.lower() == "none" and not cookie_meta["secure"]:
            findings.append(Finding(
                id=next_id(),
                title=f"Cookie '{c_name}' Has SameSite=None Without Secure",
                category="cookies",
                severity="medium",
                confidence=0.99,
                description=f"Cookie '{c_name}' has SameSite=None but is missing the Secure attribute. Modern browsers reject SameSite=None cookies unless Secure is enabled.",
                evidence={
                    "cookie_name": c_name,
                    "samesite": samesite,
                    "secure": False
                },
                recommendation=f"Add 'Secure' whenever using 'SameSite=None'."
            ))

    return cookies_metadata, findings
