"""
Authentication and Session Surface Analysis Engine.
"""
import re
from typing import List, Dict, Any, Set
from .models import AuthSurfaceRecord, SessionSurfaceRecord


KNOWN_SESSION_COOKIE_NAMES = {
    "sessionid", "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid",
    "laravel_session", "rack.session", "auth_token", "jwt", "access_token",
    "refresh_token", "id_token", "remember_me", "authtoken", "session", "sid",
    "user_session", "session_id", "csrftoken", "_csrf"
}


def build_authentication_surface(
    endpoints: List[Dict[str, Any]],
    forms: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
) -> List[AuthSurfaceRecord]:
    """
    Extracts and correlates all authentication surface entry points from endpoints,
    HTML forms, and API endpoints.
    """
    auth_records: List[AuthSurfaceRecord] = []
    seen_endpoints: Set[str] = set()

    # 1. Inspect forms for login / registration
    for form in forms:
        action = form.get("action") or "/"
        classification = form.get("classification") or ""
        method = form.get("method", "POST").upper()
        if classification in ("login", "registration", "password"):
            sig = f"{method}:{action}"
            if sig not in seen_endpoints:
                seen_endpoints.add(sig)
                evidence = [f"HTML {classification.upper()} form with inputs: {', '.join(form.get('input_names', [])[:4])}"]
                auth_type = "login" if classification == "login" else ("registration" if classification == "registration" else "password_reset")
                auth_records.append(AuthSurfaceRecord(
                    endpoint=action,
                    type=auth_type,
                    method=method,
                    source="form",
                    confidence=0.96,
                    evidence=evidence
                ))

    # 2. Inspect discovered URLs/endpoints
    for ep in endpoints:
        path = ep.get("path") or ep.get("url") or ""
        path_lower = path.lower()
        method = ep.get("method", "GET").upper()

        auth_match_type = None
        if re.search(r"/(?:login|signin)(?:/|$|\?)", path_lower):
            auth_match_type = "login"
        elif re.search(r"/(?:logout|signout)(?:/|$|\?)", path_lower):
            auth_match_type = "logout"
        elif re.search(r"/(?:register|signup)(?:/|$|\?)", path_lower):
            auth_match_type = "registration"
        elif re.search(r"/(?:forgot-password|reset-password)(?:/|$|\?)", path_lower):
            auth_match_type = "password_reset"
        elif re.search(r"/(?:oauth|authorize|token)(?:/|$|\?)", path_lower):
            auth_match_type = "oauth"
        elif re.search(r"/(?:sso|2fa|verify)(?:/|$|\?)", path_lower):
            auth_match_type = "sso"
        elif re.search(r"/auth(?:/|$)", path_lower):
            auth_match_type = "login"

        if auth_match_type:
            sig = f"{method}:{path}"
            if sig not in seen_endpoints:
                seen_endpoints.add(sig)
                auth_records.append(AuthSurfaceRecord(
                    endpoint=path,
                    type=auth_match_type,
                    method=method,
                    source=ep.get("source", "crawler"),
                    confidence=0.90,
                    evidence=[f"URL path pattern matches authentication route ({auth_match_type})"]
                ))

    # 3. Inspect API endpoints with auth indicators
    for api_ep in api_endpoints:
        path = api_ep.get("path") or api_ep.get("endpoint") or ""
        method = api_ep.get("method", "GET").upper()
        auth_info = api_ep.get("authentication") or {}
        
        is_token_route = bool(re.search(r"/(?:auth|token|login|session|oauth)", path.lower()))
        if is_token_route or auth_info.get("required"):
            sig = f"{method}:{path}"
            if sig not in seen_endpoints:
                seen_endpoints.add(sig)
                auth_type = "token" if is_token_route else "api_auth"
                evidence = []
                if auth_info.get("type"):
                    evidence.append(f"Requires {auth_info['type'].upper()} authentication")
                if is_token_route:
                    evidence.append("API path indicates authentication/token management")

                auth_records.append(AuthSurfaceRecord(
                    endpoint=path,
                    type=auth_type,
                    method=method,
                    source="api_analysis",
                    confidence=0.95,
                    evidence=evidence or ["API authentication mechanism observed"]
                ))

    return auth_records


def build_session_surface(cookie_records: List[Dict[str, Any]]) -> List[SessionSurfaceRecord]:
    """
    Analyzes cookies to identify session identifiers and security flags.
    Never stores or returns raw cookie values.
    """
    session_records: List[SessionSurfaceRecord] = []
    seen_cookie_names: Set[str] = set()

    for c in cookie_records:
        name = c.get("name") or c.get("cookie_name") or ""
        if not name:
            continue
        clean_name = name.strip()
        if clean_name.lower() in seen_cookie_names:
            continue
        seen_cookie_names.add(clean_name.lower())

        is_session = clean_name.lower() in KNOWN_SESSION_COOKIE_NAMES or any(
            sub in clean_name.lower() for sub in ("sess", "auth", "token", "jwt", "login")
        )

        session_records.append(SessionSurfaceRecord(
            cookie_name=clean_name,
            is_secure=bool(c.get("is_secure") or c.get("secure", False)),
            is_httponly=bool(c.get("is_httponly") or c.get("httponly", False)),
            same_site=c.get("same_site") or c.get("samesite") or "None",
            domain=c.get("domain"),
            path=c.get("path") or "/",
            likely_session_indicator=is_session
        ))

    return session_records
