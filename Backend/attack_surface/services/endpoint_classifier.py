"""
Endpoint and Form Classification Engine for Web Application Attack-Surface Analysis.
"""
import re
import urllib.parse
from typing import Dict, Any, Tuple, List


# Regex patterns for endpoint classification
API_REGEX = re.compile(r"/(?:api(?:/v\d+)?|rest|graphql|rpc|json|v\d+)/", re.IGNORECASE)
AUTH_REGEX = re.compile(
    r"/(?:login|signin|logout|signout|register|signup|forgot-password|reset-password|verify|oauth|authorize|token|sso|2fa|auth(?:/|$))",
    re.IGNORECASE
)
ADMIN_REGEX = re.compile(
    r"/(?:admin(?:istrator)?|manage(?:ment)?|dashboard|control-panel|cpanel|sysadmin|master-control)(?:/|$|\?)",
    re.IGNORECASE
)
UPLOAD_REGEX = re.compile(
    r"/(?:upload|file-upload|uploader|import|attachments?|media/upload|assets/upload)(?:/|$|\?)",
    re.IGNORECASE
)
DOCS_REGEX = re.compile(
    r"/(?:swagger(?:-ui)?(?:\.json|\.yaml)?|openapi(?:\.json|\.yaml)?|api-docs|docs|redoc|schema(?:\.json|\.yaml)?)(?:/|$|\?)",
    re.IGNORECASE
)
HEALTH_REGEX = re.compile(
    r"/(?:healthz?|status|metrics|ready(?:ness)?|liveness|ping|live)(?:/|$|\?)",
    re.IGNORECASE
)
STATIC_EXT_REGEX = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|otf|map|pdf|mp4|webm)(?:\?.*)?$",
    re.IGNORECASE
)


def classify_endpoint(raw_url_or_path: str, content_type: str = "", source: str = "crawler") -> Tuple[str, float]:
    """
    Classifies an endpoint path/URL into an attack surface category and assigns confidence.
    Categories: page | api | authentication | administrative | static | upload | documentation | health | unknown
    """
    path = raw_url_or_path or "/"
    try:
        if "://" in raw_url_or_path:
            parsed = urllib.parse.urlparse(raw_url_or_path)
            path = parsed.path or "/"
    except Exception:
        path = raw_url_or_path or "/"

    if not path.startswith("/"):
        path = "/" + path

    path_lower = path.lower()
    ct_lower = (content_type or "").lower()

    if STATIC_EXT_REGEX.search(path_lower):
        return "static", 0.99

    if DOCS_REGEX.search(path_lower) or source == "openapi":
        return "documentation", 0.95

    if AUTH_REGEX.search(path_lower):
        return "authentication", 0.92

    if ADMIN_REGEX.search(path_lower):
        return "administrative", 0.88

    if UPLOAD_REGEX.search(path_lower):
        return "upload", 0.90

    if HEALTH_REGEX.search(path_lower):
        return "health", 0.90

    if API_REGEX.search(path_lower) or "application/json" in ct_lower or "application/graphql" in ct_lower:
        return "api", 0.94

    if "text/html" in ct_lower or path.endswith((".html", ".htm", "/")) or not "." in path.split("/")[-1]:
        return "page", 0.85

    return "unknown", 0.50


def classify_form(action: str, method: str, input_names: List[str], input_types: List[str]) -> Tuple[str, float]:
    """
    Classifies an HTML form into a functional category based on field names, input types, and action URL.
    Categories: login | registration | search | contact | upload | password | feedback | unknown
    """
    types_lower = [t.lower() for t in input_types]
    names_lower = [n.lower() for n in input_names]
    action_lower = action.lower()

    # File upload form
    if "file" in types_lower or UPLOAD_REGEX.search(action_lower):
        return "upload", 0.98

    # Password management / reset
    has_curr_pw = any("current" in n or "old" in n for n in names_lower) and "password" in types_lower
    has_confirm_pw = any("confirm" in n or "retype" in n or "repeat" in n for n in names_lower) and "password" in types_lower
    if "reset-password" in action_lower or "forgot-password" in action_lower:
        return "password", 0.94
    if has_curr_pw and has_confirm_pw:
        return "password", 0.92

    # Login vs Registration
    has_password = "password" in types_lower or any("pass" in n or "pwd" in n for n in names_lower)
    has_user_identifier = any(
        n in ("user", "username", "email", "login", "identifier", "account", "user_id")
        for n in names_lower
    )

    if has_password and has_user_identifier:
        # Check registration indicators
        if "register" in action_lower or "signup" in action_lower or "create-account" in action_lower:
            return "registration", 0.95
        if has_confirm_pw or any("first_name" in n or "fname" in n or "phone" in n for n in names_lower):
            return "registration", 0.90
        # If small field count and login/signin/auth keywords
        if len(input_names) <= 5:
            return "login", 0.94

    # Search form
    if any(n in ("q", "query", "search", "keyword", "keywords", "s", "term") for n in names_lower):
        return "search", 0.95
    if "search" in action_lower:
        return "search", 0.88

    # Contact / Feedback
    has_message = any("message" in n or "comment" in n or "body" in n or "feedback" in n for n in names_lower)
    has_contact_meta = any("name" in n or "email" in n or "subject" in n for n in names_lower)
    if has_message and has_contact_meta:
        if "feedback" in action_lower or any("feedback" in n for n in names_lower):
            return "feedback", 0.90
        return "contact", 0.92

    if "login" in action_lower or "signin" in action_lower:
        return "login", 0.85
    if "register" in action_lower or "signup" in action_lower:
        return "registration", 0.85

    return "unknown", 0.50
