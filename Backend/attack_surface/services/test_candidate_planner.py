"""
Security Test Candidate Generator (Potential Testing Areas for Future Test Planner).
"""
from typing import List, Dict, Any, Set
from .models import TestCandidateRecord


def generate_test_candidates(
    auth_surfaces: List[Dict[str, Any]],
    upload_surfaces: List[Dict[str, Any]],
    admin_surfaces: List[Dict[str, Any]],
    api_endpoints: List[Dict[str, Any]],
    parameters: List[Dict[str, Any]],
    session_surfaces: List[Dict[str, Any]],
    websockets: List[Dict[str, Any]],
    doc_surfaces: List[Dict[str, Any]],
    debug_surfaces: List[Dict[str, Any]],
) -> List[TestCandidateRecord]:
    """
    Synthesizes the mapped attack surface into prioritised testing candidates
    for the future Security Test Planner module.
    """
    candidates: List[TestCandidateRecord] = []
    seen: Set[str] = set()

    def add_candidate(area: str, endpoint: str, method: str, reason: str, priority: str):
        sig = f"{area}:{method}:{endpoint}"
        if sig not in seen:
            seen.add(sig)
            candidates.append(TestCandidateRecord(
                area=area,
                endpoint=endpoint,
                method=method,
                reason=reason,
                priority=priority
            ))

    # 1. File Uploads (High Priority)
    for u in upload_surfaces:
        ep = u.get("endpoint") or "/"
        method = u.get("method", "POST")
        add_candidate(
            area="file_upload",
            endpoint=ep,
            method=method,
            reason="File upload interface detected; test for extension filtering, MIME validation, and path traversal.",
            priority="high"
        )

    # 2. Authentication Entry Points (High Priority)
    for a in auth_surfaces:
        ep = a.get("endpoint") or "/"
        method = a.get("method", "POST")
        auth_type = a.get("type", "login")
        add_candidate(
            area="authentication",
            endpoint=ep,
            method=method,
            reason=f"Discovered {auth_type} surface; candidate for rate limiting, credential handling, and lockout analysis.",
            priority="high"
        )

    # 3. Administrative Interfaces (High Priority)
    for adm in admin_surfaces:
        ep = adm.get("endpoint") or "/"
        add_candidate(
            area="administration",
            endpoint=ep,
            method="GET",
            reason="Administrative panel detected; candidate for access control, privilege escalation, and bypass testing.",
            priority="high"
        )

    # 4. Session Management (High / Medium Priority)
    for s in session_surfaces:
        cname = s.get("cookie_name", "")
        if not s.get("is_secure") or not s.get("is_httponly"):
            add_candidate(
                area="session_management",
                endpoint=f"Cookie: {cname}",
                method="HTTP",
                reason=f"Session identifier '{cname}' lacks Secure or HttpOnly attributes.",
                priority="high" if not s.get("is_httponly") else "medium"
            )

    # 5. APIs & Authorization (High / Medium Priority)
    for api_ep in api_endpoints:
        ep = api_ep.get("endpoint") or api_ep.get("path") or ""
        method = api_ep.get("method", "GET")
        auth_info = api_ep.get("authentication") or {}
        if auth_info.get("required"):
            add_candidate(
                area="authorization",
                endpoint=ep,
                method=method,
                reason=f"Authenticated API ({auth_info.get('type', 'bearer')}); test for object-level (BOLA/IDOR) access controls.",
                priority="high"
            )
        elif api_ep.get("type") == "GraphQL":
            add_candidate(
                area="api",
                endpoint=ep,
                method=method,
                reason="GraphQL endpoint discovered; check for query depth, batching, and field suggestion behavior.",
                priority="medium"
            )

    # 6. Parameter Input Validation (Medium Priority)
    for param in parameters[:10]:
        pname = param.get("name") or ""
        endpoints = param.get("endpoints") or []
        target_ep = endpoints[0] if endpoints else "/api"
        add_candidate(
            area="input_validation",
            endpoint=f"{target_ep} ({pname})",
            method="GET",
            reason=f"Parameter '{pname}' observed in {param.get('location', 'query')}; test for boundary conditions and injection.",
            priority="medium"
        )

    # 7. WebSockets (Medium Priority)
    for ws in websockets:
        ws_url = ws.get("url") or ""
        add_candidate(
            area="websocket",
            endpoint=ws_url,
            method="WS",
            reason="WebSocket endpoint observed; evaluate connection handshake authentication and message sanitization.",
            priority="medium"
        )

    # 8. Documentation Exposure (Low Priority)
    for d in doc_surfaces:
        doc_url = d.get("documentation_url") or ""
        add_candidate(
            area="information_disclosure",
            endpoint=doc_url,
            method="GET",
            reason=f"Public API documentation ({d.get('spec_format', 'openapi')}) discovered; useful for mapping hidden endpoints.",
            priority="low"
        )

    # 9. Debug / Error disclosure (Low Priority)
    for deb in debug_surfaces:
        add_candidate(
            area="information_disclosure",
            endpoint=deb.get("endpoint", "/"),
            method="GET",
            reason=f"Potential {deb.get('type', 'disclosure')} detected in response headers or body.",
            priority="low"
        )

    # Sort candidates by priority: high -> medium -> low
    priority_order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: priority_order.get(c.priority, 3))
    return candidates
