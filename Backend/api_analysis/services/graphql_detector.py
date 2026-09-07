"""
GraphQL Endpoint Detection & Safe Analysis Service
"""
import json
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional
import requests
from .models import ApiEndpoint, ApiParameter, ApiAuthIndicator, ApiResponseInfo, ApiFinding

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
]


def detect_graphql_endpoint(
    base_target: str,
    known_urls: Optional[List[str]] = None,
    timeout: float = 4.0
) -> Tuple[List[ApiEndpoint], List[ApiFinding]]:
    """
    Safely probes for exposed GraphQL services and evaluates introspection / authentication.
    """
    discovered_endpoints: List[ApiEndpoint] = []
    findings: List[ApiFinding] = []

    parsed_target = urllib.parse.urlparse(base_target)
    base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    hostname = parsed_target.hostname or ""

    candidates = set()
    for path in COMMON_GRAPHQL_PATHS:
        candidates.add(urllib.parse.urljoin(base_origin, path))

    if known_urls:
        for u in known_urls:
            if "graphql" in u.lower():
                candidates.add(u)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackLens/1.0",
        "Accept": "application/json,application/graphql+json,*/*",
        "Content-Type": "application/json"
    })

    for endpoint_url in candidates:
        try:
            # 1. Non-destructive standard probe: query { __typename }
            probe_payload = {"query": "{ __typename }"}
            resp = session.post(
                endpoint_url,
                json=probe_payload,
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )

            is_graphql = False
            evidence_list = []
            auth_required = False
            auth_type = "none"
            introspection_enabled = False

            content_type = resp.headers.get("Content-Type", "").lower()
            text = resp.text.strip()

            # Check 1: 200 OK with valid JSON GraphQL data
            if resp.status_code == 200 and "json" in content_type:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and ("data" in data or "errors" in data):
                        is_graphql = True
                        evidence_list.append("Valid GraphQL response returned for query { __typename }")
                except Exception:
                    pass

            # Check 2: 400 Bad Request with GraphQL error signatures
            elif resp.status_code in (400, 422) and "json" in content_type:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and "errors" in data:
                        errs = data["errors"]
                        if isinstance(errs, list) and any("graphql" in str(e).lower() or "syntax" in str(e).lower() or "query" in str(e).lower() for e in errs):
                            is_graphql = True
                            evidence_list.append("GraphQL error structure returned on POST")
                except Exception:
                    pass

            # Check 3: 401 Unauthorized / 403 Forbidden on explicit /graphql path
            elif resp.status_code in (401, 403) and "/graphql" in endpoint_url.lower():
                is_graphql = True
                auth_required = True
                auth_type = "bearer"
                evidence_list.append(f"HTTP {resp.status_code} challenge on GraphQL endpoint")

            # Check 4: GET method fallback
            if not is_graphql:
                get_resp = session.get(
                    f"{endpoint_url}?query={{__typename}}",
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
                if get_resp.status_code == 200 and "json" in get_resp.headers.get("Content-Type", "").lower():
                    try:
                        g_data = json.loads(get_resp.text)
                        if isinstance(g_data, dict) and ("data" in g_data or "errors" in g_data):
                            is_graphql = True
                            evidence_list.append("GraphQL GET query returned structured response")
                    except Exception:
                        pass

            if is_graphql:
                # 2. Test safe introspection: query { __schema { queryType { name } } }
                try:
                    intro_resp = session.post(
                        endpoint_url,
                        json={"query": "{ __schema { queryType { name } } }"},
                        timeout=timeout,
                        verify=False
                    )
                    if intro_resp.status_code == 200:
                        i_data = json.loads(intro_resp.text)
                        if isinstance(i_data, dict) and "data" in i_data and i_data["data"] and "__schema" in i_data["data"]:
                            introspection_enabled = True
                except Exception:
                    pass

                # Build ApiEndpoint model
                path = urllib.parse.urlparse(endpoint_url).path or "/graphql"
                graphql_ep = ApiEndpoint(
                    endpoint=endpoint_url,
                    path=path,
                    hostname=hostname,
                    method="POST",
                    api_type="GraphQL",
                    version=None,
                    source="direct",
                    summary="GraphQL Query & Mutation Endpoint",
                    description="Standard GraphQL API interface.",
                    parameters=[
                        ApiParameter(name="query", location="body", param_type="string", required=True, description="GraphQL Document"),
                        ApiParameter(name="variables", location="body", param_type="object", required=False, description="GraphQL Query Variables"),
                        ApiParameter(name="operationName", location="body", param_type="string", required=False, description="Optional Operation Name")
                    ],
                    authentication=ApiAuthIndicator(
                        required=auth_required,
                        auth_type=auth_type,
                        evidence=evidence_list
                    ),
                    response=ApiResponseInfo(
                        status_code=resp.status_code,
                        content_type=content_type,
                        structure="object"
                    ),
                    confidence=0.99
                )
                discovered_endpoints.append(graphql_ep)

                # Generate Findings
                findings.append(ApiFinding(
                    id="API-GQL-001",
                    title="Exposed GraphQL API Endpoint Discovered",
                    category="graphql",
                    severity="info",
                    confidence=0.99,
                    description=f"A functional GraphQL endpoint was identified at '{endpoint_url}'.",
                    evidence={
                        "endpoint": endpoint_url,
                        "status_code": resp.status_code,
                        "introspection_enabled": introspection_enabled,
                        "evidence": evidence_list
                    },
                    recommendation="Ensure queries are bounded with depth limits, query complexity analysis, and strict authentication."
                ))

                if introspection_enabled:
                    findings.append(ApiFinding(
                        id="API-GQL-002",
                        title="GraphQL Schema Introspection Enabled",
                        category="graphql",
                        severity="low",
                        confidence=0.99,
                        description=f"The GraphQL service at '{endpoint_url}' answered full schema introspection queries. This enables clients to reconstruct the entire schema, types, queries, and mutations.",
                        evidence={
                            "endpoint": endpoint_url,
                            "introspection_query": "{ __schema { queryType { name } } }"
                        },
                        recommendation="Disable GraphQL schema introspection in production environments unless public API exploration is intended."
                    ))

                # Stop after discovering active GraphQL endpoint
                break

        except Exception:
            continue

    return discovered_endpoints, findings
