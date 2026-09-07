"""
HTTP Security Headers Analyzer
"""
import re
from typing import Dict, Any, List, Tuple
from .findings import Finding

SECURITY_HEADER_KEYS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "feature-policy": "Feature-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cache-control": "Cache-Control",
    "pragma": "Pragma",
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
    "x-generator": "X-Generator",
    "x-runtime": "X-Runtime",
    "via": "Via",
}


def parse_csp_directives(csp_value: str) -> Dict[str, List[str]]:
    """Parses CSP raw string into a structured dictionary of directive -> sources."""
    directives: Dict[str, List[str]] = {}
    if not csp_value:
        return directives

    tokens = [t.strip() for t in csp_value.split(";") if t.strip()]
    for token in tokens:
        parts = token.split()
        if parts:
            directive_name = parts[0].lower()
            sources = parts[1:]
            directives[directive_name] = sources
    return directives


def parse_hsts_attributes(hsts_value: str) -> Dict[str, Any]:
    """Parses HSTS header into max_age, include_subdomains, and preload flags."""
    res = {
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "raw": hsts_value
    }
    if not hsts_value:
        return res

    tokens = [t.strip().lower() for t in hsts_value.split(";") if t.strip()]
    for t in tokens:
        if t.startswith("max-age="):
            try:
                res["max_age"] = int(t.split("=")[1])
            except ValueError:
                res["max_age"] = None
        elif t == "includesubdomains":
            res["include_subdomains"] = True
        elif t == "preload":
            res["preload"] = True
    return res


def analyze_security_headers(
    headers: Dict[str, str],
    is_https: bool = True
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Analyzes all HTTP security headers and generates structured details + findings.
    """
    findings: List[Finding] = []
    finding_counter = 1

    def next_id():
        nonlocal finding_counter
        fid = f"SEC-HDR-{finding_counter:03d}"
        finding_counter += 1
        return fid

    # Normalize response headers to lowercase keys
    norm_headers: Dict[str, str] = {k.lower(): v.strip() for k, v in headers.items()}

    results: Dict[str, Any] = {}

    # 1. Content-Security-Policy
    csp_raw = norm_headers.get("content-security-policy")
    csp_report_only = norm_headers.get("content-security-policy-report-only")
    
    if csp_raw:
        directives = parse_csp_directives(csp_raw)
        has_default_src = "default-src" in directives
        has_script_src = "script-src" in directives
        has_object_src = "object-src" in directives
        has_base_uri = "base-uri" in directives
        has_frame_ancestors = "frame-ancestors" in directives

        weak_aspects = []
        script_sources = directives.get("script-src", directives.get("default-src", []))
        
        if "'unsafe-inline'" in script_sources:
            weak_aspects.append("script-src contains 'unsafe-inline'")
        if "'unsafe-eval'" in script_sources:
            weak_aspects.append("script-src contains 'unsafe-eval'")
        if "*" in script_sources or "http:" in script_sources or "https:" in script_sources:
            weak_aspects.append("script-src uses overly broad source (* or generic scheme)")
        if not has_object_src and not (has_default_src and "'none'" in directives.get("default-src", [])):
            weak_aspects.append("object-src is not explicitly restricted")
        if not has_base_uri:
            weak_aspects.append("base-uri directive is missing (allows base tag hijacking)")

        results["Content-Security-Policy"] = {
            "present": True,
            "status": "warning" if weak_aspects else "pass",
            "value": csp_raw,
            "directives": directives,
            "weak_aspects": weak_aspects,
            "has_frame_ancestors": has_frame_ancestors,
            "report_only": False
        }

        if weak_aspects:
            findings.append(Finding(
                id=next_id(),
                title="Weak Content-Security-Policy Directives Observed",
                category="security_headers",
                severity="low",
                confidence=0.90,
                description=f"A Content-Security-Policy header is present, but contains potentially permissive configurations: {', '.join(weak_aspects)}.",
                evidence={
                    "header": "Content-Security-Policy",
                    "observed_value": csp_raw,
                    "weak_directives": weak_aspects
                },
                recommendation="Refine the CSP to eliminate 'unsafe-inline' and 'unsafe-eval' by adopting nonces/hashes, restrict object-src to 'none', and restrict base-uri."
            ))
    elif csp_report_only:
        directives = parse_csp_directives(csp_report_only)
        results["Content-Security-Policy"] = {
            "present": True,
            "status": "info",
            "value": csp_report_only,
            "directives": directives,
            "weak_aspects": [],
            "has_frame_ancestors": "frame-ancestors" in directives,
            "report_only": True
        }
        findings.append(Finding(
            id=next_id(),
            title="Content-Security-Policy in Report-Only Mode",
            category="security_headers",
            severity="info",
            confidence=0.95,
            description="The server returns Content-Security-Policy-Report-Only. Policies are logged but not actively enforced by user agents.",
            evidence={
                "header": "Content-Security-Policy-Report-Only",
                "observed": True
            },
            recommendation="Review violation reports and transition the policy to active Content-Security-Policy enforcement."
        ))
    else:
        results["Content-Security-Policy"] = {
            "present": False,
            "status": "fail",
            "value": None,
            "directives": {},
            "weak_aspects": [],
            "has_frame_ancestors": False,
            "report_only": False
        }
        findings.append(Finding(
            id=next_id(),
            title="Missing Content-Security-Policy",
            category="security_headers",
            severity="medium",
            confidence=0.95,
            description="The target response does not include a Content-Security-Policy header. A strong CSP helps prevent Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.",
            evidence={
                "header": "Content-Security-Policy",
                "observed": False
            },
            recommendation="Implement a robust Content-Security-Policy (CSP) that restricts script, frame, object, and style sources."
        ))

    # 2. Strict-Transport-Security (HSTS)
    hsts_raw = norm_headers.get("strict-transport-security")
    if is_https:
        if hsts_raw:
            hsts_parsed = parse_hsts_attributes(hsts_raw)
            max_age = hsts_parsed["max_age"]
            is_adequate = max_age is not None and max_age >= 15768000  # at least 6 months
            is_zero = max_age == 0

            status = "pass"
            if is_zero:
                status = "fail"
                findings.append(Finding(
                    id=next_id(),
                    title="HSTS Disabled via max-age=0",
                    category="security_headers",
                    severity="medium",
                    confidence=0.99,
                    description="The Strict-Transport-Security header has max-age set to 0, which disables browser HSTS caching and protection.",
                    evidence={
                        "header": "Strict-Transport-Security",
                        "observed_value": hsts_raw,
                        "max_age": 0
                    },
                    recommendation="Set max-age to at least 31536000 (1 year) with includeSubDomains."
                ))
            elif not is_adequate:
                status = "warning"
                findings.append(Finding(
                    id=next_id(),
                    title="Short HSTS max-age Duration",
                    category="security_headers",
                    severity="low",
                    confidence=0.95,
                    description=f"Strict-Transport-Security max-age is {max_age} seconds, which is less than the recommended minimum of 15768000 seconds (6 months).",
                    evidence={
                        "header": "Strict-Transport-Security",
                        "observed_value": hsts_raw,
                        "max_age": max_age
                    },
                    recommendation="Increase HSTS max-age to at least 31536000 seconds (1 year)."
                ))

            results["Strict-Transport-Security"] = {
                "present": True,
                "status": status,
                "value": hsts_raw,
                "max_age": max_age,
                "include_subdomains": hsts_parsed["include_subdomains"],
                "preload": hsts_parsed["preload"]
            }
        else:
            results["Strict-Transport-Security"] = {
                "present": False,
                "status": "fail",
                "value": None,
                "max_age": None,
                "include_subdomains": False,
                "preload": False
            }
            findings.append(Finding(
                id=next_id(),
                title="Missing Strict-Transport-Security (HSTS)",
                category="security_headers",
                severity="medium",
                confidence=0.95,
                description="The HTTPS server does not return a Strict-Transport-Security header. This exposes users to SSL-stripping man-in-the-middle attacks.",
                evidence={
                    "header": "Strict-Transport-Security",
                    "observed": False
                },
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."
            ))
    else:
        # HTTP connection: HSTS should not be sent over plain HTTP
        results["Strict-Transport-Security"] = {
            "present": bool(hsts_raw),
            "status": "info" if not hsts_raw else "warning",
            "value": hsts_raw,
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
            "note": "Target is HTTP; HSTS applies only to HTTPS connections."
        }

    # 3. X-Content-Type-Options
    xcto = norm_headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        results["X-Content-Type-Options"] = {
            "present": True,
            "status": "pass",
            "value": xcto
        }
    else:
        results["X-Content-Type-Options"] = {
            "present": bool(xcto),
            "status": "fail",
            "value": xcto
        }
        findings.append(Finding(
            id=next_id(),
            title="Missing X-Content-Type-Options: nosniff",
            category="security_headers",
            severity="low",
            confidence=0.95,
            description="The response is missing 'X-Content-Type-Options: nosniff'. Browsers may attempt to MIME-sniff response bodies into executable formats.",
            evidence={
                "header": "X-Content-Type-Options",
                "observed": xcto or False
            },
            recommendation="Add 'X-Content-Type-Options: nosniff' header to prevent MIME type sniffing."
        ))

    # 4. X-Frame-Options & Clickjacking Protection
    xfo = norm_headers.get("x-frame-options")
    csp_has_frame_ancestors = results.get("Content-Security-Policy", {}).get("has_frame_ancestors", False)

    if xfo:
        xfo_val = xfo.upper()
        if "DENY" in xfo_val or "SAMEORIGIN" in xfo_val or "ALLOW-FROM" in xfo_val:
            results["X-Frame-Options"] = {
                "present": True,
                "status": "pass",
                "value": xfo
            }
        else:
            results["X-Frame-Options"] = {
                "present": True,
                "status": "warning",
                "value": xfo
            }
    elif csp_has_frame_ancestors:
        # CSP frame-ancestors is the modern standard overriding X-Frame-Options
        results["X-Frame-Options"] = {
            "present": False,
            "status": "pass",
            "value": None,
            "note": "Clickjacking mitigated via CSP 'frame-ancestors' directive."
        }
    else:
        results["X-Frame-Options"] = {
            "present": False,
            "status": "medium",
            "value": None
        }
        findings.append(Finding(
            id=next_id(),
            title="Missing Clickjacking Defense (X-Frame-Options / CSP frame-ancestors)",
            category="security_headers",
            severity="medium",
            confidence=0.90,
            description="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was found on the response. The application may be framed by external origins and subjected to Clickjacking attacks.",
            evidence={
                "header_x_frame_options": False,
                "csp_frame_ancestors": False
            },
            recommendation="Configure 'X-Frame-Options: SAMEORIGIN' or 'DENY', and declare CSP 'frame-ancestors' directive."
        ))

    # 5. Referrer-Policy
    rp = norm_headers.get("referrer-policy")
    if rp:
        rp_lower = rp.lower()
        if "unsafe-url" in rp_lower:
            results["Referrer-Policy"] = {
                "present": True,
                "status": "fail",
                "value": rp
            }
            findings.append(Finding(
                id=next_id(),
                title="Insecure Referrer-Policy: unsafe-url",
                category="security_headers",
                severity="low",
                confidence=0.95,
                description="The Referrer-Policy header is configured to 'unsafe-url', exposing complete URLs including paths and query parameters across all origins.",
                evidence={
                    "header": "Referrer-Policy",
                    "observed_value": rp
                },
                recommendation="Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
            ))
        elif rp_lower in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "origin"):
            results["Referrer-Policy"] = {
                "present": True,
                "status": "pass",
                "value": rp
            }
        else:
            results["Referrer-Policy"] = {
                "present": True,
                "status": "warning",
                "value": rp
            }
    else:
        results["Referrer-Policy"] = {
            "present": False,
            "status": "warning",
            "value": None
        }
        findings.append(Finding(
            id=next_id(),
            title="Missing Referrer-Policy Header",
            category="security_headers",
            severity="info",
            confidence=0.90,
            description="No Referrer-Policy header was configured. Browsers will default to their standard policy (often strict-origin-when-cross-origin), but explicitly setting it guarantees consistent privacy.",
            evidence={
                "header": "Referrer-Policy",
                "observed": False
            },
            recommendation="Set 'Referrer-Policy: strict-origin-when-cross-origin'."
        ))

    # 6. Permissions-Policy
    perm_policy = norm_headers.get("permissions-policy") or norm_headers.get("feature-policy")
    if perm_policy:
        results["Permissions-Policy"] = {
            "present": True,
            "status": "pass",
            "value": perm_policy
        }
    else:
        results["Permissions-Policy"] = {
            "present": False,
            "status": "info",
            "value": None
        }
        findings.append(Finding(
            id=next_id(),
            title="Missing Permissions-Policy Header",
            category="security_headers",
            severity="info",
            confidence=0.85,
            description="The application does not declare a Permissions-Policy (Feature-Policy) header to explicitly restrict browser capabilities (e.g. camera, microphone, geolocation).",
            evidence={
                "header": "Permissions-Policy",
                "observed": False
            },
            recommendation="Add Permissions-Policy to restrict unused browser features (e.g., 'camera=(), microphone=(), geolocation=()')."
        ))

    # 7. Cross-Origin-Opener-Policy (COOP)
    coop = norm_headers.get("cross-origin-opener-policy")
    if coop:
        results["Cross-Origin-Opener-Policy"] = {
            "present": True,
            "status": "pass" if coop.lower() in ("same-origin", "same-origin-allow-popups") else "warning",
            "value": coop
        }
    else:
        results["Cross-Origin-Opener-Policy"] = {
            "present": False,
            "status": "info",
            "value": None
        }

    # 8. Cross-Origin-Resource-Policy (CORP)
    corp = norm_headers.get("cross-origin-resource-policy")
    if corp:
        results["Cross-Origin-Resource-Policy"] = {
            "present": True,
            "status": "pass",
            "value": corp
        }
    else:
        results["Cross-Origin-Resource-Policy"] = {
            "present": False,
            "status": "info",
            "value": None
        }

    # 9. Cross-Origin-Embedder-Policy (COEP)
    coep = norm_headers.get("cross-origin-embedder-policy")
    if coep:
        results["Cross-Origin-Embedder-Policy"] = {
            "present": True,
            "status": "pass",
            "value": coep
        }
    else:
        results["Cross-Origin-Embedder-Policy"] = {
            "present": False,
            "status": "info",
            "value": None
        }

    # 10. Cache-Control & Pragma
    cache_ctrl = norm_headers.get("cache-control")
    pragma = norm_headers.get("pragma")
    results["Cache-Control"] = {
        "present": bool(cache_ctrl),
        "status": "pass" if cache_ctrl else "info",
        "value": cache_ctrl
    }
    if pragma:
        results["Pragma"] = {
            "present": True,
            "status": "info",
            "value": pragma
        }

    return results, findings
