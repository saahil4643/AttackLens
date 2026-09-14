"""
Attack Surface Correlation Engine
Extracts, deduplicates, and correlates assets, endpoints, technologies, services, ports,
and security findings into a unified relational attack surface graph.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..models import Finding, UnifiedScanRecord
from .risk_engine import RiskScoringEngine

logger = logging.getLogger("unified_scan.correlation_engine")


class AttackSurfaceCorrelationEngine:
    """
    Constructs the correlated multi-tier attack surface:
    Target -> Domain/IP -> Port -> Service -> Technology -> Endpoint/API -> Finding
    """

    @classmethod
    def correlate_target(cls, target: str) -> Dict[str, Any]:
        """
        Builds the complete attack surface correlation for a target host/domain/URL.
        """
        target_clean = target.strip()
        # Find latest completed or active scan record for target
        scan_record = (
            UnifiedScanRecord.objects.filter(target__icontains=target_clean)
            .order_by("-created_at")
            .first()
        )
        if not scan_record:
            scan_record = (
                UnifiedScanRecord.objects.filter(cleaned_target__icontains=target_clean)
                .order_by("-created_at")
                .first()
            )

        findings = list(Finding.objects.filter(target__icontains=target_clean).select_related("scan"))

        return cls.build_correlation_graph(
            target=target_clean,
            scan_record=scan_record,
            findings=findings
        )

    @classmethod
    def correlate_scan(cls, scan_id: str) -> Dict[str, Any]:
        """
        Builds the attack surface correlation for a specific UnifiedScanRecord.
        """
        scan = UnifiedScanRecord.objects.filter(id=scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID '{scan_id}' not found.")

        findings = list(Finding.objects.filter(scan_id=scan.id).select_related("scan"))
        # If no findings specifically linked by scan foreign key, fallback to target match
        if not findings:
            findings = list(Finding.objects.filter(target__icontains=scan.target).select_related("scan"))

        return cls.build_correlation_graph(
            target=scan.target,
            scan_record=scan,
            findings=findings
        )

    @classmethod
    def build_correlation_graph(
        cls,
        target: str,
        scan_record: Optional[UnifiedScanRecord] = None,
        findings: Optional[List[Finding]] = None
    ) -> Dict[str, Any]:
        """
        Core correlation algorithm combining raw scan results and unified findings.
        """
        if findings is None:
            findings = []

        module_results = scan_record.module_results if scan_record else {}
        cleaned_target = scan_record.cleaned_target if scan_record and scan_record.cleaned_target else target
        resolved_ip = scan_record.resolved_ip if scan_record and scan_record.resolved_ip else ""

        # Parse target hostname
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname or cleaned_target or target
        port_num = parsed.port or (443 if parsed.scheme == "https" else 80)

        # ─── Data structures for Graph & Inventory ───────────────────────────
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_ids: Set[str] = set()
        edge_keys: Set[str] = set()

        def add_node(node_id: str, label: str, n_type: str, category: str, risk_score: float = 0.0, severity: str = "info", metadata: Dict[str, Any] = None):
            if node_id in node_ids:
                return
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": n_type,
                "category": category,
                "risk_score": round(risk_score, 1),
                "severity": severity,
                "metadata": metadata or {},
            })

        def add_edge(source_id: str, target_id: str, relationship: str, label: str = ""):
            edge_key = f"{source_id}->{target_id}:{relationship}"
            if edge_key in edge_keys:
                return
            edge_keys.add(edge_key)
            edges.append({
                "id": f"e_{len(edges) + 1}",
                "source": source_id,
                "target": target_id,
                "relationship": relationship,
                "label": label or relationship.replace("_", " ").title(),
            })

        # Inventory collections
        inv_domains: List[Dict[str, Any]] = []
        inv_ports: List[Dict[str, Any]] = []
        inv_services: List[Dict[str, Any]] = []
        inv_techs: List[Dict[str, Any]] = []
        inv_endpoints: List[Dict[str, Any]] = []
        inv_apis: List[Dict[str, Any]] = []
        inv_tls: List[Dict[str, Any]] = []
        inv_findings: List[Dict[str, Any]] = []

        # 1. Target Root Node
        target_node_id = f"target_{hash(target) & 0xfffffff}"
        add_node(target_node_id, target, "target", "Scope", metadata={"raw_target": target, "hostname": hostname})

        # 2. Host / Domain / IP Nodes
        host_node_id = f"host_{hostname}"
        add_node(host_node_id, hostname, "domain", "Infrastructure", metadata={"hostname": hostname, "ip": resolved_ip})
        add_edge(target_node_id, host_node_id, "resolves_to", "Resolves to Host")
        inv_domains.append({"name": hostname, "ip": resolved_ip, "type": "domain"})

        if resolved_ip and resolved_ip != hostname:
            ip_node_id = f"ip_{resolved_ip}"
            add_node(ip_node_id, resolved_ip, "ip", "Infrastructure", metadata={"ip": resolved_ip, "hostname": hostname})
            add_edge(host_node_id, ip_node_id, "maps_to_ip", "Bound to IP")
            inv_domains.append({"name": resolved_ip, "ip": resolved_ip, "type": "ip"})
            parent_net_id = ip_node_id
        else:
            parent_net_id = host_node_id

        # 3. Ports & Services Extraction
        port_results = module_results.get("ports", {})
        open_ports_list = port_results.get("open_ports", [])
        port_details = port_results.get("open_port_details", [])

        # If port scan wasn't run, fallback to default target port (80 or 443)
        if not open_ports_list:
            open_ports_list = [port_num]
            port_details = [{"port": port_num, "service": "HTTPS" if port_num == 443 else "HTTP", "status": "open"}]

        port_node_map: Dict[int, str] = {}
        service_node_map: Dict[int, str] = {}

        for pd in port_details:
            p_num = pd.get("port")
            if not p_num:
                continue
            s_name = pd.get("service") or "Unknown Service"
            p_id = f"port_{p_num}"
            port_node_map[p_num] = p_id

            add_node(p_id, f"Port {p_num}/TCP", "port", "Network & Port", metadata={"port": p_num, "protocol": "tcp", "service": s_name})
            add_edge(parent_net_id, p_id, "listens_on", f"Port {p_num}")
            inv_ports.append({"port": p_num, "protocol": "tcp", "service": s_name, "state": "open"})

            # Service node
            srv_id = f"service_{p_num}_{s_name.replace(' ', '_')}"
            service_node_map[p_num] = srv_id
            add_node(srv_id, s_name, "service", "Network Service", metadata={"port": p_num, "service": s_name, "banner": pd.get("banner", "")})
            add_edge(p_id, srv_id, "runs_service", "Runs")
            inv_services.append({"name": s_name, "port": p_num, "banner": pd.get("banner", "")})

        # 4. TLS Configuration Node
        tls_results = module_results.get("tls", {})
        if tls_results and tls_results.get("success"):
            tls_ver = tls_results.get("tls_version") or "TLS 1.2/1.3"
            cipher = tls_results.get("cipher_suite") or "Standard Suite"
            issuer = tls_results.get("certificate_issuer") or "Certificate Authority"
            tls_node_id = f"tls_{hostname}"
            add_node(
                tls_node_id,
                f"TLS ({tls_ver})",
                "tls",
                "Encryption",
                metadata={"version": tls_ver, "cipher": cipher, "issuer": issuer, "expiry": tls_results.get("certificate_expiry")}
            )
            # Connect TLS to port 443 or main service
            tls_parent = port_node_map.get(443) or port_node_map.get(port_num) or parent_net_id
            add_edge(tls_parent, tls_node_id, "uses_tls", "Secured with TLS")
            inv_tls.append({"version": tls_ver, "cipher": cipher, "issuer": issuer})

        # 5. Technology Fingerprint Nodes
        fingerprint_results = module_results.get("fingerprint", {})
        detected_techs = fingerprint_results.get("technologies", [])
        if not detected_techs and "technology_fingerprint" in module_results:
            detected_techs = module_results["technology_fingerprint"].get("technologies", [])

        # Default web server service fallback if no technologies explicitly parsed
        if not detected_techs:
            http_res = module_results.get("http", {})
            server_hdr = http_res.get("headers", {}).get("server") or http_res.get("server")
            if server_hdr:
                detected_techs = [{"name": server_hdr, "category": "Web Server", "version": ""}]

        # Category snake_case -> human-readable label mapping
        _cat_labels = {
            "web_server": "Web Server",
            "backend": "Backend Framework",
            "frontend": "Frontend Framework",
            "javascript": "JavaScript Library",
            "css": "CSS Framework",
            "cms": "CMS Platform",
            "cdn": "CDN / Cloud",
            "hosting": "Hosting & Platform",
            "analytics": "Analytics",
            "authentication": "Auth & Identity",
            "api": "API Architecture",
            "database": "Database",
        }

        tech_node_map: Dict[str, str] = {}
        for tech in detected_techs:
            # Fingerprint engine uses key 'technology'; fallback to 'name' for legacy data
            t_name = tech.get("technology") or tech.get("name") or "Unknown Technology"
            raw_cat = tech.get("category") or "other"
            t_cat = _cat_labels.get(raw_cat, raw_cat.replace("_", " ").title() if raw_cat else "Framework & Libs")
            t_ver = tech.get("version") or ""
            t_label = f"{t_name} {t_ver}".strip()
            t_id = f"tech_{t_name.lower().replace(' ', '_').replace('.', '_')}"
            tech_node_map[t_name.lower()] = t_id

            add_node(t_id, t_label, "technology", t_cat, metadata={"name": t_name, "category": t_cat, "version": t_ver})
            # Connect tech to primary web service (port 80/443 or first open port)
            tech_parent = service_node_map.get(port_num) or (list(service_node_map.values())[0] if service_node_map else host_node_id)
            add_edge(tech_parent, t_id, "powers", "Powered by")
            inv_techs.append({"name": t_name, "category": t_cat, "version": t_ver})

        # 6. HTTP Endpoints & Web Attack Surface
        endpoint_results = module_results.get("endpoints", {})

        # Pull from structured discovered_endpoints (new format) first
        structured_eps = endpoint_results.get("discovered_endpoints", [])
        # Fallback: plain URL string lists
        plain_url_list = endpoint_results.get("in_scope_endpoints", []) or endpoint_results.get("endpoints", [])
        # Also pull in API paths discovered by the wordlist probe
        api_path_urls = endpoint_results.get("in_scope_api_paths", []) or endpoint_results.get("api_paths", [])

        # Also pull from web application attack surface module
        app_surface = module_results.get("attack-surface", {})
        if app_surface:
            for ep in app_surface.get("endpoints", []):
                if isinstance(ep, dict) and ep.get("url"):
                    plain_url_list.append(ep["url"])

        # Deduplicate and normalize all endpoints into path strings
        clean_endpoints: Dict[str, Dict] = {}  # path -> metadata

        for item in structured_eps:
            if isinstance(item, dict):
                ep_path = item.get("path") or urlparse(item.get("url", "")).path or "/"
                if ep_path not in clean_endpoints:
                    clean_endpoints[ep_path] = {
                        "path": ep_path,
                        "method": item.get("method", "GET"),
                        "status_code": item.get("status_code", 200),
                        "is_api": item.get("is_api", False),
                    }

        for url_item in plain_url_list:
            if isinstance(url_item, str):
                ep_path = urlparse(url_item).path or "/"
            elif isinstance(url_item, dict):
                ep_path = url_item.get("path") or urlparse(url_item.get("url", "")).path or "/"
            else:
                continue
            if ep_path not in clean_endpoints:
                clean_endpoints[ep_path] = {"path": ep_path, "method": "GET", "status_code": 200, "is_api": False}

        # Add API paths from the wordlist probe
        for url_item in api_path_urls:
            if isinstance(url_item, str):
                ep_path = urlparse(url_item).path or "/"
            else:
                ep_path = str(url_item)
            if ep_path not in clean_endpoints:
                clean_endpoints[ep_path] = {"path": ep_path, "method": "GET", "status_code": 200, "is_api": True}

        if not clean_endpoints:
            clean_endpoints["/"] = {"path": "/", "method": "GET", "status_code": 200, "is_api": False}

        endpoint_node_map: Dict[str, str] = {}
        for ep_path, ep_meta in sorted(clean_endpoints.items())[:50]:  # Top 50 endpoints for graph visualization
            ep_id = f"ep_{hash(ep_path) & 0xfffffff}"
            endpoint_node_map[ep_path] = ep_id
            add_node(ep_id, ep_path, "endpoint", "Web Route", metadata={"path": ep_path, "target": target, "is_api": ep_meta.get("is_api", False)})
            # Connect to primary web service or host
            ep_parent = list(tech_node_map.values())[0] if tech_node_map else (list(service_node_map.values())[0] if service_node_map else host_node_id)
            add_edge(ep_parent, ep_id, "exposes_endpoint", "Exposes")
            inv_endpoints.append({"path": ep_path, "method": ep_meta.get("method", "GET"), "status_code": ep_meta.get("status_code", 200)})

        # 7. API Inventory Nodes
        api_results = module_results.get("api-analysis", {})
        api_endpoints = api_results.get("api_endpoints", []) or api_results.get("endpoints", [])
        api_node_map: Dict[str, str] = {}

        for api_item in api_endpoints[:15]:
            if isinstance(api_item, dict):
                a_path = api_item.get("path") or api_item.get("endpoint") or "/api"
                a_method = api_item.get("method") or "GET"
                a_auth = api_item.get("auth_required", False)
            else:
                a_path = str(api_item)
                a_method = "GET"
                a_auth = False

            a_id = f"api_{hash(a_path) & 0xfffffff}"
            api_node_map[a_path] = a_id
            add_node(a_id, f"{a_method} {a_path}", "api", "API Interface", metadata={"path": a_path, "method": a_method, "auth_required": a_auth})
            ep_parent = endpoint_node_map.get(a_path) or (list(tech_node_map.values())[0] if tech_node_map else host_node_id)
            add_edge(ep_parent, a_id, "serves_api", "API Route")
            inv_apis.append({"path": a_path, "method": a_method, "auth_required": a_auth})

        # 8. Correlate Unified Security Findings into Asset Hierarchy
        for f in findings:
            f_dict = f.to_dict() if isinstance(f, Finding) else f
            f_id = f"finding_{f_dict['id'][:8]}"
            f_title = f_dict.get("title", "Security Finding")
            f_sev = f_dict.get("severity", "medium").lower()
            f_cvss = float(f_dict.get("cvss") or f_dict.get("cvss_score") or 0.0)
            f_status = f_dict.get("status", "open").lower()
            f_loc = str(f_dict.get("location") or f_dict.get("affectedAsset") or "").lower()
            f_cwe = f_dict.get("cwe", "")
            f_mod = f_dict.get("source_module", "")

            # Calculate individual finding risk
            f_risk = RiskScoringEngine.calculate_finding_risk(f)

            add_node(
                f_id,
                f_title,
                "finding",
                "Security Vulnerability",
                risk_score=f_risk,
                severity=f_sev,
                metadata={
                    "finding_id": f_dict["id"],
                    "title": f_title,
                    "cwe": f_cwe,
                    "severity": f_sev,
                    "cvss": f_cvss,
                    "status": f_status,
                    "remediation": f_dict.get("remediation", ""),
                    "source_module": f_mod,
                    "location": f_loc,
                }
            )

            # Smart Correlation Matching to Parent Node
            correlated_parent_id = None
            correlated_parent_label = "Host"

            # Check for API path match
            for a_path, a_id in api_node_map.items():
                if a_path.lower() in f_loc or a_path.lower() in f_title.lower():
                    correlated_parent_id = a_id
                    correlated_parent_label = f"API ({a_path})"
                    break

            # Check for Endpoint path match
            if not correlated_parent_id:
                for ep_path, ep_id in endpoint_node_map.items():
                    if ep_path != "/" and ep_path.lower() in f_loc:
                        correlated_parent_id = ep_id
                        correlated_parent_label = f"Endpoint ({ep_path})"
                        break

            # Check for Specific Port match (e.g. 3306, 21, 22, 6379, 80, 443)
            if not correlated_parent_id:
                for p_num, p_id in port_node_map.items():
                    if str(p_num) in f_loc or str(p_num) in f_title:
                        correlated_parent_id = service_node_map.get(p_num) or p_id
                        correlated_parent_label = f"Port {p_num}"
                        break

            # Check for Technology match
            if not correlated_parent_id:
                for t_name, t_id in tech_node_map.items():
                    if t_name in f_loc or t_name in f_title.lower():
                        correlated_parent_id = t_id
                        correlated_parent_label = f"Tech ({t_name.title()})"
                        break

            # Check for TLS finding
            if not correlated_parent_id and ("tls" in f_mod or "ssl" in f_title.lower() or "cipher" in f_title.lower()):
                if "tls_results" in locals() and tls_results.get("success"):
                    correlated_parent_id = f"tls_{hostname}"
                    correlated_parent_label = "TLS Configuration"
                elif 443 in port_node_map:
                    correlated_parent_id = service_node_map.get(443) or port_node_map[443]
                    correlated_parent_label = "HTTPS Service"

            # Default correlation to host
            if not correlated_parent_id:
                correlated_parent_id = host_node_id
                correlated_parent_label = "Host System"

            add_edge(correlated_parent_id, f_id, "has_vulnerability", "Contains Vulnerability")

            inv_findings.append({
                "id": f_dict["id"],
                "title": f_title,
                "severity": f_sev,
                "cvss": f_cvss,
                "status": f_status,
                "cwe": f_cwe,
                "source_module": f_mod,
                "correlated_asset_id": correlated_parent_id,
                "correlated_asset_label": correlated_parent_label,
            })

        # Calculate composite risk profile
        risk_profile = RiskScoringEngine.calculate_risk_profile(findings, target_name=target)

        # ─── Hierarchical Tree Builder ──────────────────────────────────────
        tree_root = {
            "id": target_node_id,
            "name": target,
            "type": "target",
            "category": "Target Scope",
            "children": [
                {
                    "id": host_node_id,
                    "name": hostname,
                    "type": "domain",
                    "ip": resolved_ip,
                    "children": [
                        {
                            "id": p_id,
                            "name": f"Port {p_num}",
                            "type": "port",
                            "children": [
                                {
                                    "id": service_node_map.get(p_num, f"srv_{p_num}"),
                                    "name": inv_services[i]["name"] if i < len(inv_services) else "Service",
                                    "type": "service",
                                    "children": [
                                        {
                                            "id": t_id,
                                            "name": t_key.title(),
                                            "type": "technology",
                                            "children": []
                                        }
                                        for t_key, t_id in tech_node_map.items()
                                    ] if p_num in (80, 443, port_num) else []
                                }
                            ]
                        }
                        for i, (p_num, p_id) in enumerate(port_node_map.items())
                    ]
                }
            ]
        }

        total_assets = (
            len(inv_domains) + len(inv_ports) + len(inv_services) +
            len(inv_techs) + len(inv_endpoints) + len(inv_apis) + len(inv_tls)
        )

        return {
            "success": True,
            "target": target,
            "scan_id": str(scan_record.id) if scan_record else None,
            "summary": {
                "total_assets": total_assets,
                "domain_count": len(inv_domains),
                "ip_count": len([d for d in inv_domains if d["type"] == "ip"]),
                "port_count": len(inv_ports),
                "service_count": len(inv_services),
                "technology_count": len(inv_techs),
                "endpoint_count": len(inv_endpoints),
                "api_count": len(inv_apis),
                "tls_count": len(inv_tls),
                "finding_count": len(findings),
                "overall_risk_score": risk_profile["overall_risk_score"],
                "posture_score": risk_profile["posture_score"],
                "risk_level": risk_profile["risk_level"],
                "grade": risk_profile["grade"],
            },
            "graph": {
                "nodes": nodes,
                "edges": edges,
            },
            "tree": tree_root,
            "inventory": {
                "domains": inv_domains,
                "ports": inv_ports,
                "services": inv_services,
                "technologies": inv_techs,
                "endpoints": inv_endpoints,
                "apis": inv_apis,
                "tls": inv_tls,
                "findings": inv_findings,
            },
            "risk_profile": risk_profile,
        }
