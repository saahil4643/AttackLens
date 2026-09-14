"""
Dashboard Aggregation Views for AttackLens Security Command Center
Provides comprehensive, high-performance security metrics combining
Unified Scans, Unified Findings, Risk Scoring, and Attack Surface Correlation.
"""

import logging
from typing import Any, Dict, List, Optional
from collections import defaultdict
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Finding, UnifiedScanRecord
from .services.risk_engine import RiskScoringEngine
from .services.correlation_engine import AttackSurfaceCorrelationEngine

logger = logging.getLogger("unified_scan.dashboard")


class DashboardSummaryView(APIView):
    """
    GET /api/dashboard/summary/?target=<optional_target>
    Returns all aggregated metrics for the Security Command Center Dashboard:
    - Overall Risk Profile & Posture
    - Severity & Status Breakdown
    - Attack Surface Asset Inventory Counts
    - Recent Unified Scans
    - Top Vulnerabilities
    - Most Exposed / High-Risk Assets
    - Module-by-Module Risk Matrix
    - Risk History / Trends
    - Scanned Targets Overview
    """

    def get(self, request: Request) -> Response:
        target = request.query_params.get("target", "").strip() or None

        try:
            # 1. Risk Profile & Posture Breakdown
            if target and target.lower() != "all":
                risk_profile = RiskScoringEngine.calculate_target_risk(target)
                findings_qs = Finding.objects.filter(target__icontains=target)
                scans_qs = UnifiedScanRecord.objects.filter(target__icontains=target)
            else:
                risk_profile = RiskScoringEngine.calculate_global_risk()
                findings_qs = Finding.objects.all()
                scans_qs = UnifiedScanRecord.objects.all()

            # 2. Attack Surface Asset Inventory Summary
            attack_surface_summary = self._compute_attack_surface_summary(target)

            # 3. Recent Unified Scans
            recent_scans = self._get_recent_scans(scans_qs)

            # 4. Top Vulnerabilities
            top_vulnerabilities = self._get_top_vulnerabilities(findings_qs)

            # 5. Most Exposed / High-Risk Assets
            high_risk_assets = self._compute_high_risk_assets(findings_qs)

            # 6. Risk Trend History
            risk_trends = RiskScoringEngine.get_risk_trends(limit=10)

            # 7. Targets Overview List
            targets_overview = self._compute_targets_overview()

            return Response(
                {
                    "status": "success",
                    "timestamp": timezone.now().isoformat(),
                    "selected_target": target or "all",
                    "risk": risk_profile,
                    "attack_surface": attack_surface_summary,
                    "recent_scans": recent_scans,
                    "top_vulnerabilities": top_vulnerabilities,
                    "high_risk_assets": high_risk_assets,
                    "module_risk_breakdown": risk_profile.get("module_risk_breakdown", {}),
                    "risk_trends": risk_trends,
                    "targets_overview": targets_overview,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            logger.exception(f"Error generating dashboard summary: {str(e)}")
            return Response(
                {"error": f"Failed to generate dashboard summary: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _compute_attack_surface_summary(self, target: Optional[str]) -> Dict[str, Any]:
        """Calculates deduplicated asset summary counters across all security modules."""
        if target and target.lower() != "all":
            corr = AttackSurfaceCorrelationEngine.correlate_target(target)
            inv = corr.get("inventory", {})
            return {
                "total_assets": corr.get("summary", {}).get("total_assets", 0),
                "total_targets": 1,
                "domains_count": len(inv.get("domains", [])),
                "ips_count": len(inv.get("ips", [])),
                "open_ports_count": len(inv.get("ports", [])),
                "services_count": len(inv.get("services", [])),
                "technologies_count": len(inv.get("technologies", [])),
                "endpoints_count": len(inv.get("endpoints", [])),
                "apis_count": len(inv.get("apis", [])),
                "tls_configs_count": len(inv.get("tls", [])),
                "correlated_findings_count": len(inv.get("findings", [])),
            }

        # Global aggregate across all distinct targets
        distinct_targets = list(
            UnifiedScanRecord.objects.values_list("target", flat=True).distinct()
        )
        if not distinct_targets:
            distinct_targets = list(
                Finding.objects.values_list("target", flat=True).distinct()
            )

        total_assets = 0
        domains_set = set()
        ips_set = set()
        ports_set = set()
        services_set = set()
        tech_set = set()
        endpoints_set = set()
        apis_set = set()
        tls_set = set()
        findings_set = set()

        # Aggregate across all discovered targets
        for t in set(distinct_targets[:15]):  # limit to top 15 targets for high speed
            try:
                corr = AttackSurfaceCorrelationEngine.correlate_target(t)
                inv = corr.get("inventory", {})
                for d in inv.get("domains", []):
                    domains_set.add(d.get("name"))
                for ip in inv.get("ips", []):
                    ips_set.add(ip.get("ip"))
                for p in inv.get("ports", []):
                    ports_set.add(f"{t}:{p.get('port')}")
                for s in inv.get("services", []):
                    services_set.add(f"{t}:{s.get('name')}:{s.get('port')}")
                for tech in inv.get("technologies", []):
                    tech_set.add(f"{t}:{tech.get('name')}")
                for ep in inv.get("endpoints", []):
                    endpoints_set.add(f"{t}:{ep.get('path')}")
                for a in inv.get("apis", []):
                    apis_set.add(f"{t}:{a.get('method')}:{a.get('path')}")
                for tl in inv.get("tls", []):
                    tls_set.add(f"{t}:{tl.get('domain')}")
                for f in inv.get("findings", []):
                    findings_set.add(f.get("id"))
            except Exception as e:
                logger.warning(f"Error correlating target {t} for dashboard summary: {e}")

        total_assets = (
            len(distinct_targets)
            + len(domains_set)
            + len(ips_set)
            + len(ports_set)
            + len(tech_set)
            + len(endpoints_set)
            + len(apis_set)
        )

        return {
            "total_assets": max(total_assets, len(distinct_targets)),
            "total_targets": len(distinct_targets),
            "domains_count": len(domains_set),
            "ips_count": len(ips_set),
            "open_ports_count": len(ports_set),
            "services_count": len(services_set),
            "technologies_count": len(tech_set),
            "endpoints_count": len(endpoints_set),
            "apis_count": len(apis_set),
            "tls_configs_count": len(tls_set),
            "correlated_findings_count": len(findings_set),
        }

    def _get_recent_scans(self, qs: Any) -> List[Dict[str, Any]]:
        """Retrieves recent unified scans with metadata and risk results."""
        scans = qs.order_by("-created_at")[:6]
        recent = []
        for s in scans:
            risk_score = getattr(s, "overall_score", 0)
            sec_posture = getattr(s, "security_posture", None)
            if isinstance(sec_posture, dict):
                risk_score = sec_posture.get("overall_risk_score", risk_score)

            findings_count = 0
            findings_attr = getattr(s, "findings", None)
            if isinstance(findings_attr, list):
                findings_count = len(findings_attr)
            elif hasattr(findings_attr, "count") and callable(findings_attr.count):
                try:
                    findings_count = findings_attr.count()
                except TypeError:
                    findings_count = 0
            if findings_count == 0:
                findings_count = Finding.objects.filter(scan=s).count()
            if findings_count == 0 and isinstance(getattr(s, "module_results", None), dict):
                for m_data in s.module_results.values():
                    if isinstance(m_data, dict):
                        findings_count += len(m_data.get("findings", []))

            scan_mode = getattr(s, "scan_profile", "") or getattr(s, "scan_mode", "standard")
            progress = getattr(s, "progress_percent", 0)
            active_mods = getattr(s, "active_modules", []) or []
            comp_mods = getattr(s, "completed_modules", []) or []
            if not comp_mods and isinstance(getattr(s, "module_statuses", None), dict):
                comp_mods = [k for k, v in s.module_statuses.items() if isinstance(v, dict) and v.get("status") == "completed"]

            recent.append(
                {
                    "id": str(s.id),
                    "target": s.target,
                    "scan_mode": scan_mode,
                    "intensity": getattr(s, "intensity", "normal"),
                    "status": s.status.lower() if isinstance(s.status, str) else "completed",
                    "progress": progress,
                    "total_modules": len(active_mods),
                    "completed_modules": len(comp_mods),
                    "findings_count": findings_count,
                    "risk_score": round(risk_score, 1),
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                }
            )
        return recent

    def _get_top_vulnerabilities(self, qs: Any) -> List[Dict[str, Any]]:
        """Returns top high-impact findings ordered by severity weight and CVSS."""
        severity_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        findings = qs.filter(
            status__in=["open", "confirmed"]
        ).order_by("-cvss_score", "-created_at")[:25]

        # In-memory sort with severity order
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_priority.get(f.severity.lower(), 99),
                -(f.cvss_score or 0.0),
            ),
        )[:10]

        top_list = []
        for f in sorted_findings:
            loc = getattr(f, "location", "") or f.target
            top_list.append(
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description[:180] + ("..." if len(f.description) > 180 else ""),
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "status": f.status,
                    "target": f.target,
                    "affected_asset": loc,
                    "location": loc,
                    "source_module": f.source_module,
                    "cvss_score": f.cvss_score,
                    "cwe": getattr(f, "cwe", ""),
                    "remediation": f.remediation,
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                }
            )
        return top_list

    def _compute_high_risk_assets(self, qs: Any) -> List[Dict[str, Any]]:
        """Aggregates findings per asset to determine the top most exposed targets/assets."""
        asset_map: Dict[str, Dict[str, Any]] = {}

        for f in qs.filter(status__in=["open", "confirmed"]):
            asset_key = getattr(f, "location", "") or f.target
            if not asset_key:
                continue

            if asset_key not in asset_map:
                asset_type = "host"
                if ":" in asset_key and any(c.isdigit() for c in asset_key.split(":")[-1]):
                    asset_type = "port"
                elif "/" in asset_key:
                    asset_type = "endpoint"
                elif f.source_module == "fingerprint":
                    asset_type = "technology"

                asset_map[asset_key] = {
                    "asset": asset_key,
                    "target": f.target,
                    "type": asset_type,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "total_findings": 0,
                    "max_cvss": 0.0,
                    "source_modules": set(),
                }

            entry = asset_map[asset_key]
            entry["total_findings"] += 1
            sev = f.severity.lower()
            if sev == "critical":
                entry["critical_count"] += 1
            elif sev == "high":
                entry["high_count"] += 1
            elif sev == "medium":
                entry["medium_count"] += 1
            elif sev == "low":
                entry["low_count"] += 1

            if f.cvss_score and f.cvss_score > entry["max_cvss"]:
                entry["max_cvss"] = f.cvss_score

            entry["source_modules"].add(f.source_module)

        high_risk_list = []
        for entry in asset_map.values():
            raw_risk = (
                entry["critical_count"] * 35.0
                + entry["high_count"] * 20.0
                + entry["medium_count"] * 8.0
                + entry["low_count"] * 2.5
            )
            import math
            asset_score = round(100.0 * (1.0 - math.exp(-raw_risk / 30.0)), 1)
            high_risk_list.append(
                {
                    "asset": entry["asset"],
                    "target": entry["target"],
                    "type": entry["type"],
                    "total_findings": entry["total_findings"],
                    "critical_count": entry["critical_count"],
                    "high_count": entry["high_count"],
                    "medium_count": entry["medium_count"],
                    "low_count": entry["low_count"],
                    "max_cvss": round(entry["max_cvss"], 1),
                    "risk_score": asset_score,
                    "source_modules": list(entry["source_modules"]),
                }
            )

        high_risk_list.sort(key=lambda x: (x["risk_score"], x["critical_count"], x["total_findings"]), reverse=True)
        return high_risk_list[:8]

    def _compute_targets_overview(self) -> List[Dict[str, Any]]:
        """Computes summary cards for each distinct target scanned in the system."""
        targets = list(
            Finding.objects.values_list("target", flat=True).distinct()
        )
        scan_targets = list(
            UnifiedScanRecord.objects.values_list("target", flat=True).distinct()
        )
        all_distinct = sorted(list(set([t for t in targets + scan_targets if t])))

        overview = []
        for t in all_distinct[:12]:
            t_profile = RiskScoringEngine.calculate_target_risk(t)
            last_scan = (
                UnifiedScanRecord.objects.filter(target__icontains=t)
                .order_by("-created_at")
                .first()
            )
            findings_count = Finding.objects.filter(target__icontains=t).count()

            overview.append(
                {
                    "target": t,
                    "risk_score": t_profile.get("overall_risk_score", 0),
                    "risk_level": t_profile.get("risk_level", "Informational"),
                    "grade": t_profile.get("grade", "A"),
                    "total_findings": findings_count,
                    "critical_count": t_profile.get("severity_breakdown", {}).get("critical", 0),
                    "high_count": t_profile.get("severity_breakdown", {}).get("high", 0),
                    "last_scanned": last_scan.created_at.isoformat() if last_scan and last_scan.created_at else None,
                    "last_scan_status": last_scan.status if last_scan else "none",
                }
            )

        overview.sort(key=lambda x: x["risk_score"], reverse=True)
        return overview
