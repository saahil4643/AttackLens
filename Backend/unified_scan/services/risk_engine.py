"""
Risk Scoring Engine
Standardized, weighted, and deduplicated risk scoring for AttackLens security engines.
"""

import math
import logging
from typing import Any, Dict, List, Optional, Union
from django.db.models import QuerySet
from django.utils import timezone

from ..models import Finding, UnifiedScanRecord

logger = logging.getLogger("unified_scan.risk_engine")

MODULE_METADATA_MAP = {
    "ports": "Port & Network Discovery",
    "http": "HTTP Detection & Header Audit",
    "endpoints": "Endpoint & Route Discovery",
    "attack-surface": "Web Application & Form Analysis",
    "fingerprint": "Technology Fingerprinting",
    "tls": "TLS / SSL Security Analysis",
    "security-config": "Security Configuration Audit",
    "api-analysis": "API Security & Deep Analysis",
    "codebase-analysis": "Codebase Security (SAST & Secrets)",
}

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 35.0,
    "high": 20.0,
    "medium": 8.0,
    "low": 2.5,
    "info": 0.5,
}

CONFIDENCE_MULTIPLIERS: Dict[str, float] = {
    "certain": 1.0,
    "firm": 0.85,
    "tentative": 0.65,
}

STATUS_MULTIPLIERS: Dict[str, float] = {
    "confirmed": 1.0,
    "open": 0.95,
    "accepted": 0.20,
    "accepted_risk": 0.20,
    "remediated": 0.0,
    "false_positive": 0.0,
    "resolved": 0.0,
}

SENSITIVE_ASSET_KEYWORDS = [
    "3306", "5432", "6379", "27017", "21", "22", "23",
    "admin", "root", "secret", "password", "key", "token",
    "api/v1/admin", "api/admin", ".env", "config.py"
]


class RiskScoringEngine:
    """
    Isolated service implementing mathematical risk scoring algorithms.
    """

    @staticmethod
    def calculate_finding_risk(finding: Union[Finding, Dict[str, Any]]) -> float:
        """
        Calculates the raw risk contribution Ri for an individual finding:
        Ri = W_sev * M_cvss * M_conf * M_status * M_asset * M_occ
        """
        if isinstance(finding, Finding):
            severity = (finding.severity or "medium").lower()
            cvss = float(finding.cvss_score or 0.0)
            confidence = (finding.confidence or "firm").lower()
            status = (finding.status or "open").lower()
            location = (finding.location or "").lower()
            target = (finding.target or "").lower()
            title = (finding.title or "").lower()
            occurrence_count = max(1, int(finding.occurrence_count or 1))
        else:
            severity = str(finding.get("severity", "medium")).lower()
            cvss_raw = finding.get("cvss") or finding.get("cvss_score") or 0.0
            try:
                cvss = float(cvss_raw)
            except (ValueError, TypeError):
                cvss = 0.0
            confidence = str(finding.get("confidence", "firm")).lower()
            status = str(finding.get("status", "open")).lower()
            location = str(finding.get("location") or finding.get("affectedAsset") or "").lower()
            target = str(finding.get("target") or "").lower()
            title = str(finding.get("title") or "").lower()
            occurrence_count = max(1, int(finding.get("occurrence_count", 1)))

        # Status multiplier (remediated / false_positive have 0 risk)
        status_mult = STATUS_MULTIPLIERS.get(status, 0.95)
        if status_mult <= 0.0:
            return 0.0

        # Base severity weight
        base_weight = SEVERITY_WEIGHTS.get(severity, 7.0)

        # CVSS multiplier (0.5 to 1.0)
        cvss_mult = 0.5 + (min(10.0, max(0.0, cvss)) / 10.0) * 0.5

        # Confidence multiplier
        conf_mult = CONFIDENCE_MULTIPLIERS.get(confidence, 0.85)

        # Asset / Location sensitivity multiplier
        asset_mult = 1.0
        combined_text = f"{location} {target} {title}"
        if any(kw in combined_text for kw in SENSITIVE_ASSET_KEYWORDS):
            asset_mult = 1.15

        # Recurrence / occurrence scaling (sub-linear, max 1.5x)
        occ_mult = min(1.5, 1.0 + math.log2(occurrence_count) * 0.15) if occurrence_count > 1 else 1.0

        raw_risk = base_weight * cvss_mult * conf_mult * status_mult * asset_mult * occ_mult
        return round(raw_risk, 3)

    @staticmethod
    def normalize_risk_score(total_raw_risk: float) -> float:
        """
        Transforms raw cumulative risk into a normalized 0-100 risk score
        using an asymptotic saturation curve: Score = 100 * (1 - e^(-R / 35.0))
        """
        if total_raw_risk <= 0.0:
            return 0.0
        score = 100.0 * (1.0 - math.exp(-total_raw_risk / 35.0))
        return round(min(100.0, max(0.0, score)), 1)

    @staticmethod
    def get_risk_level(risk_score: float) -> tuple[str, str]:
        """
        Returns (risk_level, grade) based on normalized 0-100 risk score.
        """
        if risk_score >= 75.0:
            return "Critical", "F"
        elif risk_score >= 50.0:
            return "High", "D"
        elif risk_score >= 25.0:
            return "Medium", "C"
        elif risk_score >= 10.0:
            return "Low", "B"
        else:
            return "Informational", "A"

    @classmethod
    def calculate_risk_profile(
        cls,
        findings_list: Union[List[Union[Finding, Dict[str, Any]]], QuerySet],
        target_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Computes the complete risk assessment for a collection of findings.
        """
        total_raw_risk = 0.0
        active_findings_count = 0
        remediated_count = 0
        accepted_count = 0

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        active_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        severity_risk_sums = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0, "info": 0.0}

        module_raw_risk: Dict[str, float] = {k: 0.0 for k in MODULE_METADATA_MAP}
        module_finding_counts: Dict[str, int] = {k: 0 for k in MODULE_METADATA_MAP}
        module_highest_sev: Dict[str, str] = {k: "info" for k in MODULE_METADATA_MAP}

        target_risk_map: Dict[str, float] = {}
        target_counts: Dict[str, int] = {}

        evaluated_findings = []

        for f in findings_list:
            if isinstance(f, Finding):
                f_dict = f.to_dict()
                source_mod = f.source_module or f.source_module_name or "ports"
                status = (f.status or "open").lower()
                sev = (f.severity or "medium").lower()
                tgt = f.target or target_name or "Global"
            else:
                f_dict = f
                source_mod = f.get("source_module") or f.get("moduleId") or "ports"
                status = str(f.get("status", "open")).lower()
                sev = str(f.get("severity", "medium")).lower()
                tgt = f.get("target") or target_name or "Global"

            if sev not in severity_counts:
                sev = "medium"

            severity_counts[sev] += 1
            if status == "remediated" or status == "resolved":
                remediated_count += 1
            elif status == "accepted" or status == "accepted_risk":
                accepted_count += 1
            elif status != "false_positive":
                active_findings_count += 1
                active_severity_counts[sev] += 1

            # Compute individual finding risk
            f_risk = cls.calculate_finding_risk(f)
            total_raw_risk += f_risk
            severity_risk_sums[sev] += f_risk

            # Module breakdown
            if source_mod in module_raw_risk:
                module_raw_risk[source_mod] += f_risk
                module_finding_counts[source_mod] += 1
                # Track highest severity
                sev_order = ["info", "low", "medium", "high", "critical"]
                curr_highest = module_highest_sev[source_mod]
                if sev_order.index(sev) > sev_order.index(curr_highest):
                    module_highest_sev[source_mod] = sev

            # Target breakdown
            target_risk_map[tgt] = target_risk_map.get(tgt, 0.0) + f_risk
            target_counts[tgt] = target_counts.get(tgt, 0) + 1

            # Store for top risks evaluation
            if f_risk > 0.0:
                evaluated_findings.append({
                    "finding": f_dict,
                    "risk_value": f_risk,
                    "severity": sev,
                    "status": status,
                    "cvss": f_dict.get("cvss") or f_dict.get("cvss_score") or 0.0,
                })

        # Overall Normalized Risk Score (0-100)
        overall_risk_score = cls.normalize_risk_score(total_raw_risk)
        # Security Posture Score (100 = Clean, 0 = Compromised)
        posture_score = round(max(0.0, 100.0 - overall_risk_score), 1)
        risk_level, grade = cls.get_risk_level(overall_risk_score)

        # Sort top risks
        evaluated_findings.sort(key=lambda x: x["risk_value"], reverse=True)
        top_risks = [item["finding"] for item in evaluated_findings[:8]]

        # Module Risk Matrix
        module_breakdown = {}
        for mod_id, raw_r in module_raw_risk.items():
            mod_score = cls.normalize_risk_score(raw_r)
            mod_level, mod_grade = cls.get_risk_level(mod_score)
            module_breakdown[mod_id] = {
                "module_id": mod_id,
                "name": MODULE_METADATA_MAP.get(mod_id, mod_id),
                "risk_score": mod_score,
                "posture_score": round(max(0.0, 100.0 - mod_score), 1),
                "risk_level": mod_level,
                "grade": mod_grade,
                "finding_count": module_finding_counts[mod_id],
                "highest_severity": module_highest_sev[mod_id],
            }

        # Target Risk Breakdown
        target_breakdown = []
        for tgt, raw_r in sorted(target_risk_map.items(), key=lambda x: x[1], reverse=True)[:10]:
            t_score = cls.normalize_risk_score(raw_r)
            t_level, t_grade = cls.get_risk_level(t_score)
            target_breakdown.append({
                "target": tgt,
                "risk_score": t_score,
                "risk_level": t_level,
                "grade": t_grade,
                "finding_count": target_counts[tgt],
            })

        # Severity risk contributions (%)
        total_risk_sum = sum(severity_risk_sums.values())
        severity_contributions = {}
        for s, r_val in severity_risk_sums.items():
            pct = round((r_val / total_risk_sum * 100.0), 1) if total_risk_sum > 0 else 0.0
            severity_contributions[s] = pct

        return {
            "overall_risk_score": overall_risk_score,
            "posture_score": posture_score,
            "risk_level": risk_level,
            "grade": grade,
            "total_findings": len(findings_list),
            "active_findings_count": active_findings_count,
            "remediated_count": remediated_count,
            "accepted_risk_count": accepted_count,
            "severity_breakdown": {
                **severity_counts,
                "total": len(findings_list),
                "active_critical": active_severity_counts["critical"],
                "active_high": active_severity_counts["high"],
                "active_medium": active_severity_counts["medium"],
                "active_low": active_severity_counts["low"],
                "active_info": active_severity_counts["info"],
            },
            "severity_risk_contributions": severity_contributions,
            "module_risk_breakdown": module_breakdown,
            "target_risk_breakdown": target_breakdown,
            "top_risks": top_risks,
            "calculated_at": timezone.now().isoformat(),
        }

    @classmethod
    def calculate_target_risk(cls, target: str) -> Dict[str, Any]:
        """Calculates risk profile for a specific target asset."""
        target_clean = target.strip()
        findings = Finding.objects.filter(target__icontains=target_clean).select_related("scan")
        res = cls.calculate_risk_profile(findings, target_name=target_clean)
        res["target"] = target_clean
        return res

    @classmethod
    def calculate_scan_risk(cls, scan_id: str) -> Dict[str, Any]:
        """Calculates risk profile for a specific UnifiedScanRecord."""
        scan = UnifiedScanRecord.objects.filter(id=scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID '{scan_id}' not found.")
        findings = Finding.objects.filter(scan_id=scan_id).select_related("scan")
        res = cls.calculate_risk_profile(findings, target_name=scan.target)
        res["scan_id"] = str(scan.id)
        res["target"] = scan.target
        return res

    @classmethod
    def calculate_global_risk(cls) -> Dict[str, Any]:
        """Calculates organizational-wide risk profile across all active findings."""
        findings = Finding.objects.all().select_related("scan")
        return cls.calculate_risk_profile(findings, target_name="All Targets")

    @classmethod
    def get_risk_trends(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves historical risk trends across recent completed scans.
        """
        scans = UnifiedScanRecord.objects.filter(status="COMPLETED").order_by("-created_at")[:limit]
        trends = []
        for s in reversed(list(scans)):
            score = 100 - s.overall_score if s.overall_score is not None else 0
            trends.append({
                "scan_id": str(s.id),
                "target": s.target,
                "timestamp": s.completed_at.isoformat() if s.completed_at else s.created_at.isoformat(),
                "risk_score": score,
                "posture_score": s.overall_score,
                "grade": s.score_grade,
                "risk_rating": s.risk_rating,
                "findings_summary": s.findings_summary or {},
            })
        return trends
