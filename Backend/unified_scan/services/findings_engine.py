"""
Findings Engine Service
Standardizes, normalizes, deduplicates, and manages security findings across all 9 AttackLens security engines.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from django.db.models import Count, Q, QuerySet
from django.utils import timezone

from ..models import Finding, UnifiedScanRecord

logger = logging.getLogger("unified_scan.findings_engine")

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

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"open", "confirmed", "remediated", "accepted", "false_positive"}
VALID_CONFIDENCES = {"certain", "firm", "tentative"}


class FindingsEngine:
    """
    Core engine responsible for ingesting, deduplicating, querying, and updating
    unified security findings from all scanners.
    """

    @staticmethod
    def compute_fingerprint(
        source_module: str,
        target: str,
        location: str,
        cwe: str,
        title: str
    ) -> str:
        """
        Computes a deterministic SHA-256 fingerprint hash to identify identical findings.
        """
        mod_norm = (source_module or "").strip().lower()
        target_norm = (target or "").strip().lower()
        loc_norm = (location or "").strip().lower()
        cwe_norm = (cwe or "").strip().lower()
        title_norm = (title or "").strip().lower()

        raw_key = f"{mod_norm}:{target_norm}:{loc_norm}:{cwe_norm}:{title_norm}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @staticmethod
    def normalize_finding(raw_finding: Dict[str, Any], source_module: str, target: str) -> Dict[str, Any]:
        """
        Normalizes a raw scanner finding dictionary into standard Finding fields.
        """
        title = raw_finding.get("title") or raw_finding.get("name") or "Security Finding"
        description = raw_finding.get("description") or raw_finding.get("details") or ""
        
        # Severity normalization
        raw_sev = str(raw_finding.get("severity", "medium")).strip().lower()
        if raw_sev not in VALID_SEVERITIES:
            raw_sev = "medium"
        
        # Confidence normalization
        raw_conf = str(raw_finding.get("confidence", "firm")).strip().lower()
        if raw_conf not in VALID_CONFIDENCES:
            raw_conf = "firm"

        # CVSS Score
        cvss = raw_finding.get("cvss") or raw_finding.get("cvss_score") or 0.0
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = 0.0

        cwe = str(raw_finding.get("cwe") or "").strip()
        location = str(
            raw_finding.get("location") 
            or raw_finding.get("affectedAsset") 
            or raw_finding.get("asset") 
            or raw_finding.get("endpoint") 
            or raw_finding.get("path") 
            or target
        ).strip()

        # Evidence normalization
        evidence = raw_finding.get("evidence")
        if evidence is None:
            evidence = {}
        elif not isinstance(evidence, dict):
            if isinstance(evidence, (list, str, int, float, bool)):
                evidence = {"details": evidence}
            else:
                evidence = {"raw": str(evidence)}

        request_data = str(raw_finding.get("request") or raw_finding.get("request_data") or "")
        response_data = str(raw_finding.get("response") or raw_finding.get("response_data") or "")
        remediation = str(raw_finding.get("remediation") or raw_finding.get("solution") or "")

        references = raw_finding.get("references")
        if references is None:
            references = []
        elif isinstance(references, str):
            references = [references]
        elif not isinstance(references, list):
            references = [str(references)]

        source_module_name = (
            raw_finding.get("moduleName") 
            or raw_finding.get("source_module_name") 
            or MODULE_METADATA_MAP.get(source_module, source_module)
        )

        return {
            "title": title[:256],
            "description": description,
            "severity": raw_sev,
            "confidence": raw_conf,
            "cvss_score": round(cvss, 1),
            "cwe": cwe[:64],
            "source_module": source_module,
            "source_module_name": source_module_name[:128],
            "target": target[:512],
            "location": location[:512],
            "evidence": evidence,
            "request_data": request_data,
            "response_data": response_data,
            "remediation": remediation,
            "references": references,
        }

    @classmethod
    def ingest_finding(
        cls,
        raw_finding: Dict[str, Any],
        source_module: str,
        target: str,
        scan_record: Optional[UnifiedScanRecord] = None
    ) -> Tuple[Finding, bool]:
        """
        Ingests and deduplicates a single finding.
        If a finding with the same fingerprint hash exists:
          - Increments occurrence_count
          - Updates last_seen
          - Updates scan association to the latest scan
          - Enriches evidence / references if newer
        If new:
          - Creates Finding with status='open', first_seen=now, last_seen=now.
        """
        norm = cls.normalize_finding(raw_finding, source_module, target)
        fingerprint = cls.compute_fingerprint(
            source_module=norm["source_module"],
            target=norm["target"],
            location=norm["location"],
            cwe=norm["cwe"],
            title=norm["title"]
        )

        now = timezone.now()
        existing = Finding.objects.filter(fingerprint_hash=fingerprint).first()

        if existing:
            existing.occurrence_count += 1
            existing.last_seen = now
            if scan_record:
                existing.scan = scan_record
            
            # Enrich existing record with new details if present
            if norm["description"] and len(norm["description"]) > len(existing.description or ""):
                existing.description = norm["description"]
            if norm["remediation"] and not existing.remediation:
                existing.remediation = norm["remediation"]
            if norm["evidence"]:
                existing.evidence = {**existing.evidence, **norm["evidence"]}
            if norm["references"]:
                merged_refs = list(set((existing.references or []) + norm["references"]))
                existing.references = merged_refs
            if norm["cvss_score"] > existing.cvss_score:
                existing.cvss_score = norm["cvss_score"]
            if norm["request_data"] and not existing.request_data:
                existing.request_data = norm["request_data"]
            if norm["response_data"] and not existing.response_data:
                existing.response_data = norm["response_data"]

            existing.save()
            return existing, False
        else:
            new_finding = Finding.objects.create(
                scan=scan_record,
                title=norm["title"],
                description=norm["description"],
                severity=norm["severity"],
                confidence=norm["confidence"],
                cvss_score=norm["cvss_score"],
                cwe=norm["cwe"],
                source_module=norm["source_module"],
                source_module_name=norm["source_module_name"],
                target=norm["target"],
                location=norm["location"],
                evidence=norm["evidence"],
                request_data=norm["request_data"],
                response_data=norm["response_data"],
                remediation=norm["remediation"],
                references=norm["references"],
                status="open",
                fingerprint_hash=fingerprint,
                occurrence_count=1,
                first_seen=now,
                last_seen=now,
            )
            return new_finding, True

    @classmethod
    def ingest_findings(
        cls,
        source_module: str,
        target: str,
        raw_findings: List[Dict[str, Any]],
        scan_record: Optional[UnifiedScanRecord] = None
    ) -> List[Finding]:
        """
        Ingests a list of findings from a specific security module execution.
        """
        ingested = []
        for raw in raw_findings:
            try:
                finding_obj, _ = cls.ingest_finding(
                    raw_finding=raw,
                    source_module=source_module,
                    target=target,
                    scan_record=scan_record
                )
                ingested.append(finding_obj)
            except Exception as e:
                logger.error(f"Failed to ingest finding '{raw.get('title')}': {e}", exc_info=True)
        return ingested

    @staticmethod
    def get_findings_queryset(filters: Optional[Dict[str, Any]] = None) -> QuerySet:
        """
        Builds a filtered Django QuerySet for Finding objects based on criteria.
        """
        qs = Finding.objects.all().select_related("scan")
        if not filters:
            return qs

        # Severity filter (supports comma-separated list e.g., 'critical,high')
        severity = filters.get("severity")
        if severity:
            if isinstance(severity, str):
                sevs = [s.strip().lower() for s in severity.split(",") if s.strip()]
            elif isinstance(severity, list):
                sevs = [s.lower() for s in severity]
            else:
                sevs = [str(severity).lower()]
            if sevs:
                qs = qs.filter(severity__in=sevs)

        # Status filter (supports comma-separated list e.g., 'open,confirmed')
        status = filters.get("status")
        if status:
            if isinstance(status, str):
                stats = [s.strip().lower() for s in status.split(",") if s.strip()]
            elif isinstance(status, list):
                stats = [s.lower() for s in status]
            else:
                stats = [str(status).lower()]
            if stats:
                qs = qs.filter(status__in=stats)

        # Module filter (source_module or module)
        module = filters.get("module") or filters.get("source_module")
        if module:
            if isinstance(module, str):
                mods = [m.strip() for m in module.split(",") if m.strip()]
            elif isinstance(module, list):
                mods = module
            else:
                mods = [str(module)]
            if mods:
                qs = qs.filter(source_module__in=mods)

        # Target filter
        target = filters.get("target")
        if target:
            qs = qs.filter(target__icontains=target.strip())

        # Scan ID filter
        scan_id = filters.get("scan_id") or filters.get("scanId")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)

        # CWE filter
        cwe = filters.get("cwe")
        if cwe:
            qs = qs.filter(cwe__icontains=cwe.strip())

        # Free-text Search
        search = filters.get("search") or filters.get("q")
        if search:
            q_term = search.strip()
            qs = qs.filter(
                Q(title__icontains=q_term)
                | Q(description__icontains=q_term)
                | Q(location__icontains=q_term)
                | Q(cwe__icontains=q_term)
                | Q(target__icontains=q_term)
                | Q(source_module_name__icontains=q_term)
            )

        # CVSS Range
        min_cvss = filters.get("min_cvss")
        if min_cvss is not None:
            try:
                qs = qs.filter(cvss_score__gte=float(min_cvss))
            except (ValueError, TypeError):
                pass

        max_cvss = filters.get("max_cvss")
        if max_cvss is not None:
            try:
                qs = qs.filter(cvss_score__lte=float(max_cvss))
            except (ValueError, TypeError):
                pass

        # Ordering
        ordering = filters.get("ordering") or "-last_seen"
        allowed_orderings = {
            "-last_seen", "last_seen",
            "-first_seen", "first_seen",
            "-cvss_score", "cvss_score",
            "title", "-title",
            "severity", "-severity",
            "status", "-status"
        }
        if ordering in allowed_orderings:
            qs = qs.order_by(ordering)
        else:
            qs = qs.order_by("-last_seen", "-cvss_score")

        return qs

    @staticmethod
    def get_stats(target: Optional[str] = None, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates comprehensive summary statistics across findings.
        """
        qs = Finding.objects.all()
        if target:
            qs = qs.filter(target__icontains=target.strip())
        if scan_id:
            qs = qs.filter(scan_id=scan_id)

        total_count = qs.count()

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": total_count}
        for item in qs.values("severity").annotate(count=Count("id")):
            sev = item["severity"]
            if sev in severity_counts:
                severity_counts[sev] = item["count"]

        # Status breakdown
        status_counts = {"open": 0, "confirmed": 0, "remediated": 0, "accepted": 0, "false_positive": 0}
        for item in qs.values("status").annotate(count=Count("id")):
            st = item["status"]
            if st in status_counts:
                status_counts[st] = item["count"]

        # Module breakdown
        module_counts = {}
        for item in qs.values("source_module").annotate(count=Count("id")):
            mod = item["source_module"]
            module_counts[mod] = item["count"]

        # Top Targets
        top_targets = list(
            qs.values("target").annotate(count=Count("id")).order_by("-count")[:5]
        )

        # Top CWEs
        top_cwes = list(
            qs.exclude(cwe="").values("cwe").annotate(count=Count("id")).order_by("-count")[:5]
        )

        return {
            "total_findings": total_count,
            "active_vulnerabilities": status_counts["open"] + status_counts["confirmed"],
            "remediated_count": status_counts["remediated"],
            "accepted_risk_count": status_counts["accepted"],
            "false_positive_count": status_counts["false_positive"],
            "by_severity": severity_counts,
            "by_status": status_counts,
            "by_module": module_counts,
            "top_targets": top_targets,
            "top_cwes": top_cwes,
        }

    @staticmethod
    def update_finding_status(
        finding_id: str,
        new_status: str,
        note: str = ""
    ) -> Optional[Finding]:
        """
        Updates the status and optional note for a finding.
        """
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {', '.join(VALID_STATUSES)}")

        finding = Finding.objects.filter(id=finding_id).first()
        if not finding:
            return None

        finding.status = new_status
        if note:
            finding.status_note = note
        finding.save()
        return finding
