"""
AttackLens Unified Scan Orchestration Engine

Coordinates and executes security scans across all 9 AttackLens security engines in sequence:
1. Port & Network Discovery (scan)
2. HTTP Detection & Header Audit (scan)
3. Endpoint & Route Discovery (scan)
4. Web Application Attack-Surface Analysis (attack_surface)
5. Technology Fingerprinting (technology_fingerprinting)
6. TLS / SSL Security Analysis (tls_analysis)
7. Security Configuration Audit (analysis)
8. API Security Deep Analysis (api_analysis)
9. Codebase Security Analysis / SAST (codebase_analysis)
"""

import datetime
import io
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Callable

from django.utils import timezone

from .findings_engine import FindingsEngine
from .risk_engine import RiskScoringEngine
from ..models import UnifiedScanRecord

# Import existing scanner engines directly
from scan.views import (
    clean_and_extract_target,
    parse_http_target,
    COMMON_PORTS,
    scan_single_port,
    perform_http_detection,
    crawl_target_endpoints
)
from attack_surface.services.web_application_analyzer import analyze_web_application_attack_surface
from technology_fingerprinting.views import analyze_target_technologies
from tls_analysis.services.tls_scanner import scan_tls_security
from analysis.engine.analyzer import analyze_security_configuration
from api_analysis.services.api_scanner import scan_api_inventory
from codebase_analysis.services.codebase_scanner import (
    analyze_extracted_workspace,
    scan_project_zip
)

logger = logging.getLogger(__name__)

MODULE_METADATA: Dict[str, Dict[str, Any]] = {
    "ports": {
        "name": "Port & Network Discovery",
        "short_name": "Port Scanner",
        "page_id": "ports",
        "category": "Network & Host"
    },
    "http": {
        "name": "HTTP Detection & Header Audit",
        "short_name": "HTTP Inspector",
        "page_id": "http",
        "category": "Web Application"
    },
    "endpoints": {
        "name": "Endpoint & Route Discovery",
        "short_name": "Endpoint Discovery",
        "page_id": "endpoints",
        "category": "Web Application"
    },
    "attack-surface": {
        "name": "Web Application & Form Analysis",
        "short_name": "Web App Analysis",
        "page_id": "attack-surface",
        "category": "Web Application"
    },
    "fingerprint": {
        "name": "Technology Fingerprinting",
        "short_name": "Tech Fingerprint",
        "page_id": "fingerprint",
        "category": "Web Application"
    },
    "tls": {
        "name": "TLS / SSL Security Analysis",
        "short_name": "TLS/SSL Audit",
        "page_id": "tls",
        "category": "Encryption & Config"
    },
    "security-config": {
        "name": "Security Configuration Audit",
        "short_name": "Security Config",
        "page_id": "security-config",
        "category": "Encryption & Config"
    },
    "api-analysis": {
        "name": "API Security & Deep Analysis",
        "short_name": "API Security",
        "page_id": "api-analysis",
        "category": "Source & API"
    },
    "codebase-analysis": {
        "name": "Codebase Security (SAST & Secrets)",
        "short_name": "SAST & Secrets",
        "page_id": "codebase-analysis",
        "category": "Source & API"
    }
}

# Global registry of abort signals for active scans
ACTIVE_SCAN_ABORT_SIGNALS: Dict[str, threading.Event] = {}


class UnifiedScanOrchestrator:
    """
    Stateful orchestrator executing the selected suite of security modules for a given UnifiedScanRecord.
    """

    def __init__(
        self,
        scan_record_id: str,
        target: str,
        active_module_ids: List[str],
        scan_profile: str = "standard",
        intensity: str = "normal",
        codebase_source_type: str = "path",
        codebase_path: str = "",
        uploaded_zip_bytes: Optional[bytes] = None,
        uploaded_zip_name: str = "",
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.scan_record_id = str(scan_record_id)
        self.target = target.strip()
        self.active_module_ids = [m for m in active_module_ids if m in MODULE_METADATA]
        self.scan_profile = scan_profile.lower()
        self.intensity = intensity.lower()
        self.codebase_source_type = codebase_source_type
        self.codebase_path = codebase_path
        self.uploaded_zip_bytes = uploaded_zip_bytes
        self.uploaded_zip_name = uploaded_zip_name
        self.event_callback = event_callback

        self.abort_event = threading.Event()
        ACTIVE_SCAN_ABORT_SIGNALS[self.scan_record_id] = self.abort_event

        self.cleaned_target = clean_and_extract_target(self.target) or self.target
        self.resolved_ip = ""
        self.logs: List[Dict[str, Any]] = []
        self.module_statuses: Dict[str, Dict[str, Any]] = {}
        self.module_results: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.start_time = 0.0

        # Initialize module statuses
        for mod_id in MODULE_METADATA:
            if mod_id in self.active_module_ids:
                self.module_statuses[mod_id] = {
                    "id": mod_id,
                    "status": "pending",
                    "progress_percent": 0,
                    "current_step": "Queued in orchestration pipeline",
                    "duration_seconds": 0.0,
                    "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "summary_text": "Waiting for execution slot"
                }
            else:
                self.module_statuses[mod_id] = {
                    "id": mod_id,
                    "status": "skipped",
                    "progress_percent": 0,
                    "current_step": "Skipped by configuration",
                    "duration_seconds": 0.0,
                    "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "summary_text": "Module disabled"
                }

    def emit_event(self, event_type: str, module_id: str, module_name: str, level: str, message: str, data: Any = None):
        """Emits a structured log/progress event and invokes the listener callback."""
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = {
            "id": f"{int(time.time() * 1000)}-{len(self.logs)}",
            "timestamp": now_str,
            "module_id": module_id,
            "module_name": module_name,
            "level": level,
            "message": message
        }
        self.logs.append(log_entry)

        payload = {
            "event": event_type,
            "scan_id": self.scan_record_id,
            "module_id": module_id,
            "module_name": module_name,
            "level": level,
            "message": message,
            "log": log_entry,
            "elapsed_seconds": round(time.time() - self.start_time, 2) if self.start_time else 0.0,
            "module_statuses": self.module_statuses,
            "data": data
        }

        if self.event_callback:
            try:
                self.event_callback(payload)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")

    def update_db_record(self, status: str, progress_percent: int, current_module_id: str = "", error_msg: str = ""):
        """Persists intermediate or final scan status to database record."""
        try:
            from ..models import UnifiedScanRecord
            record = UnifiedScanRecord.objects.filter(id=self.scan_record_id).first()
            if not record:
                return

            record.status = status
            record.progress_percent = progress_percent
            record.current_module_id = current_module_id
            record.cleaned_target = self.cleaned_target
            record.resolved_ip = self.resolved_ip
            record.module_statuses = self.module_statuses
            record.module_results = self.module_results
            record.findings = self.findings
            record.logs = self.logs[-200:]  # Keep last 200 logs
            
            if error_msg:
                record.error_message = error_msg

            if status == "RUNNING" and not record.started_at:
                record.started_at = timezone.now()
            elif status in ("COMPLETED", "FAILED", "ABORTED"):
                record.completed_at = timezone.now()
                score, grade, risk_text, summary_counts = self.calculate_security_posture()
                record.overall_score = score
                record.score_grade = grade
                record.risk_rating = risk_text
                record.findings_summary = summary_counts

            record.save()
        except Exception as e:
            logger.error(f"Failed to update UnifiedScanRecord in DB: {e}")

    def run(self) -> Dict[str, Any]:
        """
        Executes the unified scan sequence synchronously or within a background worker.
        """
        self.start_time = time.time()
        self.update_db_record(status="RUNNING", progress_percent=0, current_module_id="orchestrator")

        self.emit_event(
            "init", "orchestrator", "Unified Orchestrator", "info",
            f"Initiating Unified Security Assessment on [{self.target}] with {len(self.active_module_ids)} active module(s) ({self.scan_profile.upper()} profile)"
        )

        # Pre-resolve target IP
        try:
            addr_info = socket.getaddrinfo(self.cleaned_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            self.resolved_ip = addr_info[0][4][0]
            self.emit_event(
                "dns_resolved", "orchestrator", "Unified Orchestrator", "info",
                f"Target resolved: {self.cleaned_target} -> {self.resolved_ip}"
            )
        except Exception as e:
            self.emit_event(
                "dns_warning", "orchestrator", "Unified Orchestrator", "warn",
                f"DNS pre-resolution warning for '{self.cleaned_target}': {e}"
            )

        total_active = len(self.active_module_ids)

        for index, module_id in enumerate(self.active_module_ids):
            if self.abort_event.is_set():
                self.emit_event("aborted", "orchestrator", "Unified Orchestrator", "warn", "Unified scan aborted by user.")
                self.update_db_record(status="ABORTED", progress_percent=int((index / max(1, total_active)) * 100), error_msg="Aborted by user request")
                break

            mod_meta = MODULE_METADATA.get(module_id, {"name": module_id, "short_name": module_id})
            mod_name = mod_meta["short_name"]

            # Update module state to running
            self.module_statuses[module_id]["status"] = "running"
            self.module_statuses[module_id]["current_step"] = "Executing security engine..."
            mod_start = time.time()

            base_progress = int((index / max(1, total_active)) * 100)
            self.update_db_record(status="RUNNING", progress_percent=base_progress, current_module_id=module_id)

            self.emit_event("module_start", module_id, mod_name, "info", f"Started module execution: [{mod_meta['name']}]")

            try:
                mod_result, mod_findings = self._execute_single_module(module_id)
                mod_duration = round(time.time() - mod_start, 2)

                self.module_results[module_id] = mod_result
                self.findings.extend(mod_findings)

                # Persist and deduplicate findings in Unified Findings database
                try:
                    scan_rec = UnifiedScanRecord.objects.filter(id=self.scan_record_id).first()
                    FindingsEngine.ingest_findings(
                        source_module=module_id,
                        target=self.target,
                        raw_findings=mod_findings,
                        scan_record=scan_rec
                    )
                except Exception as fe_err:
                    logger.warning(f"Could not persist findings to FindingsEngine: {fe_err}")

                findings_count = {
                    "critical": len([f for f in mod_findings if f["severity"] == "critical"]),
                    "high": len([f for f in mod_findings if f["severity"] == "high"]),
                    "medium": len([f for f in mod_findings if f["severity"] == "medium"]),
                    "low": len([f for f in mod_findings if f["severity"] == "low"]),
                    "info": len([f for f in mod_findings if f["severity"] == "info"]),
                }

                self.module_statuses[module_id]["status"] = "completed"
                self.module_statuses[module_id]["progress_percent"] = 100
                self.module_statuses[module_id]["duration_seconds"] = mod_duration
                self.module_statuses[module_id]["findings_count"] = findings_count
                self.module_statuses[module_id]["summary_text"] = f"{len(mod_findings)} finding(s) detected ({mod_duration}s)"
                self.module_statuses[module_id]["current_step"] = "Completed successfully"

                level = "warn" if (findings_count["critical"] > 0 or findings_count["high"] > 0) else "success"
                self.emit_event(
                    "module_complete", module_id, mod_name, level,
                    f"Completed [{mod_meta['name']}] with {len(mod_findings)} finding(s) in {mod_duration}s."
                )

            except Exception as e:
                mod_duration = round(time.time() - mod_start, 2)
                err_msg = str(e)
                logger.error(f"Module {module_id} failed during unified scan: {err_msg}", exc_info=True)

                self.module_statuses[module_id]["status"] = "failed"
                self.module_statuses[module_id]["progress_percent"] = 100
                self.module_statuses[module_id]["duration_seconds"] = mod_duration
                self.module_statuses[module_id]["current_step"] = f"Failed: {err_msg}"
                self.module_statuses[module_id]["summary_text"] = f"Error: {err_msg[:60]}"

                self.emit_event(
                    "module_error", module_id, mod_name, "error",
                    f"Module [{mod_meta['name']}] encountered error: {err_msg}"
                )

            curr_progress = int(((index + 1) / max(1, total_active)) * 100)
            self.update_db_record(status="RUNNING", progress_percent=curr_progress, current_module_id=module_id)

        # Finalize scan
        if not self.abort_event.is_set():
            score, grade, risk_text, summary_counts = self.calculate_security_posture()
            self.update_db_record(status="COMPLETED", progress_percent=100, current_module_id="")
            
            total_duration = round(time.time() - self.start_time, 2)
            self.emit_event(
                "complete", "orchestrator", "Unified Orchestrator", "success",
                f"Unified Security Assessment finished in {total_duration}s. Posture Score: {score}/100 (Grade {grade} - {risk_text})"
            )

        # Clean up abort signal
        ACTIVE_SCAN_ABORT_SIGNALS.pop(self.scan_record_id, None)

        score, grade, risk_text, summary_counts = self.calculate_security_posture()
        return {
            "id": self.scan_record_id,
            "target": self.target,
            "status": "COMPLETED" if not self.abort_event.is_set() else "ABORTED",
            "progress_percent": 100 if not self.abort_event.is_set() else self.module_statuses,
            "overall_score": score,
            "score_grade": grade,
            "risk_rating": risk_text,
            "findings_summary": summary_counts,
            "module_statuses": self.module_statuses,
            "module_results": self.module_results,
            "findings": self.findings,
            "logs": self.logs
        }

    # ─── Individual Module Execution Handlers ───────────────────────────────────

    def _execute_single_module(self, module_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Routes execution to the designated security module implementation."""
        if module_id == "ports":
            return self._run_port_scan()
        elif module_id == "http":
            return self._run_http_detection()
        elif module_id == "endpoints":
            return self._run_endpoint_discovery()
        elif module_id == "attack-surface":
            return self._run_attack_surface()
        elif module_id == "fingerprint":
            return self._run_technology_fingerprint()
        elif module_id == "tls":
            return self._run_tls_analysis()
        elif module_id == "security-config":
            return self._run_security_config()
        elif module_id == "api-analysis":
            return self._run_api_analysis()
        elif module_id == "codebase-analysis":
            return self._run_codebase_analysis()
        else:
            raise ValueError(f"Unknown module ID: {module_id}")

    def _run_port_scan(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Port & Network Discovery."""
        ip = self.resolved_ip
        if not ip:
            addr_info = socket.getaddrinfo(self.cleaned_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ip = addr_info[0][4][0]
            self.resolved_ip = ip

        if self.scan_profile == "deep":
            # Extended port set
            ports_to_scan = sorted(list(COMMON_PORTS.keys()) + [8008, 8081, 8888, 9090, 9200, 9443, 10000, 27017])
            timeout = 0.4
            max_workers = 35
        elif self.scan_profile == "quick":
            ports_to_scan = [21, 22, 80, 443, 3000, 8000, 8080]
            timeout = 0.3
            max_workers = 10
        else:
            ports_to_scan = sorted(COMMON_PORTS.keys())
            timeout = 0.4
            max_workers = 25

        open_ports = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_single_port, ip, port, timeout, 0.005): port
                for port in ports_to_scan
            }
            for future in as_completed(futures):
                p = future.result()
                if p is not None:
                    open_ports.append(p)

        open_ports.sort()
        port_details = [
            {"port": p, "service": COMMON_PORTS.get(p, "UNKNOWN"), "status": "open"}
            for p in open_ports
        ]

        result = {
            "success": True,
            "target": self.target,
            "cleaned_target": self.cleaned_target,
            "ip": ip,
            "total_ports_scanned": len(ports_to_scan),
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "open_port_details": port_details
        }

        findings = []
        # Flag sensitive / risky exposed ports
        risky_ports = {
            21: ("Exposed FTP Port (21/TCP)", "Cleartext FTP protocol allows credential interception.", "CWE-319", 6.5, "high"),
            23: ("Exposed Telnet Port (23/TCP)", "Unencrypted remote terminal service detected.", "CWE-319", 7.5, "high"),
            3306: ("Exposed MySQL Database Port (3306/TCP)", "Direct database listener open to network perimeter.", "CWE-284", 6.8, "medium"),
            5432: ("Exposed PostgreSQL Port (5432/TCP)", "Database listener accessible from external network.", "CWE-284", 6.8, "medium"),
            6379: ("Exposed Redis Key-Value Store (6379/TCP)", "Redis service exposed without perimeter firewall.", "CWE-284", 7.2, "high"),
            27017: ("Exposed MongoDB Service (27017/TCP)", "NoSQL database listening on network interface.", "CWE-284", 7.2, "high"),
        }

        for p in open_ports:
            if p in risky_ports:
                title, desc, cwe, cvss, sev = risky_ports[p]
                findings.append({
                    "id": f"port-{p}-{int(time.time())}",
                    "moduleId": "ports",
                    "moduleName": "Port Scanner",
                    "title": title,
                    "severity": sev,
                    "cvss": cvss,
                    "cwe": cwe,
                    "location": f"{self.cleaned_target}:{p}",
                    "description": desc,
                    "remediation": f"Restrict access to port {p} via host firewall or bind listener strictly to localhost (127.0.0.1)."
                })

        return result, findings

    def _run_http_detection(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes HTTP / HTTPS Inspection."""
        target_info, err = parse_http_target(self.target)
        if err or not target_info:
            target_info = {"raw_target": self.target, "hostname": self.cleaned_target, "path": "/", "has_explicit_scheme": False}

        result = perform_http_detection(target_info)
        findings = []

        # Analyze HTTP inspector security findings
        if result.get("reachable"):
            sec_headers = result.get("security_headers", {})
            if not sec_headers.get("Strict-Transport-Security", {}).get("present") and result.get("protocol") == "HTTP":
                findings.append({
                    "id": f"http-hsts-{int(time.time())}",
                    "moduleId": "http",
                    "moduleName": "HTTP Inspector",
                    "title": "Missing Strict-Transport-Security (HSTS) on HTTP Listener",
                    "severity": "low",
                    "cvss": 3.7,
                    "cwe": "CWE-319",
                    "location": result.get("final_url") or self.target,
                    "description": "The web service does not enforce HTTPS communication via HSTS response header.",
                    "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains header and enforce HTTPS redirection."
                })

            server_header = result.get("server")
            if server_header and any(char.isdigit() for char in server_header):
                findings.append({
                    "id": f"http-banner-{int(time.time())}",
                    "moduleId": "http",
                    "moduleName": "HTTP Inspector",
                    "title": f"Web Server Version Disclosure ({server_header})",
                    "severity": "low",
                    "cvss": 2.6,
                    "cwe": "CWE-200",
                    "location": result.get("final_url") or self.target,
                    "description": f"Detailed server software version banner leaked in HTTP response: '{server_header}'.",
                    "remediation": "Configure server (e.g. server_tokens off in Nginx) to suppress precise version numbers."
                })

        return result, findings

    def _run_endpoint_discovery(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Endpoint & Route Discovery."""
        target_info, _ = parse_http_target(self.target)
        if not target_info:
            target_info = {"raw_target": self.target, "hostname": self.cleaned_target, "scheme": "http", "path": "/"}

        max_pages = 25 if self.scan_profile == "deep" else (10 if self.scan_profile == "standard" else 5)
        result = crawl_target_endpoints(target_info, max_pages=max_pages)
        findings = []

        # Detect sensitive endpoints
        discovered_eps = result.get("discovered_endpoints", [])
        sensitive_keywords = ["/admin", "/debug", "/.env", "/.git", "/api/schema", "/swagger", "/actuator", "/metrics"]

        for ep in discovered_eps:
            url_str = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            for kw in sensitive_keywords:
                if kw in url_str.lower():
                    findings.append({
                        "id": f"ep-sens-{abs(hash(url_str)) % 100000}",
                        "moduleId": "endpoints",
                        "moduleName": "Endpoint Discovery",
                        "title": f"Potentially Sensitive Endpoint Discovered: {kw}",
                        "severity": "medium" if kw in ("/.env", "/.git", "/debug") else "info",
                        "cvss": 5.3 if kw in ("/.env", "/.git") else 0.0,
                        "cwe": "CWE-200",
                        "location": url_str,
                        "description": f"Automated crawler discovered exposed sensitive route ({url_str}).",
                        "remediation": "Ensure administrative, debug, and metadata routes require authentication or are blocked in production."
                    })
                    break

        return result, findings

    def _run_attack_surface(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Web Application Attack-Surface Analysis."""
        max_pages = 20 if self.scan_profile == "deep" else (10 if self.scan_profile == "standard" else 5)
        result = analyze_web_application_attack_surface(self.target, max_crawl_pages=max_pages)
        findings = []

        # Extract vulnerabilities and findings from engine result
        raw_findings = result.get("findings", [])
        for f in raw_findings:
            findings.append({
                "id": f.get("id") or f"as-{int(time.time())}-{len(findings)}",
                "moduleId": "attack-surface",
                "moduleName": "Web App Analysis",
                "title": f.get("title") or "Web Application Attack Vector Identified",
                "severity": (f.get("severity") or "medium").lower(),
                "cvss": float(f.get("cvss_score") or f.get("cvss") or 5.0),
                "cwe": f.get("cwe") or "CWE-20",
                "location": f.get("location") or f.get("url") or self.target,
                "description": f.get("description") or "Input or form attack surface detected.",
                "remediation": f.get("remediation") or "Validate and sanitize user input parameters on server side."
            })

        return result, findings

    def _run_technology_fingerprint(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Technology Fingerprinting."""
        target_info, _ = parse_http_target(self.target)
        if not target_info:
            target_info = {"raw_target": self.target, "hostname": self.cleaned_target, "scheme": "http", "path": "/"}

        max_pages = 10 if self.scan_profile == "deep" else (5 if self.scan_profile == "standard" else 3)
        result = analyze_target_technologies(target_info, max_pages=max_pages)
        findings = []

        # Check for outdated or sensitive technology disclosures
        tech_list = result.get("technologies", [])
        for t in tech_list:
            if isinstance(t, dict):
                cat = t.get("category", "")
                # Fingerprint engine uses key 'technology'; fallback to 'name' for legacy data
                name = t.get("technology") or t.get("name", "")
                version = t.get("version", "")
                if cat == "cms" and version:
                    findings.append({
                        "id": f"fp-{int(time.time())}-{len(findings)}",
                        "moduleId": "fingerprint",
                        "moduleName": "Tech Fingerprint",
                        "title": f"CMS Platform Fingerprinted: {name} {version}",
                        "severity": "low",
                        "cvss": 3.1,
                        "cwe": "CWE-200",
                        "location": self.target,
                        "description": f"The application discloses its CMS platform and version: {name} {version}.",
                        "remediation": "Keep CMS plugins and core updated to latest security patches."
                    })

        return result, findings

    def _run_tls_analysis(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes TLS / SSL Security Analysis."""
        result = scan_tls_security(self.target)
        findings = []

        raw_findings = result.get("findings", [])
        for f in raw_findings:
            findings.append({
                "id": f.get("id") or f"tls-{int(time.time())}-{len(findings)}",
                "moduleId": "tls",
                "moduleName": "TLS/SSL Audit",
                "title": f.get("title") or "TLS/SSL Cryptographic Weakness",
                "severity": (f.get("severity") or "medium").lower(),
                "cvss": float(f.get("cvss_score") or f.get("cvss") or 6.0),
                "cwe": f.get("cwe") or "CWE-326",
                "location": f"{self.cleaned_target}:443",
                "description": f.get("description") or "Cryptographic configuration weakness detected in TLS/SSL parameters.",
                "remediation": f.get("remediation") or "Disable obsolete protocols and enforce modern cipher suites with PFS."
            })

        return result, findings

    def _run_security_config(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Security Configuration Audit."""
        result = analyze_security_configuration(self.target)
        findings = []

        raw_findings = result.get("findings", [])
        for f in raw_findings:
            findings.append({
                "id": f.get("id") or f"sec-{int(time.time())}-{len(findings)}",
                "moduleId": "security-config",
                "moduleName": "Security Config",
                "title": f.get("title") or "Security Configuration Weakness",
                "severity": (f.get("severity") or "medium").lower(),
                "cvss": float(f.get("cvss_score") or f.get("cvss") or 5.0),
                "cwe": f.get("cwe") or "CWE-693",
                "location": f.get("header_name") or f.get("location") or self.target,
                "description": f.get("description") or "Security configuration audit identified missing or permissive controls.",
                "remediation": f.get("remediation") or "Configure strict HTTP security headers and cookie flags."
            })

        return result, findings

    def _run_api_analysis(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes API Security & Deep Analysis."""
        max_pages = 25 if self.scan_profile == "deep" else (15 if self.scan_profile == "standard" else 5)
        result = scan_api_inventory(self.target, max_crawl_pages=max_pages)
        findings = []

        raw_findings = result.get("findings", [])
        for f in raw_findings:
            findings.append({
                "id": f.get("id") or f"api-{int(time.time())}-{len(findings)}",
                "moduleId": "api-analysis",
                "moduleName": "API Security",
                "title": f.get("title") or "API Endpoint Security Finding",
                "severity": (f.get("severity") or "medium").lower(),
                "cvss": float(f.get("cvss_score") or f.get("cvss") or 6.5),
                "cwe": f.get("cwe") or "CWE-639",
                "location": f.get("endpoint") or f.get("location") or self.target,
                "description": f.get("description") or "API vulnerability detected during automated endpoint testing.",
                "remediation": f.get("remediation") or "Enforce server-side authorization and rate limiting."
            })

        return result, findings

    def _run_codebase_analysis(self) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Executes Codebase Security Analysis (SAST & Secrets)."""
        findings = []

        if self.codebase_source_type == "zip" and self.uploaded_zip_bytes:
            zip_file_obj = io.BytesIO(self.uploaded_zip_bytes)
            zip_file_obj.name = self.uploaded_zip_name or "uploaded_project.zip"
            result = scan_project_zip(zip_file_obj, project_name=self.uploaded_zip_name)
        elif self.codebase_path and os.path.isdir(self.codebase_path):
            result = analyze_extracted_workspace(self.codebase_path, project_name=os.path.basename(self.codebase_path))
        else:
            # Fallback to current project root directory
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            result = analyze_extracted_workspace(backend_dir, project_name="AttackLens Workspace")

        raw_findings = result.get("findings", [])
        for f in raw_findings:
            findings.append({
                "id": f.get("id") or f"sast-{int(time.time())}-{len(findings)}",
                "moduleId": "codebase-analysis",
                "moduleName": "SAST & Secrets",
                "title": f.get("title") or "Static Code Security Vulnerability",
                "severity": (f.get("severity") or "medium").lower(),
                "cvss": float(f.get("cvss") or f.get("cvss_score") or 6.0),
                "cwe": f.get("cwe") or "CWE-798",
                "location": f"{f.get('file', 'source')}:{f.get('line', 1)}",
                "description": f.get("description") or "Static analysis rule flagged security weakness in code.",
                "remediation": f.get("remediation") or "Refactor code to sanitize inputs and remove hardcoded secrets."
            })

        return result, findings

    # ─── Security Posture & Risk Calculation ───────────────────────────────────

    def calculate_security_posture(self) -> tuple[int, str, str, Dict[str, int]]:
        """
        Calculates unified security posture score (0-100), letter grade (A-F), and summary counts
        using the standardized RiskScoringEngine.
        """
        profile = RiskScoringEngine.calculate_risk_profile(self.findings, target_name=self.target)
        posture_score = int(round(profile["posture_score"]))
        grade = profile["grade"]
        risk_text = f"{profile['risk_level']} Risk"
        counts = profile["severity_breakdown"]

        return posture_score, grade, risk_text, counts


def launch_unified_scan_background(
    record_id: str,
    target: str,
    active_module_ids: List[str],
    scan_profile: str = "standard",
    intensity: str = "normal",
    codebase_source_type: str = "path",
    codebase_path: str = "",
    uploaded_zip_bytes: Optional[bytes] = None,
    uploaded_zip_name: str = ""
):
    """
    Launches the UnifiedScanOrchestrator in a background daemon thread.
    Extensible: Can easily be dispatched to a Celery worker task in production!
    """
    def worker():
        try:
            orchestrator = UnifiedScanOrchestrator(
                scan_record_id=record_id,
                target=target,
                active_module_ids=active_module_ids,
                scan_profile=scan_profile,
                intensity=intensity,
                codebase_source_type=codebase_source_type,
                codebase_path=codebase_path,
                uploaded_zip_bytes=uploaded_zip_bytes,
                uploaded_zip_name=uploaded_zip_name
            )
            orchestrator.run()
        except Exception as e:
            logger.error(f"Background unified scan execution failed for {record_id}: {e}", exc_info=True)

    thread = threading.Thread(target=worker, daemon=True, name=f"UnifiedScan-{record_id[:8]}")
    thread.start()
    return thread
