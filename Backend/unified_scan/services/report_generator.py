"""
Professional Security Report Generation Service
Generates executive and technical pentest deliverables using real scan findings,
mathematical risk scoring, attack surface correlation, and evidence.
"""

import html
import logging
from typing import Any, Dict, List, Optional
from django.utils import timezone

from ..models import Finding, SecurityReport, UnifiedScanRecord
from .risk_engine import RiskScoringEngine
from .correlation_engine import AttackSurfaceCorrelationEngine

logger = logging.getLogger("unified_scan.report_generator")


class SecurityReportGenerator:
    """
    Constructs high-impact, professional executive and technical deliverables.
    """

    @classmethod
    def generate_report(
        cls,
        target: Optional[str] = None,
        scan_id: Optional[str] = None,
        report_type: str = "executive",
        format_type: str = "pdf",
        title: Optional[str] = None
    ) -> SecurityReport:
        """
        Generates and saves a SecurityReport based on real database records.
        """
        target_clean = (target or "").strip()
        scan_record = None

        if scan_id:
            scan_record = UnifiedScanRecord.objects.filter(id=scan_id).first()
            if scan_record and not target_clean:
                target_clean = scan_record.target

        # Determine target scope label
        scope_label = target_clean if target_clean and target_clean.lower() != "all" else "Global Organization Scope"

        # 1. Compute Risk Profile from Risk Engine
        if scan_record:
            risk_profile = RiskScoringEngine.calculate_scan_risk(str(scan_record.id))
            findings_qs = Finding.objects.filter(scan=scan_record).select_related("scan")
            if not findings_qs.exists():
                findings_qs = Finding.objects.filter(target__icontains=scan_record.target).select_related("scan")
        elif target_clean and target_clean.lower() != "all":
            risk_profile = RiskScoringEngine.calculate_target_risk(target_clean)
            findings_qs = Finding.objects.filter(target__icontains=target_clean).select_related("scan")
        else:
            risk_profile = RiskScoringEngine.calculate_global_risk()
            findings_qs = Finding.objects.all().select_related("scan")

        # 2. Extract Attack Surface Telemetry
        attack_surface_data = {}
        try:
            if scan_record:
                corr = AttackSurfaceCorrelationEngine.correlate_scan(str(scan_record.id))
            elif target_clean and target_clean.lower() != "all":
                corr = AttackSurfaceCorrelationEngine.correlate_target(target_clean)
            else:
                corr = AttackSurfaceCorrelationEngine.correlate_target(scope_label)
            attack_surface_data = corr
        except Exception as e:
            logger.warning(f"Failed to extract correlation for report: {e}")
            attack_surface_data = {"summary": {}, "inventory": {}}

        # 3. Sort & Prioritize Findings
        findings_list = list(findings_qs.order_by("-cvss_score", "-last_seen"))
        severity_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        findings_list = sorted(
            findings_list,
            key=lambda f: (
                severity_priority.get(f.severity.lower(), 99),
                -(f.cvss_score or 0.0)
            )
        )

        overall_risk_score = risk_profile.get("overall_risk_score", 0.0)
        risk_level = risk_profile.get("risk_level", "Informational")
        grade = risk_profile.get("grade", "A")
        sev_breakdown = risk_profile.get("severity_breakdown", {})

        # Default Title
        report_type_display = {
            "executive": "Executive Security Briefing",
            "technical": "Technical Penetration Testing Report",
            "attack_surface": "Attack Surface & Perimeter Audit",
            "full_audit": "Comprehensive 360° Security Assessment",
        }.get(report_type, "Security Assessment Report")

        final_title = title.strip() if title and title.strip() else f"{report_type_display} — {scope_label}"

        # 4. Compile Structured Summary Data
        summary_data = {
            "title": final_title,
            "report_type": report_type,
            "target": scope_label,
            "generated_at": timezone.now().isoformat(),
            "risk_profile": risk_profile,
            "attack_surface_summary": attack_surface_data.get("summary", {}),
            "attack_surface_inventory": attack_surface_data.get("inventory", {}),
            "findings_count": len(findings_list),
            "severity_breakdown": sev_breakdown,
        }

        # 5. Render Standalone HTML Content
        html_content = cls._render_html_report(
            title=final_title,
            report_type=report_type,
            scope_label=scope_label,
            risk_profile=risk_profile,
            attack_surface_data=attack_surface_data,
            findings=findings_list,
            scan_record=scan_record
        )

        # 6. Save and Return SecurityReport
        report = SecurityReport.objects.create(
            title=final_title,
            report_type=report_type,
            format=format_type,
            target=scope_label,
            scan=scan_record,
            status="completed",
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            grade=grade,
            total_findings=len(findings_list),
            severity_breakdown=sev_breakdown,
            summary_data=summary_data,
            html_content=html_content,
        )

        return report

    @classmethod
    def _render_html_report(
        cls,
        title: str,
        report_type: str,
        scope_label: str,
        risk_profile: Dict[str, Any],
        attack_surface_data: Dict[str, Any],
        findings: List[Finding],
        scan_record: Optional[UnifiedScanRecord] = None
    ) -> str:
        """Renders a standalone, printable, corporate security audit HTML document."""

        now_str = timezone.now().strftime("%B %d, %Y - %H:%M UTC")
        risk_score = risk_profile.get("overall_risk_score", 0)
        posture_score = risk_profile.get("posture_score", 100)
        risk_level = risk_profile.get("risk_level", "Informational")
        grade = risk_profile.get("grade", "A")
        sev = risk_profile.get("severity_breakdown", {})
        crit_count = sev.get("critical", 0)
        high_count = sev.get("high", 0)
        med_count = sev.get("medium", 0)
        low_count = sev.get("low", 0)
        info_count = sev.get("info", 0)
        total_findings = len(findings)

        # Theme color based on risk score
        risk_color = "#ef4444" if risk_score >= 75 else ("#f97316" if risk_score >= 50 else ("#eab308" if risk_score >= 25 else ("#3b82f6" if risk_score >= 10 else "#10b981")))
        grade_color = "#10b981" if grade == "A" else ("#3b82f6" if grade == "B" else ("#eab308" if grade == "C" else ("#f97316" if grade == "D" else "#ef4444")))

        as_summary = attack_surface_data.get("summary", {})
        inv = attack_surface_data.get("inventory", {})

        ports_count = len(inv.get("ports", []))
        tech_count = len(inv.get("technologies", []))
        endpoints_count = len(inv.get("endpoints", []))
        apis_count = len(inv.get("apis", []))
        tls_count = len(inv.get("tls", []))
        total_assets = as_summary.get("total_assets", ports_count + tech_count + endpoints_count + apis_count + 1)

        # Build Detailed Findings HTML Cards
        findings_html = ""
        for idx, f in enumerate(findings, start=1):
            s_color = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "info": "#a855f7"
            }.get(f.severity.lower(), "#64748b")

            loc = html.escape(f.location or f.target)
            f_title = html.escape(f.title)
            desc = html.escape(f.description)
            remed = html.escape(f.remediation or "Apply current vendor security patches, configure defensive access control, and enforce strict input validation.")
            cwe = html.escape(f.cwe or "N/A")
            mod_name = html.escape(f.source_module_name or f.source_module)

            evidence_str = ""
            if f.evidence and isinstance(f.evidence, dict):
                evidence_items = []
                for k, v in f.evidence.items():
                    evidence_items.append(f"<strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}")
                evidence_str = f"<div class='evidence-block'>{'<br>'.join(evidence_items)}</div>"

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title-group">
                        <span class="finding-num">#{idx}</span>
                        <span class="badge" style="background: {s_color}22; color: {s_color}; border: 1px solid {s_color}44;">
                            {f.severity.upper()}
                        </span>
                        <h4 class="finding-title">{f_title}</h4>
                    </div>
                    <div class="cvss-badge">
                        <span>CVSS</span>
                        <strong>{f.cvss_score:.1f}</strong>
                    </div>
                </div>

                <div class="finding-meta-grid">
                    <div><strong>Target Asset:</strong> <code>{loc}</code></div>
                    <div><strong>Source Engine:</strong> {mod_name}</div>
                    <div><strong>CWE:</strong> {cwe}</div>
                    <div><strong>Status:</strong> {f.status.upper()}</div>
                </div>

                <div class="finding-body">
                    <p><strong>Description:</strong> {desc}</p>
                    {evidence_str}
                    <div class="remediation-box">
                        <strong>Actionable Remediation:</strong>
                        <p>{remed}</p>
                    </div>
                </div>
            </div>
            """

        if not findings_html:
            findings_html = """
            <div class="clean-state">
                <div style="font-size: 36px; margin-bottom: 8px;">🛡️</div>
                <h3>Zero Open Vulnerabilities Detected</h3>
                <p>All scanned security modules returned clean or have been fully remediated.</p>
            </div>
            """

        # Return full self-contained HTML
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        :root {{
            --bg-page: #0f172a;
            --bg-card: #1e293b;
            --bg-inset: #090d16;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --text-subtle: #64748b;
            --accent: #38bdf8;
            --font-main: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, "Cascadia Code", "Source Code Pro", Menlo, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-page);
            color: var(--text-primary);
            font-family: var(--font-main);
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .report-wrapper {{
            max-width: 960px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 48px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        /* Header Cover */
        .report-header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 28px;
            margin-bottom: 36px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #ffffff;
            margin-bottom: 6px;
        }}
        .brand-sub {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700;
        }}
        .report-confidential-pill {{
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        /* Scope Meta */
        .scope-box {{
            background: var(--bg-inset);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 36px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            font-size: 13px;
        }}
        .scope-box strong {{ color: var(--text-muted); text-transform: uppercase; font-size: 11px; display: block; margin-bottom: 2px; }}
        .scope-box span {{ font-size: 14px; font-weight: 600; color: var(--text-primary); }}

        /* Score Cards Grid */
        .score-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 36px;
        }}
        .score-card {{
            background: var(--bg-inset);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px 20px;
            text-align: center;
        }}
        .score-card-label {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 6px;
        }}
        .score-card-value {{
            font-size: 32px;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 4px;
        }}
        .score-card-sub {{ font-size: 11px; color: var(--text-subtle); }}

        /* Section Headings */
        .section-title {{
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #ffffff;
            margin: 36px 0 16px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        /* Attack Surface Grid */
        .surface-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-bottom: 24px;
        }}
        .surface-table th, .surface-table td {{
            padding: 10px 14px;
            border: 1px solid var(--border);
            text-align: left;
        }}
        .surface-table th {{ background: var(--bg-inset); color: var(--text-muted); font-size: 11px; text-transform: uppercase; font-weight: 700; }}

        /* Findings List */
        .finding-card {{
            background: var(--bg-inset);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 18px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }}
        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding-num {{
            font-size: 13px;
            font-weight: 800;
            color: var(--text-subtle);
        }}
        .badge {{
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .finding-title {{
            font-size: 15px;
            font-weight: 700;
            color: #ffffff;
        }}
        .cvss-badge {{
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .cvss-badge span {{ font-size: 10px; color: var(--text-muted); }}
        .cvss-badge strong {{ color: #ffffff; font-weight: 800; }}

        .finding-meta-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px 16px;
            font-size: 12px;
            background: var(--bg-card);
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 14px;
            border: 1px solid var(--border);
        }}
        .finding-meta-grid code {{
            font-family: var(--font-mono);
            color: var(--accent);
            background: rgba(56, 189, 248, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .finding-body p {{
            font-size: 13px;
            color: #e2e8f0;
            margin-bottom: 10px;
        }}
        .evidence-block {{
            background: #000000;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 14px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: #38bdf8;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid #10b981;
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            font-size: 12px;
            color: #d1fae5;
            margin-top: 10px;
        }}
        .clean-state {{
            padding: 40px;
            text-align: center;
            background: var(--bg-inset);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-muted);
        }}

        /* Print Actions / Toolbar */
        .print-toolbar {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            display: flex;
            gap: 12px;
            z-index: 1000;
        }}
        .btn-print {{
            background: #1f6feb;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 4px 16px rgba(31, 111, 235, 0.4);
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        @media print {{
            body {{ background: #ffffff !important; color: #000000 !important; padding: 0 !important; }}
            .report-wrapper {{ box-shadow: none !important; border: none !important; max-width: 100% !important; padding: 0 !important; }}
            .print-toolbar {{ display: none !important; }}
            .score-card, .finding-card, .scope-box {{ background: #f8fafc !important; color: #000000 !important; border-color: #cbd5e1 !important; page-break-inside: avoid; }}
            .finding-title, .brand-title, .section-title {{ color: #000000 !important; }}
            .finding-body p {{ color: #334155 !important; }}
            .remediation-box {{ background: #f0fdf4 !important; color: #166534 !important; border-color: #22c55e !important; }}
            .evidence-block {{ background: #f1f5f9 !important; color: #0f172a !important; border-color: #cbd5e1 !important; }}
        }}
    </style>
</head>
<body>
    <div class="report-wrapper">
        <!-- Cover & Title -->
        <header class="report-header">
            <div>
                <h1 class="brand-title">AttackLens Security Assessment</h1>
                <div class="brand-sub">CONFIDENTIAL SECURITY AUDIT DELIVERABLE</div>
            </div>
            <div class="report-confidential-pill">
                CONFIDENTIAL
            </div>
        </header>

        <!-- Scope & Assessment Context -->
        <div class="scope-box">
            <div>
                <strong>Assessment Target Scope</strong>
                <span>{html.escape(scope_label)}</span>
            </div>
            <div>
                <strong>Report Type</strong>
                <span>{html.escape(title.split('—')[0].strip())}</span>
            </div>
            <div>
                <strong>Assessment Date</strong>
                <span>{now_str}</span>
            </div>
            <div>
                <strong>Auditor Engine</strong>
                <span>AttackLens Autonomous Security Suite</span>
            </div>
        </div>

        <!-- Executive Metrics KPI -->
        <div class="score-grid">
            <div class="score-card">
                <div class="score-card-label">Overall Risk Score</div>
                <div class="score-card-value" style="color: {risk_color};">{risk_score:.1f}</div>
                <div class="score-card-sub">{risk_level} Threat Posture</div>
            </div>
            <div class="score-card">
                <div class="score-card-label">Security Grade</div>
                <div class="score-card-value" style="color: {grade_color};">{grade}</div>
                <div class="score-card-sub">{posture_score:.1f}% Posture Readiness</div>
            </div>
            <div class="score-card">
                <div class="score-card-label">Attack Surface</div>
                <div class="score-card-value" style="color: #38bdf8;">{total_assets}</div>
                <div class="score-card-sub">Cataloged Assets</div>
            </div>
            <div class="score-card">
                <div class="score-card-label">Open Findings</div>
                <div class="score-card-value" style="color: #ef4444;">{total_findings}</div>
                <div class="score-card-sub">{crit_count} Critical, {high_count} High</div>
            </div>
        </div>

        <!-- Section 1: Executive Summary -->
        <h3 class="section-title">1. Executive Summary</h3>
        <p style="font-size: 14px; color: #cbd5e1; margin-bottom: 16px;">
            AttackLens completed an automated security assessment on <strong>{html.escape(scope_label)}</strong>. 
            The target evaluated at a <strong>{risk_level} Threat Level (Grade {grade}, Risk Score {risk_score:.1f}/100)</strong>. 
            A total of <strong>{total_assets}</strong> attack surface assets were identified across network ports, active services, technologies, and API routes.
            The inspection cataloged <strong>{total_findings}</strong> deduplicated security findings, comprising 
            <strong style="color: #ef4444;">{crit_count} Critical</strong>, 
            <strong style="color: #f97316;">{high_count} High</strong>, 
            <strong style="color: #eab308;">{med_count} Medium</strong>, and 
            <strong style="color: #3b82f6;">{low_count + info_count} Low/Informational</strong> issues.
        </p>

        <!-- Section 2: Attack Surface Breakdown -->
        <h3 class="section-title">2. Attack Surface & Asset Inventory</h3>
        <table class="surface-table">
            <thead>
                <tr>
                    <th>Asset Category</th>
                    <th>Count</th>
                    <th>Security Exposure Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Open Network Ports</strong></td>
                    <td>{ports_count}</td>
                    <td>Discovered TCP/UDP listeners exposing running services.</td>
                </tr>
                <tr>
                    <td><strong>Web Technologies</strong></td>
                    <td>{tech_count}</td>
                    <td>Identified frameworks, programming runtimes, UI libraries, and web servers.</td>
                </tr>
                <tr>
                    <td><strong>HTTP Endpoints</strong></td>
                    <td>{endpoints_count}</td>
                    <td>Crawled web routes, authentication portals, and hidden directories.</td>
                </tr>
                <tr>
                    <td><strong>API Interfaces</strong></td>
                    <td>{apis_count}</td>
                    <td>Cataloged REST / GraphQL endpoints and request parameters.</td>
                </tr>
                <tr>
                    <td><strong>TLS / SSL Configurations</strong></td>
                    <td>{tls_count}</td>
                    <td>Audited certificates, cipher suites, and protocol versions.</td>
                </tr>
            </tbody>
        </table>

        <!-- Section 3: Detailed Vulnerability Findings -->
        <h3 class="section-title">3. Detailed Security Findings & Evidence</h3>
        <div class="findings-list">
            {findings_html}
        </div>

        <!-- Section 4: Remediation Roadmap -->
        <h3 class="section-title">4. Strategic Remediation Roadmap</h3>
        <div style="background: var(--bg-inset); border: 1px solid var(--border); border-radius: 8px; padding: 20px 24px; font-size: 13px;">
            <ol style="padding-left: 20px; line-height: 1.8; color: #cbd5e1;">
                <li><strong>Immediate (24-48 Hours):</strong> Remediate all {crit_count} Critical severity vulnerabilities and isolate exposed database/administrative ports from the public internet.</li>
                <li><strong>Near-Term (1-2 Weeks):</strong> Apply security patches for all {high_count} High severity issues, implement strict CORS/CSP header directives, and renew TLS cipher suites.</li>
                <li><strong>Continuous:</strong> Integrate AttackLens automated unified scans into the continuous delivery pipeline to detect attack surface drift.</li>
            </ol>
        </div>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); font-size: 11px; color: var(--text-subtle); display: flex; justify-content: space-between;">
            <span>Generated by AttackLens Security Suite</span>
            <span>Document ID: {html.escape(scope_label)}-{timezone.now().strftime("%Y%m%d")}</span>
        </footer>
    </div>

    <!-- Interactive Print Button -->
    <div class="print-toolbar">
        <button class="btn-print" onclick="window.print()">
            🖨️ Print / Save as PDF
        </button>
    </div>
</body>
</html>
"""
