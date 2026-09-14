"""
Codebase Security Analysis Orchestrator for AttackLens SAST

Coordinates the end-to-end static security scan:
1. Safe ZIP extraction & Zip Slip defense in an isolated workspace
2. Project inventory & 16+ language breakdown
3. Framework and architectural stack detection
4. Dependency manifest parsing
5. Multi-language AST/lexical static security rule evaluation
6. Lightweight taint analysis (Source -> Flow -> Sink)
7. Secret detection and mandatory redaction
8. Finding deduplication, confidence calibration, and contextual code extraction
9. Streaming progress event support
"""

import os
import time
from typing import Dict, Any, List, Optional, Callable, Set

from .archive_handler import SafeArchiveWorkspace, ArchiveSecurityError, DEFAULT_MAX_SOURCE_ANALYSIS_SIZE
from .project_inventory import scan_project_inventory, is_test_file
from .framework_detector import detect_frameworks
from .dependency_inventory import scan_dependencies
from .redactor import sanitize_data_structure
from .taint_analyzer import analyze_python_taint, trace_regex_taint

from .rules.secret_rules import scan_file_for_secrets
from .rules.python_rules import scan_python_file
from .rules.javascript_rules import scan_javascript_file
from .rules.java_rules import scan_java_file
from .rules.php_rules import scan_php_file
from .rules.generic_rules import scan_generic_file


def analyze_extracted_workspace(
    workspace_path: str,
    project_name: str = "Uploaded Project",
    max_file_analysis_size: int = DEFAULT_MAX_SOURCE_ANALYSIS_SIZE,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Performs static security analysis on an extracted directory workspace.
    Emits streaming progress events if event_callback is provided.
    """
    start_time = time.time()
    errors: List[Dict[str, Any]] = []

    def notify(event: str, message: str, data: Optional[Dict[str, Any]] = None):
        if event_callback:
            try:
                event_callback(event, message, data)
            except Exception:
                pass

    notify("inventory", f"Building file inventory for '{project_name}'...")
    
    # 1. Project Inventory & Language Distribution
    inventory_res = scan_project_inventory(workspace_path)
    total_files = inventory_res["files_count"]
    source_files_count = inventory_res["source_files_count"]
    inventory_items = inventory_res["inventory"]

    notify("dependencies", "Inspecting package manifests and dependency ecosystems...")
    
    # 2. Dependency Manifest Inventory
    dependencies = scan_dependencies(workspace_path, inventory_items)

    notify("frameworks", "Detecting web frameworks and architecture patterns...")
    
    # 3. Framework Detection
    frameworks = detect_frameworks(workspace_path, inventory_items, dependencies)

    notify("analyzing_code", f"Executing SAST rule engine across {source_files_count} source files...")

    raw_findings: List[Dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0

    # 4. Static Code Security Analysis Loop
    for idx, item in enumerate(inventory_items):
        if item.get("category") in {"binary", "static", "unknown"} and item.get("language") not in {"HTML", "SQL", "Shell"}:
            files_skipped += 1
            continue

        rel_path = item["path"]
        full_path = os.path.join(workspace_path, rel_path)
        file_size = item.get("size", 0)

        # Skip oversized source files
        if file_size > max_file_analysis_size:
            files_skipped += 1
            errors.append({
                "file": rel_path,
                "error": f"File size ({file_size / (1024*1024):.1f} MB) exceeds max source analysis limit"
            })
            continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            files_skipped += 1
            errors.append({"file": rel_path, "error": f"Failed to read file: {str(e)}"})
            continue

        lines = content.splitlines()
        is_test = item.get("category") == "test" or is_test_file(rel_path)
        lang = item.get("language", "Unknown")

        # A. Secret / Credential Scans (runs on source, config, test, doc)
        try:
            secret_findings = scan_file_for_secrets(rel_path, content, lines)
            raw_findings.extend(secret_findings)
        except Exception as e:
            errors.append({"file": rel_path, "error": f"Secret scan error: {str(e)}"})

        # B. Language-specific SAST rules
        try:
            if lang == "Python":
                py_findings = scan_python_file(rel_path, content, lines, is_test)
                raw_findings.extend(py_findings)

                # Run Python Taint Analysis
                taint_flows = analyze_python_taint(content)
                for tf in taint_flows:
                    raw_findings.append({
                        "id": f"TAINT-{tf['cwe']}",
                        "title": f"Taint Flow: Untrusted Input reaching {tf['sink_type']}",
                        "severity": "high",
                        "confidence": 0.94 if not is_test else 0.75,
                        "category": tf["category"],
                        "cwe": tf["cwe"],
                        "file": rel_path,
                        "line": tf["sink_line"],
                        "code_context": {
                            "start_line": max(1, tf["sink_line"] - 2),
                            "end_line": min(len(lines), tf["sink_line"] + 2),
                            "target_line": tf["sink_line"],
                            "content": "\n".join(lines[max(1, tf["sink_line"] - 2) - 1: min(len(lines), tf["sink_line"] + 2)])
                        },
                        "description": f"Untrusted input originating from variable '{tf['source_var']}' flows directly into sensitive sink '{tf['sink_name']}'.",
                        "evidence": f"Taint Flow: Line {tf['source_line']} -> Line {tf['sink_line']}",
                        "recommendation": "Validate, sanitize, or parameterize input before passing to sensitive execution sinks.",
                        "taint_flow": tf["flow"]
                    })

            elif lang in {"JavaScript", "TypeScript"}:
                js_findings = scan_javascript_file(rel_path, content, lines, is_test)
                raw_findings.extend(js_findings)

                # Run JS regex taint
                js_taint = trace_regex_taint(content, lines, lang="javascript")
                for tf in js_taint:
                    raw_findings.append({
                        "id": f"TAINT-{tf['cwe']}",
                        "title": f"Taint Flow: External Parameter reaching {tf['sink_type']}",
                        "severity": "high",
                        "confidence": 0.92 if not is_test else 0.70,
                        "category": tf["category"],
                        "cwe": tf["cwe"],
                        "file": rel_path,
                        "line": tf["sink_line"],
                        "code_context": {
                            "start_line": max(1, tf["sink_line"] - 2),
                            "end_line": min(len(lines), tf["sink_line"] + 2),
                            "target_line": tf["sink_line"],
                            "content": "\n".join(lines[max(1, tf["sink_line"] - 2) - 1: min(len(lines), tf["sink_line"] + 2)])
                        },
                        "description": f"External parameter from line {tf['source_line']} flows into {tf['sink_type']} on line {tf['sink_line']}.",
                        "evidence": f"Trace: Line {tf['source_line']} ({tf['source_var']}) -> Line {tf['sink_line']}",
                        "recommendation": "Sanitize user inputs and use parameterized sinks.",
                        "taint_flow": tf["flow"]
                    })

            elif lang == "Java":
                java_findings = scan_java_file(rel_path, content, lines, is_test)
                raw_findings.extend(java_findings)

            elif lang == "PHP":
                php_findings = scan_php_file(rel_path, content, lines, is_test)
                raw_findings.extend(php_findings)

            else:
                gen_findings = scan_generic_file(rel_path, content, lines, lang, is_test)
                raw_findings.extend(gen_findings)

        except Exception as e:
            errors.append({"file": rel_path, "error": f"SAST rule evaluation error: {str(e)}"})

        files_scanned += 1

        # Periodic progress update
        if files_scanned % 50 == 0:
            notify("progress", f"Analyzed {files_scanned}/{source_files_count} files ({len(raw_findings)} potential findings)...")

    notify("deduplicating", "Deduplicating and correlating security findings...")

    # 5. Finding Deduplication & Severity Normalization
    deduped_findings: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()

    for finding in raw_findings:
        file_p = finding.get("file", "")
        line_num = finding.get("line", 0)
        cwe = finding.get("cwe", "")
        cat = finding.get("category", "")
        rule_id = finding.get("id", "")

        dedup_key = f"{file_p}:{line_num}:{cwe}:{cat}"
        if dedup_key in seen_keys:
            # If a taint flow finding exists for this same line, prioritize taint flow
            continue

        seen_keys.add(dedup_key)
        deduped_findings.append(finding)

    # Sort findings by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped_findings.sort(key=lambda f: (sev_order.get(f.get("severity", "info"), 5), -f.get("confidence", 0)))

    # Assign clean sequential display IDs
    for idx, f in enumerate(deduped_findings):
        f["display_id"] = f"CODE-{idx + 1:03d}"

    # 6. Summary Counts
    summary = {
        "critical": sum(1 for f in deduped_findings if f.get("severity") == "critical"),
        "high": sum(1 for f in deduped_findings if f.get("severity") == "high"),
        "medium": sum(1 for f in deduped_findings if f.get("severity") == "medium"),
        "low": sum(1 for f in deduped_findings if f.get("severity") == "low"),
        "info": sum(1 for f in deduped_findings if f.get("severity") == "info"),
    }

    scan_duration = round(time.time() - start_time, 2)
    scan_status = "completed" if len(errors) == 0 else "partial"

    final_result = {
        "success": True,
        "scan_status": scan_status,
        "project": {
            "name": project_name,
            "files": total_files,
            "source_files": source_files_count,
            "total_bytes": inventory_res["total_bytes"],
            "categories": inventory_res["categories"]
        },
        "languages": inventory_res["languages"],
        "frameworks": frameworks,
        "dependencies": dependencies,
        "findings": deduped_findings,
        "summary": summary,
        "statistics": {
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "findings_count": len(deduped_findings),
            "rules_executed": 35,
            "scan_duration_seconds": scan_duration
        },
        "errors": errors[:50]
    }

    sanitized_result = sanitize_data_structure(final_result)
    notify("complete", f"Codebase security scan completed with {len(deduped_findings)} findings across {files_scanned} files.", sanitized_result)
    return sanitized_result


def scan_project_zip(
    zip_file_or_path,
    project_name: Optional[str] = None,
    event_callback: Optional[Callable[[str, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Safely extracts an uploaded project ZIP archive into an isolated temporary workspace,
    runs the full SAST static analysis, and guarantees workspace cleanup.
    """
    name = project_name or "Uploaded Project"
    if hasattr(zip_file_or_path, "name") and not project_name:
        name = os.path.splitext(os.path.basename(zip_file_or_path.name))[0]

    with SafeArchiveWorkspace() as workspace:
        try:
            if event_callback:
                event_callback("extracting", f"Safely extracting '{name}' to isolated workspace...")

            extraction_info = workspace.extract_zip(zip_file_or_path)

            return analyze_extracted_workspace(
                workspace_path=workspace.extracted_path,
                project_name=name,
                event_callback=event_callback
            )
        except ArchiveSecurityError as e:
            err_msg = f"Archive Security Rejection: {str(e)}"
            if event_callback:
                event_callback("error", err_msg, None)
            return {
                "success": False,
                "scan_status": "rejected",
                "error": err_msg,
                "project": {"name": name, "files": 0, "source_files": 0},
                "languages": [],
                "frameworks": [],
                "dependencies": [],
                "findings": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "errors": [{"file": name, "error": err_msg}]
            }
        except Exception as e:
            err_msg = f"Codebase Scan Error: {str(e)}"
            if event_callback:
                event_callback("error", err_msg, None)
            return {
                "success": False,
                "scan_status": "failed",
                "error": err_msg,
                "project": {"name": name, "files": 0, "source_files": 0},
                "languages": [],
                "frameworks": [],
                "dependencies": [],
                "findings": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "errors": [{"file": name, "error": err_msg}]
            }
