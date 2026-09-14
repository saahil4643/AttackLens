"""
Unified Scan Django REST Views
"""

import json
import queue
import time
from typing import Generator

from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import add_cors_headers, parse_request_params
from .models import UnifiedScanRecord
from .services.orchestrator import (
    MODULE_METADATA,
    ACTIVE_SCAN_ABORT_SIGNALS,
    UnifiedScanOrchestrator,
    launch_unified_scan_background
)


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def start_unified_scan(request):
    """
    Starts an asynchronous Unified Security Assessment.
    Supports application/json and multipart/form-data (with optional codebase ZIP file).
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    uploaded_file = request.FILES.get("file") or request.FILES.get("project")
    uploaded_zip_bytes = None
    uploaded_zip_name = ""

    if uploaded_file:
        uploaded_zip_bytes = uploaded_file.read()
        uploaded_zip_name = uploaded_file.name

    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    raw_target = params.get("target") or params.get("host") or params.get("url")
    if not raw_target:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": "Target parameter is required (e.g. 'http://127.0.0.1:8000' or 'example.com')"
        }, status=400))

    raw_target = str(raw_target).strip()

    # Parse requested modules
    raw_modules = params.get("modules") or params.get("selected_modules")
    if isinstance(raw_modules, str):
        try:
            active_modules = json.loads(raw_modules)
        except Exception:
            active_modules = [m.strip() for m in raw_modules.split(",") if m.strip()]
    elif isinstance(raw_modules, list):
        active_modules = raw_modules
    else:
        active_modules = list(MODULE_METADATA.keys())

    # Filter valid modules and deduplicate
    active_modules = list(dict.fromkeys([m for m in active_modules if m in MODULE_METADATA]))
    if not active_modules:
        active_modules = list(MODULE_METADATA.keys())

    scan_profile = str(params.get("scan_profile") or params.get("profile") or "standard").lower()
    if scan_profile not in ("quick", "standard", "deep"):
        scan_profile = "standard"

    intensity = str(params.get("intensity") or "normal").lower()
    if intensity not in ("low", "normal", "aggressive"):
        intensity = "normal"

    codebase_source_type = str(params.get("codebase_source_type") or ("zip" if uploaded_file else "path")).lower()
    codebase_path = str(params.get("codebase_path") or "").strip()

    # Create Database Record
    record = UnifiedScanRecord.objects.create(
        target=raw_target,
        scan_profile=scan_profile,
        intensity=intensity,
        status="PENDING",
        progress_percent=0,
        codebase_source_type=codebase_source_type,
        codebase_path=codebase_path,
        codebase_zip_name=uploaded_zip_name,
        active_modules=active_modules,
        findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        module_statuses={
            m: {
                "id": m,
                "status": "pending",
                "progress_percent": 0,
                "current_step": "Queued in orchestration pipeline",
                "summary_text": "Waiting for execution slot"
            }
            for m in active_modules
        }
    )

    # Launch background orchestration thread
    launch_unified_scan_background(
        record_id=str(record.id),
        target=raw_target,
        active_module_ids=active_modules,
        scan_profile=scan_profile,
        intensity=intensity,
        codebase_source_type=codebase_source_type,
        codebase_path=codebase_path,
        uploaded_zip_bytes=uploaded_zip_bytes,
        uploaded_zip_name=uploaded_zip_name
    )

    response = JsonResponse({
        "success": True,
        "scan_id": str(record.id),
        "status": record.status,
        "message": f"Unified scan initialized with {len(active_modules)} modules ({scan_profile.upper()} profile)",
        "scan": record.to_dict()
    }, status=201)
    return add_cors_headers(response)


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def get_unified_scan_status(request, scan_id: str):
    """
    Retrieves the lightweight real-time execution progress of a Unified Scan.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    record = UnifiedScanRecord.objects.filter(id=scan_id).first()
    if not record:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": f"Unified scan '{scan_id}' not found."
        }, status=404))

    response = JsonResponse({
        "success": True,
        "scan_id": str(record.id),
        "target": record.target,
        "cleaned_target": record.cleaned_target,
        "resolved_ip": record.resolved_ip,
        "status": record.status,
        "progress_percent": record.progress_percent,
        "current_module_id": record.current_module_id,
        "scan_profile": record.scan_profile,
        "overall_score": record.overall_score,
        "score_grade": record.score_grade,
        "risk_rating": record.risk_rating,
        "findings_summary": record.findings_summary or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "module_statuses": record.module_statuses,
        "logs": record.logs[-40:],  # Last 40 log events
        "error_message": record.error_message,
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None
    })
    return add_cors_headers(response)


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def get_unified_scan_results(request, scan_id: str):
    """
    Retrieves full completed results, consolidated findings, and module breakdowns.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    record = UnifiedScanRecord.objects.filter(id=scan_id).first()
    if not record:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": f"Unified scan '{scan_id}' not found."
        }, status=404))

    response = JsonResponse({
        "success": True,
        "scan": record.to_dict(include_raw_results=True)
    })
    return add_cors_headers(response)


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def abort_unified_scan(request, scan_id: str):
    """
    Signals active scan orchestrator to abort execution gracefully.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    record = UnifiedScanRecord.objects.filter(id=scan_id).first()
    if not record:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": f"Unified scan '{scan_id}' not found."
        }, status=404))

    if scan_id in ACTIVE_SCAN_ABORT_SIGNALS:
        ACTIVE_SCAN_ABORT_SIGNALS[scan_id].set()

    if record.status in ("PENDING", "RUNNING"):
        record.status = "ABORTED"
        record.completed_at = timezone.now()
        record.error_message = "Scan aborted by user request"
        record.save()

    response = JsonResponse({
        "success": True,
        "scan_id": scan_id,
        "status": "ABORTED",
        "message": "Unified scan abortion signal delivered."
    })
    return add_cors_headers(response)


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def list_unified_scans(request):
    """
    Returns list of recent 20 unified scans.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    scans = UnifiedScanRecord.objects.all()[:20]
    data = [s.to_dict(include_raw_results=False) for s in scans]

    response = JsonResponse({
        "success": True,
        "count": len(data),
        "scans": data
    })
    return add_cors_headers(response)


def stream_unified_scan_generator(scan_id: str) -> Generator[str, None, None]:
    """
    Generator streaming real-time Server-Sent Events (SSE) for a unified scan.
    """
    start_time = time.time()
    last_log_count = 0
    record = UnifiedScanRecord.objects.filter(id=scan_id).first()

    if not record:
        yield f"data: {json.dumps({'event': 'error', 'message': 'Scan record not found'})}\n\n"
        return

    init_payload = {
        "event": "init",
        "scan_id": str(record.id),
        "target": record.target,
        "status": record.status,
        "progress_percent": record.progress_percent,
        "active_modules": record.active_modules,
        "timestamp": time.time()
    }
    yield f"data: {json.dumps(init_payload)}\n\n"

    while True:
        try:
            record.refresh_from_db()
            logs = record.logs or []
            
            # Emit any new log events
            if len(logs) > last_log_count:
                for log_item in logs[last_log_count:]:
                    log_event = {
                        "event": "log",
                        "scan_id": str(record.id),
                        "log": log_item,
                        "progress_percent": record.progress_percent,
                        "current_module_id": record.current_module_id,
                        "module_statuses": record.module_statuses
                    }
                    yield f"data: {json.dumps(log_event)}\n\n"
                last_log_count = len(logs)

            if record.status in ("COMPLETED", "FAILED", "ABORTED"):
                complete_payload = {
                    "event": "complete" if record.status == "COMPLETED" else "finished",
                    "scan_id": str(record.id),
                    "status": record.status,
                    "progress_percent": 100 if record.status == "COMPLETED" else record.progress_percent,
                    "overall_score": record.overall_score,
                    "score_grade": record.score_grade,
                    "risk_rating": record.risk_rating,
                    "findings_summary": record.findings_summary,
                    "module_statuses": record.module_statuses,
                    "findings": record.findings,
                    "elapsed_seconds": round(time.time() - start_time, 2)
                }
                yield f"data: {json.dumps(complete_payload)}\n\n"
                break

            time.sleep(0.5)
        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"
            break


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def stream_unified_scan(request, scan_id: str):
    """
    Live streaming SSE endpoint for Unified Scan status and log events.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    response = StreamingHttpResponse(
        stream_unified_scan_generator(scan_id),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
