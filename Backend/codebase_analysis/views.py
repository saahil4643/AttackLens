"""
Codebase Security Analysis Django Views
"""

import json
import time
from typing import Generator
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import add_cors_headers, parse_request_params
from .services.codebase_scanner import scan_project_zip
from .services.sample_project import build_sample_vulnerable_project_zip


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def codebase_scan(request):
    """
    Standard synchronous Codebase Security Analysis API.
    Accepts multipart/form-data with `project` or `file` containing the ZIP archive.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    uploaded_file = request.FILES.get("project") or request.FILES.get("file")
    if not uploaded_file:
        return add_cors_headers(JsonResponse({
            "success": False,
            "scan_status": "rejected",
            "error": "No project ZIP file provided in upload. Expected multipart form field 'project' or 'file'."
        }, status=400))

    project_name = request.POST.get("name") or uploaded_file.name

    try:
        result = scan_project_zip(uploaded_file, project_name=project_name)
        status_code = 200 if result.get("success", False) else 400
        return add_cors_headers(JsonResponse(result, status=status_code))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "scan_status": "failed",
            "error": f"Internal scan error: {str(e)}"
        }, status=500))


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def sample_codebase_scan(request):
    """
    Instant 1-Click Codebase Security Scan using the modeled multi-language sample project.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    try:
        sample_zip = build_sample_vulnerable_project_zip()
        result = scan_project_zip(sample_zip, project_name="AttackLens Demo Multi-Stack Repository")
        return add_cors_headers(JsonResponse(result, status=200))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "scan_status": "failed",
            "error": f"Sample scan error: {str(e)}"
        }, status=500))


def stream_codebase_generator(uploaded_file, project_name: str) -> Generator[str, None, None]:
    """
    Generator streaming real-time Server-Sent Events (SSE) during codebase scanning.
    """
    start_time = time.time()
    events_buffer = []

    init_event = {
        "event": "init",
        "message": f"Starting Codebase Security Scan for '{project_name}'...",
        "project": project_name,
        "elapsed_seconds": 0.0
    }
    yield f"data: {json.dumps(init_event)}\n\n"

    try:
        def on_event(evt: str, msg: str, d=None):
            events_buffer.append((evt, msg, d))

        result = scan_project_zip(uploaded_file, project_name=project_name, event_callback=on_event)

        for evt, msg, d in events_buffer:
            stage_event = {
                "event": evt,
                "message": msg,
                "project": project_name,
                "elapsed_seconds": round(time.time() - start_time, 2),
                "data": d if evt == "complete" else None
            }
            yield f"data: {json.dumps(stage_event)}\n\n"

    except Exception as e:
        err_event = {
            "event": "error",
            "message": f"Scan failed: {str(e)}",
            "project": project_name,
            "error": str(e)
        }
        yield f"data: {json.dumps(err_event)}\n\n"


@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def stream_codebase_scan(request):
    """
    Live streaming SSE Codebase Security Scan API.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    uploaded_file = request.FILES.get("project") or request.FILES.get("file")
    if not uploaded_file:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": "No project ZIP file provided in upload."
        }, status=400))

    project_name = request.POST.get("name") or uploaded_file.name

    response = StreamingHttpResponse(
        stream_codebase_generator(uploaded_file, project_name),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
