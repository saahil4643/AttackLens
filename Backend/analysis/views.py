"""
Analysis Views: Security Configuration & Web Security Analysis
"""
import json
import time
from typing import Generator
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import parse_request_params, add_cors_headers
from .engine.analyzer import analyze_security_configuration


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def security_configuration(request):
    """
    Standard synchronous Security Configuration Analysis API.
    GET/POST: target=<target>
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    raw_target = params.get("target") or params.get("host") or params.get("url")
    if not raw_target:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": "Target parameter is required (e.g. ?target=https://example.com)"
        }, status=400))

    try:
        result = analyze_security_configuration(str(raw_target).strip())
        status_code = 200 if result.get("success", False) else 400
        return add_cors_headers(JsonResponse(result, status=status_code))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "target": raw_target,
            "error": f"Internal scan error: {str(e)}"
        }, status=500))


def stream_security_config_generator(raw_target: str) -> Generator[str, None, None]:
    """
    Generator that executes security analysis and streams real-time SSE progress events.
    """
    start_time = time.time()

    def sse_callback(event_name: str, message: str, data=None):
        nonlocal sse_callback
        payload = {
            "event": event_name,
            "message": message,
            "target": raw_target,
            "elapsed_seconds": round(time.time() - start_time, 2),
            "data": data
        }
        return f"data: {json.dumps(payload)}\n\n"

    events_buffer = []

    def collector_callback(event_name: str, message: str, data=None):
        events_buffer.append({
            "event": event_name,
            "message": message,
            "data": data,
            "elapsed": round(time.time() - start_time, 2)
        })

    # To yield SSE live smoothly during multi-step analysis:
    # 1. Initial event
    init_event = {
        "event": "init",
        "message": f"Starting security configuration assessment for target '{raw_target}'...",
        "target": raw_target,
        "elapsed_seconds": 0.0
    }
    yield f"data: {json.dumps(init_event)}\n\n"

    try:
        # Run analyzer with live yield closure if possible or run synchronously and yield stages
        result = analyze_security_configuration(
            raw_target=raw_target,
            event_callback=lambda evt, msg, d=None: events_buffer.append((evt, msg, d))
        )

        for evt, msg, d in events_buffer:
            stage_event = {
                "event": evt,
                "message": msg,
                "target": raw_target,
                "elapsed_seconds": round(time.time() - start_time, 2),
                "data": d if evt == "complete" else None
            }
            yield f"data: {json.dumps(stage_event)}\n\n"

    except Exception as e:
        error_event = {
            "event": "error",
            "message": f"Security configuration scan failed: {str(e)}",
            "target": raw_target,
            "error": str(e)
        }
        yield f"data: {json.dumps(error_event)}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_security_configuration(request):
    """
    Live Streaming Security Configuration API via Server-Sent Events (SSE).
    """
    if request.method == "OPTIONS":
        return add_cors_headers(HttpResponse(status=204))

    params, err = parse_request_params(request)
    if err:
        return add_cors_headers(JsonResponse({"success": False, "error": err}, status=400))

    raw_target = params.get("target") or params.get("host") or params.get("url")
    if not raw_target:
        return add_cors_headers(JsonResponse({
            "success": False,
            "error": "Target parameter is required"
        }, status=400))

    response = StreamingHttpResponse(
        stream_security_config_generator(str(raw_target).strip()),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
