"""
TLS Analysis Views
"""
import json
import time
from typing import Generator
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import parse_request_params, add_cors_headers
from .services.tls_scanner import scan_tls_security


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def tls_analysis(request):
    """
    Standard synchronous TLS/SSL Security Analysis API.
    GET / POST: ?target=<target>
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
        result = scan_tls_security(str(raw_target).strip())
        status_code = 200 if result.get("success", False) else 400
        return add_cors_headers(JsonResponse(result, status=status_code))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "target": raw_target,
            "error": f"Internal TLS scan error: {str(e)}"
        }, status=500))


def stream_tls_generator(raw_target: str) -> Generator[str, None, None]:
    """
    Generator that executes TLS security analysis and yields real-time SSE progress events.
    """
    start_time = time.time()
    events_buffer = []

    init_event = {
        "event": "init",
        "message": f"Starting TLS/SSL assessment for target '{raw_target}'...",
        "target": raw_target,
        "elapsed_seconds": 0.0
    }
    yield f"data: {json.dumps(init_event)}\n\n"

    try:
        result = scan_tls_security(
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
            "message": f"TLS security assessment failed: {str(e)}",
            "target": raw_target,
            "error": str(e)
        }
        yield f"data: {json.dumps(error_event)}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_tls_analysis(request):
    """
    Live Streaming TLS/SSL Security Analysis API via Server-Sent Events (SSE).
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
        stream_tls_generator(str(raw_target).strip()),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
