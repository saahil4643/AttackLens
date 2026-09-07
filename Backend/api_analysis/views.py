"""
API Deep Analysis Views
"""
import json
import time
from typing import Generator
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import parse_request_params, add_cors_headers
from .services.api_scanner import scan_api_inventory


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def api_analysis(request):
    """
    Standard synchronous API Deep Analysis & Inventory API.
    GET / POST: ?target=<target>&max_pages=15
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
        max_pages = int(params.get("max_pages", 15))
        max_pages = max(1, min(max_pages, 50))
    except (ValueError, TypeError):
        max_pages = 15

    try:
        result = scan_api_inventory(str(raw_target).strip(), max_crawl_pages=max_pages)
        status_code = 200 if result.get("success", False) else 400
        return add_cors_headers(JsonResponse(result, status=status_code))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "target": raw_target,
            "error": f"Internal API scan error: {str(e)}"
        }, status=500))


def stream_api_generator(raw_target: str, max_pages: int = 15) -> Generator[str, None, None]:
    """
    Generator that executes API Deep Analysis and streams real-time SSE progress events.
    """
    start_time = time.time()
    events_buffer = []

    init_event = {
        "event": "init",
        "message": f"Starting API Deep Analysis for target '{raw_target}'...",
        "target": raw_target,
        "elapsed_seconds": 0.0
    }
    yield f"data: {json.dumps(init_event)}\n\n"

    try:
        result = scan_api_inventory(
            raw_target=raw_target,
            max_crawl_pages=max_pages,
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
            "message": f"API Deep Analysis failed: {str(e)}",
            "target": raw_target,
            "error": str(e)
        }
        yield f"data: {json.dumps(error_event)}\n\n"


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_api_analysis(request):
    """
    Live Streaming API Deep Analysis API via Server-Sent Events (SSE).
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

    try:
        max_pages = int(params.get("max_pages", 15))
        max_pages = max(1, min(max_pages, 50))
    except (ValueError, TypeError):
        max_pages = 15

    response = StreamingHttpResponse(
        stream_api_generator(str(raw_target).strip(), max_pages=max_pages),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
