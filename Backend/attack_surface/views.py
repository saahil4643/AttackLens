"""
Views for Overall Web Application Attack-Surface Analysis.
"""
import json
import time
from typing import Generator
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from scan.views import parse_request_params, add_cors_headers
from .services.web_application_analyzer import analyze_web_application_attack_surface


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def web_application_analysis(request):
    """
    Standard synchronous Overall Web Application Attack-Surface Analysis API.
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
        result = analyze_web_application_attack_surface(str(raw_target).strip(), max_crawl_pages=max_pages)
        status_code = 200 if result.get("success", False) else 400
        return add_cors_headers(JsonResponse(result, status=status_code))
    except Exception as e:
        return add_cors_headers(JsonResponse({
            "success": False,
            "target": raw_target,
            "error": f"Internal attack surface analysis error: {str(e)}"
        }, status=500))


def stream_attack_surface_generator(raw_target: str, max_pages: int = 15) -> Generator[str, None, None]:
    """
    Generator that executes Web Application Attack-Surface Analysis and streams real-time SSE progress events.
    """
    import queue
    import threading

    start_time = time.time()
    event_queue = queue.Queue()

    init_event = {
        "event": "init",
        "message": f"Starting Attack-Surface Mapping for target '{raw_target}'...",
        "target": raw_target,
        "elapsed_seconds": 0.0
    }
    yield f"data: {json.dumps(init_event)}\n\n"

    def worker():
        try:
            def on_event(evt, msg, d=None):
                event_queue.put((evt, msg, d))

            result = analyze_web_application_attack_surface(
                raw_target=raw_target,
                max_crawl_pages=max_pages,
                event_callback=on_event
            )
            event_queue.put(("complete", "Attack surface analysis completed successfully.", result))
            event_queue.put(None)  # Sentinel to terminate queue stream
        except Exception as e:
            event_queue.put(("error", f"Attack Surface Analysis failed: {str(e)}", str(e)))
            event_queue.put(None)

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()

    while True:
        try:
            item = event_queue.get(timeout=0.2)
            if item is None:
                break
            evt, msg, d = item
            stage_event = {
                "event": evt,
                "message": msg,
                "target": raw_target,
                "elapsed_seconds": round(time.time() - start_time, 2),
                "data": d if evt == "complete" else None
            }
            if evt == "error":
                stage_event["error"] = str(d)
            yield f"data: {json.dumps(stage_event)}\n\n"
        except queue.Empty:
            if not worker_thread.is_alive() and event_queue.empty():
                break
            continue


@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def stream_web_application_analysis(request):
    """
    Live Streaming Web Application Attack-Surface Analysis API via Server-Sent Events (SSE).
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
        stream_attack_surface_generator(str(raw_target).strip(), max_pages=max_pages),
        content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return add_cors_headers(response)
