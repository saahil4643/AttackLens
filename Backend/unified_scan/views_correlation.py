"""
REST API Views for Attack Surface Correlation Engine.
Exposes endpoints for correlated attack surface graph, hierarchical tree, and asset inventory.
"""

import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .services.correlation_engine import AttackSurfaceCorrelationEngine
from .models import UnifiedScanRecord

logger = logging.getLogger("unified_scan.views_correlation")


@csrf_exempt
@require_http_methods(["GET"])
def get_attack_surface_correlation_view(request):
    """
    GET /api/attack-surface/correlation/ or /api/attack-surface/graph/
    Returns full relational attack surface graph (nodes, edges), hierarchical tree, and inventory.
    Query parameters:
      - target: target host or URL (default to most recent scan target)
      - scan_id: specific UnifiedScanRecord UUID
    """
    try:
        scan_id = request.GET.get("scan_id") or request.GET.get("scanId")
        target = request.GET.get("target")

        if scan_id:
            data = AttackSurfaceCorrelationEngine.correlate_scan(scan_id)
        elif target:
            data = AttackSurfaceCorrelationEngine.correlate_target(target)
        else:
            # Pick most recent scan or fallback to default
            latest_scan = UnifiedScanRecord.objects.order_by("-created_at").first()
            if latest_scan:
                data = AttackSurfaceCorrelationEngine.correlate_scan(str(latest_scan.id))
            else:
                data = AttackSurfaceCorrelationEngine.correlate_target("http://127.0.0.1:8000")

        return JsonResponse(data, status=200)
    except ValueError as ve:
        return JsonResponse({"success": False, "error": str(ve)}, status=404)
    except Exception as e:
        logger.error(f"Error computing attack surface correlation: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_attack_surface_inventory_view(request):
    """
    GET /api/attack-surface/inventory/
    Returns categorized asset inventory (domains, ports, services, technologies, endpoints, apis, findings).
    """
    try:
        target = request.GET.get("target")
        scan_id = request.GET.get("scan_id")

        if scan_id:
            full_data = AttackSurfaceCorrelationEngine.correlate_scan(scan_id)
        elif target:
            full_data = AttackSurfaceCorrelationEngine.correlate_target(target)
        else:
            latest_scan = UnifiedScanRecord.objects.order_by("-created_at").first()
            if latest_scan:
                full_data = AttackSurfaceCorrelationEngine.correlate_scan(str(latest_scan.id))
            else:
                full_data = AttackSurfaceCorrelationEngine.correlate_target("http://127.0.0.1:8000")

        return JsonResponse({
            "success": True,
            "target": full_data.get("target"),
            "summary": full_data.get("summary"),
            "inventory": full_data.get("inventory"),
        }, status=200)
    except Exception as e:
        logger.error(f"Error retrieving attack surface inventory: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def recalculate_attack_surface_view(request):
    """
    POST /api/attack-surface/correlate/
    Forces re-correlation of attack surface for target or scan.
    """
    try:
        try:
            body = json.loads(request.body.decode("utf-8")) if request.body else {}
        except json.JSONDecodeError:
            body = {}

        target = body.get("target") or request.GET.get("target")
        scan_id = body.get("scan_id") or request.GET.get("scan_id")

        if scan_id:
            data = AttackSurfaceCorrelationEngine.correlate_scan(scan_id)
        elif target:
            data = AttackSurfaceCorrelationEngine.correlate_target(target)
        else:
            latest_scan = UnifiedScanRecord.objects.order_by("-created_at").first()
            if latest_scan:
                data = AttackSurfaceCorrelationEngine.correlate_scan(str(latest_scan.id))
            else:
                data = AttackSurfaceCorrelationEngine.correlate_target("http://127.0.0.1:8000")

        return JsonResponse({
            "success": True,
            "message": "Attack surface correlation refreshed.",
            "data": data
        }, status=200)
    except Exception as e:
        logger.error(f"Error recalculating attack surface: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)
