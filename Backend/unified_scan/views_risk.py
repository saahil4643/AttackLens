"""
REST API Views for Risk Scoring Engine.
Exposes endpoints for overall, target-specific, and scan-specific risk assessments.
"""

import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .services.risk_engine import RiskScoringEngine

logger = logging.getLogger("unified_scan.views_risk")


@csrf_exempt
@require_http_methods(["GET"])
def get_risk_summary_view(request):
    """
    GET /api/risk/summary/ or /api/risk/
    Returns enterprise-wide risk score, posture rating, severity breakdown, top risks, and module risk matrix.
    Query parameter:
      - target: optional target filter to compute risk specifically for that target.
    """
    try:
        target = request.GET.get("target")
        if target:
            data = RiskScoringEngine.calculate_target_risk(target)
        else:
            data = RiskScoringEngine.calculate_global_risk()

        return JsonResponse({"success": True, "risk": data}, status=200)
    except Exception as e:
        logger.error(f"Error calculating risk summary: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_target_risk_view(request):
    """
    GET /api/risk/target/?target=<url_or_domain>
    Returns risk calculation tailored to a single target asset.
    """
    try:
        target = request.GET.get("target")
        if not target:
            return JsonResponse({"success": False, "error": "Missing 'target' parameter."}, status=400)

        data = RiskScoringEngine.calculate_target_risk(target)
        return JsonResponse({"success": True, "risk": data}, status=200)
    except Exception as e:
        logger.error(f"Error calculating target risk for '{request.GET.get('target')}': {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_scan_risk_view(request, scan_id):
    """
    GET /api/risk/scan/<scan_id>/
    Returns risk evaluation specific to a single UnifiedScanRecord.
    """
    try:
        data = RiskScoringEngine.calculate_scan_risk(str(scan_id))
        return JsonResponse({"success": True, "risk": data}, status=200)
    except ValueError as ve:
        return JsonResponse({"success": False, "error": str(ve)}, status=404)
    except Exception as e:
        logger.error(f"Error calculating scan risk for '{scan_id}': {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_risk_trends_view(request):
    """
    GET /api/risk/trends/
    Returns historical timeline of risk scores over recent completed scans.
    """
    try:
        limit = int(request.GET.get("limit", "15"))
        trends = RiskScoringEngine.get_risk_trends(limit=limit)
        return JsonResponse({"success": True, "trends": trends}, status=200)
    except Exception as e:
        logger.error(f"Error retrieving risk trends: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def recalculate_risk_view(request):
    """
    POST /api/risk/recalculate/
    Explicitly forces recalculation and returns fresh risk posture data.
    """
    try:
        target = request.GET.get("target")
        if target:
            data = RiskScoringEngine.calculate_target_risk(target)
        else:
            data = RiskScoringEngine.calculate_global_risk()

        return JsonResponse({
            "success": True,
            "message": "Risk scores recalculated successfully.",
            "risk": data
        }, status=200)
    except Exception as e:
        logger.error(f"Error recalculating risk: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)
