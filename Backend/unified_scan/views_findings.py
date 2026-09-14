"""
REST API Views for Unified Findings Engine.
Exposes endpoints to query, filter, inspect, and manage security findings across all scanners.
"""

import json
import logging
from typing import Any, Dict

from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Finding, UnifiedScanRecord
from .services.findings_engine import FindingsEngine, VALID_STATUSES

logger = logging.getLogger("unified_scan.views_findings")


@csrf_exempt
@require_http_methods(["GET"])
def list_findings_view(request):
    """
    GET /api/findings/
    Lists unified security findings with filtering, search, sorting, and pagination.

    Query parameters:
      - severity: comma-separated severities (e.g. 'critical,high')
      - module / source_module: comma-separated module IDs
      - status: comma-separated statuses ('open,confirmed,remediated,accepted,false_positive')
      - target: search substring in target
      - search / q: free text search query across title, description, CWE, asset
      - scan_id: filter by specific UnifiedScanRecord UUID
      - cwe: CWE code
      - min_cvss / max_cvss: CVSS range
      - ordering: '-last_seen', '-cvss_score', 'severity', 'title', etc.
      - page: page number (default 1)
      - page_size: items per page (default 50, max 200, 0 for all)
      - include_stats: 'true' to include stats summary in response
    """
    try:
        params = request.GET.dict()
        qs = FindingsEngine.get_findings_queryset(params)

        # Pagination
        page_size_str = request.GET.get("page_size", "50")
        try:
            page_size = int(page_size_str)
        except (ValueError, TypeError):
            page_size = 50

        page_num = request.GET.get("page", "1")

        if page_size > 0:
            paginator = Paginator(qs, min(page_size, 200))
            try:
                page_obj = paginator.page(page_num)
            except PageNotAnInteger:
                page_obj = paginator.page(1)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages) if paginator.num_pages > 0 else []

            findings_list = [f.to_dict() for f in page_obj]
            total_items = paginator.count
            total_pages = paginator.num_pages
            current_page = page_obj.number if hasattr(page_obj, "number") else 1
        else:
            findings_list = [f.to_dict() for f in qs]
            total_items = len(findings_list)
            total_pages = 1
            current_page = 1

        response_data: Dict[str, Any] = {
            "success": True,
            "total": total_items,
            "page": current_page,
            "page_size": page_size,
            "total_pages": total_pages,
            "findings": findings_list,
        }

        # Include summary stats if requested or default
        if request.GET.get("include_stats", "true").lower() in ("true", "1", "yes"):
            target_filter = request.GET.get("target")
            scan_id_filter = request.GET.get("scan_id")
            stats = FindingsEngine.get_stats(target=target_filter, scan_id=scan_id_filter)
            response_data["stats"] = stats

        return JsonResponse(response_data, status=200)

    except Exception as e:
        logger.error(f"Error listing findings: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_finding_detail_view(request, finding_id):
    """
    GET /api/findings/<id>/
    Retrieves full details for a single unified security finding.
    """
    try:
        finding = Finding.objects.filter(id=finding_id).select_related("scan").first()
        if not finding:
            return JsonResponse({"success": False, "error": f"Finding with ID '{finding_id}' not found."}, status=404)

        return JsonResponse({
            "success": True,
            "finding": finding.to_dict()
        }, status=200)

    except Exception as e:
        logger.error(f"Error fetching finding {finding_id}: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST", "PATCH"])
def update_finding_status_view(request, finding_id):
    """
    POST/PATCH /api/findings/<id>/status/
    Updates the lifecycle status of a finding (open, confirmed, remediated, accepted, false_positive).
    Payload:
      {
        "status": "remediated",
        "status_note": "Applied security patch and verified port closure."
      }
    """
    try:
        try:
            body = json.loads(request.body.decode("utf-8")) if request.body else {}
        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)

        new_status = body.get("status", "").strip().lower()
        if not new_status:
            return JsonResponse({"success": False, "error": "Missing 'status' parameter."}, status=400)

        if new_status not in VALID_STATUSES:
            return JsonResponse({
                "success": False,
                "error": f"Invalid status '{new_status}'. Allowed values: {', '.join(VALID_STATUSES)}"
            }, status=400)

        note = body.get("status_note") or body.get("note") or ""

        finding = FindingsEngine.update_finding_status(
            finding_id=finding_id,
            new_status=new_status,
            note=note
        )

        if not finding:
            return JsonResponse({"success": False, "error": f"Finding with ID '{finding_id}' not found."}, status=404)

        return JsonResponse({
            "success": True,
            "message": f"Finding status updated to '{new_status}'.",
            "finding": finding.to_dict()
        }, status=200)

    except Exception as e:
        logger.error(f"Error updating finding {finding_id} status: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def bulk_update_finding_status_view(request):
    """
    POST /api/findings/bulk-status/
    Bulk updates the status of multiple findings at once.
    Payload:
      {
        "finding_ids": ["uuid1", "uuid2"],
        "status": "confirmed",
        "status_note": "Triage verified during penetration test review."
      }
    """
    try:
        try:
            body = json.loads(request.body.decode("utf-8")) if request.body else {}
        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)

        finding_ids = body.get("finding_ids", [])
        if not isinstance(finding_ids, list) or not finding_ids:
            return JsonResponse({"success": False, "error": "Must provide a non-empty 'finding_ids' list."}, status=400)

        new_status = body.get("status", "").strip().lower()
        if new_status not in VALID_STATUSES:
            return JsonResponse({
                "success": False,
                "error": f"Invalid status '{new_status}'. Allowed values: {', '.join(VALID_STATUSES)}"
            }, status=400)

        note = body.get("status_note") or body.get("note") or ""

        updated_count = 0
        for f_id in finding_ids:
            res = FindingsEngine.update_finding_status(f_id, new_status, note)
            if res:
                updated_count += 1

        return JsonResponse({
            "success": True,
            "updated_count": updated_count,
            "message": f"Updated status for {updated_count} finding(s) to '{new_status}'."
        }, status=200)

    except Exception as e:
        logger.error(f"Error in bulk updating finding status: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_findings_stats_view(request):
    """
    GET /api/findings/stats/
    Returns aggregated metrics by severity, status, source module, top targets, and top CWEs.
    """
    try:
        target = request.GET.get("target")
        scan_id = request.GET.get("scan_id")
        stats = FindingsEngine.get_stats(target=target, scan_id=scan_id)
        return JsonResponse({"success": True, "stats": stats}, status=200)
    except Exception as e:
        logger.error(f"Error retrieving findings stats: {e}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)
