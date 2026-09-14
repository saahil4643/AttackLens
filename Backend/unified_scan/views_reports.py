"""
REST API Views for Professional Security Reporting System
Provides endpoints for listing, generating, previewing, and downloading reports.
"""

import logging
from django.http import HttpResponse, Http404
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import SecurityReport, UnifiedScanRecord
from .services.report_generator import SecurityReportGenerator

logger = logging.getLogger("unified_scan.views_reports")


class SecurityReportListCreateView(APIView):
    """
    GET /api/reports/?target=<target>
    List generated security reports.

    POST /api/reports/ or POST /api/reports/generate/
    Generate a new executive or technical security report.
    """

    def get(self, request: Request) -> Response:
        target = request.query_params.get("target", "").strip()
        qs = SecurityReport.objects.all()

        if target and target.lower() != "all":
            qs = qs.filter(target__icontains=target)

        reports_data = [r.to_dict(include_html=False) for r in qs]
        return Response(reports_data, status=status.HTTP_200_OK)

    def post(self, request: Request) -> Response:
        data = request.data or {}
        target = data.get("target") or data.get("target_url")
        scan_id = data.get("scan_id") or data.get("scanId")
        report_type = data.get("report_type") or data.get("type", "executive")
        format_type = data.get("format") or data.get("format_type", "pdf")
        title = data.get("title") or data.get("name")

        try:
            report = SecurityReportGenerator.generate_report(
                target=target,
                scan_id=scan_id,
                report_type=report_type,
                format_type=format_type,
                title=title
            )
            return Response(report.to_dict(include_html=False), status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.exception(f"Report generation error: {e}")
            return Response(
                {"error": f"Failed to generate security report: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecurityReportDetailView(APIView):
    """
    GET /api/reports/<uuid:report_id>/
    Retrieve report metadata and JSON summary.

    DELETE /api/reports/<uuid:report_id>/
    Delete a generated report.
    """

    def get(self, request: Request, report_id: str) -> Response:
        report = SecurityReport.objects.filter(id=report_id).first()
        if not report:
            return Response({"error": f"Report '{report_id}' not found."}, status=status.HTTP_404_NOT_FOUND)

        include_html = request.query_params.get("include_html", "false").lower() == "true"
        return Response(report.to_dict(include_html=include_html), status=status.HTTP_200_OK)

    def delete(self, request: Request, report_id: str) -> Response:
        report = SecurityReport.objects.filter(id=report_id).first()
        if not report:
            return Response({"error": f"Report '{report_id}' not found."}, status=status.HTTP_404_NOT_FOUND)

        report.delete()
        return Response({"success": True, "message": "Report deleted successfully."}, status=status.HTTP_200_OK)


class SecurityReportHtmlView(APIView):
    """
    GET /api/reports/<uuid:report_id>/html/
    Returns rendered standalone HTML report for browser preview or iframe embed.
    """

    def get(self, request: Request, report_id: str) -> HttpResponse:
        report = SecurityReport.objects.filter(id=report_id).first()
        if not report:
            raise Http404(f"Report '{report_id}' not found.")

        response = HttpResponse(report.html_content, content_type="text/html; charset=utf-8")
        response["X-Frame-Options"] = "SAMEORIGIN"
        return response


class SecurityReportDownloadView(APIView):
    """
    GET /api/reports/<uuid:report_id>/download/
    Direct file download for the security report.
    """

    def get(self, request: Request, report_id: str) -> HttpResponse:
        report = SecurityReport.objects.filter(id=report_id).first()
        if not report:
            raise Http404(f"Report '{report_id}' not found.")

        safe_filename = f"AttackLens-{report.report_type.upper()}-{report.id}.html"
        response = HttpResponse(report.html_content, content_type="text/html; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        return response
