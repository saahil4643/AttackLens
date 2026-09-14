"""
URL configuration for Professional Security Reports API
"""

from django.urls import path
from .views_reports import (
    SecurityReportListCreateView,
    SecurityReportDetailView,
    SecurityReportHtmlView,
    SecurityReportDownloadView,
)

urlpatterns = [
    path('', SecurityReportListCreateView.as_view(), name='report-list-create'),
    path('generate/', SecurityReportListCreateView.as_view(), name='report-generate'),
    path('<uuid:report_id>/', SecurityReportDetailView.as_view(), name='report-detail'),
    path('<uuid:report_id>/html/', SecurityReportHtmlView.as_view(), name='report-html'),
    path('<uuid:report_id>/download/', SecurityReportDownloadView.as_view(), name='report-download'),
    path('<uuid:report_id>/pdf/', SecurityReportDownloadView.as_view(), name='report-pdf'),
]
