from django.urls import path, include
from .views import (
    start_unified_scan,
    get_unified_scan_status,
    get_unified_scan_results,
    abort_unified_scan,
    list_unified_scans,
    stream_unified_scan
)

urlpatterns = [
    # Unified Findings Endpoints
    path('findings/', include('unified_scan.urls_findings')),
    path('risk/', include('unified_scan.urls_risk')),
    path('correlation/', include('unified_scan.urls_correlation')),
    path('dashboard/', include('unified_scan.urls_dashboard')),
    path('reports/', include('unified_scan.urls_reports')),

    # Start Unified Scan
    path('start/', start_unified_scan, name='start_unified_scan'),
    path('start', start_unified_scan, name='start_unified_scan_noslash'),
    
    # List scans
    path('list/', list_unified_scans, name='list_unified_scans'),
    path('list', list_unified_scans, name='list_unified_scans_noslash'),

    # Status, Results, Stream, Abort
    path('<uuid:scan_id>/status/', get_unified_scan_status, name='get_unified_scan_status'),
    path('<uuid:scan_id>/status', get_unified_scan_status, name='get_unified_scan_status_noslash'),
    path('<str:scan_id>/status/', get_unified_scan_status, name='get_unified_scan_status_str'),

    path('<uuid:scan_id>/results/', get_unified_scan_results, name='get_unified_scan_results'),
    path('<uuid:scan_id>/results', get_unified_scan_results, name='get_unified_scan_results_noslash'),
    path('<str:scan_id>/results/', get_unified_scan_results, name='get_unified_scan_results_str'),

    path('<uuid:scan_id>/abort/', abort_unified_scan, name='abort_unified_scan'),
    path('<uuid:scan_id>/abort', abort_unified_scan, name='abort_unified_scan_noslash'),
    path('<str:scan_id>/abort/', abort_unified_scan, name='abort_unified_scan_str'),

    path('<uuid:scan_id>/stream/', stream_unified_scan, name='stream_unified_scan'),
    path('<uuid:scan_id>/stream', stream_unified_scan, name='stream_unified_scan_noslash'),
    path('<str:scan_id>/stream/', stream_unified_scan, name='stream_unified_scan_str'),
]
