from django.urls import path
from .views_findings import (
    list_findings_view,
    get_finding_detail_view,
    update_finding_status_view,
    bulk_update_finding_status_view,
    get_findings_stats_view,
)

urlpatterns = [
    # List & Search
    path('', list_findings_view, name='list_findings'),
    path('list/', list_findings_view, name='list_findings_slash'),
    path('list', list_findings_view, name='list_findings_noslash'),

    # Statistics summary
    path('stats/', get_findings_stats_view, name='get_findings_stats'),
    path('stats', get_findings_stats_view, name='get_findings_stats_noslash'),

    # Bulk status updates
    path('bulk-status/', bulk_update_finding_status_view, name='bulk_update_finding_status'),
    path('bulk-status', bulk_update_finding_status_view, name='bulk_update_finding_status_noslash'),

    # Single finding operations
    path('<uuid:finding_id>/', get_finding_detail_view, name='get_finding_detail'),
    path('<uuid:finding_id>', get_finding_detail_view, name='get_finding_detail_noslash'),
    path('<str:finding_id>/status/', update_finding_status_view, name='update_finding_status'),
    path('<str:finding_id>/status', update_finding_status_view, name='update_finding_status_noslash'),
    path('<str:finding_id>/', get_finding_detail_view, name='get_finding_detail_str'),
    path('<str:finding_id>', get_finding_detail_view, name='get_finding_detail_str_noslash'),
]
