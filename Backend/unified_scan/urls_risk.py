from django.urls import path
from .views_risk import (
    get_risk_summary_view,
    get_target_risk_view,
    get_scan_risk_view,
    get_risk_trends_view,
    recalculate_risk_view,
)

urlpatterns = [
    # Global / Filtered Risk Summary
    path('', get_risk_summary_view, name='get_risk_summary'),
    path('summary/', get_risk_summary_view, name='get_risk_summary_slash'),
    path('summary', get_risk_summary_view, name='get_risk_summary_noslash'),

    # Target-specific risk
    path('target/', get_target_risk_view, name='get_target_risk'),
    path('target', get_target_risk_view, name='get_target_risk_noslash'),

    # Scan-specific risk
    path('scan/<uuid:scan_id>/', get_scan_risk_view, name='get_scan_risk'),
    path('scan/<uuid:scan_id>', get_scan_risk_view, name='get_scan_risk_noslash'),
    path('scan/<str:scan_id>/', get_scan_risk_view, name='get_scan_risk_str'),
    path('scan/<str:scan_id>', get_scan_risk_view, name='get_scan_risk_str_noslash'),

    # Trends / Historical Timeline
    path('trends/', get_risk_trends_view, name='get_risk_trends'),
    path('trends', get_risk_trends_view, name='get_risk_trends_noslash'),

    # Recalculate
    path('recalculate/', recalculate_risk_view, name='recalculate_risk'),
    path('recalculate', recalculate_risk_view, name='recalculate_risk_noslash'),
]
