"""
URLs for Security Command Center Dashboard APIs
"""

from django.urls import path
from .views_dashboard import DashboardSummaryView

urlpatterns = [
    path('', DashboardSummaryView.as_view(), name='dashboard-summary-root'),
    path('summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
    path('stats/', DashboardSummaryView.as_view(), name='dashboard-stats'),
]
