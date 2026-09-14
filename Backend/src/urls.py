"""
URL configuration for src project.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('scan/', include('scan.urls')),
    path('', include('scan.urls')),
    path('api/', include('technology_fingerprinting.urls')),
    path('', include('technology_fingerprinting.urls')),
    path('api/', include('analysis.urls')),
    path('', include('analysis.urls')),
    path('api/', include('tls_analysis.urls')),
    path('', include('tls_analysis.urls')),
    path('api/', include('api_analysis.urls')),
    path('', include('api_analysis.urls')),
    path('api/', include('attack_surface.urls')),
    path('', include('attack_surface.urls')),
    path('api/', include('codebase_analysis.urls')),
    path('', include('codebase_analysis.urls')),
    path('api/unified-scan/', include('unified_scan.urls')),
    path('unified-scan/', include('unified_scan.urls')),
    path('api/findings/', include('unified_scan.urls_findings')),
    path('findings/', include('unified_scan.urls_findings')),
    path('api/risk/', include('unified_scan.urls_risk')),
    path('risk/', include('unified_scan.urls_risk')),
    path('api/attack-surface/', include('unified_scan.urls_correlation')),
    path('attack-surface/', include('unified_scan.urls_correlation')),
    path('api/dashboard/', include('unified_scan.urls_dashboard')),
    path('dashboard/', include('unified_scan.urls_dashboard')),
    path('api/reports/', include('unified_scan.urls_reports')),
    path('reports/', include('unified_scan.urls_reports')),
]
