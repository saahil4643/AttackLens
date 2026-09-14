from django.urls import path
from . import views

urlpatterns = [
    path('codebase-scan/', views.codebase_scan, name='codebase_scan'),
    path('codebase-scan/sample/', views.sample_codebase_scan, name='sample_codebase_scan'),
    path('stream-codebase-scan/', views.stream_codebase_scan, name='stream_codebase_scan'),
]
