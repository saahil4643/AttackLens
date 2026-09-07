from django.urls import path
from .views import tls_analysis, stream_tls_analysis

urlpatterns = [
    path('tls-analysis/', tls_analysis, name='tls_analysis'),
    path('stream-tls-analysis/', stream_tls_analysis, name='stream_tls_analysis'),
]
