from django.urls import path
from .views import (
    check_ports,
    stream_ports,
    http_https_detection,
    stream_http_detection,
    discover_endpoints,
    stream_endpoint_discovery,
)

urlpatterns = [
    # Port Scanner Endpoints
    path('check-ports/', check_ports, name='check_ports'),
    path('stream-ports/', stream_ports, name='stream_ports'),

    # HTTP/HTTPS Web Inspector Endpoints
    path('http-detection/', http_https_detection, name='http_https_detection'),
    path('stream-http-detection/', stream_http_detection, name='stream_http_detection'),

    # Endpoint & Web Surface Discovery Endpoints
    path('discover-endpoints/', discover_endpoints, name='discover_endpoints'),
    path('stream-endpoint-discovery/', stream_endpoint_discovery, name='stream_endpoint_discovery'),
]

