from django.urls import path
from .views import technology_fingerprint, stream_technology_fingerprint

urlpatterns = [
    path('technology-fingerprint/', technology_fingerprint, name='technology_fingerprint'),
    path('stream-technology-fingerprint/', stream_technology_fingerprint, name='stream_technology_fingerprint'),
]
