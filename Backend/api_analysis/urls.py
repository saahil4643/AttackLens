from django.urls import path
from .views import api_analysis, stream_api_analysis

urlpatterns = [
    path('api-analysis/', api_analysis, name='api_analysis'),
    path('stream-api-analysis/', stream_api_analysis, name='stream_api_analysis'),
]
