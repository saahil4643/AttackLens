from django.urls import re_path
from scans.consumers import AssessmentConsumer

websocket_urlpatterns = [
    re_path(r'^ws/assessments/(?P<assessment_id>\d+)/$', AssessmentConsumer.as_asgi()),
]
