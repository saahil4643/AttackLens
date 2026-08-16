import os
import django
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')
django.setup()

from rest_framework.test import APIRequestFactory
from projects.views import AssessmentViewSet
from projects.models import Project, AssessmentScope

proj, _ = Project.objects.get_or_create(
    name="Test Project",
    defaults={"description": "Test Description"}
)

# Create a scope since Safety Gate requires it
factory = APIRequestFactory()
data = {
    "project": proj.id,
    "name": "Test Assessment",
    "live_url": "http://example.com",
    "selected_modules": ["web_security_headers_test"],
    "configuration": {},
    "status": "READY"
}

view = AssessmentViewSet.as_view({'post': 'create'})
request = factory.post('/api/assessments/', data=json.dumps(data), content_type='application/json')
response = view(request)

print("STATUS CODE:", response.status_code)
print("RESPONSE DATA:", response.data)
