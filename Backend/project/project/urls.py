from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from projects.views import ProjectViewSet, AssessmentViewSet
from targets.views import TargetViewSet
from assets.views import AssetViewSet
from scans.views import ScanViewSet, ScanJobViewSet
from findings.views import FindingViewSet, FindingEvidenceViewSet
from reports.views import ReportViewSet
from core.views import TestingModuleViewSet

router = DefaultRouter()
router.register(r'projects', ProjectViewSet, basename='project')
router.register(r'assessments', AssessmentViewSet, basename='assessment')
router.register(r'targets', TargetViewSet, basename='target')
router.register(r'assets', AssetViewSet, basename='asset')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'jobs', ScanJobViewSet, basename='scanjob')
router.register(r'findings', FindingViewSet, basename='finding')
router.register(r'evidence', FindingEvidenceViewSet, basename='findingevidence')
router.register(r'reports', ReportViewSet, basename='report')
router.register(r'testing-modules', TestingModuleViewSet, basename='testingmodule')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
]
