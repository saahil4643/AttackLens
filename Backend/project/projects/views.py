from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Project, Assessment, AssessmentScope
from .serializers import ProjectSerializer, AssessmentSerializer, AssessmentScopeSerializer
from targets.serializers import TargetSerializer
from scans.serializers import ScanSerializer
from findings.serializers import FindingSerializer

class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all().order_by('-created_at')
    serializer_class = ProjectSerializer

    @action(detail=True, methods=['get'], url_path='dashboard')
    def dashboard(self, request, pk=None):
        project = self.get_object()
        
        # Counts
        target_count = project.targets.count()
        asset_count = project.assets.count()
        scan_count = project.scans.count()
        active_scans = project.scans.filter(status__in=['QUEUED', 'RUNNING']).count()
        finding_count = project.findings.count()
        
        # Findings severities
        critical_findings = project.findings.filter(severity='CRITICAL').count()
        high_findings = project.findings.filter(severity='HIGH').count()
        medium_findings = project.findings.filter(severity='MEDIUM').count()
        low_findings = project.findings.filter(severity='LOW').count()
        
        # Recent items (ordered by creation, limit to 5)
        recent_scans = project.scans.all().order_by('-created_at')[:5]
        recent_findings = project.findings.all().order_by('-created_at')[:5]
        
        # Serializing recent items
        recent_scans_data = ScanSerializer(recent_scans, many=True).data
        recent_findings_data = FindingSerializer(recent_findings, many=True).data
        
        data = {
            'project': ProjectSerializer(project).data,
            'target_count': target_count,
            'asset_count': asset_count,
            'scan_count': scan_count,
            'active_scans': active_scans,
            'finding_count': finding_count,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'medium_findings': medium_findings,
            'low_findings': low_findings,
            'recent_scans': recent_scans_data,
            'recent_findings': recent_findings_data
        }
        return Response(data)

    @action(detail=True, methods=['get', 'post'], url_path='targets')
    def project_targets(self, request, pk=None):
        project = self.get_object()
        if request.method == 'GET':
            targets = project.targets.all().order_by('-created_at')
            serializer = TargetSerializer(targets, many=True)
            return Response(serializer.data)
        elif request.method == 'POST':
            data = request.data.copy()
            data['project'] = project.id
            serializer = TargetSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], url_path='source')
    def upload_source(self, request, pk=None):
        project = self.get_object()
        uploaded_file = request.FILES.get('file') or request.FILES.get('source_zip')
        
        if not uploaded_file:
            return Response({'error': 'No file uploaded under key "file" or "source_zip".'}, status=status.HTTP_400_BAD_REQUEST)
            
        MAX_UPLOAD_SIZE = 50 * 1024 * 1024
        if uploaded_file.size > MAX_UPLOAD_SIZE:
            return Response({'error': 'Source ZIP exceeds maximum upload size of 50MB.'}, status=status.HTTP_400_BAD_REQUEST)
            
        import os
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext != '.zip':
            return Response({'error': 'Only ZIP archives are allowed.'}, status=status.HTTP_400_BAD_REQUEST)
            
        import uuid
        from django.utils import timezone
        safe_name = f"source_{project.id}_{uuid.uuid4().hex}{ext}"
        uploaded_file.name = safe_name
        
        project.source_archive = uploaded_file
        project.source_archive_name = uploaded_file.name
        project.source_archive_size = uploaded_file.size
        project.source_uploaded_at = timezone.now()
        project.save()
        
        return Response({
            'message': 'Source code ZIP uploaded successfully.',
            'source_archive_name': project.source_archive_name,
            'source_archive_size': project.source_archive_size,
            'source_uploaded_at': project.source_uploaded_at
        }, status=status.HTTP_200_OK)


class AssessmentViewSet(viewsets.ModelViewSet):
    queryset = Assessment.objects.all().order_by('-created_at')
    serializer_class = AssessmentSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        project = instance.project
        scopes_data = AssessmentScopeSerializer(instance.scopes.all(), many=True).data
        
        from core.models import TestingModule
        from core.serializers import TestingModuleSerializer
        
        selected_keys = instance.selected_modules or []
        modules_qs = TestingModule.objects.filter(key__in=selected_keys)
        modules_data = TestingModuleSerializer(modules_qs, many=True).data
        
        config_schema = {}
        for mod in modules_qs:
            config_schema[mod.key] = {
                'name': mod.name,
                'description': mod.description,
                'configuration_schema': mod.configuration_schema,
                'requires_authentication': mod.requires_authentication
            }
            
        data = {
            'project': {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'status': project.status,
            },
            'assessment': {
                'id': instance.id,
                'name': instance.name,
                'configuration': instance.configuration,
            },
            'live_url': instance.live_url or project.live_url,
            'source_code': {
                'name': project.source_archive_name,
                'size': project.source_archive_size,
                'uploaded_at': project.source_uploaded_at,
            } if project.source_archive else None,
            'scope': scopes_data,
            'selected_modules': modules_data,
            'available_module_configuration': config_schema,
            'status': instance.status,
            'created_at': instance.created_at,
            'updated_at': instance.updated_at
        }
        return Response(data)

    @action(detail=True, methods=['get'], url_path='overview')
    def overview(self, request, pk=None):
        assessment = self.get_object()
        
        primary_scope = assessment.scopes.filter(target_type='LIVE_URL').first() or assessment.scopes.first()
        target = primary_scope.target if primary_scope else assessment.live_url
        
        from core.models import TestingModule
        from core.serializers import TestingModuleSerializer
        
        selected_keys = assessment.selected_modules or []
        modules_qs = TestingModule.objects.filter(key__in=selected_keys)
        modules_data = TestingModuleSerializer(modules_qs, many=True).data
        
        findings = assessment.findings.all()
        critical_count = findings.filter(severity='CRITICAL').count()
        high_count = findings.filter(severity='HIGH').count()
        medium_count = findings.filter(severity='MEDIUM').count()
        low_count = findings.filter(severity='LOW').count()
        info_count = findings.filter(severity='INFO').count()

        data = {
            'assessment': {
                'id': assessment.id,
                'name': assessment.name,
            },
            'project': {
                'id': assessment.project.id,
                'name': assessment.project.name,
            },
            'target': target,
            'selected_modules': modules_data,
            'module_count': len(selected_keys),
            'status': assessment.status,
            'finding_count': findings.count(),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'medium_findings': medium_count,
            'low_findings': low_count,
            'info_findings': info_count,
            'created_at': assessment.created_at
        }
        return Response(data)

    @action(detail=True, methods=['post'], url_path='start')
    def start(self, request, pk=None):
        from scans.services.assessment_service import AssessmentService
        assessment = self.get_object()
        
        try:
            assessment, jobs_created, result_state = AssessmentService.start_assessment(assessment.id)
        except Exception as e:
            err_msg = str(e)
            if hasattr(e, 'detail'):
                err_msg = getattr(e, 'detail')
            return Response({'error': err_msg}, status=status.HTTP_400_BAD_REQUEST)
            
        if result_state == "already_active":
            return Response(
                {'error': 'Assessment is already active (queued or running).'},
                status=status.HTTP_409_CONFLICT
            )
            
        jobs_data = []
        for j in assessment.jobs.all():
            jobs_data.append({
                'id': j.id,
                'module': j.testing_module.key,
                'module_name': j.testing_module.name,
                'status': j.status,
                'progress': j.progress
            })
            
        return Response({
            'assessment_id': assessment.id,
            'status': assessment.status,
            'jobs_created': jobs_created,
            'jobs': jobs_data
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='jobs')
    def jobs(self, request, pk=None):
        assessment = self.get_object()
        
        status_filter = request.query_params.get('status')
        queryset = assessment.jobs.all().order_by('id')
        if status_filter:
            queryset = queryset.filter(status=status_filter.upper())
            
        jobs_data = []
        for j in queryset:
            jobs_data.append({
                'id': j.id,
                'module': j.testing_module.key,
                'category': j.testing_module.category,
                'status': j.status,
                'progress': j.progress,
                'priority': j.priority,
                'created_time': j.created_at,
                'started_time': j.started_at,
                'completed_time': j.completed_at,
                'error_message': j.error_message
            })
        return Response(jobs_data)

    @action(detail=True, methods=['get'], url_path='execution')
    def execution(self, request, pk=None):
        assessment = self.get_object()
        
        jobs = assessment.jobs.all()
        total_jobs = jobs.count()
        queued = jobs.filter(status='QUEUED').count()
        running = jobs.filter(status='RUNNING').count()
        completed = jobs.filter(status='COMPLETED').count()
        failed = jobs.filter(status='FAILED').count()
        cancelled = jobs.filter(status='CANCELLED').count()
        
        if total_jobs > 0:
            import django.db.models as db_models
            avg_progress = jobs.aggregate(avg=db_models.Avg('progress'))['avg']
            progress = int(avg_progress) if avg_progress is not None else 0
        else:
            progress = 0
            
        jobs_data = []
        for j in jobs:
            jobs_data.append({
                'id': j.id,
                'module': j.testing_module.key,
                'status': j.status,
                'progress': j.progress
            })
            
        return Response({
            'assessment_id': assessment.id,
            'status': assessment.status,
            'total_jobs': total_jobs,
            'queued': queued,
            'running': running,
            'completed': completed,
            'failed': failed,
            'cancelled': cancelled,
            'progress': progress,
            'jobs': jobs_data
        })



