from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from .models import Scan, ScanJob, ExecutionLog
from .serializers import ScanSerializer, ScanJobSerializer, ExecutionLogSerializer

class ScanViewSet(mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.UpdateModelMixin,
                  viewsets.GenericViewSet):
    queryset = Scan.objects.all().order_by('-created_at')
    serializer_class = ScanSerializer

    def get_queryset(self):
        queryset = self.queryset
        project_id = self.request.query_params.get('project')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset


class ScanJobViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = ScanJob.objects.all().order_by('-created_at')
    serializer_class = ScanJobSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data
        
        # Build clean custom response format targeting specific detail keys:
        # job, assessment, testing_module, execution, status, progress, result, timestamps
        response_data = {
            'job': {
                'id': instance.id,
                'priority': instance.priority,
                'error_message': instance.error_message
            },
            'assessment': {
                'id': instance.assessment.id,
                'name': instance.assessment.name,
                'status': instance.assessment.status
            },
            'testing_module': {
                'id': instance.testing_module.id,
                'key': instance.testing_module.key,
                'name': instance.testing_module.name,
                'category': instance.testing_module.category
            },
            'execution': data.get('executions', []),
            'status': instance.status,
            'progress': instance.progress,
            'result': instance.result,
            'timestamps': {
                'created_at': instance.created_at,
                'updated_at': instance.updated_at,
                'started_at': instance.started_at,
                'completed_at': instance.completed_at
            }
        }
        return Response(response_data)

    @action(detail=True, methods=['get'], url_path='logs')
    def logs(self, request, pk=None):
        job = self.get_object()
        
        level_filter = request.query_params.get('level')
        queryset = job.logs.all().order_by('timestamp')
        if level_filter:
            queryset = queryset.filter(level=level_filter.upper())
            
        serializer = ExecutionLogSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='cancel')
    def cancel(self, request, pk=None):
        job = self.get_object()
        
        # Validation checks
        if job.status in ['COMPLETED', 'FAILED', 'CANCELLED', 'SKIPPED']:
            return Response(
                {'error': f"Cannot cancel a job that is already in '{job.status}' status."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        job.status = 'CANCELLED'
        job.completed_at = timezone.now()
        job.save()
        
        # Cancel active execution trackers
        job.executions.filter(status__in=['QUEUED', 'RUNNING']).update(
            status='CANCELLED',
            completed_at=timezone.now()
        )
        
        # Log event
        ExecutionLog.objects.create(
            scan_job=job,
            level='WARNING',
            message="Scan job cancelled by user."
        )
        
        return Response({
            'job_id': job.id,
            'status': job.status,
            'message': 'Job successfully cancelled.'
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='execute')
    def execute(self, request, pk=None):
        from scans.services.execution_service import ExecutionService
        job = self.get_object()
        
        try:
            job = ExecutionService.execute_job(job.id)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response({
            'job_id': job.id,
            'status': job.status,
            'progress': job.progress,
            'result': job.result
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='retry')
    def retry(self, request, pk=None):
        return Response(
            {'error': 'Job retries are not implemented yet.'},
            status=status.HTTP_501_NOT_IMPLEMENTED
        )

