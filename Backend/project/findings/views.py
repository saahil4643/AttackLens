from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from .models import Finding, FindingEvidence
from .serializers import FindingSerializer, FindingEvidenceSerializer

class FindingViewSet(mixins.ListModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.UpdateModelMixin,
                     viewsets.GenericViewSet):
    queryset = Finding.objects.all().order_by('-created_at')
    serializer_class = FindingSerializer

    def get_queryset(self):
        queryset = self.queryset
        
        # Retrieve filters from query params
        project = self.request.query_params.get('project')
        assessment = self.request.query_params.get('assessment')
        scan_job = self.request.query_params.get('scan_job')
        testing_module = self.request.query_params.get('testing_module')
        severity = self.request.query_params.get('severity')
        status_param = self.request.query_params.get('status')
        category = self.request.query_params.get('category')
        
        if project:
            queryset = queryset.filter(project_id=project)
        if assessment:
            queryset = queryset.filter(assessment_id=assessment)
        if scan_job:
            queryset = queryset.filter(scan_job_id=scan_job)
        if testing_module:
            queryset = queryset.filter(testing_module_id=testing_module)
        if severity:
            queryset = queryset.filter(severity=severity.upper())
        if status_param:
            queryset = queryset.filter(status=status_param.upper())
        if category:
            queryset = queryset.filter(category=category.upper())

        # Retrieve search parameters
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) | 
                Q(description__icontains=search) |
                Q(asset__value__icontains=search)
            )
            
        return queryset

    @action(detail=True, methods=['get'], url_path='evidence')
    def evidence(self, request, pk=None):
        finding = self.get_object()
        evidence_qs = finding.evidence_records.all().order_by('id')
        serializer = FindingEvidenceSerializer(evidence_qs, many=True)
        return Response(serializer.data)


class FindingEvidenceViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = FindingEvidence.objects.all().order_by('id')
    serializer_class = FindingEvidenceSerializer
