from rest_framework import viewsets
from .models import Target
from .serializers import TargetSerializer

class TargetViewSet(viewsets.ModelViewSet):
    queryset = Target.objects.all().order_by('-created_at')
    serializer_class = TargetSerializer

    def get_queryset(self):
        queryset = self.queryset
        project_id = self.request.query_params.get('project')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset
