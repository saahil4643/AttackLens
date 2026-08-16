from rest_framework import viewsets, mixins
from .models import Asset
from .serializers import AssetSerializer

class AssetViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = Asset.objects.all().order_by('-discovered_at')
    serializer_class = AssetSerializer

    def get_queryset(self):
        queryset = self.queryset
        project_id = self.request.query_params.get('project')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset
