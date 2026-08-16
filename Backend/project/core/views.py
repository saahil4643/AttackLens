from rest_framework import viewsets, mixins
from .models import TestingModule
from .serializers import TestingModuleSerializer

class TestingModuleViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = TestingModule.objects.all().order_by('category', 'key')
    serializer_class = TestingModuleSerializer

    def get_queryset(self):
        queryset = self.queryset
        category = self.request.query_params.get('category')
        enabled = self.request.query_params.get('enabled')
        
        if category:
            queryset = queryset.filter(category=category.upper())
        if enabled is not None:
            val = enabled.lower() == 'true'
            queryset = queryset.filter(enabled=val)
            
        return queryset
