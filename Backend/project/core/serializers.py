from rest_framework import serializers
from .models import TestingModule

class TestingModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestingModule
        fields = [
            'id', 'key', 'name', 'description', 'category', 'version', 
            'enabled', 'requires_live_url', 'requires_source_code', 
            'requires_authentication', 'supports_live_testing', 
            'supports_local_testing', 'configuration_schema', 
            'created_at', 'updated_at'
        ]
