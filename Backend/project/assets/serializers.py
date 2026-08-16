from rest_framework import serializers
from .models import Asset

class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = [
            'id', 'project', 'target', 'asset_type', 'value',
            'status', 'metadata', 'discovered_at', 'updated_at'
        ]
        read_only_fields = ['id', 'discovered_at', 'updated_at']

    def validate_value(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Asset value is required.")
        return value

    def validate(self, attrs):
        project = attrs.get('project')
        target = attrs.get('target')
        
        if target and project and target.project != project:
            raise serializers.ValidationError("Target must belong to the selected project.")
        return attrs
