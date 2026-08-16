from rest_framework import serializers
from .models import Target
from assets.models import Asset

class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = [
            'id', 'project', 'name', 'target_type', 'value',
            'environment', 'scope', 'status', 'notes',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_value(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Target value is required.")
        return value

    def validate_target_type(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Target type is required.")
        
        upper_val = value.upper()
        choices = [c[0] for c in Target.TARGET_TYPE_CHOICES]
        if upper_val not in choices:
            raise serializers.ValidationError(f"Invalid target type. Must be one of {choices}.")
        return upper_val

    def validate_environment(self, value):
        if not value:
            return 'DEVELOPMENT'
        upper_val = value.upper()
        choices = [c[0] for c in Target.ENVIRONMENT_CHOICES]
        if upper_val not in choices:
            raise serializers.ValidationError(f"Invalid environment. Must be one of {choices}.")
        return upper_val

    def validate_status(self, value):
        if not value:
            return 'ACTIVE'
        upper_val = value.upper()
        choices = [c[0] for c in Target.STATUS_CHOICES]
        if upper_val not in choices:
            raise serializers.ValidationError(f"Invalid status. Must be one of {choices}.")
        return upper_val

    def validate(self, attrs):
        # Validate that project is provided
        if 'project' not in attrs:
            raise serializers.ValidationError("Target must belong to a project.")
        return attrs

    def create(self, validated_data):
        target = Target.objects.create(**validated_data)
        
        # Auto-create asset representation
        val_str = target.value
        import re
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+', val_str)
        is_sub = '.' in val_str and not val_str[0].isdigit()
        
        if is_ip:
            a_type = 'IP'
        elif is_sub:
            a_type = 'SUBDOMAIN'
        elif val_str.startswith('http'):
            a_type = 'URL'
        else:
            a_type = 'DOMAIN'
            
        Asset.objects.create(
            project=target.project,
            target=target,
            asset_type=a_type,
            value=val_str,
            status='SAFE',
            metadata={
                'ipAddress': val_str if is_ip else '192.168.10.100',
                'ports': [80, 443],
                'services': ['HTTP', 'HTTPS'],
                'technologies': ['Apache', 'Nginx']
            }
        )
        return target
