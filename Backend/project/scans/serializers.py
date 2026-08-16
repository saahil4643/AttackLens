from rest_framework import serializers
from .models import Scan, ScanJob, ModuleExecution, ExecutionLog

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            'id', 'project', 'name', 'scan_type', 'status',
            'progress', 'configuration', 'started_at', 'completed_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Scan name is required.")
        return value

    def create(self, validated_data):
        validated_data['status'] = 'QUEUED'
        validated_data['progress'] = 0
        return super().create(validated_data)


class ExecutionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExecutionLog
        fields = ['id', 'scan_job', 'level', 'message', 'timestamp']
        read_only_fields = ['id', 'timestamp']


class ModuleExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ModuleExecution
        fields = [
            'id', 'scan_job', 'module_key', 'execution_environment',
            'status', 'result', 'started_at', 'completed_at', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class ScanJobSerializer(serializers.ModelSerializer):
    module_name = serializers.CharField(source='testing_module.name', read_only=True)
    module_key = serializers.CharField(source='testing_module.key', read_only=True)
    module_category = serializers.CharField(source='testing_module.category', read_only=True)
    executions = ModuleExecutionSerializer(many=True, read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            'id', 'assessment', 'testing_module', 'module_name', 'module_key', 'module_category',
            'status', 'progress', 'priority', 'started_at', 'completed_at',
            'error_message', 'result', 'executions', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
