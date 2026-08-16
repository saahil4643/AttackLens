from rest_framework import serializers
from .models import Project, Assessment, AssessmentScope
from targets.models import Target

class ProjectSerializer(serializers.ModelSerializer):
    target_count = serializers.SerializerMethodField()
    finding_count = serializers.SerializerMethodField()
    scan_count = serializers.SerializerMethodField()
    targets = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='value'
    )
    initial_targets = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
        required=False
    )

    class Meta:
        model = Project
        fields = [
            'id', 'name', 'description', 'status', 
            'created_at', 'updated_at', 'targets',
            'target_count', 'finding_count', 'scan_count',
            'initial_targets', 'live_url', 'source_archive',
            'source_archive_name', 'source_archive_size', 'source_uploaded_at'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 
            'source_archive_name', 'source_archive_size', 'source_uploaded_at'
        ]

    def get_target_count(self, obj):
        return obj.targets.count()

    def get_scan_count(self, obj):
        return obj.scans.count()

    def get_finding_count(self, obj):
        findings = obj.findings.all()
        return {
            'critical': findings.filter(severity='CRITICAL').count(),
            'high': findings.filter(severity='HIGH').count(),
            'medium': findings.filter(severity='MEDIUM').count(),
            'low': findings.filter(severity='LOW').count(),
            'info': findings.filter(severity='INFO').count(),
        }

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Project name is required.")
        return value

    def create(self, validated_data):
        initial_targets = validated_data.pop('initial_targets', [])
        project = Project.objects.create(**validated_data)
        
        for idx, val in enumerate(initial_targets):
            val_str = str(val).strip()
            if not val_str:
                continue
            
            import re
            is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+', val_str)
            is_sub_or_domain = '.' in val_str and not val_str[0].isdigit()
            
            if is_ip:
                t_type = 'IP'
            elif is_sub_or_domain:
                t_type = 'DOMAIN'
            elif val_str.startswith('http'):
                t_type = 'URL'
            else:
                t_type = 'DOMAIN'
                
            Target.objects.create(
                project=project,
                name=val_str,
                target_type=t_type,
                value=val_str,
                environment='DEVELOPMENT',
                scope=True,
                status='ACTIVE'
            )
            
        return project


class AssessmentScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentScope
        fields = ['id', 'assessment', 'target_type', 'target', 'included', 'notes', 'created_at']
        read_only_fields = ['id', 'created_at']


class AssessmentSerializer(serializers.ModelSerializer):
    project = serializers.PrimaryKeyRelatedField(
        queryset=Project.objects.all(),
        required=False,
        allow_null=True
    )
    project_name = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    source_zip = serializers.FileField(write_only=True, required=False)
    scopes = AssessmentScopeSerializer(many=True, read_only=True)
    finding_count_detail = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()

    class Meta:
        model = Assessment
        fields = [
            'id', 'project', 'project_name', 'name', 'live_url', 'status',
            'selected_modules', 'configuration', 'scopes',
            'created_at', 'updated_at', 'started_at', 'completed_at',
            'source_zip', 'finding_count_detail', 'progress'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at',
            'finding_count_detail', 'progress'
        ]

    def get_finding_count_detail(self, obj):
        findings = obj.findings.all()
        return {
            'critical': findings.filter(severity='CRITICAL').count(),
            'high': findings.filter(severity='HIGH').count(),
            'medium': findings.filter(severity='MEDIUM').count(),
            'low': findings.filter(severity='LOW').count(),
            'info': findings.filter(severity='INFO').count(),
        }

    def get_progress(self, obj):
        jobs = obj.jobs.all()
        total = jobs.count()
        if total > 0:
            import django.db.models as db_models
            avg = jobs.aggregate(avg=db_models.Avg('progress'))['avg']
            return int(avg) if avg is not None else 0
        return 0

    def to_internal_value(self, data):
        # Helper to parse string representation of JSON field selected_modules
        if 'selected_modules' in data:
            val = data.get('selected_modules')
            if isinstance(val, str):
                import json
                try:
                    parsed = json.loads(val)
                    if isinstance(parsed, list):
                        mutable_data = data.copy()
                        mutable_data['selected_modules'] = parsed
                        data = mutable_data
                except json.JSONDecodeError:
                    # Comma-separated list fallback
                    vals = [x.strip() for x in val.split(',') if x.strip()]
                    mutable_data = data.copy()
                    mutable_data['selected_modules'] = vals
                    data = mutable_data
        return super().to_internal_value(data)

    def validate(self, attrs):
        # Either project or project_name is required during creation
        if not self.instance:
            project = attrs.get('project')
            project_name = attrs.get('project_name')
            if not project and not project_name:
                raise serializers.ValidationError("Either project or project_name is required.")
        return attrs

    def validate_source_zip(self, value):
        if value:
            # 1. Size check: 50MB max limit
            MAX_UPLOAD_SIZE = 50 * 1024 * 1024
            if value.size > MAX_UPLOAD_SIZE:
                raise serializers.ValidationError("Source ZIP exceeds maximum upload size of 50MB.")
            
            # 2. Extension check
            import os
            ext = os.path.splitext(value.name)[1].lower()
            if ext != '.zip':
                raise serializers.ValidationError("Only ZIP archives are allowed.")
            
            # 3. MIME check where practical
            content_type = getattr(value, 'content_type', '')
            if content_type and not any(t in content_type for t in ['zip', 'octet-stream']):
                raise serializers.ValidationError("Invalid file MIME type. Must be a ZIP archive.")
        
        return value

    def run_safety_gate_validation(self, assessment, live_url=None, has_source=False, selected_modules_keys=None):
        from scans.services.assessment_service import AssessmentService
        
        # Temporarily mock fields for validation if they are in transition
        original_live_url = assessment.live_url
        if live_url is not None:
            assessment.live_url = live_url
            
        try:
            AssessmentService.run_safety_gate(assessment)
        except Exception as e:
            # Revert temp mock
            assessment.live_url = original_live_url
            # Raise DRF Validation error
            import rest_framework
            if hasattr(e, 'detail'):
                raise serializers.ValidationError(e.detail)
            raise serializers.ValidationError(str(e))
        finally:
            assessment.live_url = original_live_url


    def create(self, validated_data):
        project = validated_data.get('project')
        project_name = validated_data.get('project_name')
        source_zip = validated_data.pop('source_zip', None)
        selected_modules_list = validated_data.get('selected_modules', [])
        
        # 1. Project intake
        if not project:
            project, created = Project.objects.get_or_create(
                name=project_name,
                defaults={'description': 'Auto-created assessment project'}
            )
            
        # 2. File and URL updates on Project
        project_changed = False
        live_url = validated_data.get('live_url', '')
        if live_url and not project.live_url:
            project.live_url = live_url
            project_changed = True
            
        if source_zip:
            import uuid
            from django.utils import timezone
            import os
            
            # Generate safe file name
            ext = os.path.splitext(source_zip.name)[1].lower()
            safe_name = f"source_{project.id}_{uuid.uuid4().hex}{ext}"
            source_zip.name = safe_name
            
            project.source_archive = source_zip
            project.source_archive_name = source_zip.name
            project.source_archive_size = source_zip.size
            project.source_uploaded_at = timezone.now()
            project_changed = True
            
        if project_changed:
            project.save()
            
        # 3. Create the Assessment
        assessment = Assessment.objects.create(
            project=project,
            name=validated_data.get('name'),
            live_url=live_url or project.live_url,
            status=validated_data.get('status', 'DRAFT'),
            selected_modules=selected_modules_list,
            configuration=validated_data.get('configuration', {})
        )
        
        # 4. Auto-create Scopes
        url_to_scope = live_url or project.live_url
        if url_to_scope:
            AssessmentScope.objects.create(
                assessment=assessment,
                target_type='LIVE_URL',
                target=url_to_scope,
                included=True,
                notes='Initial live URL target.'
            )
            
        if project.source_archive:
            AssessmentScope.objects.create(
                assessment=assessment,
                target_type='SOURCE_CODE',
                target=project.source_archive.name,
                included=True,
                notes='Initial source code archive target.'
            )
            
        # 5. Safety Gate Validation
        if assessment.status == 'READY':
            self.run_safety_gate_validation(
                assessment,
                live_url=url_to_scope,
                has_source=bool(project.source_archive),
                selected_modules_keys=selected_modules_list
            )
            
        return assessment

    def update(self, instance, validated_data):
        source_zip = validated_data.pop('source_zip', None)
        
        if source_zip:
            import uuid
            from django.utils import timezone
            import os
            
            project = instance.project
            ext = os.path.splitext(source_zip.name)[1].lower()
            safe_name = f"source_{project.id}_{uuid.uuid4().hex}{ext}"
            source_zip.name = safe_name
            
            project.source_archive = source_zip
            project.source_archive_name = source_zip.name
            project.source_archive_size = source_zip.size
            project.source_uploaded_at = timezone.now()
            project.save()
            
            # Auto-create source code scope if not exists
            if not instance.scopes.filter(target_type='SOURCE_CODE', target=project.source_archive.name).exists():
                AssessmentScope.objects.create(
                    assessment=instance,
                    target_type='SOURCE_CODE',
                    target=project.source_archive.name,
                    included=True,
                    notes='Uploaded source code archive.'
                )
                
        # standard update
        status_val = validated_data.get('status', instance.status)
        
        # Check if transitioning to READY
        if status_val == 'READY' and instance.status != 'READY':
            self.run_safety_gate_validation(
                instance,
                live_url=validated_data.get('live_url'),
                has_source=bool(instance.project.source_archive) or bool(source_zip),
                selected_modules_keys=validated_data.get('selected_modules')
            )
            
        return super().update(instance, validated_data)
