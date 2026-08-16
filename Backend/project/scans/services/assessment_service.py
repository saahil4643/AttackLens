from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from projects.models import Assessment
from core.models import TestingModule
from scans.models import ScanJob, ModuleExecution, ExecutionLog

class AssessmentService:
    @staticmethod
    def run_safety_gate(assessment):
        # 1. Scope validation
        scopes_count = assessment.scopes.count()
        if scopes_count == 0:
            raise ValidationError("Safety Gate failed: Assessment has no explicit scope.")
            
        # 2. Selected modules validation
        selected_keys = assessment.selected_modules or []
        if not selected_keys:
            raise ValidationError("Safety Gate failed: No testing modules selected.")
            
        # 3. Fetch active modules from database
        modules = {m.key: m for m in TestingModule.objects.filter(key__in=selected_keys, enabled=True)}
        
        # Verify all selected modules exist and are enabled
        for key in selected_keys:
            if key not in modules:
                raise ValidationError(f"Safety Gate failed: Selected module '{key}' is disabled or not found.")
                
            module = modules[key]
            
            # Live URL requirement
            if module.requires_live_url and not assessment.live_url:
                raise ValidationError(
                    f"Safety Gate failed: Module '{module.name}' requires a live URL, but none was provided."
                )
                
            # Source code requirement
            if module.requires_source_code and not assessment.project.source_archive:
                raise ValidationError(
                    f"Safety Gate failed: Module '{module.name}' requires a source-code ZIP archive, but none was uploaded."
                )

    @classmethod
    def start_assessment(cls, assessment_id):
        with transaction.atomic():
            try:
                assessment = Assessment.objects.select_for_update().get(id=assessment_id)
            except Assessment.DoesNotExist:
                raise ValidationError("Assessment not found.")
                
            # 1. Status checks
            if assessment.status in ['COMPLETED', 'FAILED']:
                raise ValidationError("Cannot start an assessment that has already been completed or failed.")
                
            # Idempotency check: if already active (QUEUED or RUNNING)
            if assessment.status in ['QUEUED', 'RUNNING']:
                return assessment, 0, "already_active"
                
            # Check if active jobs already exist
            active_jobs_exist = assessment.jobs.filter(status__in=['QUEUED', 'RUNNING']).exists()
            if active_jobs_exist:
                return assessment, 0, "already_active"
                
            # 2. Run safety gate validation
            cls.run_safety_gate(assessment)
            
            # 3. Retrieve selected modules
            selected_keys = assessment.selected_modules or []
            modules = {m.key: m for m in TestingModule.objects.filter(key__in=selected_keys, enabled=True)}
            
            jobs_created = []
            for key in selected_keys:
                module = modules[key]
                
                # Determine environment based on categories and requirements
                if module.requires_live_url:
                    env = 'LIVE'
                elif module.requires_source_code or module.category in ['CODE', 'SUPPLY_CHAIN']:
                    env = 'SANDBOX'
                else:
                    env = 'LOCAL'
                    
                # Create ScanJob
                job = ScanJob.objects.create(
                    assessment=assessment,
                    testing_module=module,
                    status='QUEUED',
                    progress=0,
                    priority=10
                )
                
                # Create ModuleExecution record
                ModuleExecution.objects.create(
                    scan_job=job,
                    module_key=module.key,
                    execution_environment=env,
                    status='QUEUED'
                )
                
                # Create initial ExecutionLog
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='INFO',
                    message=f"Initialized scan job tracking for module: {module.name} ({module.key}) under environment: {env}."
                )
                
                jobs_created.append(job)
                
            # 4. Update Assessment status
            assessment.status = 'QUEUED'
            assessment.save()
            
            # Log audit event
            print(f"[AUDIT] Assessment {assessment.id} started. Created {len(jobs_created)} ScanJobs.")
            
            return assessment, len(jobs_created), "started"
