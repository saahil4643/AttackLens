from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from projects.models import Assessment
from core.models import TestingModule
from scans.models import ScanJob, ModuleExecution, ExecutionLog
from scans.scanners.base import ScannerContext
from scans.services.scanner_registry import ScannerRegistry
from scans.scanners.placeholders.not_implemented_scanner import SkipJobException
from scans.scanners.placeholders.placeholder_scanner import ScopeException

class ExecutionService:
    VALID_TRANSITIONS = {
        'QUEUED': ['RUNNING', 'CANCELLED', 'SKIPPED'],
        'RUNNING': ['COMPLETED', 'FAILED', 'CANCELLED', 'SKIPPED'],
    }

    @classmethod
    def validate_transition(cls, old_status, new_status):
        if old_status == new_status:
            return
        allowed = cls.VALID_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            raise ValidationError(f"Invalid job status transition from '{old_status}' to '{new_status}'.")

    @classmethod
    def update_progress(cls, job, percentage, message=None):
        clamped = max(0, min(100, int(percentage)))
        old_progress = job.progress
        job.progress = clamped
        job.save()
        
        # Log if progress has changed or if a specific message is provided
        if clamped != old_progress or message:
            log_msg = f"Progress: {clamped}%"
            if message:
                log_msg = f"Progress: {clamped}% - {message}"
            
            last_log = ExecutionLog.objects.filter(scan_job=job).order_by('-timestamp').first()
            if not last_log or last_log.message != log_msg:
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='INFO',
                    message=log_msg
                )

    @classmethod
    def update_assessment_status(cls, assessment):
        jobs = assessment.jobs.all()
        if not jobs.exists():
            return
            
        statuses = set(jobs.values_list('status', flat=True))
        
        # 1. At least one job is currently RUNNING
        if 'RUNNING' in statuses:
            assessment.status = 'RUNNING'
        # 2. At least one job is still QUEUED (and none is running)
        elif 'QUEUED' in statuses:
            assessment.status = 'QUEUED'
        # 3. All jobs completed or skipped
        elif statuses.issubset({'COMPLETED', 'SKIPPED'}):
            assessment.status = 'COMPLETED'
        # 4. All jobs cancelled
        elif statuses == {'CANCELLED'}:
            assessment.status = 'CANCELLED'
        # 5. Job contains failures or mixed errors
        elif 'FAILED' in statuses or 'CANCELLED' in statuses:
            assessment.status = 'FAILED'
        else:
            assessment.status = 'FAILED'
            
        assessment.save()

    @classmethod
    def execute_job(cls, job_id):
        # 1. Fetch job with lock inside a transaction block
        with transaction.atomic():
            try:
                job = ScanJob.objects.select_for_update().get(id=job_id)
            except ScanJob.DoesNotExist:
                return None
                
            # If job is already cancelled or finished, do not run it
            if job.status in ['COMPLETED', 'FAILED', 'CANCELLED', 'SKIPPED']:
                return job

            # Validate start transition
            cls.validate_transition(job.status, 'RUNNING')
            
            # Transition to RUNNING
            job.status = 'RUNNING'
            job.started_at = timezone.now()
            job.save()

        # Update parent assessment status
        cls.update_assessment_status(job.assessment)
        
        # Create execution logging
        ExecutionLog.objects.create(
            scan_job=job,
            level='INFO',
            message="Job started."
        )
        
        # Update corresponding ModuleExecution status to RUNNING
        job.executions.filter(status='QUEUED').update(
            status='RUNNING',
            started_at=job.started_at
        )

        scanner = None
        try:
            # 2. Setup Context and Resolve Scanner
            context = ScannerContext(job)
            scanner = ScannerRegistry.get_scanner(job.testing_module.key, context)
            
            # Audit log
            ExecutionLog.objects.create(
                scan_job=job,
                level='INFO',
                message="Scanner initialized."
            )
            
            # 3. Validate Scope (Scope Guard)
            scanner.validate(job.assessment, job.assessment.project)
            
            # 4. Prepare Scanner
            scanner.prepare()
            ExecutionLog.objects.create(
                scan_job=job,
                level='INFO',
                message="Scanner preparation completed."
            )
            
            ExecutionLog.objects.create(
                scan_job=job,
                level='INFO',
                message="Testing phase started."
            )
            
            # 5. Run Scanner
            def progress_cb(pct, msg=None):
                cls.update_progress(job, pct, msg)
                
            result = scanner.run(progress_callback=progress_cb)
            
            # Normalize findings and assets if returned by scanner result contract
            findings_count = 0
            assets_created_count = 0
            if isinstance(result, dict):
                # 1. Persist discovered assets
                raw_assets = result.get('assets', [])
                if isinstance(raw_assets, list):
                    from assets.models import Asset
                    for asset_data in raw_assets:
                        # Prevent duplicate assets: lookup by project, value, and type
                        asset_obj, created = Asset.objects.get_or_create(
                            project=job.assessment.project,
                            value=asset_data['value'],
                            asset_type=asset_data['asset_type'],
                            defaults={
                                'status': 'SAFE',
                                'metadata': asset_data.get('metadata', {})
                            }
                        )
                        if not created:
                            # Update existing metadata
                            if isinstance(asset_data.get('metadata'), dict):
                                if not isinstance(asset_obj.metadata, dict):
                                    asset_obj.metadata = {}
                                asset_obj.metadata.update(asset_data['metadata'])
                                asset_obj.save()
                        assets_created_count += 1

                # 2. Normalize security findings
                if 'findings' in result:
                    from findings.services.normalizer import FindingNormalizer
                    raw_findings = result.get('findings', [])
                    if isinstance(raw_findings, list):
                        for raw_f in raw_findings:
                            FindingNormalizer.normalize_finding(job, raw_f)
                        findings_count = len(raw_findings)

            # Build unified ScanJob result schema representation
            if not isinstance(result, dict):
                result = {"status": "completed", "findings_count": 0, "assets_created": 0}
            else:
                result["findings_count"] = findings_count
                result["assets_created"] = assets_created_count
                if "status" not in result:
                    result["status"] = "completed"
            
            # 6. Success save
            # Check for cancellation before marking complete
            job.refresh_from_db()
            if job.status == 'CANCELLED':
                # Scanner was cancelled during run
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='WARNING',
                    message="Testing phase cancelled during execution."
                )
                return job
                
            cls.validate_transition(job.status, 'COMPLETED')
            job.status = 'COMPLETED'
            job.result = result
            job.progress = 100
            job.completed_at = timezone.now()
            job.save()
            
            # Update corresponding executions status to COMPLETED
            job.executions.filter(status='RUNNING').update(
                status='COMPLETED',
                result=result,
                completed_at=job.completed_at
            )
            
            ExecutionLog.objects.create(
                scan_job=job,
                level='INFO',
                message="Testing phase completed."
            )
            ExecutionLog.objects.create(
                scan_job=job,
                level='INFO',
                message="Job completed."
            )
            
        except SkipJobException as e:
            # Module was skipped (e.g. NotImplementedScanner)
            job.refresh_from_db()
            if job.status != 'CANCELLED':
                job.status = 'SKIPPED'
                job.completed_at = timezone.now()
                job.result = {"status": "skipped", "message": str(e)}
                job.save()
                
                job.executions.filter(status='RUNNING').update(
                    status='SKIPPED',
                    result=job.result,
                    completed_at=job.completed_at
                )
                
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='WARNING',
                    message=f"Job skipped: {str(e)}"
                )

        except ScopeException as e:
            # Failed scope guard checks
            job.refresh_from_db()
            if job.status != 'CANCELLED':
                job.status = 'FAILED'
                job.error_message = str(e)
                job.completed_at = timezone.now()
                job.save()
                
                job.executions.filter(status='RUNNING').update(
                    status='FAILED',
                    result={"error": str(e)},
                    completed_at=job.completed_at
                )
                
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='ERROR',
                    message=f"Scope validation failed: {str(e)}"
                )

        except Exception as e:
            # Job crashed/failed
            job.refresh_from_db()
            if job.status != 'CANCELLED':
                job.status = 'FAILED'
                job.error_message = f"Execution failed: {str(e)}"
                job.completed_at = timezone.now()
                job.save()
                
                job.executions.filter(status='RUNNING').update(
                    status='FAILED',
                    result={"error": str(e)},
                    completed_at=job.completed_at
                )
                
                # Internal logging to stdout/stderr, safe log to ExecutionLog
                import traceback
                print(f"[ERROR] Job {job.id} failed:")
                traceback.print_exc()
                
                ExecutionLog.objects.create(
                    scan_job=job,
                    level='ERROR',
                    message="Scanner execution failed."
                )
        finally:
            # 7. Always perform scanner cleanup
            if scanner:
                try:
                    scanner.cleanup()
                except Exception as ex:
                    print(f"[ERROR] Scanner cleanup failed: {str(ex)}")

        # 8. Re-evaluate parent assessment status
        cls.update_assessment_status(job.assessment)
        
        job.refresh_from_db()
        return job
