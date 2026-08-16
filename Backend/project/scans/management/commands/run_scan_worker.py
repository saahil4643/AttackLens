import time
from django.core.management.base import BaseCommand
from django.db import transaction
from scans.models import ScanJob
from scans.services.execution_service import ExecutionService

class Command(BaseCommand):
    help = 'Runs the AttackLens scan job worker to process queued scan jobs.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting AttackLens scan worker... (Ctrl+C to quit)"))
        
        try:
            while True:
                # Lock and claim the next queued job inside an atomic block
                job = self.claim_next_job()
                if job:
                    self.stdout.write(f"Claimed Job {job.id} for module '{job.testing_module.key}'")
                    
                    try:
                        ExecutionService.execute_job(job.id)
                        self.stdout.write(self.style.SUCCESS(f"Finished processing Job {job.id}"))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Error executing Job {job.id}: {str(e)}"))
                else:
                    # Idle poll delay
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\nWorker shutdown requested. Exiting gracefully."))

    def claim_next_job(self):
        # Transaction-level row locking with SQLite fallback compatibility
        with transaction.atomic():
            job = ScanJob.objects.select_for_update().filter(status='QUEUED').order_by('priority', 'created_at').first()
            if job:
                job.status = 'RUNNING'
                job.save()
                return job
            return None
