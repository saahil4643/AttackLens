class ScannerContext:
    def __init__(self, scan_job):
        self.scan_job = scan_job
        self.assessment = scan_job.assessment
        self.project = scan_job.assessment.project
        self.testing_module = scan_job.testing_module
        self.configuration = scan_job.assessment.configuration
        self.scopes = list(scan_job.assessment.scopes.all())
        
        # Determine primary target URL or fallback
        primary_scope = scan_job.assessment.scopes.filter(target_type='LIVE_URL').first() or scan_job.assessment.scopes.first()
        self.target = primary_scope.target if primary_scope else scan_job.assessment.live_url


class BaseScanner:
    def __init__(self, context: ScannerContext):
        self.context = context
        self.scan_job = context.scan_job

    def validate(self, assessment, project):
        """
        Validate targets and configurations before running.
        """
        pass

    def prepare(self):
        """
        Prepare files, environments, keys, or network paths.
        """
        pass

    def run(self):
        """
        Execute scanner checks. Must return a result dictionary.
        """
        raise NotImplementedError("Scanner subclasses must implement run()")

    def cancel(self):
        """
        Trigger interruption or graceful cancellation.
        """
        pass

    def cleanup(self):
        """
        Perform cleanup of temporary files or networking connections.
        """
        pass
