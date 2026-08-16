import time
from scans.scanners.base import BaseScanner

class ScopeException(Exception):
    pass

class PlaceholderScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.is_cancelled = False

    def validate(self, assessment, project):
        if not self.context.scopes:
            raise ScopeException("No valid assessment scope available.")
        
        module = self.context.testing_module
        if module.requires_live_url and not self.context.target:
            raise ScopeException(f"Target scope missing required Live URL for module '{module.name}'.")
        if module.requires_source_code and not self.context.project.source_archive:
            raise ScopeException(f"Target scope missing required Source Code ZIP for module '{module.name}'.")

    def prepare(self):
        pass

    def run(self, progress_callback=None):
        steps = [
            (10, "Initializing scan environment configurations"),
            (30, "Resolving target scope perimeter boundaries"),
            (60, "Running vulnerability pattern heuristics"),
            (100, "Vulnerability scan completed, generating execution logs summary")
        ]
        
        for percent, msg in steps:
            if self.is_cancelled:
                break
            if progress_callback:
                progress_callback(percent, msg)
            time.sleep(0.05)  # Fast delay for worker execution simulations

        if self.is_cancelled:
            return {
                "status": "cancelled",
                "scanner": "placeholder",
                "scanner_version": "0.1.0",
                "message": "Scanner execution was cancelled."
            }

        return {
            "status": "completed",
            "scanner": "placeholder",
            "scanner_version": "0.1.0",
            "findings_count": 0,
            "data": {},
            "message": "Development placeholder. No security testing was executed."
        }

    def cancel(self):
        self.is_cancelled = True

    def cleanup(self):
        pass
