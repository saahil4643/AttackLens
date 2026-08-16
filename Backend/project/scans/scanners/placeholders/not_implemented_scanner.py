from scans.scanners.base import BaseScanner

class SkipJobException(Exception):
    pass

class NotImplementedScanner(BaseScanner):
    def validate(self, assessment, project):
        pass

    def prepare(self):
        pass

    def run(self, progress_callback=None):
        raise SkipJobException("Scanner is registered but not implemented yet in the current version.")

    def cancel(self):
        pass

    def cleanup(self):
        pass
