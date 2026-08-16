import shutil
from django.core.management.base import BaseCommand
from scans.scanners.network.nmap_runner import NmapRunner

class Command(BaseCommand):
    help = 'Diagnostic command to check if Nmap is installed and available in the environment PATH.'

    def handle(self, *args, **options):
        if NmapRunner.is_nmap_installed():
            version = NmapRunner.get_nmap_version()
            executable = shutil.which("nmap")
            self.stdout.write(self.style.SUCCESS("Nmap detected"))
            self.stdout.write(f"Version: {version}")
            self.stdout.write(f"Executable: {executable}")
        else:
            self.stdout.write(self.style.ERROR("Nmap not found"))
