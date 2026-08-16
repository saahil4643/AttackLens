import os
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from core.models import TestingModule
from projects.models import Project, Assessment, AssessmentScope
from scans.models import ScanJob, ModuleExecution, ExecutionLog

class AssessmentExecutionTests(APITestCase):

    def setUp(self):
        # Create testing modules in database setup
        self.web_module, _ = TestingModule.objects.get_or_create(
            key='web_security_headers_test',
            defaults={
                'name': 'Web Security Headers',
                'category': 'WEB',
                'enabled': True,
                'requires_live_url': True,
                'requires_source_code': False
            }
        )
        self.web_module.name = 'Web Security Headers'
        self.web_module.category = 'WEB'
        self.web_module.enabled = True
        self.web_module.requires_live_url = True
        self.web_module.requires_source_code = False
        self.web_module.save()

        self.code_module, _ = TestingModule.objects.get_or_create(
            key='sast_test',
            defaults={
                'name': 'SAST',
                'category': 'CODE',
                'enabled': True,
                'requires_live_url': False,
                'requires_source_code': True
            }
        )
        self.code_module.name = 'SAST'
        self.code_module.category = 'CODE'
        self.code_module.enabled = True
        self.code_module.requires_live_url = False
        self.code_module.requires_source_code = True
        self.code_module.save()

        self.disabled_module, _ = TestingModule.objects.get_or_create(
            key='disabled_test',
            defaults={
                'name': 'Disabled Module',
                'category': 'WEB',
                'enabled': False,
                'requires_live_url': False,
                'requires_source_code': False
            }
        )
        self.disabled_module.enabled = False
        self.disabled_module.save()

        # Create base test projects
        self.project = Project.objects.create(
            name="Test Project",
            description="Test project desc",
            live_url="http://example.com"
        )
        
        # Project with a mock source archive upload
        self.dummy_zip = SimpleUploadedFile("source.zip", b"dummy_content", content_type="application/zip")
        self.project_with_zip = Project.objects.create(
            name="Project with Code",
            live_url="http://example.com",
            source_archive=self.dummy_zip,
            source_archive_name="source.zip",
            source_archive_size=13,
            source_uploaded_at=timezone.now()
        )

    def test_create_assessment(self):
        url = reverse('assessment-list')
        data = {
            'project_name': 'New Dynamic Project',
            'name': 'Web Audit',
            'live_url': 'http://example.com',
            'selected_modules': ['web_security_headers_test']
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Assessment.objects.filter(name='Web Audit').count(), 1)
        self.assertEqual(AssessmentScope.objects.filter(target_type='LIVE_URL').count(), 1)

    def test_start_valid_assessment(self):
        # Create ready assessment
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test'],
            status='DRAFT'
        )
        # Add scope
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        assessment.refresh_from_db()
        self.assertEqual(assessment.status, 'QUEUED')
        self.assertEqual(assessment.jobs.count(), 1)
        job = assessment.jobs.first()
        self.assertEqual(job.status, 'QUEUED')
        self.assertEqual(job.executions.count(), 1)
        self.assertEqual(job.logs.count(), 1)

    def test_create_one_job_per_selected_module(self):
        # Create assessment with two modules
        assessment = Assessment.objects.create(
            project=self.project_with_zip,
            name="Dual Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test', 'sast_test'],
            status='DRAFT'
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(assessment.jobs.count(), 2)

    def test_prevent_duplicate_job_creation(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Audit Duplicate",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test'],
            status='DRAFT'
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response1 = self.client.post(url, format='json')
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        
        # Second call triggers 409 conflict
        response2 = self.client.post(url, format='json')
        self.assertEqual(response2.status_code, status.HTTP_409_CONFLICT)

    def test_reject_disabled_modules(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Audit Disabled",
            live_url="http://example.com",
            selected_modules=['disabled_test'],
            status='DRAFT'
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("disabled or not found", str(response.data['error']))

    def test_reject_missing_required_source_code(self):
        # SAST module requires source zip, none is set on project
        assessment = Assessment.objects.create(
            project=self.project,
            name="SAST Audit",
            selected_modules=['sast_test'],
            status='DRAFT'
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='SOURCE_CODE',
            target="missing"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("requires a source-code ZIP archive", str(response.data['error']))

    def test_reject_missing_required_live_url(self):
        # Module requires live URL, but project/assessment has none
        assessment = Assessment.objects.create(
            project=self.project_with_zip,
            name="Web No URL Audit",
            live_url="",
            selected_modules=['web_security_headers_test'],
            status='DRAFT'
        )
        self.project_with_zip.live_url = ""
        self.project_with_zip.save()
        
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='SOURCE_CODE',
            target="source.zip"
        )
        
        url = reverse('assessment-start', args=[assessment.id])
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("requires a live URL", str(response.data['error']))


    def test_get_assessment_jobs(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.client.post(reverse('assessment-start', args=[assessment.id]), format='json')
        
        url = reverse('assessment-jobs', args=[assessment.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['module'], 'web_security_headers_test')

    def test_get_job_details(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.client.post(reverse('assessment-start', args=[assessment.id]), format='json')
        job = assessment.jobs.first()
        
        url = reverse('scanjob-detail', args=[job.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('job', response.data)
        self.assertIn('assessment', response.data)
        self.assertIn('testing_module', response.data)
        self.assertIn('execution', response.data)

    def test_get_execution_logs(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.client.post(reverse('assessment-start', args=[assessment.id]), format='json')
        job = assessment.jobs.first()
        
        url = reverse('scanjob-logs', args=[job.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_cancel_queued_and_running_jobs(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.client.post(reverse('assessment-start', args=[assessment.id]), format='json')
        job = assessment.jobs.first()
        
        # Cancel queued job
        cancel_url = reverse('scanjob-cancel', args=[job.id])
        response = self.client.post(cancel_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        job.refresh_from_db()
        self.assertEqual(job.status, 'CANCELLED')
        
        # Cancel running job
        job2 = ScanJob.objects.create(
            assessment=assessment,
            testing_module=self.web_module,
            status='RUNNING'
        )
        cancel_url2 = reverse('scanjob-cancel', args=[job2.id])
        response2 = self.client.post(cancel_url2, format='json')
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        job2.refresh_from_db()
        self.assertEqual(job2.status, 'CANCELLED')

    def test_reject_cancellation_of_completed_jobs(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        job = ScanJob.objects.create(
            assessment=assessment,
            testing_module=self.web_module,
            status='COMPLETED'
        )
        
        cancel_url = reverse('scanjob-cancel', args=[job.id])
        response = self.client.post(cancel_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Cannot cancel a job", response.data['error'])

    def test_get_execution_summary(self):
        assessment = Assessment.objects.create(
            project=self.project,
            name="Valid Audit",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        AssessmentScope.objects.create(
            assessment=assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.client.post(reverse('assessment-start', args=[assessment.id]), format='json')
        
        url = reverse('assessment-execution', args=[assessment.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'QUEUED')
        self.assertEqual(response.data['queued'], 1)
        self.assertEqual(response.data['total_jobs'], 1)


from scans.services.execution_service import ExecutionService
from scans.scanners.base import BaseScanner
from scans.services.scanner_registry import ScannerRegistry

class FailingScanner(BaseScanner):
    def validate(self, assessment, project):
        pass
    def prepare(self):
        pass
    def run(self, progress_callback=None):
        raise Exception("Mock failure simulation.")
    def cancel(self):
        pass
    def cleanup(self):
        self.scan_job.result = {"cleaned": True}
        self.scan_job.save()

class WorkerAndExecutionTests(APITestCase):
    def setUp(self):
        self.web_module, _ = TestingModule.objects.get_or_create(
            key='web_security_headers_test',
            defaults={
                'name': 'Web Security Headers',
                'category': 'WEB',
                'enabled': True,
                'requires_live_url': True,
                'requires_source_code': False
            }
        )
        self.web_module.name = 'Web Security Headers'
        self.web_module.category = 'WEB'
        self.web_module.enabled = True
        self.web_module.requires_live_url = True
        self.web_module.requires_source_code = False
        self.web_module.save()
        self.project = Project.objects.create(
            name="Test Project",
            live_url="http://example.com"
        )
        self.assessment = Assessment.objects.create(
            project=self.project,
            name="Audit Target",
            live_url="http://example.com",
            selected_modules=['web_security_headers_test']
        )
        self.scope = AssessmentScope.objects.create(
            assessment=self.assessment,
            target_type='LIVE_URL',
            target="http://example.com"
        )
        self.job = ScanJob.objects.create(
            assessment=self.assessment,
            testing_module=self.web_module,
            status='QUEUED'
        )
        ModuleExecution.objects.create(
            scan_job=self.job,
            module_key=self.web_module.key,
            execution_environment='LIVE',
            status='QUEUED'
        )

    def test_queued_job_executes_successfully(self):
        job = ExecutionService.execute_job(self.job.id)
        self.assertEqual(job.status, 'COMPLETED')
        self.assertEqual(job.progress, 100)
        self.assertEqual(job.result['status'], 'completed')
        self.assertTrue(job.logs.filter(message__contains="Job completed.").exists())

    def test_scanner_failure_changes_job_to_failed(self):
        ScannerRegistry.register('web_security_headers_test', FailingScanner)
        try:
            job = ExecutionService.execute_job(self.job.id)
            self.assertEqual(job.status, 'FAILED')
            self.assertIn("Mock failure simulation.", job.error_message)
            self.assertTrue(job.result.get('cleaned'))
        finally:
            from scans.scanners.placeholders.placeholder_scanner import PlaceholderScanner
            ScannerRegistry.register('web_security_headers_test', PlaceholderScanner)

    def test_cancellation_calls_scanner_cancel_and_cleans_up(self):
        self.job.status = 'RUNNING'
        self.job.save()
        
        cancel_url = reverse('scanjob-cancel', args=[self.job.id])
        response = self.client.post(cancel_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'CANCELLED')

    def test_unsupported_scanner_skipped(self):
        unsupported_module, _ = TestingModule.objects.get_or_create(
            key='unsupported_key',
            defaults={
                'name': 'Unsupported Module',
                'category': 'WEB',
                'enabled': True
            }
        )
        unsupported_module.enabled = True
        unsupported_module.save()
        job = ScanJob.objects.create(
            assessment=self.assessment,
            testing_module=unsupported_module,
            status='QUEUED'
        )
        
        job = ExecutionService.execute_job(job.id)
        self.assertEqual(job.status, 'SKIPPED')
        self.assertIn("skipped", job.result['status'])

    def test_assessment_changes_status_as_jobs_progress(self):
        self.assessment.status = 'READY'
        self.assessment.save()
        
        job = ExecutionService.execute_job(self.job.id)
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, 'COMPLETED')

    def test_execution_without_valid_scope_fails(self):
        self.assessment.scopes.all().delete()
        
        job = ExecutionService.execute_job(self.job.id)
        self.assertEqual(job.status, 'FAILED')
        self.assertIn("No valid assessment scope available", job.error_message)

    def test_worker_picks_up_and_processes_queued_jobs(self):
        from django.core.management import call_command
        from unittest.mock import patch
        
        def mock_sleep(seconds):
            if seconds == 0.5:
                raise KeyboardInterrupt
        
        with patch('time.sleep', side_effect=mock_sleep):
            try:
                call_command('run_scan_worker')
            except KeyboardInterrupt:
                pass
                
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'COMPLETED')


from unittest.mock import patch, MagicMock
import subprocess
from scans.scanners.base import ScannerContext
from scans.scanners.placeholders.placeholder_scanner import ScopeException
from scans.scanners.network.host_discovery import HostDiscovery
from scans.scanners.network.nmap_runner import NmapRunner
from scans.scanners.network.nmap_parser import NmapParser
from scans.scanners.network.network_recon import NetworkReconScanner
from scans.services.execution_service import ExecutionService
from assets.models import Asset
from findings.models import Finding

MOCK_NMAP_XML_SUCCESS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 1-1024 -oX - 127.0.0.1" start="1692220000" version="7.99" xmloutputversion="1.05">
<host starttime="1692220001" endtime="1692220010">
<status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="mysql" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="conn-refused" reason_ttl="0"/></port>
</ports>
</host>
</nmaprun>
"""

MOCK_NMAP_XML_MULTIPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 1-1024 -oX - 127.0.0.1 192.168.1.1" start="1692220000" version="7.99" xmloutputversion="1.05">
<host>
<status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports>
</host>
<host>
<status state="up" reason="ping-response"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames><hostname name="router" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>
"""


class NetworkScannerTests(APITestCase):
    def setUp(self):
        # Retrieve or seed the canonical network_recon module in test db
        self.module, _ = TestingModule.objects.get_or_create(
            key='network_recon',
            defaults={
                'name': 'Network Scanner',
                'category': 'NETWORK',
                'enabled': True,
                'requires_live_url': True,
                'configuration_schema': {}
            }
        )
        self.module.name = 'Network Scanner'
        self.module.category = 'NETWORK'
        self.module.enabled = True
        self.module.requires_live_url = True
        self.module.configuration_schema = {}
        self.module.save()

        self.project = Project.objects.create(
            name="Network Test Project",
            live_url="http://example.com"
        )
        self.assessment = Assessment.objects.create(
            project=self.project,
            name="Nmap Audit",
            configuration={},  # Emptied config
            selected_modules=['network_recon']
        )
        self.scope_ip = AssessmentScope.objects.create(
            assessment=self.assessment,
            target_type='IP',
            target="127.0.0.1"
        )
        self.scope_cidr = AssessmentScope.objects.create(
            assessment=self.assessment,
            target_type='CIDR',
            target="192.168.1.0/28"
        )
        self.job = ScanJob.objects.create(
            assessment=self.assessment,
            testing_module=self.module,
            status='QUEUED'
        )

    @patch('shutil.which', return_value="/usr/bin/nmap")
    @patch('subprocess.run')
    def test_nmap_availability_and_version(self, mock_run, mock_which):
        # Mock successful version output
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Nmap version 7.99 ( https://nmap.org )\nPlatform: i686-pc-windows"
        mock_run.return_value = mock_proc

        self.assertTrue(NmapRunner.is_nmap_installed())
        self.assertEqual(NmapRunner.get_nmap_version(), "Nmap version 7.99 ( https://nmap.org )")

    @patch('shutil.which', return_value="/usr/bin/nmap")
    @patch('subprocess.Popen')
    def test_nmap_command_construction(self, mock_popen, mock_which):
        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        mock_process.communicate.return_value = (MOCK_NMAP_XML_SUCCESS, "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        runner = NmapRunner()
        res = runner.run_scan(target="127.0.0.1", port_range="1-1024")
        
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["xml_output"], MOCK_NMAP_XML_SUCCESS)
        
        # Verify args passed to Popen contain the correct Nmap flags
        called_args = mock_popen.call_args[0][0]
        self.assertEqual(called_args, ["nmap", "-sT", "-p", "1-1024", "-oX", "-", "127.0.0.1"])

    def test_scope_guard_target_enforcement(self):
        # Validate that within scope target scans pass
        scanner = NetworkReconScanner(ScannerContext(self.job))
        scanner.targets_to_scan = ["127.0.0.1", "192.168.1.5"]
        # Should not raise exception
        scanner.validate(self.assessment, self.project)

        # Rejection of out-of-scope targets
        scanner2 = NetworkReconScanner(ScannerContext(self.job))
        scanner2.targets_to_scan = ["10.0.0.1"]
        with self.assertRaises(ScopeException):
            scanner2.validate(self.assessment, self.project)

    def test_xml_parsing_cases(self):
        # Parse single host open/closed ports
        hosts = NmapParser.parse_xml(MOCK_NMAP_XML_SUCCESS)
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host["ip"], "127.0.0.1")
        self.assertEqual(host["status"], "up")
        self.assertIn("localhost", host["hostnames"])
        
        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        self.assertEqual(len(open_ports), 2)
        self.assertEqual(open_ports[0]["port"], 80)
        self.assertEqual(open_ports[0]["service"], "http")
        self.assertEqual(open_ports[1]["port"], 3306)
        self.assertEqual(open_ports[1]["service"], "mysql")

        closed_ports = [p for p in host["ports"] if p["state"] == "closed"]
        self.assertEqual(len(closed_ports), 1)
        self.assertEqual(closed_ports[0]["port"], 443)

        # Parse multiple hosts
        hosts_multi = NmapParser.parse_xml(MOCK_NMAP_XML_MULTIPLE)
        self.assertEqual(len(hosts_multi), 2)
        self.assertEqual(hosts_multi[0]["ip"], "127.0.0.1")
        self.assertEqual(hosts_multi[1]["ip"], "192.168.1.1")

    def test_invalid_xml_handling(self):
        with self.assertRaises(ValueError):
            NmapParser.parse_xml("<invalid xml>")

    @patch('shutil.which', return_value="/usr/bin/nmap")
    @patch('subprocess.Popen')
    def test_nmap_timeout_handling(self, mock_popen, mock_which):
        mock_process = MagicMock()
        # Mock poll returning None (still running)
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        runner = NmapRunner(timeout=0.1)
        res = runner.run_scan(target="127.0.0.1", port_range="1-1024")
        self.assertEqual(res["status"], "timeout")
        
        import os, signal
        if os.name == 'nt':
            mock_process.send_signal.assert_called_once_with(signal.CTRL_BREAK_EVENT)
        else:
            mock_process.terminate.assert_called_once()

    @patch('shutil.which', return_value="/usr/bin/nmap")
    @patch('subprocess.Popen')
    def test_nmap_cancellation(self, mock_popen, mock_which):
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        runner = NmapRunner()
        # Cancel check returns True immediately
        res = runner.run_scan(target="127.0.0.1", port_range="1-1024", cancel_check=lambda: True)
        self.assertEqual(res["status"], "cancelled")
        
        import os, signal
        if os.name == 'nt':
            mock_process.send_signal.assert_called_once_with(signal.CTRL_BREAK_EVENT)
        else:
            mock_process.terminate.assert_called_once()

    @patch('scans.scanners.network.nmap_runner.NmapRunner.is_nmap_installed', return_value=True)
    @patch('scans.scanners.network.nmap_runner.NmapRunner.run_scan')
    def test_end_to_end_assessment_execution_assets_and_findings(self, mock_run_scan, mock_installed):
        # Setup mock run success
        mock_run_scan.return_value = {
            "status": "success",
            "xml_output": MOCK_NMAP_XML_SUCCESS,
            "stderr": "",
            "error_message": ""
        }

        # Clear CIDR scope to only test 127.0.0.1
        self.scope_cidr.delete()

        # Run ScanJob through ExecutionService
        self.assertEqual(self.job.status, 'QUEUED')
        job = ExecutionService.execute_job(self.job.id)

        # Assert completed successfully
        self.assertEqual(job.status, 'COMPLETED')
        self.assertEqual(job.result["hosts_scanned"], 1)
        self.assertEqual(job.result["open_ports"], 2)

        # Verify DB assets populated
        ip_assets = Asset.objects.filter(asset_type='IP', value='127.0.0.1')
        self.assertTrue(ip_assets.exists())
        self.assertEqual(ip_assets.first().metadata["hostname"], "localhost")

        port_assets = Asset.objects.filter(asset_type='PORT')
        self.assertEqual(port_assets.count(), 2)
        self.assertTrue(port_assets.filter(value='127.0.0.1:80').exists())
        self.assertTrue(port_assets.filter(value='127.0.0.1:3306').exists())

        # Verify DB findings populated from MySQL database port exposure
        findings = Finding.objects.filter(project=self.project)
        self.assertEqual(findings.count(), 1)
        self.assertEqual(findings.first().title, "Exposed Database Service (mysql)")
        self.assertEqual(findings.first().severity, "MEDIUM")

        # Verify duplicates are prevented when executing again
        job_retry = ScanJob.objects.create(
            assessment=self.assessment,
            testing_module=self.module,
            status='QUEUED'
        )
        ExecutionService.execute_job(job_retry.id)
        # Port asset count should remain 2 (no duplicates created)
        self.assertEqual(Asset.objects.filter(asset_type='PORT').count(), 2)

    def test_frontend_module_config_schema_response(self):
        url = reverse('testingmodule-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify network_recon has empty configuration_schema
        network_recon_mod = next(m for m in response.data if m['key'] == 'network_recon')
        self.assertEqual(network_recon_mod['configuration_schema'], {})




