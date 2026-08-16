from django.db import migrations

def seed_canonical_modules(apps, schema_editor):
    TestingModule = apps.get_model('core', 'TestingModule')
    
    # 1. Network Reconnaissance
    network_recon_schema = {
        "port_profile": {
            "type": "select",
            "options": ["COMMON", "WEB", "DATABASE", "FULL", "CUSTOM"],
            "default": "COMMON"
        },
        "connect_timeout": {
            "type": "integer",
            "default": 2,
            "min": 1,
            "max": 10
        },
        "max_concurrency": {
            "type": "integer",
            "default": 20,
            "min": 1,
            "max": 100
        }
    }
    TestingModule.objects.get_or_create(
        key='network_recon',
        defaults={
            'name': 'Network Reconnaissance & Port Scanning',
            'category': 'RECON',
            'description': 'Discovers active hosts, scans open ports, grabs banners, and maps running services.',
            'enabled': True,
            'requires_live_url': True,
            'requires_source_code': False,
            'requires_authentication': False,
            'configuration_schema': network_recon_schema
        }
    )
    
    # 2. Web Security Headers Test (Placeholder)
    TestingModule.objects.get_or_create(
        key='web_security_headers_test',
        defaults={
            'name': 'Web Security Headers Assessment',
            'category': 'WEB',
            'description': 'Analyzes security headers (CSP, HSTS, X-Frame-Options) on the web application.',
            'enabled': True,
            'requires_live_url': True,
            'requires_source_code': False,
            'requires_authentication': False,
            'configuration_schema': {}
        }
    )
    
    # 3. SAST Code Security Review (Placeholder)
    TestingModule.objects.get_or_create(
        key='sast_test',
        defaults={
            'name': 'Static Application Security Testing (SAST)',
            'category': 'CODE',
            'description': 'Audits the uploaded source code ZIP for vulnerabilities, secrets, and code quality issues.',
            'enabled': True,
            'requires_live_url': False,
            'requires_source_code': True,
            'requires_authentication': False,
            'configuration_schema': {}
        }
    )

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0003_update_network_recon_schema'),
    ]

    operations = [
        migrations.RunPython(seed_canonical_modules),
    ]
