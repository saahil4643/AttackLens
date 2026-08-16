from django.db import migrations

def update_network_scanner_metadata(apps, schema_editor):
    TestingModule = apps.get_model('core', 'TestingModule')
    # Update the network recon module metadata as requested
    TestingModule.objects.filter(key='network_recon').update(
        name='Network Scanner',
        category='NETWORK',
        description='Discover open TCP ports on explicitly authorized targets using Nmap.',
        configuration_schema={}
    )

def rollback_network_scanner_metadata(apps, schema_editor):
    TestingModule = apps.get_model('core', 'TestingModule')
    # Rollback to original values
    original_schema = {
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
    TestingModule.objects.filter(key='network_recon').update(
        name='Network Reconnaissance & Port Scanning',
        category='RECON',
        description='Discovers active hosts, scans open ports, grabs banners, and maps running services.',
        configuration_schema=original_schema
    )

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0004_seed_canonical_modules'),
    ]

    operations = [
        migrations.RunPython(update_network_scanner_metadata, rollback_network_scanner_metadata),
    ]
