from django.db import migrations

def update_network_recon_schema(apps, schema_editor):
    TestingModule = apps.get_model('core', 'TestingModule')
    
    schema = {
        "port_profile": {
            "type": "select",
            "options": [
                "COMMON",
                "WEB",
                "DATABASE",
                "FULL",
                "CUSTOM"
            ],
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
    
    # Update seed network_recon module schema mapping
    TestingModule.objects.filter(key='network_recon').update(
        configuration_schema=schema,
        enabled=True
    )

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0002_seed_testing_modules'),
    ]

    operations = [
        migrations.RunPython(update_network_recon_schema),
    ]
