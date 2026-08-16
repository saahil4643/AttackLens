from django.contrib import admin
from .models import Finding, FindingOccurrence, FindingEvidence

@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'title', 'severity', 'confidence', 'category', 
        'status', 'project', 'assessment', 'testing_module', 'created_at', 'updated_at'
    )
    list_filter = ('severity', 'confidence', 'category', 'status', 'project')
    search_fields = ('title', 'description', 'cwe', 'remediation', 'fingerprint')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'fingerprint')


@admin.register(FindingOccurrence)
class FindingOccurrenceAdmin(admin.ModelAdmin):
    list_display = ('id', 'finding', 'scan_job', 'first_seen', 'last_seen')
    list_filter = ('scan_job',)
    search_fields = ('finding__title', 'scan_job__id')
    readonly_fields = ('first_seen', 'last_seen')


@admin.register(FindingEvidence)
class FindingEvidenceAdmin(admin.ModelAdmin):
    list_display = ('id', 'finding', 'evidence_type', 'title', 'created_at')
    list_filter = ('evidence_type',)
    search_fields = ('finding__title', 'title', 'description', 'location', 'payload')
    readonly_fields = ('created_at',)
