from django.contrib import admin
from .models import Scan, ScanJob, ModuleExecution, ExecutionLog

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'name', 'scan_type', 'status', 'progress', 'started_at', 'completed_at', 'created_at')
    list_filter = ('scan_type', 'status', 'project')
    search_fields = ('name', 'configuration')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ('id', 'assessment', 'testing_module', 'status', 'progress', 'priority', 'created_at', 'started_at', 'completed_at')
    list_filter = ('status', 'priority', 'assessment')
    search_fields = ('testing_module__name', 'testing_module__key', 'error_message')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'started_at', 'completed_at')


@admin.register(ModuleExecution)
class ModuleExecutionAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan_job', 'module_key', 'execution_environment', 'status', 'created_at')
    list_filter = ('execution_environment', 'status')
    search_fields = ('module_key',)
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'started_at', 'completed_at')


@admin.register(ExecutionLog)
class ExecutionLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan_job', 'level', 'message', 'timestamp')
    list_filter = ('level',)
    search_fields = ('message',)
    ordering = ('-timestamp',)
    readonly_fields = ('timestamp',)
