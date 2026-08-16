from django.contrib import admin
from .models import Project, Assessment, AssessmentScope

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'status', 'created_at', 'updated_at', 'source_archive_name', 'source_archive_size')
    list_filter = ('status',)
    search_fields = ('name', 'description')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'source_uploaded_at')


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'name', 'live_url', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'project')
    search_fields = ('name', 'live_url')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at', 'started_at', 'completed_at')


@admin.register(AssessmentScope)
class AssessmentScopeAdmin(admin.ModelAdmin):
    list_display = ('id', 'assessment', 'target_type', 'target', 'included', 'created_at')
    list_filter = ('target_type', 'included', 'assessment__project')
    search_fields = ('target', 'notes')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
