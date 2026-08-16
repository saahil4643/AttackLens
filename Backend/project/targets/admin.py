from django.contrib import admin
from .models import Target

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'name', 'target_type', 'value', 'environment', 'scope', 'status', 'created_at')
    list_filter = ('target_type', 'environment', 'scope', 'status', 'project')
    search_fields = ('name', 'value', 'notes')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
