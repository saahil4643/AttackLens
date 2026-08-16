from django.contrib import admin
from .models import Asset

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'target', 'asset_type', 'value', 'status', 'discovered_at')
    list_filter = ('asset_type', 'status', 'project')
    search_fields = ('value', 'metadata')
    ordering = ('-discovered_at',)
    readonly_fields = ('discovered_at', 'updated_at')
