from django.contrib import admin
from .models import TestingModule

@admin.register(TestingModule)
class TestingModuleAdmin(admin.ModelAdmin):
    list_display = ('id', 'key', 'name', 'category', 'version', 'enabled', 'requires_live_url', 'requires_source_code')
    list_filter = ('category', 'enabled', 'requires_live_url', 'requires_source_code')
    search_fields = ('key', 'name', 'description')
    ordering = ('category', 'key')
