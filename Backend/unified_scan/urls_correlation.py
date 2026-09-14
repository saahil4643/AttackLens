from django.urls import path
from .views_correlation import (
    get_attack_surface_correlation_view,
    get_attack_surface_inventory_view,
    recalculate_attack_surface_view,
)

urlpatterns = [
    # Base and Summary Alias
    path('', get_attack_surface_correlation_view, name='get_attack_surface_root'),
    path('summary/', get_attack_surface_correlation_view, name='get_attack_surface_summary'),
    path('summary', get_attack_surface_correlation_view, name='get_attack_surface_summary_noslash'),

    # Full Correlation Graph & Tree
    path('correlation/', get_attack_surface_correlation_view, name='get_attack_surface_correlation'),
    path('correlation', get_attack_surface_correlation_view, name='get_attack_surface_correlation_noslash'),
    path('graph/', get_attack_surface_correlation_view, name='get_attack_surface_graph'),
    path('graph', get_attack_surface_correlation_view, name='get_attack_surface_graph_noslash'),

    # Inventory View
    path('inventory/', get_attack_surface_inventory_view, name='get_attack_surface_inventory'),
    path('inventory', get_attack_surface_inventory_view, name='get_attack_surface_inventory_noslash'),

    # Recalculate
    path('correlate/', recalculate_attack_surface_view, name='recalculate_attack_surface'),
    path('correlate', recalculate_attack_surface_view, name='recalculate_attack_surface_noslash'),
]

