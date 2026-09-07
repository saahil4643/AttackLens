from django.urls import path
from .views import security_configuration, stream_security_configuration

urlpatterns = [
    path('security-configuration/', security_configuration, name='security_configuration'),
    path('stream-security-configuration/', stream_security_configuration, name='stream_security_configuration'),
]
