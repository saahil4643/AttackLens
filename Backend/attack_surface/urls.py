from django.urls import path
from .views import web_application_analysis, stream_web_application_analysis

urlpatterns = [
    path('web-application-analysis/', web_application_analysis, name='web_application_analysis'),
    path('stream-web-application-analysis/', stream_web_application_analysis, name='stream_web_application_analysis'),
]
