from django.urls import path
from secscan import views
app_name = 'secscan'
urlpatterns = [
    path('', views.check_headers_view, name='check_headers'),
    path('api/check-headers/', views.api_check_headers, name='api_check_headers'),
    path('api/bulk-check-headers/', views.api_bulk_check_headers, name='api_bulk_check_headers'),
]