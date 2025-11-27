"""
URL configuration for backend_python_votopia project.
"""

from django.contrib import admin
from django.urls import path, re_path
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from votopia_backend.views import LoginView, health_check, my_permissions, register

urlpatterns = [
    # Health check
    path('api/health/', health_check, name='health-check'),

    # JWT Token endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Login endpoint
    path('api/login/', LoginView.as_view(), name='api-login'),

    # Permissions endpoint
    path('api/my-permissions/', my_permissions, name='my-permissions'),

    # User routes
    path('api/users/register/', register, name='register'),

    # Admin
    path('admin/', admin.site.urls),
]