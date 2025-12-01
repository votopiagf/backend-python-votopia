from django.contrib import admin
from django.urls import path, re_path
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from votopia_backend.views import *

urlpatterns = [
    # Health check
    path('api/health/', health_check, name='health-check'),

    # JWT Token endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Login endpoint
    path('api/auth/login/', LoginView.as_view(), name='api-login'),

    # Permissions endpoint
    path('api/my-permissions/', my_permissions, name='my-permissions'),

    # User routes
    path('api/auth/register/', register, name='register'),
    path('api/users/info/', view_user_information, name='view_user_information'),
    path('api/users/all/', view_all_user, name='view_all_user'),
    path('api/users/delete/', delete_user, name='delete_user'),
    path('api/users/update/', update_user, name='update_user'),

    # Admin
    path('admin/', admin.site.urls),

    # Test
    path('test/', test, name='test'),

    #Role routes
    path('api/roles/create/', create_role, name='create_role'),
]