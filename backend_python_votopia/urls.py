from django.contrib import admin
from django.urls import path, re_path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
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

    # Role routes
    path('api/roles/create/', create_role, name='create_role'),
    path('api/roles/update/', update_role, name='update_role'),
    path('api/roles/delete/', delete_role, name='delete_role'),

    path('api/roles/all/', view_all_roles, name='view_all_roles'),
    path('api/roles/info/', view_role_information, name='view_role_information'),

    # Lists routes
    path('api/lists/update/', update_list, name='update_list'),
    path('api/lists/create/', create_list, name='create_list'),
    path('api/lists/all/', view_all_lists, name='view_all_lists'),

    # Swagger
    # schema raw
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),

    # swagger UI
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),

    # Redoc
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),

    # Files routes
    path(
        "api/files/add/",
        add_file,
        name="add_file",
    ),

    path(
        "api/files/delete/",
        delete_file,
        name="delete_file",
    ),

    # Organization routes
    path('api/organizations/by-code/', view_organization_by_code, name='view_organization_by_code'),

    #Lists routes
    path('api/campaigns/create/', create_campaign, name='create_campaign'),
]
