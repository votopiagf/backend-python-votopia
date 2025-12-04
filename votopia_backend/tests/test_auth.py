"""
Test per gli endpoint di autenticazione
"""
import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.auth
@pytest.mark.django_db
class TestAuthEndpoints:
    """Test per gli endpoint di autenticazione"""

    def test_health_check_no_auth(self, api_client):
        """Test che il health check funzioni senza autenticazione"""
        url = reverse('health-check')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'ok'
        assert 'version' in response.data

    def test_login_with_valid_credentials(self, api_client, create_test_user):
        """Test login con credenziali valide"""
        # Crea utente di test
        user = create_test_user(
            email="testuser@example.com",
            password="testpass123"
        )

        url = reverse('api-login')
        data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert 'user' in response.data
        assert response.data['user']['email'] == 'testuser@example.com'

    def test_login_with_invalid_email(self, api_client):
        """Test login con email inesistente"""
        url = reverse('api-login')
        data = {
            'email': 'nonexistent@example.com',
            'password': 'password123'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_with_invalid_password(self, api_client, create_test_user):
        """Test login con password errata"""
        user = create_test_user(
            email="testuser@example.com",
            password="correctpass"
        )

        url = reverse('api-login')
        data = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword'
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_with_missing_fields(self, api_client):
        """Test login con campi mancanti"""
        url = reverse('api-login')

        # Solo email
        response = api_client.post(url, {'email': 'test@example.com'}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Solo password
        response = api_client.post(url, {'password': 'password123'}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Nessun campo
        response = api_client.post(url, {}, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_token_refresh(self, api_client, create_test_user):
        """Test refresh token"""
        # Prima fai login per ottenere il refresh token
        user = create_test_user(
            email="testuser@example.com",
            password="testpass123"
        )

        login_url = reverse('api-login')
        login_data = {
            'email': 'testuser@example.com',
            'password': 'testpass123'
        }
        login_response = api_client.post(login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']

        # Usa il refresh token per ottenere un nuovo access token
        refresh_url = reverse('token_refresh')
        refresh_data = {'refresh': refresh_token}
        response = api_client.post(refresh_url, refresh_data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data

    def test_my_permissions_with_auth(self, authenticated_client):
        """Test endpoint my-permissions con autenticazione"""
        url = reverse('my-permissions')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'success'
        assert 'permissions' in response.data['data']
        assert 'user_info' in response.data['data']

    def test_my_permissions_without_auth(self, api_client):
        """Test endpoint my-permissions senza autenticazione"""
        url = reverse('my-permissions')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_test_endpoint_with_auth(self, authenticated_client):
        """Test endpoint di test con autenticazione"""
        url = reverse('test')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'success'
