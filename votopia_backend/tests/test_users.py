"""
Test per gli endpoint di gestione utenti
"""
import pytest
from django.urls import reverse
from rest_framework import status
from votopia_backend.models import User


@pytest.mark.django_db
class TestUserEndpoints:
    """Test per gli endpoint CRUD utenti"""

    def test_view_user_information_self(self, authenticated_client):
        """Test visualizzazione informazioni utente corrente"""
        url = reverse('view_user_information')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'success'
        assert 'users' in response.data['data']
        assert len(response.data['data']['users']) == 1
        assert response.data['data']['users'][0]['email'] == authenticated_client.test_user.email

    def test_view_user_information_other_user(self, authenticated_client, create_test_user):
        """Test visualizzazione informazioni di altro utente nella stessa org"""
        # Crea un altro utente nella stessa organizzazione
        other_user = create_test_user(
            org=authenticated_client.test_org,
            email="other@test.com"
        )

        url = reverse('view_user_information')
        response = authenticated_client.get(url, {'user_id': other_user.id})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['users'][0]['id'] == other_user.id

    def test_view_user_information_without_auth(self, api_client):
        """Test visualizzazione informazioni senza autenticazione"""
        url = reverse('view_user_information')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_view_all_users_with_permission(self, authenticated_client):
        """Test visualizzazione tutti gli utenti con permesso"""
        url = reverse('view_all_user')
        response = authenticated_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'users' in response.data['data']

    def test_view_all_users_without_auth(self, api_client):
        """Test visualizzazione tutti gli utenti senza autenticazione"""
        url = reverse('view_all_user')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_register_user_with_permission(self, authenticated_client):
        """Test registrazione nuovo utente con permessi"""
        url = reverse('register')
        data = {
            'name': 'Mario',
            'surname': 'Rossi',
            'email': 'mario.rossi@test.com',
            'password': 'securepassword123',
            'lists': [],
            'roles': []
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['status'] == 'success'
        assert 'user' in response.data['data']
        assert response.data['data']['user']['email'] == 'mario.rossi@test.com'

        # Verifica che l'utente sia stato creato nel database
        user = User.objects.get(email='mario.rossi@test.com')
        assert user.name == 'Mario'
        assert user.surname == 'Rossi'

    def test_register_user_with_missing_fields(self, authenticated_client):
        """Test registrazione utente con campi mancanti"""
        url = reverse('register')

        # Manca password
        data = {
            'name': 'Mario',
            'surname': 'Rossi',
            'email': 'mario.rossi@test.com'
        }
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Manca email
        data = {
            'name': 'Mario',
            'surname': 'Rossi',
            'password': 'password123'
        }
        response = authenticated_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_user_without_permission(self, api_client, create_test_user):
        """Test registrazione utente senza permessi"""
        # Crea un utente senza permessi di creazione
        user = create_test_user(email="noperm@test.com", roles=[])

        # Genera token per questo utente
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken()
        refresh['user_id'] = user.id
        refresh['email'] = user.email
        refresh['name'] = user.name
        refresh['surname'] = user.surname
        refresh['org_id'] = user.org.id

        access = refresh.access_token
        access['user_id'] = user.id
        access['email'] = user.email

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(access)}')

        url = reverse('register')
        data = {
            'name': 'Test',
            'surname': 'User',
            'email': 'newuser@test.com',
            'password': 'password123'
        }
        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_user_self(self, authenticated_client):
        """Test aggiornamento del proprio profilo"""
        url = reverse('update_user')
        data = {
            'name': 'Updated Name',
            'surname': 'Updated Surname'
        }

        response = authenticated_client.put(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'success'

        # Verifica l'aggiornamento nel database
        user = User.objects.get(id=authenticated_client.test_user.id)
        assert user.name == 'Updated Name'
        assert user.surname == 'Updated Surname'

    def test_update_user_email(self, authenticated_client):
        """Test aggiornamento email utente"""
        url = reverse('update_user')
        data = {
            'email': 'newemail@test.com'
        }

        response = authenticated_client.put(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK

        # Verifica l'aggiornamento
        user = User.objects.get(id=authenticated_client.test_user.id)
        assert user.email == 'newemail@test.com'

    def test_delete_user_with_permission(self, admin_client, create_test_user):
        """Test eliminazione utente con permesso"""
        # Crea un utente da eliminare nella stessa org
        user_to_delete = create_test_user(
            org=admin_client.test_org,
            email="todelete@test.com"
        )

        url = reverse('delete_user')
        response = admin_client.delete(url, {'user_id': user_to_delete.id})

        assert response.status_code == status.HTTP_200_OK

        # Verifica soft delete
        user = User.objects.get(id=user_to_delete.id)
        assert user.deleted == True

    def test_delete_user_without_permission(self, authenticated_client, create_test_user):
        """Test eliminazione utente senza permesso"""
        user_to_delete = create_test_user(
            org=authenticated_client.test_org,
            email="todelete@test.com"
        )

        url = reverse('delete_user')
        response = authenticated_client.delete(url, {'user_id': user_to_delete.id})

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_user_missing_user_id(self, admin_client):
        """Test eliminazione utente senza specificare user_id"""
        url = reverse('delete_user')
        response = admin_client.delete(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_user_duplicate_email(self, authenticated_client, create_test_user):
        """Test registrazione utente con email già esistente"""
        # Crea un utente esistente
        existing = create_test_user(
            org=authenticated_client.test_org,
            email="existing@test.com"
        )

        url = reverse('register')
        data = {
            'name': 'Test',
            'surname': 'User',
            'email': 'existing@test.com',  # Email duplicata
            'password': 'password123'
        }

        response = authenticated_client.post(url, data, format='json')

        # Dovrebbe dare errore di conflitto
        assert response.status_code == status.HTTP_409_CONFLICT
