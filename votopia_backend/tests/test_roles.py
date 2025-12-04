"""
Test per gli endpoint di gestione ruoli
"""
import pytest
from django.urls import reverse
from rest_framework import status
from votopia_backend.models import Role


@pytest.mark.django_db
class TestRoleEndpoints:
    """Test per gli endpoint CRUD ruoli"""

    def test_create_role_organization_level(self, admin_client, create_test_permission):
        """Test creazione ruolo a livello organizzazione"""
        # Crea alcuni permessi
        perm1 = create_test_permission("view_all_user_organization")
        perm2 = create_test_permission("create_user_for_organization")

        url = reverse('create_role')
        data = {
            'name': 'Coordinatore',
            'color': '#FF5733',
            'level': 5,
            'org_id': admin_client.test_org.id,
            'permissions': [perm1.id, perm2.id]
        }

        response = admin_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['status'] == 'success'
        assert 'data' in response.data

        # Verifica creazione nel database
        role = Role.objects.get(name='Coordinatore')
        assert role.level == 5
        assert role.org_id == admin_client.test_org.id
        assert role.list_id is None
        assert role.permissions.count() == 2

    def test_create_role_missing_required_fields(self, admin_client):
        """Test creazione ruolo con campi obbligatori mancanti"""
        url = reverse('create_role')

        # Manca level
        data = {
            'name': 'Test Role',
            'color': '#FF5733',
            'org_id': admin_client.test_org.id
        }
        response = admin_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Manca name
        data = {
            'color': '#FF5733',
            'level': 5,
            'org_id': admin_client.test_org.id
        }
        response = admin_client.post(url, data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_role_without_permission(self, authenticated_client):
        """Test creazione ruolo senza permesso create_role_organization"""
        url = reverse('create_role')
        data = {
            'name': 'Test Role',
            'color': '#FF5733',
            'level': 3,
            'org_id': authenticated_client.test_org.id
        }

        response = authenticated_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_role_hierarchical_violation(self, admin_client):
        """Test creazione ruolo con violazione gerarchica"""
        url = reverse('create_role')
        data = {
            'name': 'Super Role',
            'color': '#FF5733',
            'level': 999,  # Livello troppo alto
            'org_id': admin_client.test_org.id
        }

        response = admin_client.post(url, data, format='json')

        # Dovrebbe fallire per violazione gerarchica
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert 'gerarchica' in response.data.get('message', '').lower() or \
               'gerarchica' in response.data.get('error', '').lower()

    def test_view_all_roles_organization(self, admin_client, create_test_role):
        """Test visualizzazione tutti i ruoli dell'organizzazione"""
        # Crea alcuni ruoli
        role1 = create_test_role(org=admin_client.test_org, name="Role 1")
        role2 = create_test_role(org=admin_client.test_org, name="Role 2")

        url = reverse('view_all_roles')
        response = admin_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'roles' in response.data['data']
        # Dovrebbe includere anche i ruoli creati durante il setup
        assert len(response.data['data']['roles']) >= 2

    def test_view_all_roles_without_permission(self, api_client, create_test_user):
        """Test visualizzazione ruoli senza permesso"""
        user = create_test_user(email="noperm@test.com", roles=[])

        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken()
        refresh['user_id'] = user.id
        refresh['email'] = user.email
        refresh['org_id'] = user.org.id

        access = refresh.access_token
        access['user_id'] = user.id

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(access)}')

        url = reverse('view_all_roles')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_view_role_information(self, admin_client, create_test_role, create_test_permission):
        """Test visualizzazione informazioni dettagliate ruolo"""
        # Crea un ruolo con permessi
        perm = create_test_permission("test_permission")
        role = create_test_role(
            org=admin_client.test_org,
            name="Detailed Role",
            permissions=[perm]
        )

        url = reverse('view_role_information')
        response = admin_client.get(url, {'role_id': role.id})

        assert response.status_code == status.HTTP_200_OK
        assert 'role' in response.data['data']
        assert response.data['data']['role']['name'] == "Detailed Role"
        assert len(response.data['data']['role']['permissions']) >= 1

    def test_update_role(self, admin_client, create_test_role):
        """Test aggiornamento ruolo"""
        role = create_test_role(
            org=admin_client.test_org,
            name="Original Name",
            level=5
        )

        url = reverse('update_role')
        data = {
            'role_id': role.id,
            'name': 'Updated Name',
            'color': '#00FF00',
            'level': 6
        }

        response = admin_client.put(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'success'

        # Verifica aggiornamento
        updated_role = Role.objects.get(id=role.id)
        assert updated_role.name == 'Updated Name'
        assert updated_role.color == '#00FF00'
        assert updated_role.level == 6

    def test_update_role_hierarchical_violation(self, admin_client, create_test_role):
        """Test aggiornamento ruolo con violazione gerarchica"""
        role = create_test_role(
            org=admin_client.test_org,
            name="Test Role",
            level=5
        )

        url = reverse('update_role')
        data = {
            'role_id': role.id,
            'level': 999  # Livello troppo alto
        }

        response = admin_client.put(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_role(self, admin_client, create_test_role):
        """Test eliminazione ruolo"""
        role = create_test_role(
            org=admin_client.test_org,
            name="Role to Delete",
            level=3
        )
        role_id = role.id

        url = reverse('delete_role')
        response = admin_client.delete(url, {'role_id': role_id})

        assert response.status_code == status.HTTP_200_OK

        # Verifica eliminazione
        assert not Role.objects.filter(id=role_id).exists()

    def test_delete_role_without_permission(self, authenticated_client, create_test_role):
        """Test eliminazione ruolo senza permesso"""
        role = create_test_role(
            org=authenticated_client.test_org,
            name="Protected Role"
        )

        url = reverse('delete_role')
        response = authenticated_client.delete(url, {'role_id': role.id})

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_role_missing_role_id(self, admin_client):
        """Test eliminazione ruolo senza specificare role_id"""
        url = reverse('delete_role')
        response = admin_client.delete(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
