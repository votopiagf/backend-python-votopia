"""
Configurazione pytest e fixture condivise per tutti i test
"""
import pytest
from django.contrib.auth.hashers import make_password
from rest_framework.test import APIClient
from votopia_backend.models import (
    Organization, User, Role, Permission, List,
    RolePermission, UserRole, UserList, Plan
)


@pytest.fixture
def api_client():
    """Client API per effettuare richieste HTTP"""
    return APIClient()


@pytest.fixture
def create_test_organization(db):
    """Fixture per creare un'organizzazione di test"""

    def _create_org(name="Test Organization", code="TEST001"):
        # Crea prima un piano se non esiste
        plan, _ = Plan.objects.get_or_create(
            name="Basic Plan",
            defaults={"price": 0.00}
        )

        org = Organization.objects.create(
            name=name,
            code=code,
            plan=plan,
            status="active",
            max_lists=10
        )
        return org

    return _create_org


@pytest.fixture
def create_test_permission(db):
    """Fixture per creare un permesso di test"""

    def _create_permission(name, description=""):
        permission, _ = Permission.objects.get_or_create(
            name=name,
            defaults={"description": description}
        )
        return permission

    return _create_permission


@pytest.fixture
def create_test_role(db, create_test_organization):
    """Fixture per creare un ruolo di test"""

    def _create_role(org=None, name="Test Role", level=5, list_obj=None, permissions=None):
        if org is None:
            org = create_test_organization()

        role = Role.objects.create(
            org=org,
            list=list_obj,
            name=name,
            color="#FF0000",
            level=level
        )

        if permissions:
            for perm in permissions:
                RolePermission.objects.create(role=role, permission=perm)

        return role

    return _create_role


@pytest.fixture
def create_test_user(db, create_test_organization):
    """Fixture per creare un utente di test"""

    def _create_user(org=None, email="test@example.com", password="password123",
                     name="Test", surname="User", roles=None, lists=None):
        if org is None:
            org = create_test_organization()

        # Usa SHA256 come nel sistema reale
        import hashlib
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        user = User.objects.create(
            name=name,
            surname=surname,
            email=email,
            password=hashed_password,
            org=org,
            deleted=False,
            must_change_password=False
        )

        if roles:
            for role in roles:
                UserRole.objects.create(user=user, role=role)

        if lists:
            for list_obj in lists:
                UserList.objects.create(user=user, list=list_obj)

        return user

    return _create_user


@pytest.fixture
def create_test_list(db, create_test_organization):
    """Fixture per creare una lista di test"""

    def _create_list(org=None, name="Test List"):
        if org is None:
            org = create_test_organization()

        list_obj = List.objects.create(
            org=org,
            name=name,
            description="Test list description"
        )
        return list_obj

    return _create_list


@pytest.fixture
def authenticated_client(api_client, create_test_user, create_test_permission, create_test_role):
    """Client autenticato con un utente di test che ha permessi base"""
    # Crea permessi base
    view_perm = create_test_permission("view_all_user_organization", "View all users in org")
    create_perm = create_test_permission("create_user_for_organization", "Create users in org")

    # Crea ruolo con permessi
    role = create_test_role(permissions=[view_perm, create_perm])

    # Crea utente con ruolo
    user = create_test_user(
        org=role.org,
        email="admin@test.com",
        roles=[role]
    )

    # Genera token JWT per l'utente
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
    access['name'] = user.name
    access['surname'] = user.surname
    access['org_id'] = user.org.id

    # Configura il client con il token
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(access)}')
    api_client.test_user = user
    api_client.test_org = user.org

    return api_client


@pytest.fixture
def admin_client(api_client, create_test_user, create_test_permission, create_test_role):
    """Client autenticato con un utente admin che ha tutti i permessi"""
    # Crea tutti i permessi principali
    permissions = [
        create_test_permission("view_all_user_organization"),
        create_test_permission("create_user_for_organization"),
        create_test_permission("update_user_organization"),
        create_test_permission("delete_user_organization"),
        create_test_permission("create_role_organization"),
        create_test_permission("update_role_organization"),
        create_test_permission("delete_role_organization"),
        create_test_permission("view_all_role_organization"),
    ]

    # Crea ruolo admin con tutti i permessi
    role = create_test_role(name="Admin", level=10, permissions=permissions)

    # Crea utente admin
    user = create_test_user(
        org=role.org,
        email="superadmin@test.com",
        name="Super",
        surname="Admin",
        roles=[role]
    )

    # Genera token JWT
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
    access['name'] = user.name
    access['surname'] = user.surname
    access['org_id'] = user.org.id

    # Configura il client
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(access)}')
    api_client.test_user = user
    api_client.test_org = user.org

    return api_client
