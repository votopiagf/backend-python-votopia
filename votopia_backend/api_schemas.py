# -*- coding: utf-8 -*-
"""
Schema definitions e esempi per documentazione OpenAPI/Swagger.

Questo file contiene gli schemi di esempio per request e response
utilizzati nella documentazione automatica dell'API.
"""

from drf_spectacular.utils import OpenApiExample

# ============================================================================
# ESEMPI PER AUTENTICAZIONE
# ============================================================================

LOGIN_REQUEST_EXAMPLE = OpenApiExample(
    'Login Request',
    summary='Esempio richiesta login',
    description='Credenziali per ottenere i token JWT',
    value={
        'email': 'admin@votopia.com',
        'password': 'password123'
    },
    request_only=True,
)

LOGIN_RESPONSE_EXAMPLE = OpenApiExample(
    'Login Response Success',
    summary='Login riuscito',
    description='Token JWT access e refresh',
    value={
        'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
        'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
        'user': {
            'id': 1,
            'email': 'admin@votopia.com',
            'name': 'Admin',
            'surname': 'Votopia'
        }
    },
    response_only=True,
    status_codes=['200'],
)

# ============================================================================
# ESEMPI PER GESTIONE UTENTI
# ============================================================================

REGISTER_USER_REQUEST_EXAMPLE = OpenApiExample(
    'Register User Request',
    summary='Registrazione nuovo utente',
    description='Dati completi per creare un nuovo utente',
    value={
        'name': 'Mario',
        'surname': 'Rossi',
        'email': 'mario.rossi@example.com',
        'password': 'SecurePassword123!',
        'lists': [1, 2],  # ID delle liste
        'roles': [3, 4]   # ID dei ruoli
    },
    request_only=True,
)

REGISTER_USER_RESPONSE_EXAMPLE = OpenApiExample(
    'Register User Response Success',
    summary='Utente creato con successo',
    value={
        'status': 'success',
        'message': 'Utente registrato correttamente',
        'data': {
            'user': {
                'id': 42,
                'name': 'Mario',
                'surname': 'Rossi',
                'email': 'mario.rossi@example.com',
                'org_id': 1,
                'lists': [
                    {'id': 1, 'name': 'Lista A'},
                    {'id': 2, 'name': 'Lista B'}
                ],
                'roles': [
                    {'id': 3, 'name': 'Supervisore'},
                    {'id': 4, 'name': 'Operatore'}
                ]
            },
            'created_by': {
                'user_id': 1,
                'email': 'admin@votopia.com',
                'name': 'Admin Votopia'
            }
        }
    },
    response_only=True,
    status_codes=['201'],
)

USER_INFO_RESPONSE_EXAMPLE = OpenApiExample(
    'User Info Response',
    summary='Informazioni utente',
    value={
        'status': 'success',
        'data': {
            'id': 42,
            'name': 'Mario',
            'surname': 'Rossi',
            'email': 'mario.rossi@example.com',
            'org_id': 1,
            'lists': [
                {'id': 1, 'name': 'Lista A'},
                {'id': 2, 'name': 'Lista B'}
            ],
            'roles': [
                {'id': 3, 'name': 'Supervisore'},
                {'id': 4, 'name': 'Operatore'}
            ]
        }
    },
    response_only=True,
    status_codes=['200'],
)

UPDATE_USER_REQUEST_EXAMPLE = OpenApiExample(
    'Update User Request',
    summary='Aggiornamento dati utente',
    description='Campi da aggiornare per un utente esistente',
    value={
        'user_id': 42,
        'name': 'Mario',
        'surname': 'Rossi',
        'email': 'mario.rossi.new@example.com',
        'add_lists': [3],
        'remove_lists': [1],
        'add_roles': [5],
        'remove_roles': [4],
        'reset_password': False
    },
    request_only=True,
)

# ============================================================================
# ESEMPI PER GESTIONE RUOLI
# ============================================================================

CREATE_ROLE_REQUEST_EXAMPLE = OpenApiExample(
    'Create Role Request',
    summary='Creazione nuovo ruolo',
    value={
        'name': 'Coordinatore',
        'color': '#FF5733',
        'level': 5,
        'org_id': 1,
        'list_id': None,  # None per ruolo a livello organizzazione
        'permissions': [1, 2, 3, 5, 8]  # ID dei permessi
    },
    request_only=True,
)

ROLE_INFO_RESPONSE_EXAMPLE = OpenApiExample(
    'Role Info Response',
    summary='Informazioni ruolo',
    value={
        'status': 'success',
        'data': {
            'id': 10,
            'name': 'Coordinatore',
            'color': '#FF5733',
            'level': 5,
            'org_id': 1,
            'list_id': None,
            'is_organization_level': True,
            'permissions': [
                {'id': 1, 'name': 'view_all_user_organization'},
                {'id': 2, 'name': 'create_user_for_organization'},
                {'id': 3, 'name': 'update_user_organization'}
            ],
            'permissions_count': 3,
            'created_at': '2025-01-15T10:30:00Z'
        }
    },
    response_only=True,
    status_codes=['200'],
)

# ============================================================================
# ESEMPI PER GESTIONE LISTE
# ============================================================================

CREATE_LIST_REQUEST_EXAMPLE = OpenApiExample(
    'Create List Request',
    summary='Creazione nuova lista',
    value={
        'name': 'Lista Elettorale Centro',
        'org_id': 1,
        'description': 'Lista per la zona centrale della città'
    },
    request_only=True,
)

LIST_INFO_RESPONSE_EXAMPLE = OpenApiExample(
    'List Info Response',
    summary='Informazioni lista',
    value={
        'status': 'success',
        'data': {
            'id': 5,
            'name': 'Lista Elettorale Centro',
            'org_id': 1,
            'users_count': 15,
            'roles_count': 4,
            'created_at': '2025-01-10T08:00:00Z'
        }
    },
    response_only=True,
    status_codes=['200'],
)

# ============================================================================
# ESEMPI PER RISPOSTE DI ERRORE
# ============================================================================

ERROR_401_EXAMPLE = OpenApiExample(
    'Unauthorized Error',
    summary='Autenticazione richiesta',
    value={
        'error': 'Autenticazione richiesta',
        'details': 'Token JWT mancante o non valido'
    },
    response_only=True,
    status_codes=['401'],
)

ERROR_403_EXAMPLE = OpenApiExample(
    'Forbidden Error',
    summary='Permesso negato',
    value={
        'error': 'Permesso negato',
        'message': 'Non hai i permessi necessari per questa operazione',
        'required_permission': ['create_user_for_organization', 'create_user_for_list'],
        'your_permissions': ['view_all_user_list']
    },
    response_only=True,
    status_codes=['403'],
)

ERROR_404_EXAMPLE = OpenApiExample(
    'Not Found Error',
    summary='Risorsa non trovata',
    value={
        'error': 'Risorsa non trovata',
        'details': 'L\'utente/ruolo/lista richiesto non esiste'
    },
    response_only=True,
    status_codes=['404'],
)

ERROR_400_EXAMPLE = OpenApiExample(
    'Bad Request Error',
    summary='Dati non validi',
    value={
        'error': 'Dati incompleti',
        'required_fields': ['name', 'surname', 'email', 'password']
    },
    response_only=True,
    status_codes=['400'],
)

ERROR_500_EXAMPLE = OpenApiExample(
    'Internal Server Error',
    summary='Errore del server',
    value={
        'error': 'Errore interno',
        'details': 'Descrizione tecnica dell\'errore'
    },
    response_only=True,
    status_codes=['500'],
)

# ============================================================================
# PARAMETRI COMUNI
# ============================================================================

from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes

USER_ID_PARAMETER = OpenApiParameter(
    name='user_id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.QUERY,
    description='ID dell\'utente (opzionale, default: utente corrente)',
    required=False,
)

LIST_ID_PARAMETER = OpenApiParameter(
    name='list_id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.QUERY,
    description='ID della lista per filtrare gli utenti',
    required=False,
)

ROLE_ID_PARAMETER = OpenApiParameter(
    name='role_id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.QUERY,
    description='ID del ruolo',
    required=True,
)
