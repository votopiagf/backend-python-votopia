from datetime import datetime
import hashlib
import re
from uuid import uuid4

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import IntegrityError
from django.db.models import Max
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.parsers import FormParser, MultiPartParser

from votopia_backend.models import *
from rest_framework.decorators import api_view, parser_classes
from rest_framework.views import APIView

from votopia_backend.services.serializers import LoginSerializer
from votopia_backend.services.db_procedures import register_user
from votopia_backend.services.permissions import *
from votopia_backend.api_schemas import *
import random
import string


# =========================================================================
# FUNZIONI HELPER (per evitare codice ripetuto nelle view)
# =========================================================================

# NOTA: Queste funzioni helper dovrebbero idealmente trovarsi in un file di utilities/serializers
def serialize_user_data(u):
    """
    Serializza un oggetto User, includendo le sue liste e i suoi ruoli associati.

    :param user_object: L'istanza dell'oggetto User da serializzare.
    :type user_object: :class:`votopia_backend.models.User`
    :return: Dizionario contenente i dati serializzati dell'utente.
    :rtype: dict
    """
    return {
        'id': u.id,
        'name': u.name,
        'surname': u.surname,
        'email': u.email,
        # org_id è necessario in view_user_information e register, ma non sempre disponibile senza prefetch
        'org_id': u.org.id if hasattr(u, 'org') else None,
        'lists': [{'id': l.id, 'name': l.name} for l in u.lists.all()],
        'roles': [{'id': r.id, 'name': r.name} for r in u.roles.all()],
    }


def serialize_role_data(role_object):
    """
    Serializza l'oggetto modello Role (Ruolo) in un dizionario per l'output API.

    Inclusi i dati principali del ruolo e la lista dei permessi associati.

    :param role_object: L'istanza dell'oggetto Role.
    :type role_object: Role
    :returns: Dizionario contenente i dati serializzati del ruolo.
    :rtype: dict
    """

    # Recupera tutti i permessi associati a questo ruolo.
    # .values('id', 'name') estrae solo i campi ID e Nome, ottimizzando la query.
    permissions_data = list(
        role_object.permissions.all().values('id', 'name')
    )

    # Determina l'ambito del ruolo per facilitare la gestione del frontend.
    is_org_level = role_object.list is None

    role_data = {
        'id': role_object.id,
        'name': role_object.name,
        'color': role_object.color,
        'level': role_object.level,
        'created_at': role_object.created_at.isoformat() if role_object.created_at else None,

        # Campi Foreign Key
        'org_id': role_object.org_id,
        'list_id': role_object.list_id,

        # Ambito logico (sostituisce il campo org_level mancante)
        'is_organization_level': is_org_level,

        # Dati relazionali
        'permissions': permissions_data,
        'permissions_count': len(permissions_data)
    }

    return role_data


def serialize_list_data(list_object):
    """
    Serializza l'oggetto modello List in un dizionario per l'output API.

    Inclusi i dati principali della lista e il conteggio delle associazioni
    (es. utenti o ruoli, se la relazione è accessibile direttamente).

    :param list_object: L'istanza dell'oggetto List.
    :type list_object: List
    :returns: Dizionario contenente i dati serializzati della lista.
    :rtype: dict
    """

    # Assumiamo che ci sia una relazione Many-to-Many con gli utenti ('users')
    # e una con i ruoli ('roles') sul modello List, o viceversa tramite un related_name.

    # Recupera il conteggio degli elementi correlati (es. membri)
    try:
        members_count = list_object.users.count()
    except:
        # Fallback nel caso la relazione 'users' non esista o sia inaccessibile
        members_count = 0

    # Recupera il conteggio dei ruoli specifici della lista
    try:
        roles_count = list_object.roles.count()
    except:
        # Fallback
        roles_count = 0

    list_data = {
        'id': list_object.id,
        'name': list_object.name,
        'description': list_object.description,
        'slogan': list_object.slogan,
        'color_primary': list_object.color_primary,
        'color_secondary': list_object.color_secondary,

        # Foreign Key e timestamp
        'org_id': list_object.org_id,
        'logo_file_id': list_object.logo_file_id,
        'created_at': list_object.created_at.isoformat() if hasattr(list_object, 'created_at') else None,

        # Conteggi
        'members_count': members_count,
        'roles_count': roles_count,
    }

    return list_data


# =========================================================================
# VIEW IMPLEMENTATE
# =========================================================================

@extend_schema(
    summary="Health Check",
    description="Verifica che il server sia attivo e funzionante. Non richiede autenticazione.",
    tags=["System"],
    responses={
        200: {
            'description': 'Server operativo',
            'type': 'object',
            'properties': {
                'status': {'type': 'string', 'example': 'ok'},
                'message': {'type': 'string', 'example': 'Server Django attivo e funzionante'},
                'version': {'type': 'string', 'example': '1.0.0'}
            }
        }
    }
)
@api_view(['GET'])
def health_check(request):
    """
    Endpoint di health check.

    Verifica che il server Django sia attivo e risponda. Non richiede autenticazione.

    :param request: Oggetto Request di Django REST Framework.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con stato 'ok', messaggio e versione.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    """
    return Response({
        'status': 'ok',
        'message': 'Server Django attivo e funzionante',
        'version': '1.0.0'
    }, status=status.HTTP_200_OK)


@extend_schema(
    summary="Registra nuovo utente",
    description="""
    Crea un nuovo utente e lo associa a liste e ruoli specificati.

    **Permessi richiesti:** `create_user_for_organization` O `create_user_for_list`

    **Regole:**
    - Con `create_user_for_organization`: può creare utenti in qualsiasi lista
    - Con `create_user_for_list`: può creare utenti solo in una lista alla volta dove ha il permesso
    - I ruoli assegnabili dipendono dal livello gerarchico dell'utente autenticato
    """,
    tags=["Utenti"],
    examples=[REGISTER_USER_REQUEST_EXAMPLE, REGISTER_USER_RESPONSE_EXAMPLE, ERROR_401_EXAMPLE, ERROR_403_EXAMPLE],
    responses={
        201: OpenApiResponse(description='Utente creato con successo'),
        400: OpenApiResponse(description='Dati incompleti o non validi'),
        401: OpenApiResponse(description='Autenticazione richiesta'),
        403: OpenApiResponse(description='Permessi insufficienti'),
        409: OpenApiResponse(description='Email già esistente'),
        500: OpenApiResponse(description='Errore interno del server'),
    }
)
@api_view(['POST'])
def register(request):
    """
    Crea un nuovo utente e lo associa a liste e ruoli.

    Richiede autenticazione JWT e il permesso 'create_user_for_organization' o
    'create_user_for_list'. Impone controlli di gerarchia sui ruoli assegnati.

    :param request: Oggetto Request contenente i dati utente (name, surname, email, password, lists, roles).
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con i dati dell'utente creato.
    :rtype: :class:`rest_framework.response.Response`
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Utente autenticato non trovato (raro).
    :raises 403: Permessi insufficienti (generali o specifici sulla lista/livello ruolo).
    :raises 400: Dati di input obbligatori mancanti.
    :raises 409: Email già registrata (Errore DB 1062).
    """
    try:
        # 1) Autenticazione
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({
                'error': 'Autenticazione richiesta',
                'message': 'Inserisci il token JWT nell’header Authorization'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()
        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 2) Controllo permessi
        can_org = check_user_permission(auth_user.id, 'create_user_for_organization')
        can_list = check_user_permission(auth_user.id, 'create_user_for_list')

        if not (can_org or can_list):
            perms = get_user_permissions(auth_user.id)
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai i permessi necessari per creare utenti',
                'required_permission': ['create_user_for_organization', 'create_user_for_list'],
                'your_permissions': [p['name'] for p in perms]
            }, status=status.HTTP_403_FORBIDDEN)

        # 3) Validazione input
        data = request.data
        required = ['name', 'surname', 'email', 'password']
        if not all(field in data and data[field] for field in required):
            return Response({
                'error': 'Dati incompleti',
                'required_fields': required
            }, status=status.HTTP_400_BAD_REQUEST)

        lists = data.get('lists', [])
        roles = data.get('roles', [])
        org_id = auth_user.org.id

        # 4) CASO 1 — Permesso globale per l'organizzazione
        if can_org:
            new_user = register_user(
                data['name'], data['surname'], data['email'], data['password'], org_id
            )
            for lst_id in lists:
                lst = List.objects.filter(id=lst_id, org_id=org_id).first()
                if lst:
                    lst.users.add(new_user.id)

        # 5) CASO 2 — Permesso SOLO per lista
        elif can_list:
            if len(lists) != 1:
                return Response({
                    'error': 'Permesso limitato',
                    'message': 'Puoi creare utenti solo in una singola lista alla volta'
                }, status=status.HTTP_403_FORBIDDEN)

            target_list_id = lists[0]
            has_perm_in_list = auth_user.roles.filter(
                list_id=target_list_id,
                permissions__name='create_user_for_list'
            ).exists()
            if not has_perm_in_list:
                return Response({
                    'error': 'Permesso negato',
                    'message': 'Non hai il permesso per creare utenti in questa lista'
                }, status=status.HTTP_403_FORBIDDEN)

            new_user = register_user(
                data['name'], data['surname'], data['email'], data['password'], org_id
            )
            lst = List.objects.get(id=target_list_id)
            lst.users.add(new_user.id)

        # 6) Assegna ruoli rispettando permessi e livelli
        for role_id in roles:
            role = Role.objects.filter(id=role_id).first()
            if not role:
                continue

            if role.level:
                if not can_org:
                    continue
                max_level = auth_user.roles.filter(org_id=org_id, org_level=True).aggregate(Max('level'))[
                                'level__max'] or 0
                if role.level > max_level:
                    continue
            else:
                if not can_list:
                    continue
                if role.list_id not in lists:
                    continue
                max_level = auth_user.roles.filter(list_id=role.list_id, org_level=False).aggregate(Max('level'))[
                                'level__max'] or 0
                if role.level > max_level:
                    continue

            # Assegna ruolo
            new_user.roles.add(role.id)

        # 7) Risposta OK
        user_data = serialize_user_data(new_user)
        return Response({
            'status': 'success',
            'message': 'Utente registrato correttamente',
            'data': {
                'user': user_data,
                'created_by': {
                    'user_id': auth_user.id,
                    'email': auth_user.email,
                    'name': f"{auth_user.name} {auth_user.surname}"
                }
            }
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        if "1062" in str(e):
            return Response({
                'error': 'Errore Conflitto',
                'details': str(e)
            }, status=status.HTTP_409_CONFLICT)
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    summary="I miei permessi",
    description="Ritorna l'elenco completo dei permessi dell'utente autenticato con dettagli dell'account.",
    tags=["Autenticazione"],
    responses={
        200: {
            'description': 'Lista dei permessi utente',
            'type': 'object',
            'properties': {
                'status': {'type': 'string', 'example': 'success'},
                'message': {'type': 'string'},
                'data': {
                    'type': 'object',
                    'properties': {
                        'user_info': {'type': 'object'},
                        'permissions': {'type': 'array', 'items': {'type': 'object'}},
                        'total_permissions': {'type': 'integer'}
                    }
                }
            }
        },
        401: OpenApiResponse(description='Autenticazione richiesta'),
    }
)
@api_view(['GET'])
def my_permissions(request):
    """
    Ritorna i dettagli base e l'elenco completo dei permessi dell’utente autenticato.

    :param request: Oggetto Request di Django REST Framework.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON contenente informazioni utente e la lista dei permessi.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    """
    try:
        auth_user = get_user_from_token(request)

        if not auth_user:
            return Response({
                'error': 'Autenticazione richiesta'
            }, status=status.HTTP_401_UNAUTHORIZED)

        user_id = auth_user['user_id']
        perms = get_user_permissions(user_id)

        return Response({
            'status': 'success',
            'message': 'Permessi utente recuperati',
            'data': {
                'user_info': {
                    'user_id': user_id,
                    'email': auth_user['email'],
                    'name': auth_user['name'],
                    'surname': auth_user['surname'],
                    'org_id': auth_user['org_id']
                },
                'permissions': perms,
                'total_permissions': len(perms)
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    """
    View per il login utente.

    Gestisce l'autenticazione tramite credenziali e restituisce la coppia di JWT Token
    (Access e Refresh Token). Utilizza un serializer dedicato (LoginSerializer).
    """

    @extend_schema(summary="Login Utente", request=LoginSerializer,
                   responses={200: {'description': 'Login successo, token restituiti'}})
    def post(self, request):
        """
        Gestisce la richiesta POST di login.

        :param request: Oggetto Request contenente email e password.
        :type request: :class:`rest_framework.request.Request`
        :returns: Risposta JSON contenente i token JWT in caso di successo.
        :rtype: :class:`rest_framework.response.Response`
        :raises 400: Dati non validi (es. credenziali errate, campi mancanti).
        """
        try:
            serializer = LoginSerializer(data=request.data)

            if serializer.is_valid():
                # Assunto che validated_data contenga il token JWT
                return Response(serializer.validated_data,
                                status=status.HTTP_200_OK)

            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'error': 'Errore durante il login',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def test(request):
    """
    Endpoint di debug per verificare l'accesso alle liste con un permesso specifico.

    Ritorna gli ID delle liste su cui l'utente autenticato ha il permesso 'view_all_user_list'.

    :param request: Oggetto Request di Django REST Framework.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con gli ID delle liste autorizzate.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    """
    try:
        auth_user = get_user_from_token(request)

        if not auth_user:
            return Response({
                'error': 'Autenticazione richiesta'
            }, status=status.HTTP_401_UNAUTHORIZED)

        user_id = auth_user['user_id']
        user = User.objects.filter(id=user_id).first()

        # Ritorna gli ID delle liste con il permesso
        return Response({
            'status': 'success',
            'message': 'Risultato test permessi di lista',
            'data': {
                'allowed_lists_ids': list(
                    get_lists_user_has_permission(user, 'view_all_user_list').values_list('id', flat=True))
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def view_user_information(request):
    """
    Restituisce i dettagli di un utente specifico o dell'utente autenticato (self).

    La visibilità è limitata agli utenti della stessa organizzazione.
    Richiede 'view_all_user_organization' o 'view_all_user_list' per vedere altri utenti.

    :param request: Oggetto Request, accetta 'user_id' come parametro di query opzionale.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con i dettagli dell'utente/degli utenti richiesti.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Utente target non trovato.
    :raises 403: Permesso negato (utente di altra organizzazione o permessi lista insufficienti).
    """
    user_id = request.GET.get('user_id')

    # Autenticazione
    auth_user_data = get_user_from_token(request)
    if not auth_user_data:
        return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

    auth_user_id = auth_user_data.get('user_id')
    auth_user = User.objects.filter(id=auth_user_id).first()
    if not auth_user:
        return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

    perm_org = check_user_permission(auth_user_id, 'view_all_user_organization')
    perm_lists = check_user_permission(auth_user_id, 'view_all_user_list')

    if not user_id:
        users = [auth_user]
    else:
        user_to_view = User.objects.filter(id=user_id).prefetch_related('lists', 'roles').first()
        if not user_to_view:
            return Response({'error': 'Utente non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if user_to_view.org.id != auth_user.org.id:
            return Response({'error': 'Non puoi vedere utenti di altre organizzazioni'},
                            status=status.HTTP_403_FORBIDDEN)

        if perm_org:
            users = [user_to_view]
        elif perm_lists:
            my_lists = get_lists_user_has_permission(auth_user, 'view_all_user_list')
            allowed = user_to_view.lists.filter(id__in=my_lists.values_list('id', flat=True)).exists()
            if not allowed:
                return Response({'error': 'Permesso negato per visualizzare questo utente'},
                                status=status.HTTP_403_FORBIDDEN)
            users = [user_to_view]
        else:
            if user_to_view.id != auth_user.id:
                return Response({'error': 'Permesso negato per visualizzare questo utente'},
                                status=status.HTTP_403_FORBIDDEN)
            users = [auth_user]

    # Serializzazione utenti
    users_data = [serialize_user_data(u) for u in users]  # Usa la funzione helper

    return Response({
        'status': 'success',
        'message': 'Informazioni utente recuperate',
        'data': {
            'users': users_data,
            'count': len(users_data)
        }
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def view_all_user(request):
    """
    Restituisce tutti gli utenti visibili all'utente autenticato.

    Filtro per Organizzazione (list_id=None): Richiede 'view_all_user_organization'.
    Filtro per Lista (list_id=<ID>): Richiede 'view_all_user_list' sulla lista specificata.

    :param request: Oggetto Request, accetta 'list_id' come parametro di query opzionale.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con la lista degli utenti.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 403: Permesso negato (es. manca permesso Org, o si tenta di accedere a lista non autorizzata).
    """
    # 1 Recupero parametri
    list_id_raw = request.GET.get('list_id')
    list_id = int(list_id_raw) if list_id_raw is not None else None

    # 2 Autenticazione
    auth_user_data = get_user_from_token(request)
    if not auth_user_data:
        return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

    auth_user_id = auth_user_data.get('user_id')
    auth_user = User.objects.filter(id=auth_user_id).first()
    if not auth_user:
        return Response({'error': 'Utente non trovato'}, status=status.HTTP_404_NOT_FOUND)

    # 3 Controllo permessi
    perm_org = check_user_permission(auth_user_id, 'view_all_user_organization')
    perm_lists = check_user_permission(auth_user_id, 'view_all_user_list')

    users = []

    # 4 Caso: permesso globale organizzazione
    if list_id is None:
        if perm_org:
            users_qs = User.objects.filter(org_id=auth_user.org.id).prefetch_related('lists', 'roles')
            users = [serialize_user_data(u) for u in users_qs]  # Usa la funzione helper
            return Response({
                'status': 'success',
                'message': 'Utenti dell\'organizzazione recuperati',
                'data': {'users': users}
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai permesso per vedere tutti gli utenti dell’organizzazione'
            }, status=status.HTTP_403_FORBIDDEN)

    # 5 Caso: permesso per lista specifica
    if list_id is not None:
        if not perm_lists:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai permesso per vedere utenti di liste specifiche'
            }, status=status.HTTP_403_FORBIDDEN)

        my_lists = get_lists_user_has_permission(auth_user, 'view_all_user_list')
        allowed_list_ids = my_lists.values_list('id', flat=True)
        if list_id not in allowed_list_ids:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai accesso agli utenti di questa lista'
            }, status=status.HTTP_403_FORBIDDEN)

        users_qs = User.objects.filter(lists__id=list_id).prefetch_related('lists', 'roles')
        users = [serialize_user_data(u) for u in users_qs]  # Usa la funzione helper
        return Response({
            'status': 'success',
            'message': f'Utenti della lista {list_id} recuperati',
            'data': {'users': users}
        }, status=status.HTTP_200_OK)

    # 6 Nessun permesso valido
    return Response({
        'error': 'Permesso negato',
        'message': 'Non hai permessi per visualizzare utenti'
    }, status=status.HTTP_403_FORBIDDEN)


@api_view(['DELETE'])
def delete_user(request):
    """
    Esegue una **Soft Delete** (cancellazione logica: ``deleted=True``) su un utente.

    Richiede il permesso 'delete_user_organization'. Agisce solo su utenti della stessa organizzazione.

    :param request: Oggetto Request, richiede 'user_id' come parametro di query.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON di successo con ID dell'utente cancellato.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 400: Parametro 'user_id' mancante.
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Utente target da eliminare non trovato.
    :raises 403: Permesso 'delete_user_organization' mancante o tentativo di eliminare utente di altra Org.
    """
    try:
        # 1 Recupero parametro
        user_id_delete = request.GET.get('user_id')
        if not user_id_delete:
            return Response({'error': 'user_id mancante'}, status=status.HTTP_400_BAD_REQUEST)

        # 2 Autenticazione
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()
        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 3 Controllo permessi
        perm_org = check_user_permission(auth_user_id, 'delete_user_organization')
        if not perm_org:
            return Response({'error': 'Permesso negato'}, status=status.HTTP_403_FORBIDDEN)

        # 4 Recupero utente da eliminare
        user_to_delete = User.objects.filter(id=user_id_delete).first()
        if not user_to_delete:
            return Response({'error': 'Utente da eliminare non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 5 Verifica organizzazione
        if user_to_delete.org.id != auth_user.org.id:
            return Response({'error': 'Non puoi eliminare utenti di altre organizzazioni'},
                            status=status.HTTP_403_FORBIDDEN)

        # 6 Soft delete
        user_to_delete.deleted = True
        user_to_delete.save()

        return Response({
            'status': 'success',
            'message': f"Utente {user_to_delete.id} marcato come cancellato",
            'data': {'user_id': user_to_delete.id}
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
def update_user(request):
    """
    Aggiorna i campi di un utente (self o target) e gestisce l'associazione alle liste.

    Permessi richiesti (prioritari): 'update_user_organization' O 'update_user_list' O Self Update.
    Gestisce il reset password forzato (impostando un hash SHA-256 e ``must_change_password=True``).

    :param request: Oggetto Request contenente 'user_id' (opzionale) e i campi da aggiornare.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con i dati aggiornati dell'utente.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Utente target non trovato.
    :raises 403: Permesso negato (es. modifica utente di altra Org o permessi lista insufficienti).
    """
    try:
        # 1 Autenticazione
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()
        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 2 Controllo permessi
        can_modify_org = check_user_permission(auth_user_id, 'update_user_organization')
        can_modify_list = check_user_permission(auth_user_id, 'update_user_list')

        # 3 Dati da request e target
        data = request.data
        user_id_target = data.get('user_id') or auth_user.id
        user_target = User.objects.filter(id=user_id_target).first()
        if not user_target:
            return Response({'error': 'Utente da modificare non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 4 Verifica permessi generali
        if can_modify_org and user_target.org.id != auth_user.org.id:
            return Response({'error': 'Non puoi modificare utenti di altre organizzazioni'},
                            status=status.HTTP_403_FORBIDDEN)
        elif can_modify_list:
            allowed_lists = get_lists_user_has_permission(auth_user, 'update_user_list').values_list('id', flat=True)
            if not user_target.lists.filter(id__in=allowed_lists).exists() and user_target.id != auth_user.id:
                return Response({'error': 'Non puoi modificare utenti di liste non autorizzate'},
                                status=status.HTTP_403_FORBIDDEN)
        elif user_target.id != auth_user.id:
            return Response({'error': 'Permesso negato per modificare questo utente'}, status=status.HTTP_403_FORBIDDEN)

        # 5 Aggiornamento campi base (facoltativi)
        for field in ['name', 'surname', 'email']:
            if field in data and data[field] is not None:
                setattr(user_target, field, data[field])

        # 6 Reset password
        if data.get('reset_password'):
            default_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            sha256_password = hashlib.sha256(default_password.encode('utf-8')).hexdigest()
            user_target.password = sha256_password
            user_target.must_change_password = True

        # 7 Gestione liste
        lists_to_add = data.get('add_lists', [])
        lists_to_remove = data.get('remove_lists', [])

        if can_modify_org or can_modify_list:
            if can_modify_org:
                for lst_id in lists_to_add:
                    lst = List.objects.filter(id=lst_id, org_id=user_target.org.id).first()
                    if lst: lst.users.add(user_target.id)
                for lst_id in lists_to_remove:
                    lst = List.objects.filter(id=lst_id, org_id=user_target.org.id).first()
                    if lst: lst.users.remove(user_target.id)
            elif can_modify_list:
                allowed_lists = get_lists_user_has_permission(auth_user, 'update_user_list').values_list('id',
                                                                                                         flat=True)
                for lst_id in lists_to_add:
                    if lst_id in allowed_lists:
                        lst = List.objects.filter(id=lst_id).first()
                        if lst: lst.users.add(user_target.id)
                for lst_id in lists_to_remove:
                    if lst_id in allowed_lists:
                        lst = List.objects.filter(id=lst_id).first()
                        if lst:
                            lst.users.remove(user_target.id)
                            user_target.roles.filter(list_id=lst.id).delete()  # Rimuove ruoli di lista associati

        user_target.save()

        # 8 Risposta
        user_data = serialize_user_data(user_target)
        return Response({
            'status': 'success',
            'message': f'Utente {user_target.id} aggiornato correttamente',
            'data': {
                'user': user_data
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': 'Errore interno', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def create_role(request):
    """
        Crea un nuovo Ruolo a livello di Organizzazione o di Lista.

        Questa view gestisce la creazione di nuovi ruoli, applicando rigorosi controlli di
        sicurezza e gerarchia:

        1. **Autenticazione e Permesso:** Richiede un token JWT valido e il permesso
           ``create_role_organization`` (per ruoli Org) o ``create_role_list``
           (per ruoli Lista).
        2. **Controllo di Possessione dei Permessi:** L'utente può assegnare al nuovo ruolo
           SOLO i permessi che possiede personalmente.
        3. **Controllo Gerarchico:** Il ``level`` del nuovo ruolo non può superare il
           massimo ``level`` posseduto dall'utente creatore nel contesto specifico
           (Organizzazione o Lista).

        :param request: Oggetto Request di Django REST Framework.
            Il body della richiesta (JSON) deve contenere:

            * **name** (str): Nome del nuovo ruolo.
            * **color** (str): Codice colore associato al ruolo (es. '#FF0000').
            * **level** (int): Livello gerarchico del ruolo.
            * **org_id** (int, opzionale): ID dell'Organizzazione (se ruolo globale).
            * **list_id** (int, opzionale): ID della Lista (se ruolo specifico di lista).
            * **permissions** (list[int], opzionale): Lista degli ID dei permessi da assegnare.

        :type request: :class:`rest_framework.request.Request`

        :returns: Risposta JSON con i dettagli del ruolo creato (ID, name, level, etc.).
        :rtype: :class:`rest_framework.response.Response` con status 201 CREATED

        :raises 401: Autenticazione JWT mancante o non valida.
        :raises 404: Utente autenticato non trovato o Lista target non trovata/non appartenente all'Org.
        :raises 400: Dati di input mancanti o non coerenti (es. ruoli Org e Lista specificati insieme).
        :raises 403:
            * Permessi insufficienti per creare ruoli.
            * Violazione gerarchica (``new_level`` > ``max_auth_level``).
            * Tentativo di assegnare permessi non posseduti dall'utente creatore.
            * Permesso ``create_role_list`` mancante per la lista specifica.
        :raises 409: Errore di conflitto (es. nome ruolo duplicato).
        :raises 500: Errore interno del server.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({
                'status': 'error',
                'error': 'Autenticazione richiesta',
                'message': 'Token JWT mancante o non valido.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        user = User.objects.filter(id=auth_user_id).first()

        if user is None:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # 2. CONTROLLO PERMESSI DI CREAZIONE
        can_org = check_user_permission(auth_user_id, 'create_role_organization')
        can_list = check_user_permission(auth_user_id, 'create_role_list')

        if not (can_org or can_list):
            return Response({
                'status': 'error',
                'error': 'Permesso negato',
                'message': 'Non hai i permessi necessari per creare ruoli.',
            }, status=status.HTTP_403_FORBIDDEN)

        # 3. VALIDAZIONE INPUT
        data = request.data
        required = ['name', 'color', 'level']

        if not all(field in data and data[field] for field in required):
            return Response({
                'status': 'error',
                'error': 'Dati incompleti',
                'message': 'I campi name, color e level sono obbligatori.'
            }, status=status.HTTP_400_BAD_REQUEST)

        name = data['name']
        color = data['color']
        new_level = int(data['level'])
        org_id_data = data.get('org_id')
        list_id_data = data.get('list_id')
        permissions_ids = data.get('permissions', [])

        target_org = user.org  # Assumendo che l'utente abbia sempre una Org associata
        target_org_id = target_org.id if target_org else None  # Sicurezza aggiuntiva

        # Validazione base
        if target_org_id is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione valida'},
                            status=status.HTTP_403_FORBIDDEN)

        is_org_role = org_id_data is not None
        is_list_role = list_id_data is not None

        if (is_org_role and is_list_role) or (not is_org_role and not is_list_role):
            return Response({
                'status': 'error',
                'error': 'Errore di contesto',
                'message': 'Il ruolo deve essere associato ESCLUSIVAMENTE a org_id O a list_id.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 4. CONTROLLO DI POSSESSIONE DEI PERMESSI
        auth_perms = get_user_permissions(auth_user_id)
        auth_perm_ids = {p['id'] for p in auth_perms}
        invalid_perms_ids = [pid for pid in permissions_ids if pid not in auth_perm_ids]

        if invalid_perms_ids:
            return Response({
                'status': 'error',
                'error': 'Permessi non posseduti',
                'message': f'Non puoi assegnare permessi che non possiedi. ID non validi: {invalid_perms_ids}'
            }, status=status.HTTP_403_FORBIDDEN)

        valid_permissions = Permission.objects.filter(id__in=permissions_ids)
        if len(valid_permissions) != len(permissions_ids):
            return Response({
                'status': 'error',
                'error': 'Permesso inesistente',
                'message': 'Uno o più ID di permesso forniti non sono validi.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 5. CREAZIONE E CONTROLLO GERARCHICO

        # 5.1 CASO RUOLO ORGANIZZAZIONE (list_id è NULL)
        if is_org_role:
            if not can_org or org_id_data != target_org_id:
                return Response({
                    'status': 'error',
                    'error': 'Permesso Organizzazione richiesto',
                    'message': 'Devi avere il permesso create_role_organization e l\'org_id deve corrispondere.'
                }, status=status.HTTP_403_FORBIDDEN)

            # CALCOLO MAX LEVEL ORG (Filtra solo i ruoli dell'utente che hanno list=NULL)
            max_level_query = user.roles.filter(list__isnull=True, org_id=target_org_id).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

            # Controllo Gerarchico
            if new_level >= max_auth_level:
                return Response({
                    'status': 'error',
                    'error': 'Violazione gerarchica (Org)',
                    'message': f'Non puoi creare un ruolo con livello {new_level}, il tuo massimo a livello di Organizzazione è {max_auth_level}.'
                }, status=status.HTTP_403_FORBIDDEN)

            # Creazione - list è null per ruoli Org
            new_role = Role.objects.create(
                name=name, color=color, level=new_level,
                org_id=target_org_id, list_id=None  # list_id è None
            )

        # 5.2 CASO RUOLO DI LISTA (org_id NON è NULL)
        elif is_list_role:
            target_list = List.objects.filter(id=list_id_data, org_id=target_org_id).first()
            if not target_list:
                return Response({'status': 'error', 'error': 'Lista non trovata',
                                 'message': 'Lista non esistente o non nella tua organizzazione.'},
                                status=status.HTTP_404_NOT_FOUND)

            # Controllo che l'utente abbia i permessi sulla specifica lista (se non ha il permesso Org)
            if can_list and not can_org:
                has_perm_on_list = user.roles.filter(
                    list_id=list_id_data,
                    permissions__name='create_role_list'
                ).exists()
                if not has_perm_on_list:
                    return Response({
                        'status': 'error',
                        'error': 'Permesso Lista negato',
                        'message': 'Non hai il permesso "create_role_list" per questa specifica lista.'
                    }, status=status.HTTP_403_FORBIDDEN)

            # CALCOLO MAX LEVEL LISTA (Filtra solo i ruoli dell'utente che hanno list_id specifico)
            max_level_query = user.roles.filter(list_id=list_id_data).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

            # Controllo Gerarchico
            if new_level >= max_auth_level:
                return Response({
                    'status': 'error',
                    'error': 'Violazione gerarchica (Lista)',
                    'message': f'Non puoi creare un ruolo di lista con livello {new_level}, il tuo massimo per questa lista è {max_auth_level}.'
                }, status=status.HTTP_403_FORBIDDEN)

            # Creazione - list_id è l'ID della Lista
            new_role = Role.objects.create(
                name=name, color=color, level=new_level,
                org_id=target_org_id, list_id=list_id_data
            )

        # 6. ASSEGNAZIONE PERMESSI e RISPOSTA
        if new_role:
            new_role.permissions.set(valid_permissions)

            return Response({
                'status': 'success',
                'message': 'Ruolo creato correttamente.',
                'data': {
                    'id': new_role.id,
                    'name': new_role.name,
                    'level': new_role.level,
                    'color': new_role.color,
                    'org_id': new_role.org_id,
                    'list_id': new_role.list_id,
                    'permissions_count': valid_permissions.count()
                }
            }, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        # Gestisce errori di integrità come le chiavi uniche (es. nome ruolo duplicato se c'è un UniqueConstraint)
        return Response({
            'status': 'error',
            'error': 'Errore di conflitto',
            'message': 'Un ruolo con questo nome o combinazione di chiavi uniche esiste già.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        # Gestione errori generici
        return Response({
            'status': 'error',
            'error': 'Errore interno del server',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
def update_role(request):
    """
    Aggiorna i dettagli di un Ruolo esistente (name, color, level, permissions).

    Questa view implementa rigorosi controlli di visibilità, gerarchia e sicurezza:

    1. **Autorità di Modifica (Livello Ruolo Target):** L'utente può modificare solo ruoli
       con un ``level`` **strettamente inferiore** al proprio massimo livello di autorità
       nel contesto (Organizzazione o Lista).
    2. **Autorità di Assegnazione (Nuovo Livello):** Il nuovo ``level`` del ruolo target
       non può superare il massimo livello di autorità dell'utente creatore.
    3. **Controllo di Possessione dei Permessi:** L'utente può assegnare al ruolo target
       SOLO i permessi che possiede personalmente.
    4. **Permessi Richiesti:** ``update_role_organization`` (per ruoli Org/qualsiasi Lista)
       o ``update_role_list`` (per ruoli nella Lista specifica).

    :param request: Oggetto Request di Django REST Framework.
        Il body della richiesta (JSON) deve contenere:

        * **role_id** (int): ID del ruolo da aggiornare (obbligatorio).
        * **name** (str, opzionale): Nuovo nome.
        * **color** (str, opzionale): Nuovo codice colore.
        * **level** (int, opzionale): Nuovo livello gerarchico.
        * **permissions** (list[int], opzionale): Lista degli ID dei permessi da assegnare/sovrascrivere.

    :type request: :class:`rest_framework.request.Request`

    :returns: Risposta JSON con i dettagli aggiornati del ruolo.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK

    :raises 401: Autenticazione JWT mancante o non valida.
    :raises 404: Utente autenticato non trovato o Ruolo target non trovato.
    :raises 400: Parametro ``role_id`` mancante o ID di permesso non valido.
    :raises 403:
        * Permessi insufficienti per la modifica.
        * Ruolo target appartenente a un'altra Organizzazione.
        * **Violazione gerarchica:** Tentativo di modificare un ruolo con livello >= proprio max livello.
        * **Violazione gerarchica:** Tentativo di impostare un ``new_level`` > proprio max livello.
        * Tentativo di assegnare permessi non posseduti dall'utente creatore.
    :raises 409: Errore di conflitto (es. nome ruolo duplicato).
    :raises 500: Errore interno del server.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({
                'status': 'error',
                'error': 'Autenticazione richiesta',
                'message': 'Token JWT mancante o non valido.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        user = User.objects.filter(id=auth_user_id).first()

        if user is None:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        role_target_id = data.get('role_id')

        if not role_target_id:
            return Response({
                'status': 'error',
                'error': 'Dati mancanti',
                'message': 'Il campo role_id è obbligatorio per l\'aggiornamento.'
            }, status=status.HTTP_400_BAD_REQUEST)

        role_target = Role.objects.filter(id=role_target_id).first()

        if not role_target:
            return Response({
                'status': 'error',
                'error': 'Risorsa non trovata',
                'message': f'Ruolo con ID {role_target_id} non trovato.'
            }, status=status.HTTP_404_NOT_FOUND)

        # 2. CONTROLLO BASE DEI PERMESSI
        can_org = check_user_permission(user.id, 'update_role_organization')
        can_list = check_user_permission(user.id, 'update_role_list')
        target_org_id = user.org.id

        # 3. VERIFICA AMBITO DEL RUOLO TARGET E PERMESSI NECESSARI
        is_org_role_target = role_target.list_id is None  # Ruolo Org
        is_list_role_target = role_target.list_id is not None  # Ruolo Lista

        # Check: Ruolo target deve essere nella stessa Org
        if role_target.org_id != target_org_id:
            return Response({
                'status': 'error',
                'error': 'Accesso negato',
                'message': 'Non puoi modificare ruoli appartenenti ad altre organizzazioni.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Determine max_auth_level e verifica permessi specifici (List)
        max_auth_level = 0

        if is_org_role_target:
            if not can_org:
                return Response({'error': 'Permesso update_role_organization richiesto.'},
                                status=status.HTTP_403_FORBIDDEN)

            # Calcolo MAX LEVEL ORG dell'utente creatore
            max_level_query = user.roles.filter(list__isnull=True, org_id=target_org_id).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

        elif is_list_role_target:
            if not (can_org or can_list):
                return Response({'error': 'Permesso di modifica ruoli mancante (Org o Lista).'},
                                status=status.HTTP_403_FORBIDDEN)

            # Se ha solo can_list, deve avere il permesso su quella specifica lista
            if can_list and not can_org:
                has_perm_on_list = user.roles.filter(
                    list_id=role_target.list_id,
                    permissions__name='update_role_list'
                ).exists()
                if not has_perm_on_list:
                    return Response({'error': 'Non hai il permesso "update_role_list" per questa specifica lista.'},
                                    status=status.HTTP_403_FORBIDDEN)

            # Calcolo MAX LEVEL LISTA dell'utente creatore nella lista target
            max_level_query = user.roles.filter(list_id=role_target.list_id, org_id=target_org_id).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

        # 4. CONTROLLO GERARCHICO (RUOLO TARGET)
        # L'utente non può modificare un ruolo il cui livello è uguale o superiore al proprio max level
        if role_target.level >= max_auth_level:
            return Response({
                'status': 'error',
                'error': 'Violazione gerarchica',
                'message': f'Non puoi modificare il ruolo "{role_target.name}" (Level {role_target.level}) perché è uguale o superiore al tuo massimo livello di autorità ({max_auth_level}).'
            }, status=status.HTTP_403_FORBIDDEN)

        # 5. APPLICAZIONE AGGIORNAMENTI E CONTROLLO NUOVO LEVEL

        # Aggiornamento Livello: verifica che il nuovo level non superi l'autorità dell'utente
        if 'level' in data and data['level'] is not None:
            new_level = int(data['level'])
            if new_level > max_auth_level:
                return Response({
                    'status': 'error',
                    'error': 'Violazione gerarchica (Nuovo Livello)',
                    'message': f'Non puoi impostare un livello {new_level}, il tuo massimo di autorità è {max_auth_level}.'
                }, status=status.HTTP_403_FORBIDDEN)
            role_target.level = new_level

        # Aggiornamento Nome e Colore
        if 'name' in data and data['name']:
            role_target.name = data['name']
        if 'color' in data and data['color']:
            role_target.color = data['color']

        # 6. AGGIORNAMENTO PERMESSI (Controllo di Possessione)
        if 'permissions' in data and data['permissions'] is not None:
            permissions_ids = data['permissions']

            # Controllo di Possessione dei Permessi (come in create_role)
            auth_perms = get_user_permissions(auth_user_id)
            auth_perm_ids = {p['id'] for p in auth_perms}
            invalid_perms_ids = [pid for pid in permissions_ids if pid not in auth_perm_ids]

            if invalid_perms_ids:
                return Response({
                    'status': 'error',
                    'error': 'Permessi non posseduti',
                    'message': f'Non puoi assegnare permessi che non possiedi. ID non validi: {invalid_perms_ids}'
                }, status=status.HTTP_403_FORBIDDEN)

            # Esecuzione Set dei Permessi
            valid_permissions = Permission.objects.filter(id__in=permissions_ids)
            role_target.permissions.set(valid_permissions)

        # 7. SALVATAGGIO FINALE
        role_target.save()

        # 8. RISPOSTA
        return Response({
            'status': 'success',
            'message': 'Ruolo aggiornato correttamente.',
            'data': {
                'id': role_target.id,
                'name': role_target.name,
                'level': role_target.level,
                'color': role_target.color,
                'org_id': role_target.org_id,
                'list_id': role_target.list_id,
                'permissions_count': role_target.permissions.count()  # Conta i permessi dopo l'update
            }
        }, status=status.HTTP_200_OK)

    except IntegrityError as e:
        # Gestisce errori di integrità come le chiavi uniche (es. nome ruolo duplicato)
        return Response({
            'status': 'error',
            'error': 'Errore di conflitto',
            'message': 'Un ruolo con questo nome o combinazione di chiavi uniche esiste già.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
def delete_role(request):
    """
    Elimina definitivamente un Ruolo esistente (Hard Delete).

    Questa view esegue controlli stringenti di visibilità e gerarchia:

    1. **Autorità di Eliminazione:** L'utente può eliminare solo ruoli con un ``level``
       **strettamente inferiore** al proprio massimo livello di autorità nel contesto
       (Organizzazione o Lista).
    2. **Permessi Richiesti:** ``delete_role_organization`` (per ruoli Org/qualsiasi Lista)
       o ``delete_role_list`` (per ruoli nella Lista specifica, se non si possiede il permesso Org).

    :param request: Oggetto Request di Django REST Framework.
        Il parametro di query string deve contenere:

        * **role_id** (int): ID del ruolo da eliminare.

    :type request: :class:`rest_framework.request.Request`

    :returns: Risposta JSON di successo.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK

    :raises 401: Autenticazione JWT mancante o non valida.
    :raises 404: Utente autenticato non trovato o Ruolo target non trovato.
    :raises 400: Parametro ``role_id`` mancante.
    :raises 403:
        * Permessi insufficienti per l'eliminazione.
        * Ruolo target appartenente a un'altra Organizzazione.
        * **Violazione gerarchica:** Tentativo di eliminare un ruolo con livello >= proprio max livello nel contesto.
        * Permesso specifico ``delete_role_list`` mancante per la lista target.
    :raises 500: Errore interno del server.
    """
    try:
        role_id_target = request.GET.get('role_id')
        auth_user = get_user_from_token(request)

        # 1. AUTENTICAZIONE
        if auth_user is None:
            return Response({
                'status': 'error',
                'error': 'Autenticazione richiesta',
                'message': 'Token JWT mancante o non valido.'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user.get('user_id')
        user = User.objects.filter(id=auth_user_id).first()

        if not user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        target_org_id = user.org.id if user.org else None

        # 2. VALIDAZIONE INPUT
        if role_id_target is None:
            return Response({
                'status': 'error',
                'error': 'Dati mancanti',
                'message': 'Il parametro role_id è obbligatorio per l\'eliminazione.'
            }, status=status.HTTP_400_BAD_REQUEST)

        role_target = Role.objects.filter(id=role_id_target).first()

        if not role_target:
            return Response({
                'status': 'error',
                'error': 'Risorsa non trovata',
                'message': f'Ruolo con ID {role_id_target} non trovato.'
            }, status=status.HTTP_404_NOT_FOUND)

        # 3. CONTROLLO ORGANIZZAZIONE (Visibilità)
        if role_target.org_id != target_org_id:
            return Response({
                'status': 'error',
                'error': 'Accesso negato',
                'message': 'Non puoi eliminare ruoli appartenenti ad altre organizzazioni.'
            }, status=status.HTTP_403_FORBIDDEN)

        # 4. CONTROLLO PERMESSI GENERALI
        can_org = check_user_permission(user.id, 'delete_role_organization')
        can_list = check_user_permission(user.id, 'delete_role_list')

        if not (can_org or can_list):
            return Response({
                'status': 'error',
                'error': 'Permesso negato',
                'message': 'Non hai i permessi necessari per eliminare ruoli.'
            }, status=status.HTTP_403_FORBIDDEN)

        # 5. DETERMINAZIONE AMBITO DEL RUOLO TARGET
        is_org_role_target = role_target.list_id is None  # Ruolo Org
        is_list_role_target = role_target.list_id is not None  # Ruolo Lista

        max_auth_level = 0

        # 6. VERIFICA CONTESTO E GERARCHIA

        # 6.1 CASO RUOLO ORGANIZZAZIONE
        if is_org_role_target:
            if not can_org:
                return Response({'error': 'Permesso delete_role_organization richiesto per eliminare ruoli Org.'},
                                status=status.HTTP_403_FORBIDDEN)

            # Calcolo MAX LEVEL ORG (Filtra solo i ruoli dell'utente che hanno list=NULL)
            max_level_query = user.roles.filter(list__isnull=True, org_id=target_org_id).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

        # 6.2 CASO RUOLO LISTA
        elif is_list_role_target:
            # L'utente deve avere can_org OPPURE deve avere can_list SULLA SPECIFICA lista
            if not can_org:
                # Se ha solo can_list, verifica che abbia il permesso sulla lista target
                if not can_list or not user.roles.filter(list_id=role_target.list_id,
                                                         permissions__name='delete_role_list').exists():
                    return Response({'error': 'Non hai il permesso di eliminare ruoli in questa specifica lista.'},
                                    status=status.HTTP_403_FORBIDDEN)

            # Calcolo MAX LEVEL LISTA (Filtra solo i ruoli dell'utente che hanno list_id specifico)
            max_level_query = user.roles.filter(list_id=role_target.list_id, org_id=target_org_id).aggregate(
                max_level=Max('level'))
            max_auth_level = max_level_query.get('max_level') or 0

        # 7. CONTROLLO GERARCHICO FINALE
        if role_target.level >= max_auth_level:
            return Response({
                'status': 'error',
                'error': 'Violazione gerarchica',
                'message': f'Non puoi eliminare il ruolo "{role_target.name}" (Level {role_target.level}) perché è uguale o superiore al tuo massimo livello di autorità ({max_auth_level}) nel contesto.'
            }, status=status.HTTP_403_FORBIDDEN)

        # 8. ESECUZIONE ELIMINAZIONE
        role_target.delete()

        return Response({
            'status': 'success',
            'message': f'Ruolo con ID {role_id_target} eliminato correttamente.'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def view_all_roles(request):
    """
    Restituisce tutti i ruoli visibili all'utente autenticato, filtrati per Organizzazione o Lista.

    Filtro per Organizzazione (list_id=None): Richiede 'view_all_role_organization'.
    Filtro per Lista (list_id=<ID>): Richiede 'view_all_role_organization' (per tutte le liste)
    o 'view_all_role_list' (sulla lista specificata).

    :param request: Oggetto Request, accetta 'list_id' come parametro di query opzionale.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con la lista dei ruoli.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 403: Permesso negato.
    :raises 404: Utente non trovato o Lista target non trovata/non appartenente all'Org.
    """
    # 1. Recupero parametri
    list_id_raw = request.GET.get('list_id')
    list_id = int(list_id_raw) if list_id_raw is not None else None

    # 2. Autenticazione
    auth_user_data = get_user_from_token(request)
    if not auth_user_data:
        return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

    auth_user_id = auth_user_data.get('user_id')
    user = User.objects.filter(id=auth_user_id).first()

    if not user:
        return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

    target_org_id = user.org.id if user.org else None
    if target_org_id is None:
        return Response({'error': 'Utente non associato ad alcuna Organizzazione valida'},
                        status=status.HTTP_403_FORBIDDEN)

    # 3. Controllo permessi
    can_org = check_user_permission(user.id, 'view_all_role_organization')
    can_list = check_user_permission(user.id, 'view_all_role_list')

    if not (can_org or can_list):
        return Response({
            'error': 'Permesso negato',
            'message': 'Non hai permessi per visualizzare ruoli (Org o Lista)'
        }, status=status.HTTP_403_FORBIDDEN)

    roles = []

    # 4. CASO 1: Filtro Organizzazione (list_id è None)
    if list_id is None:
        if can_org:
            # Recupera TUTTI i ruoli (Org e Lista) appartenenti alla sua Organizzazione.
            roles_qs = Role.objects.filter(org_id=target_org_id)
            roles = [serialize_role_data(r) for r in roles_qs]
            return Response({
                'status': 'success',
                'message': 'Ruoli dell\'organizzazione recuperati',
                'data': {'roles': roles}
            }, status=status.HTTP_200_OK)
        else:
            # Non ha il permesso Org e list_id è None (non può vedere tutto)
            return Response({
                'error': 'Permesso negato',
                'message': 'È richiesto il permesso view_all_role_organization per visualizzare tutti i ruoli.'
            }, status=status.HTTP_403_FORBIDDEN)

    # 5. CASO 2: Filtro per Lista Specifica (list_id è presente)

    # 5.1 Verifica esistenza e appartenenza della Lista
    list_target = List.objects.filter(id=list_id, org_id=target_org_id).first()
    if list_target is None:
        return Response({
            'error': 'Risorsa non trovata',
            'message': f'Lista con ID {list_id} non trovata nella tua organizzazione.'
        }, status=status.HTTP_404_NOT_FOUND)

    # 5.2 Verifica Autorizzazione
    if can_org:
        # Se ha il permesso Organizzazione, può vedere i ruoli di qualsiasi lista
        roles_qs = Role.objects.filter(list_id=list_id)

    else:  # Solo permesso 'view_all_role_list' è presente
        if not can_list:  # Già controllato al punto 3, ma per chiarezza
            return Response({'error': 'Permesso interno mancante'}, status=status.HTTP_403_FORBIDDEN)

        # Controlla se l'utente ha il permesso 'view_all_role_list' su QUESTA specifica lista
        my_allowed_lists = get_lists_user_has_permission(user, 'view_all_role_list')
        allowed_list_ids = my_allowed_lists.values_list('id', flat=True)

        if list_id not in allowed_list_ids:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai accesso a visualizzare i ruoli di questa lista specifica.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Se autorizzato sulla lista specifica
        roles_qs = Role.objects.filter(list_id=list_id)

    # 5.3 Serializzazione e Risposta
    roles = [serialize_role_data(r) for r in roles_qs]
    return Response({
        'status': 'success',
        'message': f'Ruoli della lista {list_id} recuperati',
        'data': {'roles': roles}
    }, status=status.HTTP_200_OK)

    # 6. Fallback (Teoricamente non necessario grazie ai controlli precedenti, ma di sicurezza)
    # Ritorna 403 se list_id è None e can_org è False
    return Response({
        'error': 'Permesso negato',
        'message': 'Non hai permessi per visualizzare i ruoli richiesti'
    }, status=status.HTTP_403_FORBIDDEN)


@api_view(['GET'])
def view_role_information(request):
    """
    Restituisce i dettagli di un ruolo specifico ('role_id') o i ruoli
    dell'utente autenticato (se 'role_id' è omesso).

    La visibilità è limitata ai ruoli della stessa Organizzazione ed è governata dai permessi:
    - 'view_all_role_organization' per la visualizzazione completa dei ruoli Org/Lista.
    - 'view_all_role_list' per la visualizzazione selettiva (l'utente deve avere il permesso sulla Lista del ruolo target).

    In caso di permesso negato (403), restituisce i ruoli dell'utente autenticato per diagnostica.

    :param request: Oggetto Request, accetta 'role_id' come parametro di query opzionale.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con i dettagli del ruolo/i.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Ruolo target non trovato.
    :raises 403: Permesso negato (utente non ha autorità o viola l'Org).
    """
    role_id_raw = request.GET.get('role_id')

    # 1. Autenticazione
    auth_user_data = get_user_from_token(request)
    if not auth_user_data:
        return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

    auth_user_id = auth_user_data.get('user_id')
    auth_user = User.objects.filter(id=auth_user_id).first()

    if not auth_user:
        return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

    target_org_id = auth_user.org.id if auth_user.org else None

    # Prepara i ruoli dell'utente autenticato per le risposte 403
    auth_user_roles_data = [serialize_role_data(r) for r in auth_user.roles.all()]

    # Controllo permessi
    perm_org = check_user_permission(auth_user_id, 'view_all_role_organization')
    perm_lists = check_user_permission(auth_user_id, 'view_all_role_list')

    roles = []

    # Caso 1: Nessun role_id fornito (visualizza i propri ruoli)
    if not role_id_raw:
        roles = list(auth_user.roles.all())

    # Caso 2: role_id fornito (visualizza un ruolo specifico)
    else:
        try:
            role_id = int(role_id_raw)
        except ValueError:
            return Response({'error': 'role_id non valido'}, status=status.HTTP_400_BAD_REQUEST)

        role_to_view = Role.objects.filter(id=role_id).first()

        if not role_to_view:
            return Response({'error': 'Ruolo target non trovato'}, status=status.HTTP_404_NOT_FOUND)

        # Verifica Organizzazione (Il ruolo deve essere nella stessa Org)
        if role_to_view.org_id != target_org_id:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non puoi visualizzare ruoli di altre organizzazioni.',
                'user_roles': auth_user_roles_data
            }, status=status.HTTP_403_FORBIDDEN)

        # 2.1 Autorizzazione tramite permesso Org
        if perm_org:
            roles = [role_to_view]

        # 2.2 Autorizzazione tramite permesso Lista (Solo se il ruolo è di lista)
        elif role_to_view.list_id is not None and perm_lists:

            # Controlla se l'utente ha il permesso 'view_all_role_list' sulla lista specifica
            my_allowed_lists = get_lists_user_has_permission(auth_user, 'view_all_role_list')
            allowed_list_ids = my_allowed_lists.values_list('id', flat=True)

            if role_to_view.list_id not in allowed_list_ids:
                return Response({
                    'error': 'Permesso negato',
                    'message': 'Non hai il permesso di visualizzare ruoli in questa lista specifica.',
                    'user_roles': auth_user_roles_data
                }, status=status.HTTP_403_FORBIDDEN)

            roles = [role_to_view]

        # 2.3 Nessun permesso o il ruolo è Org e manca perm_org
        else:
            message = "Non hai permessi sufficienti per visualizzare questo ruolo."
            if role_to_view.list_id is None:
                message += " È richiesto il permesso 'view_all_role_organization'."

            return Response({
                'error': 'Permesso negato',
                'message': message,
                'user_roles': auth_user_roles_data
            }, status=status.HTTP_403_FORBIDDEN)

    # Serializzazione ruoli
    roles_data = [serialize_role_data(r) for r in roles]

    return Response({
        'status': 'success',
        'message': 'Informazioni ruolo/i recuperate',
        'data': {
            'roles': roles_data,
            'count': len(roles_data)
        }
    }, status=status.HTTP_200_OK)


# Regex per validare codici colore esadecimali (es. #FF0000)
HEX_COLOR_REGEX = re.compile(r'^#([A-Fa-f0-9]{6})$')


@api_view(['PUT'])
def update_list(request):
    """
    Aggiorna i dettagli di una Lista esistente (nome, descrizione, colori, logo, ecc.).

    Questa view implementa controlli di sicurezza rigorosi:
    1. **Verifica Organizzazione:** La Lista deve appartenere alla stessa Organizzazione dell'utente autenticato.
    2. **Autorizzazione:** L'utente deve possedere il permesso 'update_list_organization' (per modificare qualsiasi lista)
       oppure il permesso 'update_list_list' (se posseduto tramite un ruolo associato alla Lista target).
    3. **Validazione Dati:** I campi di input (es. ID, colori esadecimali) vengono validati rigorosamente.

    :param request: Oggetto Request di Django REST Framework.
        Il body della richiesta (JSON) deve contenere:

        * **list_id** (int): ID della Lista da aggiornare (obbligatorio).
        * **name** (str, opzionale): Nuovo nome della lista.
        * **description** (str, opzionale): Nuova descrizione.
        * **slogan** (str, opzionale): Nuovo slogan.
        * **color_primary** (str, opzionale): Nuovo codice colore primario (formato esadecimale #RRGGBB).
        * **color_secondary** (str, opzionale): Nuovo codice colore secondario (formato esadecimale #RRGGBB).
        * **logo_file_id** (int/None, opzionale): ID del file del logo (o None per rimuoverlo).

    :type request: :class:`rest_framework.request.Request`

    :returns: Risposta JSON con i dettagli aggiornati della Lista.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK

    :raises 401: Autenticazione JWT mancante o non valida.
    :raises 404: Utente autenticato o Lista target non trovati.
    :raises 400: Parametro ``list_id`` mancante/non valido o formato colore errato.
    :raises 403: Permesso negato (mancanza di autorizzazione o violazione dell'Organizzazione).
    :raises 409: Errore di conflitto (es. nome Lista duplicato, violazione UniqueConstraint).
    :raises 500: Errore interno del server.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        list_id_target_raw = data.get('list_id')

        # 1.1 VALIDAZIONE ID LISTA
        if not list_id_target_raw:
            return Response({'error': 'Il campo list_id è obbligatorio'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            list_id_target = int(list_id_target_raw)
        except ValueError:
            return Response({'error': 'Il campo list_id deve essere un numero intero valido.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # 1.2 RECUPERO LISTA TARGET
        list_target = List.objects.filter(id=list_id_target).first()

        if not list_target:
            return Response({'error': f'Lista con ID {list_id_target} non trovata'}, status=status.HTTP_404_NOT_FOUND)

        # 2. CONTROLLO PERMESSI
        can_modify_org = check_user_permission(auth_user_id, 'update_list_organization')
        can_modify_lists = check_user_permission(auth_user_id, 'update_list_list')

        # 3. VERIFICA ORGANIZZAZIONE
        if list_target.org.id != auth_user.org.id:
            return Response({
                'error': 'Accesso negato',
                'message': 'La lista non appartiene alla tua Organizzazione.'
            }, status=status.HTTP_403_FORBIDDEN)

        # 4. VERIFICA AUTORIZZAZIONE DI MODIFICA (Logica inalterata, corretta)
        is_authorized = False

        if can_modify_org:
            is_authorized = True

        elif can_modify_lists:
            has_perm_on_list = auth_user.roles.filter(
                list_id=list_id_target,
                permissions__name='update_list_list'
            ).exists()

            if has_perm_on_list:
                is_authorized = True

        if not is_authorized:
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai il permesso necessario (update_list_organization o update_list_list) per modificare questa lista.'
            }, status=status.HTTP_403_FORBIDDEN)

        # 5. APPLICAZIONE E VALIDAZIONE AGGIORNAMENTI
        updated = False

        if 'name' in data and data['name'] is not None:
            list_target.name = data['name'].strip()
            updated = True

        if 'description' in data and data['description'] is not None:
            list_target.description = data['description'].strip()
            updated = True

        if 'slogan' in data and data['slogan'] is not None:
            list_target.slogan = data['slogan'].strip()
            updated = True

        # Validazione Colore Primario
        if 'color_primary' in data and data['color_primary'] is not None:
            color = data['color_primary'].upper()
            if HEX_COLOR_REGEX.match(color):
                list_target.color_primary = color
                updated = True
            else:
                return Response({'error': 'Formato colore primario non valido. Deve essere #RRGGBB.'},
                                status=status.HTTP_400_BAD_REQUEST)

        # Validazione Colore Secondario
        if 'color_secondary' in data and data['color_secondary'] is not None:
            color = data['color_secondary'].upper()
            if HEX_COLOR_REGEX.match(color):
                list_target.color_secondary = color
                updated = True
            else:
                return Response({'error': 'Formato colore secondario non valido. Deve essere #RRGGBB.'},
                                status=status.HTTP_400_BAD_REQUEST)

        # Validazione logo_file_id (Assumendo che sia un intero o None)
        if 'logo_file_id' in data:
            logo_id = data['logo_file_id']
            if logo_id is None or (isinstance(logo_id, int) and logo_id > 0):
                list_target.logo_file_id = logo_id
                updated = True
            else:
                return Response({'error': 'Il campo logo_file_id non è valido.'}, status=status.HTTP_400_BAD_REQUEST)

        if updated:
            list_target.save()

            # 6. RISPOSTA DI SUCCESSO
            return Response({
                'status': 'success',
                'message': f'Lista ID {list_id_target} aggiornata correttamente.',
                'data': {
                    'id': list_target.id,
                    'name': list_target.name,
                    'description': list_target.description,
                    'slogan': list_target.slogan,
                    'color_primary': list_target.color_primary,
                    'color_secondary': list_target.color_secondary,
                    'logo_file_id': list_target.logo_file_id,
                    'org_id': list_target.org_id,
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': 'warning',
                'message': 'Nessun dato valido fornito per l\'aggiornamento.'
            }, status=status.HTTP_200_OK)

    # GESTIONE ECCEZIONI SPECIFICHE
    except IntegrityError as e:
        # Se c'è un UniqueConstraint (es. nome lista duplicato all'interno della stessa Org)
        return Response({
            'status': 'error',
            'error': 'Errore di Conflitto (Duplicato)',
            'message': 'Una lista con questo nome o ID esiste già nella tua Organizzazione.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        # Gestione errori generici inaspettati
        return Response({
            'status': 'error',
            'error': 'Errore interno del server',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def create_list(request):
    """
    Crea una nuova Lista (List) all'interno dell'Organizzazione dell'utente autenticato.

    Implementa rigorosi controlli di sicurezza e validazione:
    1. **Autenticazione:** Richiede un utente autenticato.
    2. **Permesso:** Richiede il permesso 'create_list'.
    3. **Limite Organizzazione:** Verifica che il numero di liste esistenti non superi
       il limite massimo ('max_lists') impostato per l'Organizzazione.
    4. **Validazione Dati:**
        - Il campo 'name' è obbligatorio.
        - 'color_primary' e 'color_secondary' vengono validati per il formato esadecimale (#RRGGBB).

    L'associazione all'Organizzazione viene forzata sull'Organizzazione dell'utente autenticato.

    :param request: Oggetto Request di Django REST Framework.
        Il body della richiesta (JSON) deve contenere:

        * **name** (str): Nome della Lista (obbligatorio).
        * **description** (str, opzionale): Descrizione della Lista.
        * **slogan** (str, opzionale): Slogan/Motto della Lista.
        * **color_primary** (str, opzionale): Codice colore primario (formato esadecimale #RRGGBB).
        * **color_secondary** (str, opzionale): Codice colore secondario (formato esadecimale #RRGGBB).
        * **logo_file_id** (int/None, opzionale): ID del file del logo (Foreign Key).

    :type request: :class:`rest_framework.request.Request`

    :returns: Risposta JSON con i dettagli della Lista creata.
    :rtype: :class:`rest_framework.response.Response` con status 201 CREATED

    :raises 401: Autenticazione JWT mancante o non valida.
    :raises 404: Utente autenticato non trovato.
    :raises 400: Dati incompleti o formato colore non valido.
    :raises 403: Permesso 'create_list' mancante o limite massimo di liste raggiunto.
    :raises 409: Errore di conflitto (es. nome Lista duplicato, violazione UniqueConstraint).
    :raises 500: Errore interno del server.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if auth_user.org is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione'},
                            status=status.HTTP_403_FORBIDDEN)

        target_org_id = auth_user.org.id

        # 2. CONTROLLO PERMESSO
        can_create = check_user_permission(auth_user.id, 'create_list')
        if not can_create:
            return Response({
                'status': 'error',
                'error': 'Permesso negato',
                'message': 'Permesso "create_list" richiesto.'
            }, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        required = ['name']

        # 3. VALIDAZIONE DATI BASE
        if not all(field in data and data[field] and str(data[field]).strip() for field in required):
            return Response({
                'status': 'error',
                'error': 'Dati incompleti',
                'message': 'Il campo name è obbligatorio e non può essere vuoto.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 4. CONTROLLO LIMITE MASSIMO LISTE
        if auth_user.org.max_lists is not None:
            count_list_for_organization = List.objects.filter(org_id=target_org_id).count()

            if count_list_for_organization >= auth_user.org.max_lists:
                return Response({
                    'status': 'error',
                    'error': 'Limite raggiunto',
                    'message': f'L\'Organizzazione ha raggiunto il limite massimo di {auth_user.org.max_lists} liste.'
                }, status=status.HTTP_403_FORBIDDEN)

        # 5. PREPARAZIONE E VALIDAZIONE CAMPI OPZIONALI

        list_data = {
            'name': data['name'].strip(),
            'org_id': target_org_id,
            'description': data.get('description', '').strip(),
            'slogan': data.get('slogan', '').strip(),
        }

        # Validazione Colori
        color_primary = data.get('color_primary')
        if color_primary is not None:
            color = color_primary.upper()
            if not HEX_COLOR_REGEX.match(color):
                return Response({'error': 'Formato colore primario non valido. Deve essere #RRGGBB.'},
                                status=status.HTTP_400_BAD_REQUEST)
            list_data['color_primary'] = color

        color_secondary = data.get('color_secondary')
        if color_secondary is not None:
            color = color_secondary.upper()
            if not HEX_COLOR_REGEX.match(color):
                return Response({'error': 'Formato colore secondario non valido. Deve essere #RRGGBB.'},
                                status=status.HTTP_400_BAD_REQUEST)
            list_data['color_secondary'] = color

        # Validazione logo_file_id (Assumendo che sia un intero o None)
        logo_id = data.get('logo_file_id', None)
        if logo_id is not None and not (isinstance(logo_id, int) and logo_id >= 0):
            return Response({'error': 'Il campo logo_file_id non è valido (deve essere un intero positivo o None).'},
                            status=status.HTTP_400_BAD_REQUEST)
        list_data['logo_file_id'] = logo_id

        # 6. CREAZIONE
        new_list = List.objects.create(**list_data)

        # 7. RISPOSTA
        return Response({
            'status': 'success',
            'message': 'Lista creata con successo.',
            'data': {
                'id': new_list.id,
                'name': new_list.name,
                'org_id': new_list.org_id,
                'description': new_list.description,
                'slogan': new_list.slogan,
                'color_primary': new_list.color_primary,
                'color_secondary': new_list.color_secondary,
                'logo_file_id': new_list.logo_file_id,
            }
        }, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        # Gestisce la violazione di UniqueConstraint (es. nome lista duplicato all'interno della stessa Org)
        return Response({
            'status': 'error',
            'error': 'Errore di Conflitto (Duplicato)',
            'message': 'Una lista con questo nome esiste già nella tua Organizzazione.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def view_all_lists(request):
    """
    Restituisce tutte le Liste visibili all'utente autenticato.

    La visibilità si basa sul permesso 'view_all_lists' (per vedere tutte le liste dell'Org)
    o sull'associazione diretta dell'utente a ciascuna lista.

    :param request: Oggetto Request di Django REST Framework.
    :type request: :class:`rest_framework.request.Request`
    :returns: Risposta JSON con la lista delle Liste.
    :rtype: :class:`rest_framework.response.Response` con status 200 OK
    :raises 401: Autenticazione JWT mancante.
    :raises 404: Utente autenticato non trovato.
    :raises 403: Utente non associato ad alcuna Organizzazione.
    :raises 500: Errore del database o interno del server.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')

        # Gestione di ObjectDoesNotExist nel caso in cui User.objects.filter().first() non sia nullo ma il recupero fallisca.
        # User.objects.filter().first() ritorna None, quindi il controllo è implicito dopo.
        auth_user = User.objects.filter(id=auth_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if auth_user.org is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione valida'},
                            status=status.HTTP_403_FORBIDDEN)

        target_org_id = auth_user.org.id

        # 2. CONTROLLO PERMESSI
        can_org = check_user_permission(auth_user.id, 'view_all_lists')

        lists_qs = List.objects.none()

        # 3. LOGICA DI VISIBILITÀ
        if can_org:
            # Caso 1: Vede tutte le liste dell'Organizzazione
            lists_qs = List.objects.filter(org_id=target_org_id)
        else:
            # Caso 2: Vede solo le liste a cui è associato tramite la relazione Many-to-Many 'users'
            # (Assumiamo che List abbia un campo users collegato a User)
            lists_qs = List.objects.filter(users__id=auth_user.id)

            # 4. SERIALIZZAZIONE E RISPOSTA

        # Filtra per l'Organizzazione e rimuove i duplicati (utile se l'utente è associato a una lista con più ruoli/associazioni)
        final_lists_qs = lists_qs.filter(org_id=target_org_id).distinct()

        # Gestione delle eccezioni durante la serializzazione (es. campo mancante o relazione rotta)
        try:
            lists_data = [serialize_list_data(l) for l in final_lists_qs]
        except Exception as e:
            # Errore specifico durante la serializzazione
            return Response({
                'status': 'error',
                'error': 'Errore di serializzazione dei dati della lista',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'status': 'success',
            'message': 'Liste recuperate con successo.',
            'data': {
                'lists': lists_data,
                'count': len(lists_data)
            }
        }, status=status.HTTP_200_OK)

    # GESTIONE ECCEZIONI GENERICHE (Per qualsiasi altro errore inaspettato)
    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server inatteso',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


MAX_FILE_SIZE_MB = 50  # 50 Megabytes, esempio di limite

# Conversione in byte per il controllo
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


@extend_schema(
    summary="Aggiungi File",
    description="Carica un file (foto, documento, ecc.) e crea un record nel database, associandolo all'Organizzazione o a una Lista specifica.",
    request={
        'multipart/form-data': {
            'type': 'object',
            'properties': {
                'file': {
                    'type': 'string',
                    'format': 'binary',
                    'description': 'Il file binario da caricare.'
                },
                'list_id': {
                    'type': 'integer',
                    'description': 'ID della Lista (opzionale).'
                },
                'category_id': {
                    'type': 'integer',
                    'description': 'ID della Categoria (opzionale).'
                }
            },
            'required': ['file']
        }
    },
    responses={
        201: {'description': 'File caricato e registrato con successo.'},
        400: {'description': 'Dati mancanti, ID non valido o dimensione del file eccessiva.'},
        401: {'description': 'Autenticazione richiesta.'},
        403: {'description': 'Permesso negato o utente senza Organizzazione.'},
        404: {'description': 'Lista o Categoria non trovata.'},
        409: {'description': 'Errore di integrità del database.'},
        500: {'description': 'Errore interno (es. fallimento salvataggio I/O).'}
    }
)
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def add_file(request):
    """
    Gestisce l'upload di un file generico, verificando i permessi e la dimensione massima.
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if auth_user.org is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione'},
                            status=status.HTTP_403_FORBIDDEN)

        target_org_id = auth_user.org.id

        data = request.data
        uploaded_file = request.FILES.get('file')
        list_id_target_raw = data.get('list_id')
        category_id_raw = data.get('category_id')

        # 2. CONTROLLO FILE E DIMENSIONE
        if uploaded_file is None:
            return Response({'error': 'File mancante', 'message': 'Nessun file trovato nel campo "file".'},
                            status=status.HTTP_400_BAD_REQUEST)

        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            return Response({
                'error': 'Dimensione file eccessiva',
                'message': f'La dimensione massima consentita è {MAX_FILE_SIZE_MB} MB.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 3. CONTROLLO PERMESSI E AUTORIZZAZIONE

        can_org = check_user_permission(auth_user.id, 'add_file_organization')
        can_list = check_user_permission(auth_user.id, 'add_file_list')

        is_authorized = False
        list_id_target = None

        if list_id_target_raw:
            try:
                list_id_target = int(list_id_target_raw)
            except ValueError:
                return Response({'error': 'list_id non valido'}, status=status.HTTP_400_BAD_REQUEST)

            list_target = List.objects.filter(id=list_id_target, org__id=target_org_id).first()
            if not list_target:
                return Response({'error': 'Lista non trovata'}, status=status.HTTP_404_NOT_FOUND)

            if can_org:
                is_authorized = True
            elif can_list:
                has_perm_on_list = auth_user.roles.filter(
                    list_id=list_id_target,
                    permissions__name='add_file_list'
                ).exists()
                if has_perm_on_list:
                    is_authorized = True

        else:  # Caricamento su Organizzazione (Root)
            list_id_target = None
            if can_org:
                is_authorized = True

        if not is_authorized:
            return Response({'error': 'Permesso negato',
                             'message': 'Non hai il permesso sufficiente per aggiungere file in questa posizione.'},
                            status=status.HTTP_403_FORBIDDEN)

        # 4. VALIDAZIONE CAMPI OPZIONALI
        category_id = None
        if category_id_raw:
            try:
                category_id = int(category_id_raw)
                # Verifica che la categoria esista
                if not FileCategory.objects.filter(id=category_id).exists():
                    return Response({'error': 'Categoria non valida',
                                     'message': 'La categoria file specificata non esiste.'},
                                    status=status.HTTP_404_NOT_FOUND)
            except ValueError:
                return Response({'error': 'category_id non valido'}, status=status.HTTP_400_BAD_REQUEST)

        file_name = uploaded_file.name

        # 5. SALVATAGGIO FISICO DEL FILE (Placeholder)
        file_name_original = uploaded_file.name
        mime_type = uploaded_file.content_type
        try:
            storage_folder = f'uploads/{target_org_id}/{list_id_target or "org"}/{category_id}'

            # 5.2 Generazione del nome file univoco per evitare conflitti
            # Estrae l'estensione del file originale (es. .pdf, .jpg)
            extension = file_name_original.split('.')[-1] if '.' in file_name_original else ''
            unique_file_name = f'{uuid4()}.{extension}'

            # Il percorso completo nel sistema di storage
            file_path_in_storage = f'{storage_folder}/{unique_file_name}'

            # 5.3 ESECUZIONE DEL SALVATAGGIO FISICO
            # Legge il contenuto del file caricato (in memoria)
            file_content = uploaded_file.read()

            # Utilizza il sistema di storage di Django per salvare il contenuto
            default_storage.save(file_path_in_storage, ContentFile(file_content))

        except Exception as e:
            return Response({'error': 'Errore di I/O', 'message': f'Impossibile salvare il file fisicamente: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 6. REGISTRAZIONE NEL DATABASE
        new_file = File.objects.create(
            name=file_name,
            org_id=target_org_id,
            list_id=list_id_target,
            user_id=auth_user.id,
            category_id=category_id,
            file_path=file_path_in_storage,
            mime_type=mime_type,
        )

        # 7. RISPOSTA
        file_data = {
            'id': new_file.id,
            'name': new_file.name,
            'file_path': new_file.file_path,
            'mime_type': new_file.mime_type,
            'list_id': new_file.list_id,
            'category_id': new_file.category_id,
            'user_id': new_file.user_id,
            'uploaded_at': new_file.uploaded_at.isoformat() if hasattr(new_file, 'uploaded_at') else None,
        }

        return Response({
            'status': 'success',
            'message': 'File caricato e registrato con successo.',
            'data': file_data
        }, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        return Response({
            'status': 'error',
            'error': 'Errore di integrità del database',
            'message': f'Verifica che le chiavi esterne (Lista, Categoria) siano valide.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server inatteso',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    summary="Elimina File",
    description="Esegue la cancellazione logica del record e la cancellazione fisica del file dal sistema di storage. Richiede `file_id` come parametro di query.",
    parameters=[
        OpenApiParameter(
            name='file_id',
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            required=True,
            description='ID del file da eliminare.'
        )
    ],
    responses={
        200: {'description': 'File eliminato con successo.'},
        400: {'description': 'file_id mancante o non valido.'},
        401: {'description': 'Autenticazione richiesta.'},
        403: {'description': 'Permesso negato.'},
        404: {'description': 'File non trovato o utente non associato a Org.'},
        500: {'description': 'Errore interno del server (es. fallimento cancellazione I/O).'}
    }
)
@api_view(['DELETE'])
def delete_file(request):
    """
    Gestisce l'eliminazione di un file.
    I permessi sono controllati in questo ordine di precedenza:
    1. delete_file_organization (Org-level)
    2. delete_file_list (List-level, se il file appartiene a una lista)
    3. Proprietario (L'utente che ha caricato il file)
    """
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        aut_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=aut_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if auth_user.org is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione'},
                            status=status.HTTP_403_FORBIDDEN)

        target_org_id = auth_user.org.id

        # 2. RECUPERO E VALIDAZIONE FILE
        file_id_data = request.GET.get('file_id')
        if not file_id_data:
            return Response({'error': 'file_id mancante'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_id = int(file_id_data)
        except ValueError:
            return Response({'error': 'file_id non valido'}, status=status.HTTP_400_BAD_REQUEST)

        # Filtra il file all'interno dell'Org dell'utente
        file_target = File.objects.filter(id=file_id, org__id=target_org_id).first()

        if file_target is None:
            return Response({'error': 'File non trovato nella tua Organizzazione'}, status=status.HTTP_404_NOT_FOUND)

        # 3. CONTROLLO PERMESSI
        can_org = check_user_permission(auth_user.id, 'delete_file_organization')
        can_list_perm = check_user_permission(auth_user.id, 'delete_file_list')  # Indica se ha *il* permesso List

        is_authorized = False

        # 3.1 Priorità 1: Permesso Org-Level
        if can_org:
            is_authorized = True

        # 3.2 Priorità 2: Permesso List-Level (se file associato a Lista)
        elif file_target.list_id is not None and can_list_perm:
            # Verifica se l'utente ha il ruolo necessario sulla Lista specifica del file
            has_perm_on_list = auth_user.roles.filter(
                list_id=file_target.list_id,
                permissions__name='delete_file_list'
            ).exists()
            if has_perm_on_list:
                is_authorized = True

        # 3.3 Priorità 3: Proprietario del File (Se non ha altri permessi di gestione file)
        elif file_target.user_id == auth_user.id:
            is_authorized = True

        if not is_authorized:
            return Response({'error': 'Permesso negato', 'message': 'Non hai il permesso di eliminare questo file.'},
                            status=status.HTTP_403_FORBIDDEN)

        # 4. CANCELLAZIONE FISICA E DB
        file_path_to_delete = file_target.file_path

        # 4.1 Cancellazione Record DB (prima di cancellare fisicamente in caso di errore)
        # Se la cancellazione fisica fallisce, è meglio avere il record nel DB.
        file_target.delete()

        # 4.2 Cancellazione Fisica del File
        try:
            if file_path_to_delete and default_storage.exists(file_path_to_delete):
                default_storage.delete(file_path_to_delete)
        except Exception as e:
            # NOTA: Se la cancellazione fisica fallisce, il DB è già stato aggiornato.
            # Qui si potrebbe loggare un avviso e restituire comunque successo all'utente
            # o gestire un rollback (più complesso). Restituiamo successo ma con avviso log.
            print(f"ATTENZIONE: Fallimento cancellazione fisica file {file_path_to_delete}: {e}")

        # 5. RISPOSTA
        return Response({
            'status': 'success',
            'message': f'File con ID {file_id} eliminato con successo. Percorso: {file_path_to_delete}'
        }, status=status.HTTP_200_OK)

    except IntegrityError:
        return Response({'status': 'error', 'error': 'Errore di integrità del database durante la cancellazione.'},
                        status=status.HTTP_409_CONFLICT)
    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server inatteso',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def serialize_organization_data(org_object):
    """
    Placeholder per la serializzazione dei dati dell'Organizzazione.
    Dovresti implementare questa funzione per includere i campi rilevanti.
    """
    return {
        'id': org_object.id,
        'name': org_object.name,
        'created_at': org_object.created_at.isoformat() if hasattr(org_object, 'created_at') else None,
        # ... Aggiungi qui altri campi rilevanti
    }


@extend_schema(
    summary="Visualizza Organizzazione per Codice",
    description="Recupera i dettagli di un'Organizzazione utilizzando il suo codice univoco (`org_code`). Non richiede autenticazione.",
    parameters=[
        OpenApiParameter(
            name='org_code',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            required=True,
            description='Codice univoco dell\'Organizzazione.'
        )
    ],
    responses={
        200: {'description': 'Dati Organizzazione recuperati.'},
        400: {'description': 'org_code mancante.'},
        404: {'description': 'Organizzazione non trovata per il codice specificato.'},
        500: {'description': 'Errore interno del server durante la serializzazione.'}
    }
)
@api_view(['GET'])
def view_organization_by_code(request):
    """
    Permette di recuperare i dettagli di un'Organizzazione tramite il suo codice.
    Non richiede autenticazione.
    """
    try:
        org_code = request.GET.get('org_code')

        # 1. VALIDAZIONE INPUT
        if not org_code:
            return Response({
                'status': 'error',
                'error': 'Codice Organizzazione mancante',
                'message': 'Il parametro org_code è obbligatorio.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 2. RECUPERO DATI
        # Assumiamo che il campo per l'Organizzazione sia chiamato 'Organization'
        org = Organization.objects.filter(code=org_code).first()

        if org is None:
            return Response({
                'status': 'error',
                'error': 'Organizzazione non trovata',
                'message': f'Nessuna Organizzazione trovata per il codice: {org_code}.'
            }, status=status.HTTP_404_NOT_FOUND)

        # 3. SERIALIZZAZIONE E RISPOSTA
        try:
            org_data = serialize_organization_data(org)
        except Exception as e:
            # Errore nella serializzazione
            return Response({
                'status': 'error',
                'error': 'Errore di serializzazione dei dati dell\'Organizzazione',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'status': 'success',
            'message': 'Organizzazione recuperata con successo.',
            'data': org_data
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server inatteso',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Assumiamo che List, Campaign, User e le funzioni di supporto siano importate

# Formato data atteso nel body della richiesta (es: 'YYYY-MM-DD')
DATE_FORMAT = '%Y-%m-%d'


def serialize_campaign_data(campaign_object):
    """ Placeholder per la serializzazione di un oggetto Campaign. """
    return {
        'id': campaign_object.id,
        'name': campaign_object.name,
        'list_id': campaign_object.list_id,
        'start_date': campaign_object.start_date.strftime(DATE_FORMAT),
        'end_date': campaign_object.end_date.strftime(DATE_FORMAT),
    }


@extend_schema(
    summary="Crea Campagna",
    description="Crea una nuova campagna. La lista (`list_id`) è obbligatoria per associare la campagna. Richiede permessi a livello di Organizzazione o a livello di Lista target.",
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'name': {'type': 'string', 'description': 'Nome della Campagna (Obbligatorio).'},
                'list_id': {'type': 'integer',
                            'description': 'ID della Lista a cui la campagna è associata (Obbligatorio).'},
                'description': {'type': 'string', 'description': 'Descrizione della Campagna (Opzionale).'},
                'start_date': {'type': 'string', 'format': 'date',
                               'description': 'Data di inizio della campagna (Formato YYYY-MM-DD, Obbligatorio).'},
                'end_date': {'type': 'string', 'format': 'date',
                             'description': 'Data di fine della campagna (Formato YYYY-MM-DD, Obbligatorio).'}
            },
            'required': ['name', 'list_id', 'start_date', 'end_date']
        }
    },
    responses={
        201: {'description': 'Campagna creata con successo.'},
        400: {'description': 'Dati mancanti, data non valida o formati errati.'},
        401: {'description': 'Autenticazione richiesta.'},
        403: {'description': 'Permesso negato (inclusa la violazione Org/Lista).'},
        404: {'description': 'Lista target non trovata.'},
        409: {'description': 'Errore di integrità del database.'}
    }
)
@api_view(['POST'])
def create_campaign(request):
    try:
        # 1. AUTENTICAZIONE E UTENTE
        auth_user_data = get_user_from_token(request)
        if not auth_user_data:
            return Response({'error': 'Autenticazione richiesta'}, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user_data.get('user_id')
        auth_user = User.objects.filter(id=auth_user_id).first()

        if not auth_user:
            return Response({'error': 'Utente autenticato non trovato'}, status=status.HTTP_404_NOT_FOUND)

        if auth_user.org is None:
            return Response({'error': 'Utente non associato ad alcuna Organizzazione'},
                            status=status.HTTP_403_FORBIDDEN)

        target_org_id = auth_user.org.id

        data = request.data
        required = ['name', 'list_id', 'start_date', 'end_date']

        # 2. VALIDAZIONE CAMPI OBBLIGATORI
        missing_fields = [field for field in required if not data.get(field) or str(data.get(field)).strip() == '']
        if missing_fields:
            return Response({'error': 'Campi obbligatori mancanti', 'fields': missing_fields},
                            status=status.HTTP_400_BAD_REQUEST)

        # 3. VALIDAZIONE LISTA TARGET
        try:
            list_id = int(data['list_id'])
        except ValueError:
            return Response({'error': 'list_id non valido', 'message': 'L\'ID della lista deve essere un intero.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Filtra la lista per ID e Organizzazione
        list_target = List.objects.filter(id=list_id, org__id=target_org_id).first()
        if list_target is None:
            return Response({'error': 'Lista non trovata',
                             'message': 'Lista non trovata o non appartenente alla tua Organizzazione.'},
                            status=status.HTTP_404_NOT_FOUND)

        # 4. VALIDAZIONE DATE
        try:
            start_date_obj = datetime.strptime(data['start_date'], DATE_FORMAT).date()
            end_date_obj = datetime.strptime(data['end_date'], DATE_FORMAT).date()
        except ValueError:
            return Response(
                {'error': 'Formato data non valido', 'message': f'Le date devono essere nel formato {DATE_FORMAT}.'},
                status=status.HTTP_400_BAD_REQUEST)

        if start_date_obj >= end_date_obj:
            return Response(
                {'error': 'Date non valide', 'message': 'La data di inizio deve essere precedente alla data di fine.'},
                status=status.HTTP_400_BAD_REQUEST)

        # 5. CONTROLLO PERMESSI E AUTORIZZAZIONE
        can_org = check_user_permission(auth_user.id, 'create_campaign_organization')
        can_list = check_user_permission(auth_user.id, 'create_campaign_list')

        is_authorized = False

        if can_org:
            # L'utente ha il permesso a livello Org, quindi è autorizzato (la Lista è già stata validata per l'Org al punto 3)
            is_authorized = True

        elif can_list:
            # L'utente ha il permesso a livello List, ma deve avere un ruolo che glielo conferisce sulla LISTA TARGET
            is_authorized_on_list = auth_user.roles.filter(
                list_id=list_id,
                permissions__name='create_campaign_list'
            ).exists()

            if is_authorized_on_list:
                is_authorized = True

        if not is_authorized:
            return Response({'error': 'Permesso negato',
                             'message': 'Non hai il permesso sufficiente per creare campagne in questa Lista.'},
                            status=status.HTTP_403_FORBIDDEN)

        # 6. CREAZIONE DELLA CAMPAGNA
        new_campaign = Campaign.objects.create(
            list_id=list_id,
            name=data['name'],
            description=data.get('description'),  # Opzionale
            start_date=start_date_obj,
            end_date=end_date_obj,
            # Aggiungi qui eventuali altri campi di default
        )

        # 7. RISPOSTA
        campaign_data = serialize_campaign_data(new_campaign)

        return Response({
            'status': 'success',
            'message': 'Campagna creata con successo.',
            'data': campaign_data
        }, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        return Response({
            'status': 'error',
            'error': 'Conflitto o Errore di integrità',
            'message': 'Verifica che non esista già una campagna con questo nome o che tutte le chiavi esterne siano valide.'
        }, status=status.HTTP_409_CONFLICT)

    except Exception as e:
        return Response({
            'status': 'error',
            'error': 'Errore interno del server inatteso',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

