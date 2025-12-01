import hashlib

from django.db import IntegrityError
from django.db.models import Max

from votopia_backend.models import *
from rest_framework.decorators import api_view
from rest_framework.views import APIView

from votopia_backend.services.serializers import LoginSerializer
from votopia_backend.services.db_procedures import register_user
from votopia_backend.services.permissions import *
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


# =========================================================================
# VIEW IMPLEMENTATE
# =========================================================================

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

            if role.org_level:
                if not can_org:
                    continue
                max_level = auth_user.roles.filter(org_id=org_id, org_level=True).aggregate(Max('level'))['level__max'] or 0
                if role.level > max_level:
                    continue
            else:
                if not can_list:
                    continue
                if role.list_id not in lists:
                    continue
                max_level = auth_user.roles.filter(list_id=role.list_id, org_level=False).aggregate(Max('level'))['level__max'] or 0
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
                'allowed_lists_ids': list(get_lists_user_has_permission(user, 'view_all_user_list').values_list('id', flat=True))
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
    users_data = [serialize_user_data(u) for u in users] # Usa la funzione helper

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
            users = [serialize_user_data(u) for u in users_qs] # Usa la funzione helper
            return Response({
                'status': 'success',
                'message': 'Utenti dell\'organizzazione recuperati',
                'data': { 'users': users }
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
        users = [serialize_user_data(u) for u in users_qs] # Usa la funzione helper
        return Response({
            'status': 'success',
            'message': f'Utenti della lista {list_id} recuperati',
            'data': { 'users': users }
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
            return Response({'error': 'Non puoi eliminare utenti di altre organizzazioni'}, status=status.HTTP_403_FORBIDDEN)

        # 6 Soft delete
        user_to_delete.deleted = True
        user_to_delete.save()

        return Response({
            'status': 'success',
            'message': f"Utente {user_to_delete.id} marcato come cancellato",
            'data': { 'user_id': user_to_delete.id }
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
            return Response({'error': 'Non puoi modificare utenti di altre organizzazioni'}, status=status.HTTP_403_FORBIDDEN)
        elif can_modify_list:
            allowed_lists = get_lists_user_has_permission(auth_user, 'update_user_list').values_list('id', flat=True)
            if not user_target.lists.filter(id__in=allowed_lists).exists() and user_target.id != auth_user.id:
                return Response({'error': 'Non puoi modificare utenti di liste non autorizzate'}, status=status.HTTP_403_FORBIDDEN)
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
                allowed_lists = get_lists_user_has_permission(auth_user, 'update_user_list').values_list('id', flat=True)
                for lst_id in lists_to_add:
                    if lst_id in allowed_lists:
                        lst = List.objects.filter(id=lst_id).first()
                        if lst: lst.users.add(user_target.id)
                for lst_id in lists_to_remove:
                    if lst_id in allowed_lists:
                        lst = List.objects.filter(id=lst_id).first()
                        if lst:
                            lst.users.remove(user_target.id)
                            user_target.roles.filter(list_id=lst.id).delete() # Rimuove ruoli di lista associati

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
            if new_level > max_auth_level:
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
            if new_level > max_auth_level:
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

