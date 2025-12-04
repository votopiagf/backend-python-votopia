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