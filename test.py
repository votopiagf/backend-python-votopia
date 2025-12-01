@api_view(['POST'])
def register(request):
    """
    Crea un nuovo utente.
    Richiede JWT + permesso:
        - create_user_for_organization  (crea utenti per l'intera organizzazione)
        - create_user_for_list          (crea utenti per una specifica lista)
    """
    try:
        # -----------------------------------------
        # 1) Autenticazione
        # -----------------------------------------
        auth_user = get_user_from_token(request)
        if not auth_user:
            return Response({
                'error': 'Autenticazione richiesta',
                'message': 'Inserisci il token JWT nell’header Authorization'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user.get('user_id')
        user = User.objects.filter(user_id=auth_user_id).first()

        # Utente non esiste
        if not verify_user_exists(auth_user_id) or not user:
            return Response({
                'error': 'Utente non valido',
                'message': 'L’utente autenticato non esiste nel database'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # -----------------------------------------
        # 2) Controllo permessi
        # -----------------------------------------
        can_org = check_user_permission(user.id, 'create_user_for_organization')
        can_list = check_user_permission(user.id, 'create_user_for_list')

        # Questa logica: può creare se ha almeno UNO
        if not (can_org or can_list):
            perms = get_user_permissions(user.id)
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai i permessi necessari per creare utenti',
                'required_permission': ['create_user_for_organization', 'create_user_for_list'],
                'your_permissions': [p['name'] for p in perms]
            }, status=status.HTTP_403_FORBIDDEN)

        # -----------------------------------------
        # 3) Validazione input
        # -----------------------------------------
        data = request.data
        required = ['name', 'surname', 'email', 'password']

        if not all(field in data and data[field] for field in required):
            return Response({
                'error': 'Dati incompleti',
                'required_fields': required
            }, status=status.HTTP_400_BAD_REQUEST)

        lists = data.get('lists', []) or []

        # Organizzazione dell’utente autenticato
        data['org_id'] = user.org.id

        new_user = None

        # -----------------------------------------
        # 4) CASO 1 — Permesso globale per l'organizzazione
        # -----------------------------------------
        if can_org:
            new_user = register_user(
                data['name'],
                data['surname'],
                data['email'],
                data['password'],
                data['org_id']
            )

            for lst_id in lists:
                try:
                    lst = List.objects.get(id=lst_id)
                    lst.users.add(int(new_user.get('user_id')))
                except List.DoesNotExist:
                    pass
        # -----------------------------------------
        # 5) CASO 2 — Permesso SOLO per la lista
        # -----------------------------------------
        elif can_list:
            # Deve passare esattamente UNA lista
            if len(lists) != 1:
                return Response({
                    'error': 'Permesso limitato',
                    'message': 'Puoi creare utenti solo in una singola lista alla volta'
                }, status=status.HTTP_403_FORBIDDEN)

            target_list = lists[0]

            # Controllo se l’utente ha il permesso sulla lista specifica
            has_perm_in_list = user.roles.filter(
                list_id=target_list,
                permissions__name='create_user_for_list'
            ).exists()

            if not has_perm_in_list:
                return Response({
                    'error': 'Permesso negato',
                    'message': 'Non hai il permesso per creare utenti in questa lista'
                }, status=status.HTTP_403_FORBIDDEN)

            # OK → crea utente
            new_user = register_user(
                data['name'],
                data['surname'],
                data['email'],
                data['password'],
                data['org_id']
            )

        # -----------------------------------------
        # 6) Errore creazione
        # -----------------------------------------
        if not new_user:
            return Response({
                'error': 'Registrazione fallita',
                'message': 'Email già in uso o errore nella procedura'
            }, status=status.HTTP_400_BAD_REQUEST)

        # -----------------------------------------
        # 7) Risposta OK
        # -----------------------------------------
        return Response({
            'status': 'success',
            'message': 'Utente registrato correttamente',
            'user': new_user,
            'created_by': {
                'user_id': auth_user_id,
                'email': auth_user['email'],
                'name': f"{auth_user['name']} {auth_user['surname']}"
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