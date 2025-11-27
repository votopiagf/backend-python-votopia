"""
Sistema di controllo permessi per Votopia Backend
"""
from django.db import connection
from rest_framework.response import Response
from rest_framework import status


def check_user_permission(user_id, permission_name):
    """
    Controlla se un utente ha un determinato permesso

    Args:
        user_id (int): ID dell'utente da controllare
        permission_name (str): Nome del permesso da verificare

    Returns:
        bool: True se l'utente ha il permesso, False altrimenti
    """
    try:
        with connection.cursor() as cursor:
            query = """
                    SELECT COUNT(*) as has_permission
                    FROM users u
                             INNER JOIN user_roles ur ON u.id = ur.user_id
                             INNER JOIN roles r ON ur.role_id = r.id
                             INNER JOIN role_permissions rp ON r.id = rp.role_id
                             INNER JOIN permissions p ON rp.permission_id = p.id
                    WHERE u.id = %s
                      AND p.name = %s
                      AND u.deleted = FALSE \
                    """
            cursor.execute(query, [user_id, permission_name])
            result = cursor.fetchone()

            return result[0] > 0 if result else False

    except Exception as e:
        print(f"Errore nel controllo permessi: {str(e)}")
        return False


def get_user_permissions(user_id):
    """
    Ottiene tutti i permessi di un utente

    Args:
        user_id (int): ID dell'utente

    Returns:
        list: Lista di nomi dei permessi dell'utente
    """
    try:
        with connection.cursor() as cursor:
            query = """
                    SELECT DISTINCT p.name, p.description
                    FROM users u
                             INNER JOIN user_roles ur ON u.id = ur.user_id
                             INNER JOIN roles r ON ur.role_id = r.id
                             INNER JOIN role_permissions rp ON r.id = rp.role_id
                             INNER JOIN permissions p ON rp.permission_id = p.id
                    WHERE u.id = %s
                      AND u.deleted = FALSE \
                    """
            cursor.execute(query, [user_id])
            rows = cursor.fetchall()

            permissions = []
            for row in rows:
                permissions.append({
                    'name': row[0],
                    'description': row[1]
                })

            return permissions

    except Exception as e:
        print(f"Errore nel recupero permessi: {str(e)}")
        return []


def get_user_from_token(request):
    """
    Estrae le informazioni utente dal token JWT della request

    Args:
        request: Oggetto request Django

    Returns:
        dict: Informazioni utente dal token o None se non autenticato
    """
    try:
        # Il token JWT è già stato validato dal middleware di autenticazione
        # Le informazioni sono disponibili in request.user (se usi JWTAuthentication)
        # Oppure possiamo decodificare manualmente il token

        from rest_framework_simplejwt.authentication import JWTAuthentication

        jwt_auth = JWTAuthentication()

        # Estrai il token dall'header Authorization
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]

        # Valida e decodifica il token
        validated_token = jwt_auth.get_validated_token(token)

        # Estrai i dati dal token
        user_data = {
            'user_id': validated_token.get('user_id'),
            'email': validated_token.get('email'),
            'name': validated_token.get('name'),
            'surname': validated_token.get('surname'),
            'org_id': validated_token.get('org_id')
        }

        return user_data

    except Exception as e:
        print(f"Errore nell'estrazione user dal token: {str(e)}")
        return None


def require_permission(permission_name):
    """
    Decorator per verificare che l'utente abbia un determinato permesso

    Usage:
        @require_permission('create_user')
        def my_view(request):
            ...
    """

    def decorator(view_func):
        def wrapped_view(request, *args, **kwargs):
            # Estrai utente dal token
            user_data = get_user_from_token(request)

            if not user_data:
                return Response({
                    'error': 'Autenticazione richiesta',
                    'message': 'Devi essere autenticato per accedere a questa risorsa'
                }, status=status.HTTP_401_UNAUTHORIZED)

            user_id = user_data.get('user_id')

            # Controlla il permesso
            if not check_user_permission(user_id, permission_name):
                return Response({
                    'error': 'Permesso negato',
                    'message': f'Non hai il permesso necessario: {permission_name}',
                    'required_permission': permission_name
                }, status=status.HTTP_403_FORBIDDEN)

            # Aggiungi user_data alla request per uso nella view
            request.auth_user = user_data

            # Esegui la view
            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def verify_user_exists(user_id):
    """
    Verifica che un utente esista e non sia eliminato

    Args:
        user_id (int): ID dell'utente da verificare

    Returns:
        bool: True se l'utente esiste ed è attivo, False altrimenti
    """
    try:
        with connection.cursor() as cursor:
            query = """
                    SELECT COUNT(*)
                    FROM users
                    WHERE id = %s \
                      AND deleted = 0 \
                    """
            cursor.execute(query, [user_id])
            result = cursor.fetchone()

            return result[0] > 0 if result else False

    except Exception as e:
        print(f"Errore nella verifica utente: {str(e)}")
        return False
