from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from votopia_backend.services.serializers import LoginSerializer
from votopia_backend.services.db_procedures import register_user
from votopia_backend.services.permissions import (
    get_user_from_token,
    check_user_permission,
    get_user_permissions,
    verify_user_exists
)


@api_view(['GET'])
def health_check(request):
    """
    Endpoint di health check per verificare che il server sia attivo
    """
    return Response({
        'status': 'ok',
        'message': 'Server Django attivo e funzionante',
        'version': '1.0.0'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def register(request):
    """
    Endpoint per la creazione di un nuovo utente tramite procedura MySQL.
    Richiede JWT + permesso create_user.
    """
    try:
        # 1) Estrai utente autenticato
        auth_user = get_user_from_token(request)
        if not auth_user:
            return Response({
                'error': 'Autenticazione richiesta',
                'message': 'Inserisci il token JWT nell’header Authorization'
            }, status=status.HTTP_401_UNAUTHORIZED)

        auth_user_id = auth_user.get('user_id')

        # 2) Verifica esistenza utente
        if not verify_user_exists(auth_user_id):
            return Response({
                'error': 'Utente non valido',
                'message': 'L’utente autenticato non esiste nel database'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # 3) Controllo permessi
        if not check_user_permission(auth_user_id, 'create_user'):
            perms = get_user_permissions(auth_user_id)
            return Response({
                'error': 'Permesso negato',
                'message': 'Non hai il permesso per creare utenti',
                'required_permission': 'create_user',
                'your_permissions': [p['name'] for p in perms]
            }, status=status.HTTP_403_FORBIDDEN)

        # 4) Validazione input
        data = request.data
        required = ['name', 'surname', 'email', 'password', 'org_id']

        if not all(field in data and data[field] for field in required):
            return Response({
                'error': 'Dati incompleti',
                'required_fields': required
            }, status=status.HTTP_400_BAD_REQUEST)

        # 5) Procedura MySQL
        new_user = register_user(
            data['name'],
            data['surname'],
            data['email'],
            data['password'],
            data['org_id']
        )

        if not new_user:
            return Response({
                'error': 'Registrazione fallita',
                'message': 'Email già in uso o errore nella procedura'
            }, status=status.HTTP_400_BAD_REQUEST)

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
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def my_permissions(request):
    """
    Ritorna tutti i permessi dell’utente autenticato
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
            'user': {
                'user_id': user_id,
                'email': auth_user['email'],
                'name': auth_user['name'],
                'surname': auth_user['surname'],
                'org_id': auth_user['org_id']
            },
            'permissions': perms,
            'total_permissions': len(perms)
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'error': 'Errore interno',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    """
    Login tramite stored procedure + JWT.
    """

    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)

            if serializer.is_valid():
                return Response(serializer.validated_data,
                                status=status.HTTP_200_OK)

            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'error': 'Errore durante il login',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)