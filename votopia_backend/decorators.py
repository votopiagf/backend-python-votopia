"""
Decorator personalizzati per la gestione di autenticazione e permessi
"""
from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from votopia_backend.services.permissions import check_user_permission, get_user_permissions


def require_authentication(view_func):
    """
    Decorator che richiede autenticazione JWT per accedere alla view.

    Usage:
        @require_authentication
        @api_view(['GET'])
        def my_view(request):
            user_id = request.jwt_user['user_id']
            ...
    """

    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not hasattr(request, 'jwt_user') or request.jwt_user is None:
            return Response({
                'error': 'Autenticazione richiesta',
                'message': 'Inserisci il token JWT nell\'header Authorization: Bearer <token>'
            }, status=status.HTTP_401_UNAUTHORIZED)

        return view_func(request, *args, **kwargs)

    return wrapped_view


def require_permissions(*permission_names, require_all=False):
    """
    Decorator che richiede uno o più permessi per accedere alla view.

    Args:
        *permission_names: Nomi dei permessi richiesti
        require_all: Se True, richiede TUTTI i permessi. Se False (default), basta uno

    Usage:
        @require_permissions('create_user_for_organization', 'create_user_for_list')
        @api_view(['POST'])
        def create_user(request):
            ...

        @require_permissions('admin_access', 'super_admin', require_all=True)
        @api_view(['DELETE'])
        def delete_everything(request):
            ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Prima verifica l'autenticazione
            if not hasattr(request, 'jwt_user') or request.jwt_user is None:
                return Response({
                    'error': 'Autenticazione richiesta',
                    'message': 'Inserisci il token JWT nell\'header Authorization'
                }, status=status.HTTP_401_UNAUTHORIZED)

            user_id = request.jwt_user.get('user_id')

            # Verifica i permessi
            user_perms = get_user_permissions(user_id)
            user_perm_names = {p['name'] for p in user_perms}

            if require_all:
                # Richiede TUTTI i permessi
                missing_perms = [p for p in permission_names if p not in user_perm_names]
                if missing_perms:
                    return Response({
                        'error': 'Permessi insufficienti',
                        'message': 'Non hai tutti i permessi necessari',
                        'required_permissions': list(permission_names),
                        'missing_permissions': missing_perms,
                        'your_permissions': list(user_perm_names)
                    }, status=status.HTTP_403_FORBIDDEN)
            else:
                # Richiede ALMENO UNO dei permessi
                has_permission = any(p in user_perm_names for p in permission_names)
                if not has_permission:
                    return Response({
                        'error': 'Permesso negato',
                        'message': 'Non hai i permessi necessari per questa operazione',
                        'required_permissions': list(permission_names),
                        'your_permissions': list(user_perm_names)
                    }, status=status.HTTP_403_FORBIDDEN)

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator
