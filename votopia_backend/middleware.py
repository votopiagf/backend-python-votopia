"""
Middleware personalizzati per Votopia Backend
"""
from django.utils.deprecation import MiddlewareMixin
from rest_framework.response import Response
from rest_framework import status
from votopia_backend.services.permissions import get_user_from_token


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware che estrae automaticamente le informazioni utente dal token JWT
    e le rende disponibili in request.jwt_user

    Questo middleware non blocca le richieste senza token, ma semplicemente
    aggiunge le informazioni utente se il token è presente e valido.
    """

    def process_request(self, request):
        # Percorsi che non richiedono autenticazione
        exempt_paths = [
            '/api/health/',
            '/api/token/',
            '/api/auth/login/',
            '/api/docs/',
            '/api/schema/',
            '/api/redoc/',
            '/admin/',
        ]

        # Se il path è esente, salta l'autenticazione
        if any(request.path.startswith(path) for path in exempt_paths):
            request.jwt_user = None
            return None

        # Estrai le informazioni utente dal token
        user_data = get_user_from_token(request)

        # Aggiungi i dati utente alla request
        request.jwt_user = user_data

        return None
