"""
Schemi di response per la documentazione OpenAPI
Definisce la struttura delle risposte per ogni endpoint
"""
from rest_framework import serializers


# ============================================================================
# SCHEMI DI RESPONSE - AUTENTICAZIONE
# ============================================================================

class UserBasicInfoSchema(serializers.Serializer):
    """Informazioni base dell'utente"""
    id = serializers.IntegerField()
    email = serializers.EmailField()
    name = serializers.CharField()
    surname = serializers.CharField()
    org_id = serializers.IntegerField()


class LoginResponseSchema(serializers.Serializer):
    """Schema per la risposta di login"""
    access = serializers.CharField(help_text="Token JWT access (valido 60 minuti)")
    refresh = serializers.CharField(help_text="Token JWT refresh (valido 7 giorni)")
    user = UserBasicInfoSchema()


class TokenRefreshResponseSchema(serializers.Serializer):
    """Schema per la risposta di refresh token"""
    access = serializers.CharField(help_text="Nuovo token JWT access")


# ============================================================================
# SCHEMI DI RESPONSE - UTENTI
# ============================================================================

class ListMinimalSchema(serializers.Serializer):
    """Schema minimale per una lista"""
    id = serializers.IntegerField()
    name = serializers.CharField()


class RoleMinimalSchema(serializers.Serializer):
    """Schema minimale per un ruolo"""
    id = serializers.IntegerField()
    name = serializers.CharField()


class UserDetailSchema(serializers.Serializer):
    """Schema dettagliato per un utente"""
    id = serializers.IntegerField()
    name = serializers.CharField()
    surname = serializers.CharField()
    email = serializers.EmailField()
    org_id = serializers.IntegerField()
    lists = ListMinimalSchema(many=True)
    roles = RoleMinimalSchema(many=True)


class RegisterUserResponseSchema(serializers.Serializer):
    """Schema per la risposta di registrazione utente"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


class UserInfoResponseSchema(serializers.Serializer):
    """Schema per la risposta di informazioni utente"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


class UsersListResponseSchema(serializers.Serializer):
    """Schema per la risposta di lista utenti"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


# ============================================================================
# SCHEMI DI RESPONSE - RUOLI
# ============================================================================

class PermissionSchema(serializers.Serializer):
    """Schema per un permesso"""
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField(required=False, allow_null=True)


class RoleDetailSchema(serializers.Serializer):
    """Schema dettagliato per un ruolo"""
    id = serializers.IntegerField()
    name = serializers.CharField()
    color = serializers.CharField()
    level = serializers.IntegerField()
    org_id = serializers.IntegerField()
    list_id = serializers.IntegerField(required=False, allow_null=True)
    is_organization_level = serializers.BooleanField()
    permissions = PermissionSchema(many=True)
    permissions_count = serializers.IntegerField()
    created_at = serializers.DateTimeField(required=False, allow_null=True)


class CreateRoleResponseSchema(serializers.Serializer):
    """Schema per la risposta di creazione ruolo"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


class RolesListResponseSchema(serializers.Serializer):
    """Schema per la risposta di lista ruoli"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


# ============================================================================
# SCHEMI DI RESPONSE - LISTE
# ============================================================================

class ListDetailSchema(serializers.Serializer):
    """Schema dettagliato per una lista"""
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    slogan = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    color_primary = serializers.CharField(required=False, allow_null=True)
    color_secondary = serializers.CharField(required=False, allow_null=True)
    org_id = serializers.IntegerField()
    logo_file_id = serializers.IntegerField(required=False, allow_null=True)
    created_at = serializers.DateTimeField(required=False, allow_null=True)
    members_count = serializers.IntegerField()
    roles_count = serializers.IntegerField()


class CreateListResponseSchema(serializers.Serializer):
    """Schema per la risposta di creazione lista"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


class ListsListResponseSchema(serializers.Serializer):
    """Schema per la risposta di lista liste"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


# ============================================================================
# SCHEMI DI RESPONSE - PERMESSI
# ============================================================================

class MyPermissionsResponseSchema(serializers.Serializer):
    """Schema per la risposta di permessi utente"""
    status = serializers.CharField()
    message = serializers.CharField()
    data = serializers.DictField()


# ============================================================================
# SCHEMI DI RESPONSE - ERRORI
# ============================================================================

class ErrorResponseSchema(serializers.Serializer):
    """Schema generico per risposte di errore"""
    error = serializers.CharField(help_text="Tipo di errore")
    message = serializers.CharField(help_text="Messaggio descrittivo dell'errore", required=False)
    details = serializers.CharField(help_text="Dettagli tecnici dell'errore", required=False)


class ValidationErrorResponseSchema(serializers.Serializer):
    """Schema per errori di validazione"""
    error = serializers.CharField()
    required_fields = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Campi obbligatori mancanti"
    )
    message = serializers.CharField(required=False)


class PermissionDeniedResponseSchema(serializers.Serializer):
    """Schema per errori di permessi insufficienti"""
    error = serializers.CharField()
    message = serializers.CharField()
    required_permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Permessi richiesti"
    )
    your_permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Permessi attuali dell'utente"
    )


# ============================================================================
# SCHEMI DI RESPONSE - SYSTEM
# ============================================================================

class HealthCheckResponseSchema(serializers.Serializer):
    """Schema per la risposta di health check"""
    status = serializers.CharField(help_text="Stato del server")
    message = serializers.CharField(help_text="Messaggio di stato")
    version = serializers.CharField(help_text="Versione dell'API")
