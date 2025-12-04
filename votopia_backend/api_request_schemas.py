"""
Schemi di request per la documentazione OpenAPI
Definisce la struttura dei payload di richiesta per ogni endpoint
"""
from drf_spectacular.utils import OpenApiExample, inline_serializer
from rest_framework import serializers


# ============================================================================
# SCHEMI DI REQUEST - AUTENTICAZIONE
# ============================================================================

class LoginRequestSchema(serializers.Serializer):
    """Schema per la richiesta di login"""
    email = serializers.EmailField(
        required=True,
        help_text="Indirizzo email dell'utente"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        help_text="Password dell'utente"
    )


class TokenRefreshRequestSchema(serializers.Serializer):
    """Schema per il refresh del token"""
    refresh = serializers.CharField(
        required=True,
        help_text="Token refresh JWT"
    )


# ============================================================================
# SCHEMI DI REQUEST - UTENTI
# ============================================================================

class RegisterUserRequestSchema(serializers.Serializer):
    """Schema per la registrazione di un nuovo utente"""
    name = serializers.CharField(
        required=True,
        max_length=100,
        help_text="Nome dell'utente"
    )
    surname = serializers.CharField(
        required=True,
        max_length=100,
        help_text="Cognome dell'utente"
    )
    email = serializers.EmailField(
        required=True,
        help_text="Indirizzo email (deve essere unico)"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        help_text="Password (minimo 8 caratteri)"
    )
    lists = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID delle liste a cui assegnare l'utente"
    )
    roles = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID dei ruoli da assegnare all'utente"
    )


class UpdateUserRequestSchema(serializers.Serializer):
    """Schema per l'aggiornamento di un utente"""
    user_id = serializers.IntegerField(
        required=False,
        help_text="ID dell'utente da aggiornare (se omesso, aggiorna l'utente corrente)"
    )
    name = serializers.CharField(
        required=False,
        max_length=100,
        help_text="Nuovo nome"
    )
    surname = serializers.CharField(
        required=False,
        max_length=100,
        help_text="Nuovo cognome"
    )
    email = serializers.EmailField(
        required=False,
        help_text="Nuovo indirizzo email"
    )
    add_lists = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID liste da aggiungere"
    )
    remove_lists = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID liste da rimuovere"
    )
    reset_password = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Se true, genera una nuova password e impone il cambio al prossimo login"
    )


# ============================================================================
# SCHEMI DI REQUEST - RUOLI
# ============================================================================

class CreateRoleRequestSchema(serializers.Serializer):
    """Schema per la creazione di un nuovo ruolo"""
    name = serializers.CharField(
        required=True,
        max_length=50,
        help_text="Nome del ruolo"
    )
    color = serializers.CharField(
        required=True,
        max_length=7,
        help_text="Codice colore esadecimale (es. #FF5733)"
    )
    level = serializers.IntegerField(
        required=True,
        min_value=1,
        help_text="Livello gerarchico del ruolo (più alto = più autorità)"
    )
    org_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text="ID organizzazione per ruoli a livello organizzazione (mutuamente esclusivo con list_id)"
    )
    list_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text="ID lista per ruoli specifici di lista (mutuamente esclusivo con org_id)"
    )
    permissions = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID dei permessi da assegnare al ruolo"
    )


class UpdateRoleRequestSchema(serializers.Serializer):
    """Schema per l'aggiornamento di un ruolo"""
    role_id = serializers.IntegerField(
        required=True,
        help_text="ID del ruolo da aggiornare"
    )
    name = serializers.CharField(
        required=False,
        max_length=50,
        help_text="Nuovo nome del ruolo"
    )
    color = serializers.CharField(
        required=False,
        max_length=7,
        help_text="Nuovo codice colore"
    )
    level = serializers.IntegerField(
        required=False,
        min_value=1,
        help_text="Nuovo livello gerarchico"
    )
    permissions = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Array di ID dei permessi (sovrascrive i permessi esistenti)"
    )


# ============================================================================
# SCHEMI DI REQUEST - LISTE
# ============================================================================

class CreateListRequestSchema(serializers.Serializer):
    """Schema per la creazione di una nuova lista"""
    name = serializers.CharField(
        required=True,
        max_length=100,
        help_text="Nome della lista"
    )
    org_id = serializers.IntegerField(
        required=True,
        help_text="ID dell'organizzazione a cui appartiene la lista"
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Descrizione della lista"
    )
    slogan = serializers.CharField(
        required=False,
        max_length=255,
        allow_blank=True,
        help_text="Slogan della lista"
    )
    color_primary = serializers.CharField(
        required=False,
        max_length=10,
        allow_blank=True,
        help_text="Colore primario (esadecimale)"
    )
    color_secondary = serializers.CharField(
        required=False,
        max_length=10,
        allow_blank=True,
        help_text="Colore secondario (esadecimale)"
    )


class UpdateListRequestSchema(serializers.Serializer):
    """Schema per l'aggiornamento di una lista"""
    list_id = serializers.IntegerField(
        required=True,
        help_text="ID della lista da aggiornare"
    )
    name = serializers.CharField(
        required=False,
        max_length=100,
        help_text="Nuovo nome"
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Nuova descrizione"
    )
    slogan = serializers.CharField(
        required=False,
        max_length=255,
        allow_blank=True,
        help_text="Nuovo slogan"
    )
    color_primary = serializers.CharField(
        required=False,
        max_length=10,
        allow_blank=True,
        help_text="Nuovo colore primario"
    )
    color_secondary = serializers.CharField(
        required=False,
        max_length=10,
        allow_blank=True,
        help_text="Nuovo colore secondario"
    )
