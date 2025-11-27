# serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import connection


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # Chiamata alla procedura MySQL
        with connection.cursor() as cursor:
            cursor.callproc('login_user', [email, password])
            row = cursor.fetchone()
            if not row:
                raise serializers.ValidationError("Email o password non corretti.")

            # Ottengo i nomi delle colonne
            columns = [col[0] for col in cursor.description]
            user = dict(zip(columns, row))

        # Creo il token JWT manualmente con payload custom
        refresh = RefreshToken()
        refresh['user_id'] = user['id']
        refresh['name'] = user.get('name', '')
        refresh['surname'] = user.get('surname', '')
        refresh['email'] = user['email']
        refresh['org_id'] = user.get('org_id')

        # Creo l'access token dal refresh token
        access = refresh.access_token
        access['user_id'] = user['id']
        access['name'] = user.get('name', '')
        access['surname'] = user.get('surname', '')
        access['email'] = user['email']
        access['org_id'] = user.get('org_id')

        return {
            'user': user,
            'access': str(access),
            'refresh': str(refresh)
        }