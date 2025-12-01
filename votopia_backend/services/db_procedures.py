from django.db import connection

def register_user(name, surname, email, password, org_id):
    with connection.cursor() as cursor:
        cursor.execute(
            "CALL register_user(%s, %s, %s, %s, %s)",
            [name, surname, email, password, org_id]
        )

        row = cursor.fetchone()
        if not row:
            return None

        # Mappo le colonne
        columns = [col[0] for col in cursor.description]
        user = dict(zip(columns, row))

        # --- Se la procedura non ritorna l'id, lo recupero manualmente ---
        if "user_id" not in user or not user["user_id"]:
            with connection.cursor() as c2:
                c2.execute("SELECT id FROM users WHERE email=%s", [email])
                u = c2.fetchone()
                if u:
                    user["user_id"] = u[0]

        return user