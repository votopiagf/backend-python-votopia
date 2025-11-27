from django.db import connection

def register_user(name, surname, email, password, org_id):
    with connection.cursor() as cursor:
        cursor.execute("CALL register_user(%s, %s, %s, %s, %s)",
                       [name, surname, email, password, org_id])
        row = cursor.fetchone()
        if row:
            columns = [col[0] for col in cursor.description]
            user = dict(zip(columns, row))
            return user
        return None