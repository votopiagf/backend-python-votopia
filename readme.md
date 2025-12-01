# 🚀 Documentazione Tecnica API Votopia Backend - Dettaglio Completo

Questo documento fornisce una disamina tecnica di tutti gli endpoint, inclusi i requisiti di autenticazione, i permessi di accesso, i parametri di input e le risposte di errore derivanti dalla logica implementata nel codice sorgente.

## 1. Autenticazione e Permessi Globali

L'autenticazione è gestita tramite **JWT Token**, essenziale per gli endpoint protetti.

* **Header di Autenticazione:** `Authorization: Bearer <JWT_TOKEN>`
* **Gestione Token:** Gli endpoint `/api/token/` e `/api/token/refresh/` utilizzano la gestione standard di `rest_framework_simplejwt`.

| URL Base | Metodo | Endpoint | Funzione | Auth Richiesta |
| :--- | :--- | :--- | :--- | :--- |
| `/api/auth/` | `POST` | `login/` | `LoginView` | NO |
| `/api/token/` | `POST` | (Base) | `TokenObtainPairView` | NO |
| `/api/token/` | `POST` | `refresh/` | `TokenRefreshView` | NO |
| `/api/health/` | `GET` | (Base) | `health_check` | NO |
| `/test/` | `GET` | (Base) | `test` | SÌ |

---

## 2. Gestione Utenti (CRUD)

Gli endpoint di gestione richiedono la verifica incrociata dei permessi (Organizzazione vs Lista) e, se necessario, il controllo del livello gerarchico dei ruoli.

### 2.1. Registrazione Utente

* **URL:** `POST /api/auth/register/`
* **Auth:** SÌ
* **Ruoli Richiesti (OR):** `create_user_for_organization` O `create_user_for_list`.

| Campo Input | Requisito | Tipo | Dettaglio Logica |
| :--- | :--- | :--- | :--- |
| `name`, `surname`, `email`, `password` | Obbligatori | String | Dati anagrafici essenziali. |
| `lists` | Opzionale | Array Int | ID delle liste target. **Se si usa `create_user_for_list`, deve contenere esattamente 1 ID.** |
| `roles` | Opzionale | Array Int | ID dei ruoli da assegnare. |

**Logica di Controllo Permessi Aggiuntiva:**
1.  **Assegnazione Liste:** Se l'utente ha solo `create_user_for_list`, viene bloccato (`403 Forbidden`) se tenta di inserire l'utente in più di una lista, o se non ha il permesso sulla lista specificata.
2.  **Assegnazione Ruoli:** Il richiedente può assegnare ruoli solo se il livello massimo (`level`) dei suoi ruoli è **maggiore o uguale** al livello del ruolo che sta assegnando.

| Codice HTTP | Errore | Dettaglio Causa (dal Codice) |
| :--- | :--- | :--- |
| **400 Bad Request** | Dati incompleti | Campi obbligatori (`name`, `surname`, `email`, `password`) mancanti. |
| **401 Unauthorized** | Autenticazione mancante | Token JWT assente. |
| **403 Forbidden** | Permesso negato | Manca `create_user_for_organization` e `create_user_for_list`, oppure (nel caso `create_user_for_list`) si tenta di agire su troppe liste o su liste non autorizzate. |
| **409 Conflict** | Errore Conflitto | Tentativo di registrare un'email già esistente (errore DB 1062). |
| **500 Internal Error** | Errore generico | Eccezioni non gestite. |

### 2.2. Visualizza Informazioni Utente

* **URL:** `GET /api/users/info/`
* **Auth:** SÌ
* **Parametri Query:** `user_id` (opzionale).

| Permesso | Condizione di Visualizzazione |
| :--- | :--- |
| **`view_all_user_organization`** | L'utente chiamante può vedere qualsiasi utente della stessa organizzazione. |
| **`view_all_user_list`** | L'utente chiamante può vedere l'utente target **solo se** condividono una lista su cui il chiamante ha il permesso. |
| **Nessun Permesso** | Può vedere **solo se stesso** (`user_id` omesso o uguale al proprio ID). |

**Restrizioni:** L'utente target **deve** appartenere alla stessa organizzazione dell'utente autenticato.

| Codice HTTP | Dettaglio Causa |
| :--- | :--- |
| **403 Forbidden** | Utente target non nella stessa organizzazione O target non in nessuna lista autorizzata. |
| **404 Not Found** | Utente target non esistente. |

### 2.3. Visualizza Tutti gli Utenti

* **URL:** `GET /api/users/all/`
* **Auth:** SÌ
* **Parametri Query:** `list_id` (opzionale).

| Parametro `list_id` | Permesso Richiesto | Utenti Restituiti |
| :--- | :--- | :--- |
| **`None`** | **`view_all_user_organization`** | Tutti gli utenti dell'Organizzazione del richiedente. |
| **`Int`** (specificato) | **`view_all_user_list`** sulla lista target | Tutti gli utenti appartenenti alla lista specificata. |

| Codice HTTP | Dettaglio Causa |
| :--- | :--- |
| **403 Forbidden** | Manca il permesso Org (se `list_id` è `None`) O Manca il permesso Lista (se `list_id` specificato) O `list_id` non è autorizzato per l'utente. |

### 2.4. Aggiorna Utente

* **URL:** `PUT /api/users/update/`
* **Auth:** SÌ

**Logica di Autorizzazione alla Modifica:**
Il richiedente deve soddisfare **una sola** delle seguenti condizioni per poter modificare l'utente target:
1.  `can_modify_org`: Possiede il permesso **`update_user_organization`**.
2.  `can_modify_list`: Possiede il permesso **`update_user_list`** E l'utente target è membro di almeno una lista autorizzata.
3.  `Self Update`: L'utente target è se stesso.

**Logica di Gestione Liste (`add_lists`, `remove_lists`):**
* L'utente può gestire le liste dell'utente target solo se ha `can_modify_org` o `can_modify_list`.
* Se `can_modify_list`, le modifiche sono limitate solo alle liste su cui il chiamante ha effettivamente il permesso `update_user_list`.

**Logica di Reset Password:**
* Se `reset_password: true`, viene generata una stringa casuale (`random.choices`), ne viene calcolato l'hash **SHA-256** per il salvataggio (`user_target.password = sha256_password`) e viene impostato il flag `user_target.must_change_password = True`.

### 2.5. Elimina Utente (Soft Delete)

* **URL:** `DELETE /api/users/delete/`
* **Auth:** SÌ
* **Parametri Query:** `user_id` (obbligatorio).
* **Permessi Richiesti:** **`delete_user_organization`**

**Logica di Esecuzione:**
1.  Verifica la presenza di `user_id`. (400)
2.  Verifica l'appartenenza all'organizzazione. (403)
3.  Imposta il campo `deleted = True` sull'oggetto `User` (Soft Delete).

| Codice HTTP | Dettaglio Causa |
| :--- | :--- |
| **400 Bad Request** | `user_id` mancante nei parametri query. |
| **403 Forbidden** | Permesso `delete_user_organization` mancante O tentativo di eliminare un utente di un'altra organizzazione. |
| **404 Not Found** | Utente target da eliminare non trovato. |

---

## 3. Endpoint Personali e Utility

### 3.1. I Miei Permessi

* **URL:** `GET /api/my-permissions/`
* **Auth:** SÌ
* **Scopo:** Restituire tutti i permessi aggregati (`get_user_permissions(user_id)`).

### 3.2. Health Check

* **URL:** `GET /api/health/`
* **Auth:** NO
* **Scopo:** Verifica di base del funzionamento del server.

### 3.3. Test

* **URL:** `GET /test/`
* **Auth:** SÌ
* **Scopo:** Endpoint di debug. Ritorna il risultato della query per `get_lists_user_has_permission(user, 'view_all_user_list')`.