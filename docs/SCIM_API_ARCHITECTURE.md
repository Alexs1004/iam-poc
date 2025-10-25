# 🎯 Guide Complet : API SCIM + Architecture IAM PoC

> **Objectif** : Comprendre l'API SCIM et l'architecture du projet en mode "apprentissage léger"

**Sujets couverts** :
1. ✅ Comment fonctionne l'API SCIM (RFC 7644, flux de données, sécurité)
2. ✅ Architecture fichiers/dossiers (pourquoi chaque chose est où elle est)

---

# 📘 PARTIE 1 : Comment Fonctionne l'API SCIM

## 🎯 C'est Quoi SCIM en 30 Secondes ?

**SCIM = System for Cross-domain Identity Management**

**Problème résolu** : Tu as 10 applications (Slack, GitHub, Office 365...). Quand tu embauches Alice, tu dois :
- Créer 10 comptes manuellement 😫
- Synchroniser les changements (Alice change d'équipe → 10 mises à jour)
- Désactiver 10 comptes quand Alice part

**Solution SCIM** : **Une seule API standardisée** pour provisionner des utilisateurs partout.

```
Alice rejoint → SCIM POST /Users → Tous les systèmes créent le compte
Alice part   → SCIM PATCH active=false → Tous les systèmes désactivent
```

---

## 🏗️ Architecture SCIM dans Ce Projet

### Vue d'Ensemble

```
┌────────────────────────────────────────────────────────────┐
│  CLIENT SCIM (RH, Azure AD, Okta...)                       │
│  Envoie requêtes SCIM standardisées                        │
└────────────────────────────────────────────────────────────┘
                      ↓ HTTPS (TLS 1.3)
┌────────────────────────────────────────────────────────────┐
│  NGINX (Reverse Proxy)                                     │
│  - Termine SSL/TLS                                         │
│  - Forwards à Flask: X-Forwarded-For, X-Forwarded-Proto   │
└────────────────────────────────────────────────────────────┘
                      ↓ HTTP interne
┌────────────────────────────────────────────────────────────┐
│  FLASK API (/scim/v2/*)                                    │
│  app/api/scim.py (Routes HTTP, validation OAuth)          │
└────────────────────────────────────────────────────────────┘
                      ↓ Délègue à
┌────────────────────────────────────────────────────────────┐
│  BUSINESS LOGIC                                            │
│  app/core/provisioning_service.py                          │
│  - Validation inputs (email, username format)              │
│  - Transformation SCIM ↔ Keycloak                          │
│  - Audit logging (HMAC-SHA256)                             │
└────────────────────────────────────────────────────────────┘
                      ↓ Appelle
┌────────────────────────────────────────────────────────────┐
│  KEYCLOAK CLIENT                                           │
│  scripts/jml.py                                            │
│  - HTTP calls: POST /admin/realms/demo/users              │
│  - Token management (service account OAuth)                │
└────────────────────────────────────────────────────────────┘
                      ↓ HTTP Admin API
                 [KEYCLOAK]
          (Identity Provider Backend)
```

---

## 🔐 Sécurité SCIM : 3 Couches de Protection

### Couche 1 : OAuth 2.0 Bearer Token (RFC 6750)

**Fichier** : `app/api/scim.py` ligne 88-149

```python
@bp.before_request
def validate_request():
    """Valide Bearer token sur TOUTES les requêtes SCIM."""
    
    # Guard: Bypass seulement pour tests unitaires
    if os.getenv('SKIP_OAUTH_FOR_TESTS') == 'true':
        return None
    
    # 1. Récupère header Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return scim_error(401, "Authorization header missing", "unauthorized")
    
    # 2. Vérifie format Bearer
    if not auth_header.startswith('Bearer '):
        return scim_error(401, "Must use Bearer scheme", "unauthorized")
    
    token = auth_header[7:]  # Enlève "Bearer "
    
    # 3. Valide JWT (signature, expiration, issuer)
    try:
        claims = validate_jwt_token(token)  # app/api/decorators.py
    except TokenValidationError as e:
        return scim_error(401, f"JWT validation failed: {e}", "unauthorized")
    
    # 4. Vérifie scope (scim:read ou scim:write)
    scopes = claims.get('scope', '').split()
    if not any(s in scopes for s in ['scim:read', 'scim:write']):
        return scim_error(403, "Insufficient scope", "forbidden")
    
    # 5. Stocke claims pour les routes
    g.oauth_claims = claims  # Accessible dans toutes les routes SCIM
```

**Pourquoi c'est important** :
- ✅ **Empêche accès non-autorisé** : Pas de token = pas d'accès
- ✅ **Valide provenance** : JWT signé par Keycloak (vérification signature RSA)
- ✅ **Granularité** : `scim:read` vs `scim:write` (principe du moindre privilège)

**Erreur fréquente à éviter** :
```python
# ❌ DANGEREUX : Accepter token sans validation
if auth_header:
    # Utilise token sans vérifier signature/expiration
    # → Attaquant forge un faux token
```

---

### Couche 2 : Validation Inputs (OWASP A03:2021 Injection)

**Fichier** : `app/core/provisioning_service.py` ligne 50-150

```python
def create_user_scim_like(user_data: dict) -> dict:
    """Crée utilisateur avec validation stricte."""
    
    # 1. Validation schema SCIM (RFC 7643)
    if 'userName' not in user_data:
        raise ScimError(400, "userName is required", "invalidValue")
    
    username = user_data['userName']
    
    # 2. Validation format (empêche injection)
    if not re.match(r'^[a-zA-Z0-9._-]{3,50}$', username):
        raise ScimError(400, 
            "userName must be 3-50 alphanumeric characters",
            "invalidValue")
    
    # 3. Validation email
    emails = user_data.get('emails', [])
    if emails:
        email = emails[0].get('value')
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            raise ScimError(400, "Invalid email format", "invalidValue")
    
    # 4. Détection utilisateur existant
    existing = jml.get_user_by_username(username)
    if existing:
        raise ScimError(409, f"User {username} already exists", "uniqueness")
    
    # 5. Appel Keycloak (inputs validés)
    keycloak_payload = scim_to_keycloak(user_data)
    user_id = jml.create_user(keycloak_payload)
    
    # 6. Audit logging (HMAC-SHA256)
    audit.log_jml_event(
        event_type="scim_create_user",
        username=username,
        operator=g.oauth_claims.get('sub', 'system'),
        success=True,
        details={"user_id": user_id}
    )
    
    return keycloak_to_scim(jml.get_user_by_id(user_id))
```

**Pourquoi c'est important** :
- ✅ **Empêche injection LDAP/SQL** : Regex strictes sur username/email
- ✅ **Empêche DoS** : Limite taille username (50 chars max)
- ✅ **Atomicité** : Rollback si échec Keycloak (via exceptions)
- ✅ **Traçabilité** : Audit log signé (non-répudiation)

**Erreur fréquente à éviter** :
```python
# ❌ DANGEREUX : Passer input directement à Keycloak
username = user_data['userName']  # Non validé
jml.create_user({"username": username})  # → Injection possible
```

---

### Couche 3 : Rate Limiting & IP Whitelisting (Defense in Depth)

**Fichier** : `app/flask_app.py` ligne 130-145

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],  # Toutes routes
    storage_uri="memory://"  # Redis en production
)

# SCIM API rate-limited
@limiter.limit("20 per minute")
@bp.route('/Users', methods=['POST'])
def create_user():
    ...
```

**Pourquoi c'est important** :
- ✅ **Empêche brute-force** : Max 20 créations user/minute
- ✅ **Empêche credential stuffing** : Limite tentatives login
- ✅ **Empêche DoS** : Protège Keycloak backend

**Bonne pratique** : En production, ajouter IP whitelisting :
```python
ALLOWED_SCIM_CLIENTS = os.getenv('SCIM_ALLOWED_IPS', '').split(',')

@bp.before_request
def check_ip():
    if request.remote_addr not in ALLOWED_SCIM_CLIENTS:
        return scim_error(403, "IP not whitelisted", "forbidden")
```

---

## 📡 Flux de Données Complet : Créer un Utilisateur

### Exemple Concret : Azure AD Provisionne Alice

#### 1. **Azure AD envoie requête SCIM**

```http
POST https://localhost/scim/v2/Users HTTP/1.1
Host: localhost
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice",
  "emails": [{"value": "alice@example.com", "primary": true}],
  "active": true,
  "roles": [{"value": "analyst", "display": "Analyst"}]
}
```

---

#### 2. **Nginx → Flask (Reverse Proxy)**

```
Nginx reçoit requête HTTPS
├─ Vérifie certificat client (optionnel)
├─ Termine TLS
├─ Ajoute headers proxy:
│  X-Forwarded-For: 203.0.113.42
│  X-Forwarded-Proto: https
│  X-Forwarded-Host: localhost
└─ Forward à Flask http://flask-app:8000/scim/v2/Users
```

---

#### 3. **Flask SCIM Route (app/api/scim.py)**

```python
@bp.before_request
def validate_request():
    """Exécuté AVANT toute route SCIM."""
    # Valide OAuth token (voir Couche 1 ci-dessus)
    claims = validate_jwt_token(token)
    g.oauth_claims = claims  # Stocke pour audit

@bp.route('/Users', methods=['POST'])
def create_user():
    """Route SCIM POST /Users."""
    # 1. Validation Content-Type
    if request.content_type != 'application/scim+json':
        return scim_error(400, "Must use application/scim+json", "invalidSyntax")
    
    # 2. Parse JSON
    user_data = request.get_json()
    
    # 3. Délègue à business logic
    try:
        user = provisioning_service.create_user_scim_like(user_data)
        return jsonify(user), 201, {'Location': f'/scim/v2/Users/{user["id"]}'}
    except ScimError as e:
        return scim_error(e.status, e.detail, e.scim_type)
```

**Séparation responsabilités** :
- ✅ Route = Validation HTTP (headers, Content-Type)
- ✅ Business logic = Validation métier (email format, unicité)

---

#### 4. **Provisioning Service (app/core/provisioning_service.py)**

```python
def create_user_scim_like(user_data: dict) -> dict:
    """Orchestration JML avec validation."""
    
    # 1. Validation inputs (voir Couche 2)
    validate_scim_user(user_data)
    
    # 2. Transformation SCIM → Keycloak format
    keycloak_payload = scim_to_keycloak(user_data)
    # {
    #   "username": "alice",
    #   "email": "alice@example.com",
    #   "enabled": true,
    #   "emailVerified": false,
    #   "attributes": {"scim_active": ["true"]}
    # }
    
    # 3. Appel Keycloak via client
    user_id = jml.create_user(keycloak_payload)
    
    # 4. Assignation rôles
    for role in user_data.get('roles', []):
        jml.assign_role(user_id, role['value'])
    
    # 5. Audit log (HMAC-SHA256)
    audit.log_jml_event(
        event_type="scim_create_user",
        username=user_data['userName'],
        operator=g.oauth_claims['sub'],
        success=True,
        details={"user_id": user_id, "roles": [r['value'] for r in user_data.get('roles', [])]}
    )
    
    # 6. Récupère user créé + transformation Keycloak → SCIM
    keycloak_user = jml.get_user_by_id(user_id)
    return keycloak_to_scim(keycloak_user)
```

**Pourquoi cette architecture** :
- ✅ **Testable** : `provisioning_service` mockable sans HTTP
- ✅ **Réutilisable** : Admin UI `/admin/users/create` utilise la même fonction
- ✅ **Audit centralisé** : Un seul endroit pour logger

---

#### 5. **Keycloak Client (scripts/jml.py)**

```python
def create_user(user_data: dict) -> str:
    """Crée user dans Keycloak Admin API."""
    
    # 1. Récupère token service account
    token = get_service_account_token()
    
    # 2. HTTP POST à Keycloak
    response = requests.post(
        f"{KEYCLOAK_URL}/admin/realms/demo/users",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json=user_data,
        timeout=10
    )
    
    # 3. Gestion erreurs
    if response.status_code == 409:
        raise ScimError(409, "User already exists", "uniqueness")
    elif response.status_code >= 400:
        raise ScimError(500, f"Keycloak error: {response.text}", "internal")
    
    # 4. Extract user ID from Location header
    location = response.headers.get('Location')
    user_id = location.split('/')[-1]
    
    return user_id  # UUID Keycloak
```

**Pourquoi client séparé** :
- ✅ **Standalone** : Utilisable en CLI (`python scripts/jml.py create-user`)
- ✅ **Pas de Flask** : Fonctionne sans contexte web
- ✅ **Réutilisable** : D'autres projets peuvent importer `jml.py`

---

#### 6. **Keycloak Traite la Requête**

```
Keycloak Admin API (/admin/realms/demo/users)
├─ Valide token service account (automation-cli)
├─ Vérifie permissions (manage-users)
├─ Crée user en base PostgreSQL
├─ Hash password (bcrypt)
├─ Génère user ID (UUID)
└─ Retourne 201 Created + Location header
```

---

#### 7. **Réponse SCIM à Azure AD**

```http
HTTP/1.1 201 Created
Location: https://localhost/scim/v2/Users/8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d",
  "userName": "alice",
  "emails": [{"value": "alice@example.com", "primary": true}],
  "active": true,
  "roles": [{"value": "analyst", "display": "Analyst"}],
  "meta": {
    "resourceType": "User",
    "created": "2024-10-25T14:30:00Z",
    "lastModified": "2024-10-25T14:30:00Z",
    "location": "https://localhost/scim/v2/Users/8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d"
  }
}
```

---

#### 8. **Audit Log Écrit (Append-Only)**

```json
// .runtime/audit/jml-events.jsonl
{
  "timestamp": "2024-10-25T14:30:01.234Z",
  "event_type": "scim_create_user",
  "username": "alice",
  "operator": "azure-ad-sync",
  "realm": "demo",
  "success": true,
  "details": {
    "user_id": "8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d",
    "roles": ["analyst"]
  },
  "hmac": "d4f3c2b1a0e9f8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4b3"
}
```

**Sécurité audit** :
- ✅ **HMAC-SHA256** : Signature cryptographique (non-répudiation)
- ✅ **Append-only** : Impossible de modifier logs passés
- ✅ **Timestamped** : ISO 8601 UTC (compliance)

**Vérification intégrité** :
```bash
make audit-verify  # Valide toutes les signatures HMAC
```

---

## 🔑 Points Clés SCIM (Ce Qu'un Recruteur Sécurité Veut Entendre)

### 1. **RFC 7644 Compliance**

> *"J'ai implémenté l'API SCIM 2.0 conforme RFC 7644, avec support des opérations CRUD (Create/Read/Update/Delete) sur les utilisateurs. La structure JSON respecte les schémas SCIM core (userName, emails, active) avec gestion des erreurs standardisée (scimType: uniqueness, invalidValue, etc.)."*

**Fichiers démo** :
- `app/api/scim.py` : Routes SCIM
- `tests/test_scim_api.py` : Tests compliance

---

### 2. **OAuth 2.0 Bearer Token (RFC 6750)**

> *"L'API est protégée par OAuth 2.0 Bearer tokens avec validation JWT complète : vérification signature RSA256, expiration, issuer, et scopes (scim:read/scim:write). Utilise les JWKS de Keycloak pour rotation automatique des clés."*

**Bonne pratique** : Validation avant chaque requête via `@bp.before_request`.

---

### 3. **Defense in Depth (OWASP)**

> *"J'applique une stratégie de défense en profondeur : OAuth en couche 1, validation inputs stricte en couche 2 (regex email/username, détection doublons), et rate-limiting en couche 3. Audit logs HMAC-SHA256 signés pour non-répudiation."*

**Référence** : OWASP ASVS Level 2 (Application Security Verification Standard)

---

### 4. **Separation of Concerns (Clean Architecture)**

> *"L'architecture suit Clean Architecture : routes HTTP (app/api/scim.py) délèguent à la logique métier (app/core/provisioning_service.py), qui elle-même utilise un client Keycloak standalone (scripts/jml.py). Ça permet de tester chaque couche isolément et de réutiliser la logique provisioning dans l'admin UI."*

**Bénéfice** : Testabilité (128 tests automatisés), maintenabilité, extensibilité.

---

# 🗂️ PARTIE 2 : Architecture Fichiers/Dossiers Expliquée

## 🎯 Vision Globale : Couches d'Abstraction

```
📦 iam-poc/
│
├── 🌐 app/                      # APPLICATION LAYER (Flask-aware)
│   ├── __init__.py              # Package marker
│   ├── flask_app.py             # ⚙️ Application factory (point d'entrée)
│   │
│   ├── api/                     # HTTP INTERFACE LAYER (thin routes)
│   │   ├── scim.py              # SCIM 2.0 routes (/scim/v2/*)
│   │   ├── admin.py             # Admin UI routes (/admin/*)
│   │   ├── auth.py              # OIDC callback (/auth/*)
│   │   ├── health.py            # Health check (/health)
│   │   ├── decorators.py        # OAuth validation, RBAC decorators
│   │   └── helpers/             # HTTP-specific utilities
│   │       └── admin_ui.py      # DOGFOOD_SCIM mode (admin UI calls SCIM API)
│   │
│   ├── core/                    # BUSINESS LOGIC LAYER (thick, reusable)
│   │   ├── provisioning_service.py  # 🧠 JML orchestration (central hub)
│   │   ├── rbac.py              # Role-based access control
│   │   ├── validators.py        # Input validation rules
│   │   └── keycloak/            # Keycloak-specific logic
│   │       ├── users.py         # User operations
│   │       ├── roles.py         # Role operations
│   │       └── sessions.py      # Session management
│   │
│   ├── config/                  # CONFIGURATION LAYER
│   │   └── settings.py          # 🔑 Centralized config (Azure KV, env vars)
│   │
│   ├── static/                  # Frontend assets
│   │   ├── css/
│   │   └── js/
│   │
│   └── templates/               # Jinja2 HTML templates
│       ├── admin/
│       ├── auth/
│       └── base.html
│
├── 🔧 scripts/                  # INFRASTRUCTURE LAYER (standalone)
│   ├── jml.py                   # 🛠️ Keycloak Admin API client (CLI)
│   ├── audit.py                 # HMAC-SHA256 audit logger
│   ├── demo_jml.sh              # JML workflow demo
│   ├── run_https.sh             # Stack startup (nginx, Keycloak, Flask)
│   ├── rotate_secret.sh         # Secret rotation (production)
│   ├── load_secrets_from_keyvault.sh  # Azure Key Vault loader
│   ├── validate_env.sh          # Config validation
│   ├── keycloak_entrypoint.sh   # Docker entrypoint (Keycloak)
│   └── README.md                # Scripts documentation
│
├── 🧪 tests/                    # TEST LAYER
│   ├── test_scim_api.py         # SCIM API unit tests (mocked Keycloak)
│   ├── test_scim_oauth_validation.py  # OAuth security tests
│   ├── test_provisioning_service.py   # Business logic tests
│   ├── test_jml.py              # Keycloak client tests
│   └── test_e2e_comprehensive.py      # End-to-end integration tests
│
├── 📚 docs/                     # DOCUMENTATION
│   ├── REFACTORING_GUIDE.md    # Architecture decisions
│   ├── ADMIN_DASHBOARD_FEATURES.md
│   └── API_SPECIFICATION.md
│
├── 🐳 Infrastructure Files
│   ├── docker-compose.yml       # Service orchestration
│   ├── Dockerfile               # Flask container
│   ├── nginx.conf               # Reverse proxy config
│   ├── Makefile                 # Developer workflows (30+ targets)
│   └── .env.demo                # Demo mode defaults
│
└── 🔒 Runtime (gitignored)
    ├── .runtime/audit/          # Audit logs (HMAC signed)
    ├── .runtime/secrets/        # Docker secrets (/run/secrets pattern)
    └── .runtime/certs/          # Self-signed TLS certificates
```

---

## 🧩 Règles d'Organisation (Principes Architecturaux)

### Règle 1 : **Dependency Direction** (Clean Architecture)

```
┌─────────────────────────────────────────────────────────┐
│  Outer Layers (Infrastructure)                          │
│  app/api/ (HTTP) ────────┐                              │
│  scripts/ (CLI)          │                              │
└──────────────────────────┼──────────────────────────────┘
                           │ depends on
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Inner Layer (Business Logic)                           │
│  app/core/ (provisioning_service, RBAC, validators)    │
└─────────────────────────────────────────────────────────┘
                           │ depends on
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Core Layer (Domain Models, Pure Python)                │
│  scripts/jml.py (Keycloak client), audit.py            │
└─────────────────────────────────────────────────────────┘
```

**Principe** : **Les dépendances pointent VERS LE CENTRE** (business logic), jamais l'inverse.

**Conséquence** :
- ✅ `app/api/scim.py` importe `app/core/provisioning_service` (OK)
- ✅ `app/core/provisioning_service.py` importe `scripts/jml` (OK)
- ❌ `scripts/jml.py` n'importe JAMAIS `from app.core` (interdit)

**Pourquoi** :
- Business logic réutilisable (CLI, Celery tasks, autre projet)
- Testable sans démarrer Flask
- Changement UI n'impacte pas business logic

---

### Règle 2 : **Flask-Aware vs Flask-Free**

| Dossier | Flask-Aware ? | Peut Importer Flask ? | Use Case |
|---------|---------------|----------------------|----------|
| `app/api` | ✅ OUI | ✅ `from flask import request, session` | Routes HTTP, blueprints |
| `app/core` | ⚠️ PARTIEL | ⚠️ `from flask import current_app` (logging only) | Business logic, orchestration |
| `scripts` | ❌ NON | ❌ **JAMAIS** | CLI standalone, cron jobs, CI/CD |

**Test simple** : "Est-ce que ce code fonctionne si je fais `python fichier.py` ?"
- `app/api/scim.py` → ❌ Crash (nécessite Flask context)
- `app/core/provisioning_service.py` → ⚠️ Crash SI utilise `current_app.logger`
- `scripts/jml.py` → ✅ Fonctionne (standalone)

---

### Règle 3 : **Single Responsibility Per Module**

```python
# ✅ BON : app/api/scim.py (HTTP interface only)
@bp.route('/Users', methods=['POST'])
def create_user():
    user_data = request.get_json()  # HTTP parsing
    user = provisioning_service.create_user_scim_like(user_data)  # Délègue
    return jsonify(user), 201

# ✅ BON : app/core/provisioning_service.py (business logic only)
def create_user_scim_like(user_data):
    validate_scim_user(user_data)  # Validation métier
    user_id = jml.create_user(user_data)  # Appel infra
    audit.log_jml_event(...)  # Audit
    return keycloak_to_scim(jml.get_user_by_id(user_id))

# ❌ MAUVAIS : Tout dans une route
@bp.route('/Users', methods=['POST'])
def create_user():
    user_data = request.get_json()
    # Validation inline (non réutilisable)
    if not user_data.get('userName'):
        return jsonify({"error": "Missing userName"}), 400
    # Appel Keycloak inline (non testable)
    response = requests.post(f"{KEYCLOAK_URL}/users", json=user_data)
    # Pas d'audit logging
    return jsonify(response.json()), 201
```

**Bénéfices séparation** :
- ✅ Route = 5 lignes (lisible)
- ✅ Business logic = testable sans HTTP
- ✅ Audit centralisé (un seul endroit)

---

### Règle 4 : **Configuration Centralized**

**Fichier** : `app/config/settings.py`

```python
class Config:
    """Centralized configuration loader."""
    
    # 1. Secret resolution (priority order)
    @staticmethod
    def get_secret(name: str, default: str = None) -> str:
        """Load secret: /run/secrets → env var → demo fallback."""
        # Docker secrets (/run/secrets/*)
        secret_file = f"/run/secrets/{name}"
        if os.path.exists(secret_file):
            return Path(secret_file).read_text().strip()
        
        # Environment variable
        env_value = os.getenv(name)
        if env_value:
            return env_value
        
        # Demo mode fallback
        if os.getenv('DEMO_MODE') == 'true':
            return DEMO_DEFAULTS.get(name, default)
        
        raise ValueError(f"Secret {name} not found")
    
    # 2. Config attributes
    FLASK_SECRET_KEY = get_secret('FLASK_SECRET_KEY')
    KEYCLOAK_CLIENT_SECRET = get_secret('KEYCLOAK_CLIENT_SECRET')
    AUDIT_LOG_SIGNING_KEY = get_secret('AUDIT_LOG_SIGNING_KEY')
```

**Pourquoi centralisé** :
- ✅ **Single Source of Truth** : Un seul endroit pour secrets
- ✅ **Production-ready** : Support Docker secrets + Azure Key Vault
- ✅ **Demo-friendly** : Auto-génère secrets si `DEMO_MODE=true`
- ✅ **Testable** : Mocking facile (`monkeypatch.setenv`)

---

### Règle 5 : **Tests Mirror Production Structure**

```
app/api/scim.py          →  tests/test_scim_api.py
app/core/provisioning_service.py  →  tests/test_provisioning_service.py
scripts/jml.py           →  tests/test_jml.py
```

**Structure identique** = Navigation facile.

---

## 🎯 Pourquoi `jml.py` est dans `scripts/` et pas `app/` ?

### Réponse Débutant-Friendly

**Raison simple** :
> **`app/` = Code qui a besoin de Flask pour vivre.**  
> **`scripts/` = Code qui vit tout seul (CLI, automation).**

**Conséquence pratique** :
```bash
# ✅ Fonctionne (jml.py dans scripts/)
python scripts/jml.py create-user alice

# ❌ Casserait si jml.py dans app/
python -m app.core.jml create-user alice
# RuntimeError: Flask not started
```

**Analogie** :
- `app/` = Restaurant avec serveur Flask (besoin clients HTTP)
- `scripts/` = Couteau qui coupe même si restaurant fermé

**Sécurité** :
- Si Flask piraté → Attaquant n'accède pas facilement aux outils `scripts/`
- Isolation processus Docker (Flask container ≠ scripts volume)

---

## 🔐 Sécurité : Pourquoi Cette Architecture Protège

### 1. **Isolation Processus (Docker)**

```
┌──────────────────────────────────────────────────────────┐
│  Flask Container (PID namespace isolé)                   │
│  - app/ (application code)                               │
│  - Volumes read-only: /app/scripts                       │
│  - Secrets: /run/secrets (tmpfs, jamais disque)         │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  Keycloak Container (PID namespace isolé)                │
│  - PostgreSQL backend                                    │
│  - Pas d'accès direct aux secrets Flask                 │
└──────────────────────────────────────────────────────────┘
```

**Si Flask compromis** :
- ❌ Attaquant ne peut PAS modifier `scripts/jml.py` (volume read-only)
- ❌ Attaquant ne peut PAS accéder PostgreSQL Keycloak (network isolation)
- ❌ Secrets dans tmpfs → Effacés au redémarrage container

---

### 2. **Least Privilege (RBAC)**

```python
# app/api/admin.py
@bp.route('/admin/users/create', methods=['POST'])
@require_jml_operator  # Décorateur RBAC
def create_user():
    # Seuls iam-operator et realm-admin peuvent créer users
    ...
```

**Principe** : Opérations sensibles nécessitent rôles spécifiques.

---

### 3. **Audit Trail (Non-Répudiation)**

```python
# Chaque opération JML loggée
audit.log_jml_event(
    event_type="scim_create_user",
    username="alice",
    operator="admin@example.com",  # Depuis JWT claims
    success=True,
    details={"user_id": "uuid", "roles": ["analyst"]},
    hmac="..."  # Signature HMAC-SHA256
)
```

**Bénéfice** :
- ✅ Qui a fait quoi quand (compliance RGPD, SOC 2)
- ✅ Détection tampering (signature HMAC)
- ✅ Forensics si incident

---

## 📚 Récapitulatif Architecture : Les 5 Principes

| Principe | Explication | Bénéfice |
|----------|-------------|----------|
| **1. Dependency Inversion** | Outer layers dépendent de inner layers | Testabilité, réutilisabilité |
| **2. Flask-Aware Separation** | `app/` utilise Flask, `scripts/` standalone | CLI, cron jobs, CI/CD |
| **3. Single Responsibility** | 1 module = 1 responsabilité | Lisibilité, maintenabilité |
| **4. Centralized Config** | `app/config/settings.py` = source of truth | Sécurité secrets, demo mode |
| **5. Tests Mirror Structure** | `app/X.py` → `tests/test_X.py` | Navigation facile |

---

## 🎯 TL;DR : Ce Qu'un Recruteur Veut Entendre

### Sur l'API SCIM

> *"J'ai implémenté une API SCIM 2.0 complète (RFC 7644) avec validation OAuth 2.0 Bearer tokens. L'architecture suit Clean Architecture : routes HTTP délèguent à la logique métier (provisioning_service), qui utilise un client Keycloak standalone. J'applique defense in depth : OAuth + validation inputs + rate limiting. Tous les événements sont audités avec signatures HMAC-SHA256 pour non-répudiation."*

### Sur l'Architecture

> *"Le projet suit Clean Architecture avec séparation stricte des responsabilités : `app/api/` (routes HTTP Flask), `app/core/` (business logic réutilisable), et `scripts/` (infrastructure standalone sans dépendance Flask). Les secrets sont centralisés dans `app/config/settings.py` avec support Docker secrets et Azure Key Vault. J'ai 128 tests automatisés qui couvrent unit, integration et OAuth security."*

---

**Fichiers complémentaires** :
- [OAuth Flow Complet](OAUTH_FLOW_DEEP_DIVE.md)
- [Audit Logging HMAC](AUDIT_LOGGING_HMAC.md)
- [Docker Secrets Pattern](DOCKER_SECRETS_PATTERN.md)

---

**Dernière mise à jour** : Octobre 2025  
**Auteur** : Alex (IAM PoC Portfolio)
