# SCIM Authentication - Résumé Exécutif

## Question Posée
> "Je souhaite savoir comment l'authentification SCIM est censée fonctionner en production et comment pourrais-je la tester afin de savoir si elle est dans les normes"

## Réponse Courte

**L'authentification SCIM n'est pas implémentée** ⚠️

Votre API SCIM déclare supporter OAuth 2.0 Bearer Token dans `ServiceProviderConfig`, mais aucune validation n'existe dans le code. C'est un **bloqueur production critique**.

## État Actuel vs. Attendu

### Ce qui existe ✅
```python
# app/scim_api.py - Déclaration dans ServiceProviderConfig
"authenticationSchemes": [
    {
        "name": "OAuth 2.0 Bearer Token",
        "description": "OAuth 2.0 client credentials flow",
        "type": "oauthbearertoken",
        "primary": True
    }
]
```

### Ce qui manque ❌
```python
# Ce code n'existe PAS dans app/scim_api.py
@scim.before_request
def validate_oauth_token():
    """Validate OAuth 2.0 Bearer token (RFC 6750)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(401, "Missing Authorization header")
    
    token = auth_header[7:]
    # Validate JWT signature with Keycloak JWKS
    # Check expiration, issuer, roles...
    # → CODE MANQUANT
```

## Comment Ça Devrait Fonctionner (RFC 7644 + RFC 6750)

### 1. Client Obtient Token OAuth
```bash
# Client credentials grant (service account automation-cli)
curl -X POST https://localhost/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=$(cat .runtime/secrets/keycloak-service-client-secret)" \
  | jq -r .access_token

# Résultat: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. Client Utilise Token pour Appeler SCIM
```bash
# Créer utilisateur via SCIM avec Bearer token
curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice",
    "name": {"givenName": "Alice", "familyName": "Smith"},
    "emails": [{"value": "alice@example.com", "primary": true}],
    "active": true
  }'

# Attendu: 201 Created (si OAuth implémenté)
# Actuel: 403 Forbidden (OAuth ignoré, autre problème)
```

### 3. Flask Valide Token JWT
```python
# Ce qui DEVRAIT se passer (mais n'existe pas)
def validate_bearer_token(token: str):
    """Validate JWT against Keycloak JWKS."""
    # 1. Load Keycloak public keys
    jwks_uri = "https://localhost/realms/demo/protocol/openid-connect/certs"
    key_set = JsonWebKey.import_key_set(requests.get(jwks_uri).json())
    
    # 2. Decode and verify signature
    claims = jwt.decode(
        token,
        key=key_set,
        claims_options={"iss": {"value": "https://localhost/realms/demo"}}
    )
    claims.validate()
    
    # 3. Check roles
    token_roles = claims.get("realm_access", {}).get("roles", [])
    required_roles = ["realm-admin", "iam-operator"]
    if not any(role in token_roles for role in required_roles):
        abort(403, "Insufficient privileges")
    
    return claims
```

## Tests de Conformité RFC

### Tests Obligatoires (RFC 6750 + 7644)

| Test | Commande | Status Attendu | Votre Status Actuel |
|------|----------|----------------|---------------------|
| Token absent | `curl /scim/v2/Users` | `401 Unauthorized` | ❌ Pas de validation |
| Token invalide | `curl -H "Authorization: Bearer bad"` | `401 Unauthorized` | ❌ Token ignoré |
| Token expiré | Token avec `exp` < now | `401 Unauthorized` | ❌ Pas de vérification |
| Rôles insuffisants | Token sans `realm-admin` | `403 Forbidden` | ❌ Pas de check |
| Token valide | Automation-cli token | `200/201/204` | ❌ 403 (autre raison) |
| Discovery public | `curl /ServiceProviderConfig` | `200 OK` (pas d'auth) | ✅ Fonctionne |

**Verdict**: 1/6 tests conformes RFC (17%)

## Comment Implémenter (Guide Complet)

📖 **Documentation complète**: [`docs/SCIM_AUTHENTICATION.md`](./SCIM_AUTHENTICATION.md)

### Résumé en 4 Étapes

#### Étape 1: Créer Middleware OAuth (2h)
```python
# Créer app/api/scim_auth.py
from functools import wraps
from flask import request, abort, current_app, g
from authlib.jose import jwt, JsonWebKey
import requests

def require_scim_oauth(fn):
    """Decorator: require valid OAuth 2.0 Bearer token."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Extract token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"status": "401", "detail": "Missing Authorization"}, 401
        
        token = auth_header[7:]
        
        # Validate JWT (signature, expiration, issuer)
        try:
            cfg = current_app.config["APP_CONFIG"]
            jwks = _load_jwks(cfg.keycloak_url, cfg.keycloak_realm)
            claims = jwt.decode(token, key=jwks, ...)
            claims.validate()
            
            # Check roles
            roles = claims.get("realm_access", {}).get("roles", [])
            if cfg.iam_operator_role not in roles and cfg.realm_admin_role not in roles:
                return {"status": "403", "detail": "Insufficient privileges"}, 403
            
            g.scim_token_claims = dict(claims)
        except Exception as exc:
            return {"status": "401", "detail": "Invalid token"}, 401
        
        return fn(*args, **kwargs)
    return wrapper
```

#### Étape 2: Protéger Routes SCIM (30min)
```python
# Modifier app/scim_api.py
from app.api.scim_auth import require_scim_oauth

@scim.route('/Users', methods=['POST'])
@require_scim_oauth
def create_user():
    """Create user (requires OAuth)."""
    # ... existing code

@scim.route('/Users/<user_id>', methods=['PUT'])
@require_scim_oauth
def update_user(user_id):
    """Update user (requires OAuth)."""
    # ... existing code

@scim.route('/Users/<user_id>', methods=['DELETE'])
@require_scim_oauth
def delete_user(user_id):
    """Delete user (requires OAuth)."""
    # ... existing code

# Discovery endpoints restent publics (RFC 7644)
@scim.route('/ServiceProviderConfig')
def service_provider_config():
    """Public discovery endpoint."""
    # ... existing code (no OAuth)
```

#### Étape 3: Ajouter Tests OAuth (1.5h)
```python
# Ajouter dans tests/test_scim_api.py

def test_scim_requires_bearer_token(client):
    """SCIM must reject requests without Bearer token."""
    response = client.post("/scim/v2/Users", json={"userName": "test"})
    assert response.status_code == 401
    assert "Missing Authorization" in response.get_json()["detail"]

def test_scim_rejects_invalid_token(client):
    """SCIM must reject invalid JWT tokens."""
    response = client.post(
        "/scim/v2/Users",
        json={"userName": "test"},
        headers={"Authorization": "Bearer invalid-token-123"}
    )
    assert response.status_code == 401
    assert "Invalid token" in response.get_json()["detail"]

def test_scim_rejects_insufficient_roles(client, mock_oauth_token):
    """SCIM must reject tokens without realm-admin/iam-operator."""
    # Mock token with only "analyst" role (insufficient)
    token = create_mock_jwt(roles=["analyst"])
    response = client.post(
        "/scim/v2/Users",
        json={"userName": "test"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "Insufficient privileges" in response.get_json()["detail"]

def test_scim_allows_service_account_with_realm_admin(client, service_oauth_token):
    """SCIM must accept automation-cli service account token."""
    response = client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "newuser",
            "emails": [{"value": "newuser@example.com"}],
            "active": True
        },
        headers={"Authorization": f"Bearer {service_oauth_token}"}
    )
    assert response.status_code == 201
```

#### Étape 4: Valider Conformité (30min)
```bash
# Lancer tests complets
make pytest           # Unit tests (avec mocks OAuth)
make pytest-e2e-scim  # E2E tests (avec vrai Keycloak)

# Tests manuels de conformité RFC
bash docs/SCIM_AUTHENTICATION.md  # Section "Tests de Conformité RFC"
```

## Pourquoi C'est Actuellement un Problème

### Risques Sécurité
- 🔴 **Critique**: N'importe qui peut créer/modifier/supprimer des utilisateurs sans authentification
- 🔴 **Critique**: Pas d'audit des actions SCIM (aucun `client_id` dans logs)
- 🟠 **Majeur**: Non-conformité RFC 7644 (section 2 obligatoire)
- 🟠 **Majeur**: Impossible de révoquer accès SCIM (pas de token à révoquer)

### Impact Production
```
❌ NE PAS EXPOSER /scim/v2/* PUBLIQUEMENT
```

Sans OAuth:
- Tout client HTTP peut provisionner des utilisateurs
- Pas de rate limiting par client
- Pas de traçabilité (qui a fait quoi?)
- Violation RGPD (pas de contrôle d'accès)

### Workaround Temporaire
- ✅ Utiliser `/admin/*` (protégé par OIDC session)
- ✅ Bloquer `/scim/v2/*` dans nginx jusqu'à implémentation OAuth
- ✅ Documenter limitation dans README

## Timeline Implémentation

| Étape | Durée | Priorité |
|-------|-------|----------|
| 1. Créer middleware OAuth | 2h | P0 (Bloqueur) |
| 2. Protéger routes SCIM | 30min | P0 |
| 3. Tests OAuth | 1.5h | P0 |
| 4. Tests E2E | 30min | P1 |
| 5. Logs audit enrichis | 1h | P1 |
| 6. Documentation | 30min | P2 |
| **TOTAL** | **6h** | Production-ready |

## Actions Immédiates Recommandées

### Urgence (Aujourd'hui)
1. ✅ **Documenter limitation** (déjà fait: `docs/SCIM_AUTHENTICATION.md`)
2. ⏳ **Bloquer SCIM dans nginx** (ajouter dans `proxy/nginx.conf`):
   ```nginx
   location /scim {
       deny all;
       return 503 "SCIM API temporarily disabled - OAuth implementation pending";
   }
   ```
3. ⏳ **Marquer tests E2E SCIM comme skipped** (avec référence docs)

### Court Terme (Cette Semaine)
4. ⏳ **Implémenter middleware OAuth** (`app/api/scim_auth.py`)
5. ⏳ **Ajouter tests OAuth** (unit + E2E)
6. ⏳ **Validation RFC manuelle** (checklist dans docs)

### Moyen Terme (Optionnel)
7. ⏳ Rate limiting par `client_id`
8. ⏳ Logs audit SCIM avec `sub` et `azp` claims
9. ⏳ Monitoring alertes 401/403

## Ressources

- 📖 **Guide complet**: `docs/SCIM_AUTHENTICATION.md` (architecture, code, tests)
- 📖 **Workaround E2E**: `docs/E2E_SCIM_WORKAROUND.md` (comment tester maintenant)
- 📚 **RFC 6750**: https://datatracker.ietf.org/doc/html/rfc6750 (OAuth Bearer)
- 📚 **RFC 7644 §2**: https://datatracker.ietf.org/doc/html/rfc7644#section-2 (SCIM Auth)
- 🔧 **Authlib JWT**: https://docs.authlib.org/en/latest/jose/jwt.html

## TL;DR

**Question**: Comment l'authentification SCIM fonctionne et comment la tester?

**Réponse**: 
1. ❌ **Elle ne fonctionne pas** - aucune validation OAuth implémentée
2. 📖 **Documentation complète** créée dans `docs/SCIM_AUTHENTICATION.md`
3. ⏱️ **6h pour implémenter** middleware + tests (guide détaillé fourni)
4. 🔴 **Production blocker** - ne pas exposer SCIM publiquement
5. ✅ **Workaround temporaire** - utiliser `/admin/*` (protégé OIDC)

**Prochaine étape**: Implémenter `app/api/scim_auth.py` selon guide dans docs.
