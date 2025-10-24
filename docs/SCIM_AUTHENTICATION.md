# SCIM 2.0 Authentication Guide

## Status: **NOT IMPLEMENTED** ⚠️

L'API SCIM (`/scim/v2/*`) déclare supporter OAuth 2.0 Bearer Token dans son `ServiceProviderConfig`, mais **aucune validation d'authentification n'est actuellement implémentée**.

## État Actuel

### Ce qui est implémenté ✅
- Routes SCIM 2.0 (`POST /Users`, `GET /Users`, etc.)
- Validation Content-Type (`application/scim+json`)
- Transformation SCIM ↔ Keycloak
- Délégation vers `provisioning_service.py`

### Ce qui manque ❌
- **Validation OAuth 2.0 Bearer Token** (RFC 6750)
- Vérification des scopes/rôles requis
- Gestion de l'expiration des tokens
- Rate limiting par client
- Logs d'audit des appels SCIM

## Architecture Attendue (RFC 7644 + RFC 6750)

### Flow OAuth 2.0 Client Credentials

```
┌─────────────────┐                  ┌──────────────┐
│  SCIM Client    │                  │  Keycloak    │
│ (automation-cli)│                  │              │
└────────┬────────┘                  └──────┬───────┘
         │                                   │
         │ 1. POST /token                    │
         │    grant_type=client_credentials  │
         │    client_id=automation-cli       │
         │    client_secret=xxx              │
         │──────────────────────────────────>│
         │                                   │
         │ 2. access_token (JWT)             │
         │<──────────────────────────────────│
         │                                   │
┌────────▼────────┐                  ┌──────▼───────┐
│  SCIM Client    │                  │ Flask SCIM   │
└────────┬────────┘                  │     API      │
         │                           └──────┬───────┘
         │ 3. POST /scim/v2/Users           │
         │    Authorization: Bearer <token> │
         │──────────────────────────────────>│
         │                                   │
         │                      ┌────────────▼──────────┐
         │                      │ OAuth Middleware      │
         │                      │ - Extract Bearer      │
         │                      │ - Validate signature  │
         │                      │ - Check expiration    │
         │                      │ - Verify scopes/roles │
         │                      └────────────┬──────────┘
         │                                   │
         │                      ┌────────────▼──────────┐
         │                      │ provisioning_service  │
         │                      │ Execute JML operation │
         │                      └───────────────────────┘
         │                                   │
         │ 4. 201 Created (SCIM User)        │
         │<──────────────────────────────────│
```

### Standards RFC

#### RFC 6750 - OAuth 2.0 Bearer Token
- **Format**: `Authorization: Bearer <access_token>`
- **Validation obligatoire**:
  1. Token présent dans header `Authorization`
  2. Préfixe `Bearer ` correct
  3. Signature JWT valide (vérification JWKS Keycloak)
  4. Expiration (`exp` claim) non dépassée
  5. Issuer (`iss`) correspond à Keycloak

#### RFC 7644 - SCIM 2.0 Protocol
- **Section 2: Authentication and Authorization**
  - MUST support OAuth 2.0 Bearer Tokens
  - SHOULD return `401 Unauthorized` si token absent/invalide
  - SHOULD return `403 Forbidden` si token valide mais droits insuffisants
- **Section 3.12: ServiceProviderConfig**
  - MUST déclarer les mécanismes d'authentification supportés

## Implémentation Recommandée

### 1. Middleware OAuth pour Blueprint SCIM

Créer `app/api/scim_auth.py`:

```python
"""OAuth 2.0 Bearer Token authentication middleware for SCIM API."""
from functools import wraps
from flask import request, current_app
from authlib.jose import jwt, JsonWebKey
import requests

def require_scim_oauth(fn):
    """Decorator requiring valid OAuth 2.0 Bearer token."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Extract Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "401",
                "detail": "Missing or invalid Authorization header"
            }, 401
        
        access_token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Validate JWT signature and claims
        try:
            cfg = current_app.config["APP_CONFIG"]
            jwks_uri = f"{cfg.keycloak_url}/realms/{cfg.keycloak_realm}/protocol/openid-connect/certs"
            resp = requests.get(jwks_uri, timeout=5)
            resp.raise_for_status()
            key_set = JsonWebKey.import_key_set(resp.json())
            
            issuer = f"{cfg.keycloak_url}/realms/{cfg.keycloak_realm}"
            claims = jwt.decode(
                access_token,
                key=key_set,
                claims_options={"iss": {"value": issuer}}
            )
            claims.validate()
            
            # Check required scopes/roles
            token_roles = claims.get("realm_access", {}).get("roles", [])
            required_roles = [cfg.iam_operator_role, cfg.realm_admin_role]
            
            if not any(role in token_roles for role in required_roles):
                return {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "403",
                    "detail": f"Token requires one of: {', '.join(required_roles)}"
                }, 403
            
            # Store validated claims in Flask g for downstream use
            from flask import g
            g.scim_token_claims = dict(claims)
            
        except Exception as exc:
            current_app.logger.warning(f"SCIM OAuth validation failed: {exc}")
            return {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "401",
                "detail": "Invalid or expired access token"
            }, 401
        
        return fn(*args, **kwargs)
    return wrapper
```

### 2. Appliquer aux routes SCIM

Modifier `app/scim_api.py`:

```python
from app.api.scim_auth import require_scim_oauth

@scim.route('/Users', methods=['POST'])
@require_scim_oauth
def create_user():
    """Create new user (RFC 7644 §3.3)."""
    # ... existing implementation
```

**Alternative**: Utiliser `@scim.before_request` pour protéger toutes les routes mutatives:

```python
@scim.before_request
def require_oauth():
    """Require OAuth for all SCIM operations except ServiceProviderConfig."""
    # Allow unauthenticated access to discovery endpoints
    if request.endpoint in ["scim.service_provider_config", "scim.resource_types", "scim.schemas"]:
        return
    
    # All other endpoints require OAuth
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(401, description="Missing Authorization header")
    
    # Validate token (see decorator above)
    # ...
```

### 3. Logs d'audit

Enrichir `scripts/audit.py` pour capturer les appels SCIM:

```python
def log_scim_event(
    operation: str,  # create_user, update_user, delete_user
    resource_id: str,
    client_id: str,  # From JWT "azp" claim
    success: bool,
    details: dict = None
):
    """Log SCIM API operations with OAuth client identity."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": f"scim_{operation}",
        "client_id": client_id,
        "resource_id": resource_id,
        "success": success,
        "details": details or {}
    }
    # ... existing audit logic
```

## Tests de Conformité RFC

### Test 1: Token absent → 401
```bash
curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -d '{"userName": "test"}'

# Expected: 401 Unauthorized
# {
#   "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
#   "status": "401",
#   "detail": "Missing or invalid Authorization header"
# }
```

### Test 2: Token invalide → 401
```bash
curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer invalid-token" \
  -d '{"userName": "test"}'

# Expected: 401 Unauthorized
# {
#   "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
#   "status": "401",
#   "detail": "Invalid or expired access token"
# }
```

### Test 3: Token valide mais scope insuffisant → 403
```bash
# Obtain token with limited scope
TOKEN=$(curl -X POST https://localhost/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=limited-client" \
  -d "client_secret=secret" | jq -r .access_token)

curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"userName": "test"}'

# Expected: 403 Forbidden
# {
#   "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
#   "status": "403",
#   "detail": "Token requires one of: realm-admin, iam-operator"
# }
```

### Test 4: Token valide avec scopes corrects → 201
```bash
# Obtain token from automation-cli service account
TOKEN=$(curl -X POST https://localhost/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=$(cat .runtime/secrets/keycloak-service-client-secret)" \
  | jq -r .access_token)

curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "newuser",
    "name": {"givenName": "New", "familyName": "User"},
    "emails": [{"value": "newuser@example.com", "primary": true}],
    "active": true
  }'

# Expected: 201 Created
# {
#   "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
#   "id": "...",
#   "userName": "newuser",
#   "name": {"givenName": "New", "familyName": "User"},
#   ...
# }
```

### Test 5: Token expiré → 401
```bash
# Use expired token (expires_in=300s by default)
sleep 301
curl -X GET https://localhost/scim/v2/Users \
  -H "Authorization: Bearer $EXPIRED_TOKEN"

# Expected: 401 Unauthorized
```

### Test 6: ServiceProviderConfig sans authentification → 200
```bash
# Discovery endpoint should be public
curl https://localhost/scim/v2/ServiceProviderConfig

# Expected: 200 OK (no authentication required)
```

## Checklist de Sécurité

### Validation JWT (RFC 7519)
- [ ] Vérifier signature avec JWKS Keycloak
- [ ] Vérifier `exp` (expiration)
- [ ] Vérifier `nbf` (not before)
- [ ] Vérifier `iss` (issuer) = `https://localhost/realms/demo`
- [ ] Vérifier `aud` (audience) si défini

### Autorisation
- [ ] Vérifier rôles dans `realm_access.roles` ou `resource_access`
- [ ] Rôles requis: `realm-admin` OU `iam-operator`
- [ ] Rejeter tokens utilisateur (grant_type=password) si service accounts requis

### Rate Limiting
- [ ] Limiter nombre de requêtes par `client_id` (token claim `azp`)
- [ ] Protéger contre brute-force de tokens invalides
- [ ] Implémenter backoff exponentiel

### Logs & Monitoring
- [ ] Logger toutes les tentatives d'authentification échouées
- [ ] Logger les opérations SCIM avec `client_id` et `sub` (subject)
- [ ] Alerter sur taux élevé de 401/403
- [ ] Redact tokens dans les logs (afficher seulement premiers/derniers 4 chars)

### Discovery Endpoints
- [ ] `/ServiceProviderConfig` public (pas d'auth requise)
- [ ] `/ResourceTypes` public
- [ ] `/Schemas` public
- [ ] Tous autres endpoints protégés par OAuth

## Configuration Recommandée

### Keycloak Client (automation-cli)

```json
{
  "clientId": "automation-cli",
  "enabled": true,
  "serviceAccountsEnabled": true,
  "publicClient": false,
  "protocol": "openid-connect",
  "attributes": {
    "access.token.lifespan": "900",  // 15 minutes
    "client.secret.rotation.enabled": "true"
  },
  "defaultClientScopes": ["profile", "email"],
  "optionalClientScopes": ["address", "phone"]
}
```

### Service Account Roles

Le service account `automation-cli` doit avoir le rôle `realm-admin` ou `iam-operator` sur le realm `demo`:

```bash
# Assigner realm-admin au service account
scripts/jml.py \
  --kc-url https://localhost \
  --auth-realm demo \
  --svc-client-id automation-cli \
  --svc-client-secret $(cat .runtime/secrets/keycloak-service-client-secret) \
  bootstrap-service-account \
  --realm demo \
  --admin-user admin \
  --admin-pass admin
```

## Prochaines Étapes

1. **Implémenter `app/api/scim_auth.py`** avec decorator `@require_scim_oauth`
2. **Protéger routes SCIM** dans `app/scim_api.py`
3. **Ajouter tests OAuth** dans `tests/test_scim_api.py`:
   - `test_scim_requires_bearer_token`
   - `test_scim_rejects_invalid_token`
   - `test_scim_rejects_insufficient_roles`
   - `test_scim_allows_service_account_with_realm_admin`
4. **Enrichir logs d'audit** avec `client_id` et `sub` du token
5. **Documenter obtention token** dans README et E2E tests
6. **Implémenter rate limiting** (optionnel, production)

## Références

- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7644 - SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [Keycloak Service Accounts](https://www.keycloak.org/docs/latest/server_admin/#_service_accounts)
- [Authlib JWT Documentation](https://docs.authlib.org/en/latest/jose/jwt.html)
