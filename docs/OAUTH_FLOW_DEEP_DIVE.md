# 🔐 OAuth 2.0 Flow : Guide Approfondi

> **Objectif** : Comprendre comment OAuth 2.0 protège l'API SCIM avec JWT Bearer Tokens (RFC 6750)

**Pré-requis** : Lire [SCIM_API_ARCHITECTURE.md](SCIM_API_ARCHITECTURE.md) pour le contexte global.

---

## 🎯 C'est Quoi OAuth 2.0 en 30 Secondes ?

**OAuth 2.0** = Framework d'autorisation permettant à une application (SCIM API) de vérifier qu'un client (Azure AD, Okta...) a le droit d'accéder à des ressources (créer/lire users).

**Analogie** : OAuth = Badge d'accès dans un building.
- **Client** (Azure AD) = Visiteur
- **Authorization Server** (Keycloak) = Réception qui délivre badges
- **Resource Server** (SCIM API) = Étage sécurisé qui vérifie badges
- **Token** = Badge avec photo + date d'expiration

**Différence JWT vs session** :
- **Session** : Serveur garde un cookie, regarde en base "qui est ce cookie"
- **JWT** : Serveur vérifie signature cryptographique du token (pas de base nécessaire)

---

## 🏗️ Architecture OAuth dans IAM PoC

```
┌──────────────────────────────────────────────────────────┐
│  1. CLIENT SCIM (Azure AD, Okta, script custom...)      │
│     Veut créer un utilisateur via SCIM API              │
└──────────────────────────────────────────────────────────┘
                     ↓ (1) Demande token
┌──────────────────────────────────────────────────────────┐
│  2. KEYCLOAK (Authorization Server)                      │
│     /realms/demo/protocol/openid-connect/token          │
│     Vérifie credentials client (client_id + secret)     │
│     Retourne JWT token signé avec clé privée RSA        │
└──────────────────────────────────────────────────────────┘
                     ↓ (2) Utilise token
┌──────────────────────────────────────────────────────────┐
│  3. SCIM API (Resource Server)                           │
│     app/api/scim.py                                      │
│     Valide JWT signature avec clé publique (JWKS)       │
│     Vérifie scopes (scim:read, scim:write)              │
└──────────────────────────────────────────────────────────┘
```

---

## 🔑 Flow OAuth Complet : Étape par Étape

### Étape 1 : Client Obtient un Token (Client Credentials Grant)

**Requête** :
```http
POST /realms/demo/protocol/openid-connect/token HTTP/1.1
Host: keycloak:8080
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=automation-cli
&client_secret=demo-service-secret
&scope=scim:read scim:write
```

**Explication paramètres** :
- `grant_type=client_credentials` : Type OAuth pour machine-to-machine (pas d'utilisateur)
- `client_id=automation-cli` : Identifiant du service account Keycloak
- `client_secret=demo-service-secret` : Secret partagé (équivalent mot de passe)
- `scope=scim:read scim:write` : Permissions demandées

**Code équivalent (scripts/jml.py)** :
```python
def get_service_account_token() -> str:
    """Obtient token OAuth pour service account automation-cli."""
    token_url = f"{KEYCLOAK_URL}/realms/demo/protocol/openid-connect/token"
    
    response = requests.post(
        token_url,
        data={
            'grant_type': 'client_credentials',
            'client_id': 'automation-cli',
            'client_secret': os.getenv('KEYCLOAK_SERVICE_CLIENT_SECRET'),
            'scope': 'scim:read scim:write'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=10
    )
    
    if response.status_code != 200:
        raise RuntimeError(f"Token request failed: {response.text}")
    
    return response.json()['access_token']
```

---

**Réponse Keycloak** :
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlhYWFhYIn0...",
  "expires_in": 300,
  "token_type": "Bearer",
  "scope": "scim:read scim:write"
}
```

**Explication** :
- `access_token` : JWT signé (voir structure ci-dessous)
- `expires_in` : 300 secondes (5 minutes) - après, token invalide
- `token_type` : "Bearer" (RFC 6750) - à mettre dans header `Authorization: Bearer ...`
- `scope` : Scopes accordés (peut être moins que demandé si config Keycloak restrictive)

---

### Étape 2 : Structure du JWT Token

**Token complet** (3 parties séparées par `.`) :
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlhYWFhYIn0.
eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdC9yZWFsbXMvZGVtbyIsInN1YiI6ImF1dG9tYXRpb24tY2xpIiwiYXVkIjoiYWNjb3VudCIsImV4cCI6MTYzMDQzMDAwMCwiaWF0IjoxNjMwNDI5NzAwLCJzY29wZSI6InNjaW06cmVhZCBzY2ltOndyaXRlIn0.
d4f3c2b1a0e9f8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4b3...
```

**Décodage** :

#### Partie 1 : Header (Base64)
```json
{
  "alg": "RS256",        // Algorithme signature (RSA-SHA256)
  "typ": "JWT",          // Type de token
  "kid": "XXXXX"         // Key ID (identifie quelle clé publique utiliser)
}
```

#### Partie 2 : Payload (Claims - Base64)
```json
{
  "iss": "https://localhost/realms/demo",  // Issuer (qui a émis le token)
  "sub": "automation-cli",                 // Subject (ID du client)
  "aud": "account",                        // Audience (pour qui est le token)
  "exp": 1630430000,                       // Expiration (Unix timestamp)
  "iat": 1630429700,                       // Issued At (quand émis)
  "nbf": 1630429700,                       // Not Before (pas valide avant)
  "scope": "scim:read scim:write",         // Scopes accordés
  "azp": "automation-cli",                 // Authorized Party
  "client_id": "automation-cli"            // Client ID
}
```

**Claims expliqués** :
- `iss` (issuer) : Vérifié pour empêcher token d'un autre Keycloak
- `exp` (expiration) : Validité temporelle (anti-replay attacks)
- `aud` (audience) : Vérifié pour empêcher token destiné à autre API
- `scope` : Permissions (scim:read = GET, scim:write = POST/PUT/DELETE)

#### Partie 3 : Signature (RSA-SHA256)
```
Signature = RSA_Sign(
    SHA256(base64(header) + "." + base64(payload)),
    Keycloak_Private_Key
)
```

**Pourquoi signature RSA** :
- ✅ **Asymétrique** : Keycloak signe avec clé privée, SCIM API vérifie avec clé publique
- ✅ **Pas de secret partagé** : API n'a jamais la clé privée (contrairement HMAC)
- ✅ **Rotation facile** : Keycloak peut changer clés, API récupère nouvelles via JWKS

---

### Étape 3 : Client Envoie Requête SCIM avec Token

**Requête HTTP** :
```http
POST /scim/v2/Users HTTP/1.1
Host: localhost
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice",
  "emails": [{"value": "alice@example.com", "primary": true}],
  "active": true
}
```

**Code Python équivalent** :
```python
import requests

def create_scim_user(token: str, user_data: dict):
    """Crée user via SCIM API avec token OAuth."""
    response = requests.post(
        'https://localhost/scim/v2/Users',
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/scim+json'
        },
        json=user_data,
        verify=False  # Dev only (self-signed cert)
    )
    return response.json()
```

---

### Étape 4 : SCIM API Valide le Token

**Fichier** : `app/api/scim.py` ligne 88-149

```python
@bp.before_request
def validate_request():
    """Valide OAuth Bearer token sur TOUTES les requêtes SCIM."""
    
    # 1. Extract token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return scim_error(401, "Authorization header must use Bearer scheme", "unauthorized")
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # 2. Validate JWT
    try:
        claims = validate_jwt_token(token)
    except TokenValidationError as e:
        return scim_error(401, f"Invalid token: {e}", "unauthorized")
    
    # 3. Check scopes
    scopes = claims.get('scope', '').split()
    
    # Write operations require scim:write
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if 'scim:write' not in scopes:
            return scim_error(403, "Insufficient scope. Required: scim:write", "forbidden")
    
    # Read operations require scim:read OR scim:write
    elif request.method == 'GET':
        if not any(s in scopes for s in ['scim:read', 'scim:write']):
            return scim_error(403, "Insufficient scope. Required: scim:read", "forbidden")
    
    # 4. Store claims in Flask request context (for audit logging)
    g.oauth_claims = claims
```

---

### Étape 5 : Validation JWT Détaillée

**Fichier** : `app/api/decorators.py`

```python
import jwt
from jwt import PyJWKClient
from typing import Dict

JWKS_URL = "https://localhost/realms/demo/protocol/openid-connect/certs"

class TokenValidationError(Exception):
    """Raised when JWT validation fails."""
    pass

def validate_jwt_token(token: str) -> Dict[str, any]:
    """
    Valide JWT token avec vérification complète.
    
    Validations effectuées:
    1. Signature RSA (via JWKS)
    2. Expiration (exp claim)
    3. Not Before (nbf claim)
    4. Issuer (iss claim)
    5. Audience (aud claim)
    
    Args:
        token: JWT Bearer token (sans préfixe "Bearer ")
    
    Returns:
        Dict contenant les claims du token
    
    Raises:
        TokenValidationError: Si validation échoue
    """
    try:
        # 1. Récupère clés publiques Keycloak (JWKS)
        jwks_client = PyJWKClient(JWKS_URL, cache_keys=True, timeout=10)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # 2. Décode + vérifie signature + claims
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],  # Algorithme attendu
            audience='account',    # Audience attendue
            issuer='https://localhost/realms/demo',  # Issuer attendu
            options={
                'verify_signature': True,  # Vérifie signature RSA
                'verify_exp': True,        # Vérifie expiration
                'verify_nbf': True,        # Vérifie not-before
                'verify_aud': True,        # Vérifie audience
                'verify_iss': True,        # Vérifie issuer
                'require_exp': True,       # exp claim obligatoire
                'require_iat': True        # iat claim obligatoire
            }
        )
        
        return claims
        
    except jwt.ExpiredSignatureError:
        raise TokenValidationError("Token expired")
    except jwt.InvalidIssuerError:
        raise TokenValidationError("Invalid issuer")
    except jwt.InvalidAudienceError:
        raise TokenValidationError("Invalid audience")
    except jwt.InvalidSignatureError:
        raise TokenValidationError("Invalid signature")
    except jwt.DecodeError as e:
        raise TokenValidationError(f"Token decode error: {e}")
    except Exception as e:
        raise TokenValidationError(f"Token validation failed: {e}")
```

---

## 🔐 Points de Sécurité Critiques

### 1. **Pourquoi RSA et pas HMAC ?**

**HMAC-SHA256** (symétrique) :
```
Token signé avec secret partagé
├─ Keycloak a le secret
└─ SCIM API a le MÊME secret
❌ Si SCIM API compromise → Attaquant peut forger tokens
```

**RSA-SHA256** (asymétrique) :
```
Token signé avec clé privée Keycloak
├─ Keycloak a clé privée (jamais exposée)
└─ SCIM API a clé publique (peut être exposée)
✅ Si SCIM API compromise → Attaquant ne peut PAS forger tokens
```

**Bénéfice RSA** : Principe du moindre privilège (SCIM API ne peut que vérifier, pas créer tokens).

---

### 2. **JWKS : Rotation Automatique des Clés**

**JWKS = JSON Web Key Set** : Endpoint Keycloak qui expose clés publiques.

**URL** : `https://localhost/realms/demo/protocol/openid-connect/certs`

**Exemple réponse** :
```json
{
  "keys": [
    {
      "kid": "key-2024-10",           // Key ID (référencé dans JWT header)
      "kty": "RSA",                   // Type de clé
      "alg": "RS256",                 // Algorithme
      "use": "sig",                   // Usage: signature
      "n": "0vx7agoebGc...",          // Modulus RSA (clé publique)
      "e": "AQAB"                     // Exposant RSA
    },
    {
      "kid": "key-2024-09",           // Ancienne clé (rotation en cours)
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "xjlBa9qZ...",
      "e": "AQAB"
    }
  ]
}
```

**Workflow rotation** :
```
1. Keycloak génère nouvelle paire de clés (key-2024-10)
2. JWKS expose DEUX clés (nouvelle + ancienne)
3. Nouveaux tokens signés avec key-2024-10
4. Anciens tokens (key-2024-09) encore valides jusqu'à expiration
5. Après 24h, Keycloak retire key-2024-09 du JWKS
```

**Bénéfice** : Zero-downtime key rotation (pas besoin redémarrer SCIM API).

---

### 3. **Protection Contre Replay Attacks**

**Scénario attaque** :
```
1. Attaquant intercepte token valide (man-in-the-middle)
2. Attaquant réutilise token pour faire requêtes non-autorisées
```

**Protections** :
- ✅ **Expiration courte** : `exp` claim = 5 minutes (tokens de courte durée)
- ✅ **HTTPS obligatoire** : TLS 1.3 empêche interception
- ✅ **Token binding** (optionnel) : Lier token à IP/certificat client

**Config recommandée** :
```python
# app/config/settings.py
JWT_TOKEN_LIFETIME = 300  # 5 minutes
REFRESH_TOKEN_LIFETIME = 3600  # 1 heure (refresh tokens)
```

---

### 4. **Scopes : Principe du Moindre Privilège**

**Granularité permissions** :
```
scim:read    → GET /Users, GET /Users/{id}
scim:write   → POST /Users, PUT /Users/{id}, DELETE /Users/{id}
scim:admin   → Toutes opérations + /ServiceProviderConfig
```

**Code validation scopes** :
```python
# app/api/scim.py
def check_scope(required_scope: str):
    """Vérifie que token a le scope requis."""
    token_scopes = g.oauth_claims.get('scope', '').split()
    
    if required_scope not in token_scopes:
        # Exception: scim:write implique scim:read
        if required_scope == 'scim:read' and 'scim:write' in token_scopes:
            return True
        
        raise ScimError(403, f"Missing scope: {required_scope}", "forbidden")
    
    return True

@bp.route('/Users', methods=['GET'])
def list_users():
    check_scope('scim:read')  # Vérifie scope avant traitement
    ...
```

---

## 🧪 Tests OAuth : Comment Tester la Sécurité

### Test 1 : Token Manquant (401)

**Fichier** : `tests/test_scim_oauth_validation.py`

```python
def test_missing_authorization_header(client):
    """Requête sans token doit être rejetée."""
    response = client.get('/scim/v2/Users')
    
    assert response.status_code == 401
    data = response.get_json()
    assert data['scimType'] == 'unauthorized'
    assert 'Authorization' in data['detail']
```

---

### Test 2 : Token Expiré (401)

```python
import jwt
from datetime import datetime, timedelta, timezone

def test_expired_token(client):
    """Token expiré doit être rejeté."""
    # Crée token expiré
    expired_payload = {
        'iss': 'https://localhost/realms/demo',
        'sub': 'test-client',
        'aud': 'account',
        'exp': int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expiré il y a 1h
        'iat': int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
        'scope': 'scim:read scim:write'
    }
    
    token = jwt.encode(expired_payload, 'test-secret', algorithm='HS256')
    
    response = client.get(
        '/scim/v2/Users',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert 'expired' in data['detail'].lower()
```

---

### Test 3 : Scope Insuffisant (403)

```python
@patch('app.api.scim.validate_jwt_token')
def test_insufficient_scope(mock_validate, client):
    """Token avec scim:read ne peut pas créer users."""
    # Mock validation JWT (succès)
    mock_validate.return_value = {
        'sub': 'test-client',
        'scope': 'scim:read',  # Seulement lecture
        'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    }
    
    response = client.post(
        '/scim/v2/Users',
        headers={
            'Authorization': 'Bearer valid-token',
            'Content-Type': 'application/scim+json'
        },
        json={
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName': 'alice'
        }
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data['scimType'] == 'forbidden'
    assert 'scope' in data['detail'].lower()
```

---

## 🎓 Concepts Clés pour Entretien Sécurité

### 1. **JWT vs Session Cookies**

| Aspect | JWT (Stateless) | Session Cookie (Stateful) |
|--------|-----------------|---------------------------|
| **Stockage** | Pas de stockage serveur | Session en base/Redis |
| **Scalabilité** | ✅ Excellent (pas d'état partagé) | ⚠️ Nécessite session store |
| **Révocation** | ❌ Difficile (token valide jusqu'à expiration) | ✅ Facile (supprime session) |
| **Taille** | ⚠️ ~1-2 KB (dans chaque requête) | ✅ ~50 bytes (ID session) |
| **Use case** | ✅ API machine-to-machine, microservices | ✅ Applications web user-facing |

**Pourquoi JWT pour SCIM** :
- API appelée par services externes (Azure AD, Okta...)
- Pas de session utilisateur à maintenir
- Haute scalabilité (stateless)

---

### 2. **OAuth 2.0 Grant Types**

| Grant Type | Use Case | Utilisé dans IAM PoC ? |
|------------|----------|----------------------|
| **Client Credentials** | Machine-to-machine (services) | ✅ OUI (SCIM API) |
| **Authorization Code** | User login (avec consentement) | ✅ OUI (Admin UI OIDC) |
| **Implicit** | SPA (deprecated) | ❌ NON (non sécurisé) |
| **Password** | User credentials direct (deprecated) | ❌ NON (anti-pattern) |
| **Refresh Token** | Renouvellement token sans re-auth | ⚠️ Possible (non implémenté) |

**Client Credentials** (utilisé pour SCIM) :
```
Client → Keycloak: "Voici mon client_id + secret"
Keycloak → Client: "Voici ton token"
Client → SCIM API: "Voici le token"
```

**Authorization Code** (utilisé pour Admin UI) :
```
User → Flask: "Je veux me connecter"
Flask → Keycloak: "Redirige vers login"
User login → Keycloak: "OK, voici code"
Flask → Keycloak: "Échange code contre token"
Flask → User: "Session créée, voici cookie"
```

---

### 3. **OWASP Top 10 : A02:2021 Cryptographic Failures**

**Erreurs fréquentes** :
- ❌ **Pas de validation signature** : Accepter token sans vérifier
- ❌ **Algorithme faible** : Utiliser HS256 au lieu de RS256 pour API publiques
- ❌ **Pas de vérification expiration** : Token valide pour toujours
- ❌ **Secret en clair** : `client_secret` dans code source (pas `.env`)

**Bonnes pratiques implémentées** :
- ✅ **Signature RSA vérifiée** : Via JWKS (clés publiques Keycloak)
- ✅ **Expiration stricte** : 5 minutes (configurable)
- ✅ **Secrets externalisés** : Docker secrets + Azure Key Vault
- ✅ **TLS obligatoire** : HTTPS pour toutes requêtes OAuth

---

## 🎯 Récapitulatif : Flow Complet en 10 Étapes

```
1. Client → Keycloak: POST /token (client_credentials)
2. Keycloak vérifie client_id + client_secret
3. Keycloak génère JWT signé avec clé privée RSA
4. Keycloak retourne access_token (valide 5 min)
5. Client → SCIM API: POST /Users (Authorization: Bearer <token>)
6. SCIM API extrait token du header Authorization
7. SCIM API récupère clé publique via JWKS
8. SCIM API vérifie signature RSA + exp + iss + aud
9. SCIM API vérifie scope (scim:write requis pour POST)
10. SCIM API traite requête + retourne 201 Created
```

**Si échec validation** : SCIM API retourne `401 Unauthorized` (étape 8) ou `403 Forbidden` (étape 9).

---

## 📚 Ressources Complémentaires

### RFCs Officiels
- **RFC 6749** : OAuth 2.0 Framework (grant types, endpoints)
- **RFC 6750** : Bearer Token Usage (header Authorization)
- **RFC 7519** : JWT (structure, claims standards)
- **RFC 7517** : JWK (JSON Web Key format pour JWKS)

### OWASP
- **A02:2021** : Cryptographic Failures
- **A07:2021** : Identification and Authentication Failures
- **JWT Security Best Practices** : https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

### Tests
- **Fichier** : `tests/test_scim_oauth_validation.py` (17 tests OAuth)
- **Commande** : `pytest tests/test_scim_oauth_validation.py -v`

---

**Dernière mise à jour** : Octobre 2025  
**Auteur** : Alex (IAM PoC Portfolio)
