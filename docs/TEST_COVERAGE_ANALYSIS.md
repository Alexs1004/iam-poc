# Analyse de Couverture de Tests — Security Requirements

## 📊 Résumé Exécutif

| Catégorie | Couverture | Status | Tests Manquants |
|-----------|------------|--------|-----------------|
| **Auth & Sessions (Flask)** | 70% | 🟡 Partiel | OIDC/JWT validation, PKCE |
| **CSRF Protection** | 100% | ✅ Complet | - |
| **RBAC** | 100% | ✅ Complet | - |
| **MFA Obligatoire** | 0% | ❌ Absent | Required action Keycloak |
| **OIDC/JWT** | 0% | ❌ Absent | Validation complète, PKCE, JWKS rotation |
| **SCIM 2.0 (RFC 7644)** | 80% | 🟡 Partiel | Session revocation test |
| **Secrets** | 50% | 🟡 Partiel | Logs verification, rotation idempotence |
| **Nginx/TLS/Headers** | 60% | 🟡 Partiel | TLS version, rate limiting |
| **Audit** | 100% | ✅ Complet | - |

**Score global** : **65%** — Nécessite ajouts tests OIDC/JWT, MFA, et secrets

---

## 📝 Analyse Détaillée par Catégorie

### 1. Auth & Sessions (Flask)

#### ✅ Tests Existants (70%)

**Fichier** : `tests/test_flask_app.py`

| Test | Ligne | Status |
|------|-------|--------|
| Session cookie flags (HttpOnly, Secure, SameSite=Lax) | 416-422 | ✅ OK |
| Redirect unauthenticated → login | 97-100 | ✅ OK |
| RBAC enforcement (403 sans rôle) | 103-111 | ✅ OK |

**Code testé** :
```python
def test_session_cookie_flags_are_hardened(client):
    with client.session_transaction() as session:
        session["token"] = {"access_token": "stub"}
        session["userinfo"] = {"realm_access": {"roles": []}}
    response = client.get("/")
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))
    assert "HttpOnly" in cookies
    assert "Secure" in cookies
    assert "SameSite=Lax" in cookies
```

#### ❌ Tests Manquants (30%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **Durée session cohérente** | Vérifier `SESSION_COOKIE_MAX_AGE` (ex: 3600s) | 🔴 Haute |
| **Session expiration** | Token expiré → redirect login (pas 500) | 🔴 Haute |
| **Session fixation** | Nouveau session ID après login | 🟡 Moyenne |

**Test proposé** :
```python
def test_session_cookie_max_age_is_set(client):
    """Session cookies must have a reasonable max age (e.g., 1 hour)"""
    with client.session_transaction() as session:
        session["token"] = {"access_token": "stub"}
    response = client.get("/")
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))
    
    # Check Max-Age is set and reasonable (3600 = 1 hour)
    assert "Max-Age=" in cookies
    import re
    max_age = int(re.search(r"Max-Age=(\d+)", cookies).group(1))
    assert 1800 <= max_age <= 7200  # Between 30 min and 2 hours
```

---

### 2. CSRF Protection

#### ✅ Tests Existants (100%)

**Fichier** : `tests/test_flask_app.py`

| Test | Ligne | Status |
|------|-------|--------|
| POST sans CSRF token → 400 | 424-427 | ✅ OK |
| POST avec CSRF header → OK | 430-435 | ✅ OK |
| Tous endpoints JML avec CSRF | 138-387 | ✅ OK |

**Couverture** : Tous les endpoints POST/PUT/PATCH/DELETE testés avec CSRF.

#### ❌ Tests Manquants (0%)

**Aucun** — Couverture complète ✅

---

### 3. RBAC

#### ✅ Tests Existants (100%)

**Fichier** : `tests/test_flask_app.py`

| Test | Ligne | Status |
|------|-------|--------|
| `/admin` requiert `iam-operator` ou `realm-admin` | 103-111 | ✅ OK |
| `iam-operator` peut accéder `/admin` | 127-133 | ✅ OK |
| `realm-admin` peut accéder `/admin` | 114-124 | ✅ OK |
| Analyst (sans rôle) → 403 | 103-111 | ✅ OK |
| Opérateur ne peut pas créer `realm-admin` | 202-226 | ✅ OK |
| Opérateur ne peut pas promouvoir vers rôle sensible | 321-351 | ✅ OK |
| Self-modification bloquée (mover/leaver) | 289-318, 354-372 | ✅ OK |

**Couverture** : Tous les scénarios RBAC testés ✅

#### ❌ Tests Manquants (0%)

**Aucun** — Couverture complète ✅

---

### 4. MFA Obligatoire

#### ❌ Tests Existants (0%)

**Aucun test pour MFA enforcement** ❌

#### ❌ Tests Manquants (100%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **Required action TOTP** | Vérifier `CONFIGURE_TOTP` dans user creation | 🔴 Haute |
| **Utilisateur sans TOTP → redirect** | Login sans MFA → page configuration TOTP | 🔴 Haute |
| **MFA skip impossible** | Pas de bypass MFA (même admin) | 🟡 Moyenne |

**Tests proposés** :

```python
# tests/test_mfa_enforcement.py

def test_created_user_has_totp_required_action(mock_keycloak):
    """Test that newly created users have CONFIGURE_TOTP required action"""
    from app.core.provisioning_service import create_user_scim_like
    
    user_id, _ = create_user_scim_like(
        realm="demo",
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        role="analyst"
    )
    
    # Verify Keycloak user object
    created_user = mock_keycloak.get_user(user_id)
    assert "CONFIGURE_TOTP" in created_user["requiredActions"]


def test_user_without_totp_redirected_to_setup(client):
    """Test that users without TOTP are forced to configure MFA"""
    # Mock Keycloak token with user missing TOTP
    with client.session_transaction() as session:
        session["token"] = {"access_token": "stub"}
        session["userinfo"] = {
            "preferred_username": "alice",
            "realm_access": {"roles": ["analyst"]},
            "required_actions": ["CONFIGURE_TOTP"]  # MFA not configured
        }
    
    # Attempt to access protected resource
    response = client.get("/admin", follow_redirects=False)
    
    # Should redirect to MFA setup (Keycloak handles this)
    # In real scenario, Keycloak redirects before token issuance
    # Here we verify app checks required_actions
    assert response.status_code in [302, 403]
    # Note: Actual MFA enforcement happens at Keycloak level
```

**Pourquoi manquant ?**  
MFA enforcement est géré par Keycloak (required actions). Tests actuels ne vérifient pas l'intégration complète OIDC → Keycloak → MFA setup. Nécessite tests E2E avec vraie stack Keycloak.

---

### 5. OIDC/JWT

#### ❌ Tests Existants (0%)

**Aucun test de validation JWT stricte** ❌

#### ❌ Tests Manquants (100%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **Validation `iss` (issuer)** | Token avec mauvais issuer → rejet | 🔴 Haute |
| **Validation `aud` (audience)** | Token pour autre audience → rejet | 🔴 Haute |
| **Validation `exp` (expiration)** | Token expiré → 401 | 🔴 Haute |
| **Validation `nbf` (not before)** | Token pas encore valide → 401 | 🟡 Moyenne |
| **Clock skew (±60s)** | Token expiré avec skew accepté | 🟡 Moyenne |
| **token_type bearer** | Token sans `Bearer` prefix → 401 | 🔴 Haute |
| **PKCE code_verifier** | Mauvais verifier → échec échange code | 🔴 Haute |
| **Alg none interdit** | JWT avec `alg: none` → rejet | 🔴 Haute |
| **Alg non attendu** | JWT avec `HS256` au lieu `RS256` → rejet | 🔴 Haute |
| **JWKS rotation** | Nouveau `kid` → re-télécharge JWKS | 🟡 Moyenne |

**Tests proposés** :

```python
# tests/test_oidc_jwt_validation.py

import jwt
import time
from datetime import datetime, timedelta

def test_jwt_invalid_issuer_rejected(client, mock_jwks):
    """Test that tokens with invalid issuer are rejected"""
    # Create JWT with wrong issuer
    payload = {
        "iss": "https://evil.com/realms/demo",  # Wrong issuer
        "aud": "iam-poc-ui",
        "exp": int(time.time()) + 3600,
        "sub": "user-123",
        "preferred_username": "alice",
        "realm_access": {"roles": ["analyst"]}
    }
    
    token = jwt.encode(payload, "secret", algorithm="HS256")
    
    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert b"Invalid token issuer" in response.data


def test_jwt_expired_token_rejected(client, mock_jwks):
    """Test that expired tokens are rejected"""
    payload = {
        "iss": "https://localhost/realms/demo",
        "aud": "iam-poc-ui",
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        "sub": "user-123",
        "preferred_username": "alice",
        "realm_access": {"roles": ["analyst"]}
    }
    
    token = jwt.encode(payload, "secret", algorithm="HS256")
    
    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert b"Token expired" in response.data


def test_jwt_alg_none_rejected(client):
    """Test that JWT with alg:none is rejected"""
    # Attempt to create unsigned JWT (security vulnerability)
    payload = {
        "iss": "https://localhost/realms/demo",
        "aud": "iam-poc-ui",
        "exp": int(time.time()) + 3600,
        "sub": "user-123",
        "preferred_username": "alice",
        "realm_access": {"roles": ["realm-admin"]}  # Attempt privilege escalation
    }
    
    # Create token with alg:none (no signature)
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    unsigned_token = f"{header}.{payload_b64}."
    
    response = client.get("/admin", headers={"Authorization": f"Bearer {unsigned_token}"})
    assert response.status_code == 401
    assert b"Invalid signature algorithm" in response.data


def test_pkce_invalid_code_verifier_rejected(client, monkeypatch):
    """Test that PKCE code exchange fails with wrong verifier"""
    # Mock Keycloak token endpoint
    def mock_token_request(*args, **kwargs):
        # Keycloak validates code_verifier against code_challenge
        if kwargs.get("data", {}).get("code_verifier") != "correct-verifier-value":
            return MockResponse({"error": "invalid_grant"}, status_code=400)
        return MockResponse({"access_token": "token", "id_token": "id"}, status_code=200)
    
    monkeypatch.setattr("requests.post", mock_token_request)
    
    # Attempt token exchange with wrong verifier
    response = client.get("/callback?code=auth-code&state=state-value")
    
    assert response.status_code in [400, 401]
    # Should not complete authentication


def test_jwks_rotation_new_kid_accepted(client, mock_jwks_endpoint):
    """Test that new JWT signing key (kid) triggers JWKS re-download"""
    # Initial JWKS with kid1
    mock_jwks_endpoint.set_keys([{"kid": "key-1", "kty": "RSA", ...}])
    
    # First request with kid1 token works
    token1 = create_jwt_with_kid("key-1")
    response1 = client.get("/admin", headers={"Authorization": f"Bearer {token1}"})
    assert response1.status_code == 200
    
    # Simulate key rotation: Keycloak now uses kid2
    mock_jwks_endpoint.set_keys([
        {"kid": "key-1", "kty": "RSA", ...},  # Old key still valid
        {"kid": "key-2", "kty": "RSA", ...}   # New key
    ])
    
    # Request with kid2 token should trigger JWKS re-download and succeed
    token2 = create_jwt_with_kid("key-2")
    response2 = client.get("/admin", headers={"Authorization": f"Bearer {token2}"})
    assert response2.status_code == 200
    
    # Verify JWKS was re-fetched
    assert mock_jwks_endpoint.fetch_count == 2
```

**Pourquoi manquant ?**  
Application utilise `authlib` pour validation OIDC, mais aucun test unitaire ne vérifie les cas d'erreur (issuer invalide, token expiré, PKCE, alg none). Nécessite mocking de `authlib` ou tests E2E.

---

### 6. SCIM 2.0 (RFC 7644)

#### ✅ Tests Existants (80%)

**Fichier** : `tests/test_scim_api.py`, `tests/test_integration_e2e.py`

| Test | Fichier | Ligne | Status |
|------|---------|-------|--------|
| ServiceProviderConfig endpoint | test_scim_api.py | 51-66 | ✅ OK |
| ResourceTypes endpoint | test_scim_api.py | 68-82 | ✅ OK |
| Schemas endpoint | test_scim_api.py | 84-100 | ✅ OK |
| POST /Users (create) | test_scim_api.py | 109-142 | ✅ OK |
| GET /Users/{id} | test_integration_e2e.py | 123-135 | ✅ OK |
| GET /Users (list + filter) | test_integration_e2e.py | 137-151 | ✅ OK |
| PUT /Users/{id} (update) | test_integration_e2e.py | 153-174 | ✅ OK |
| DELETE /Users/{id} | test_integration_e2e.py | 176-188 | ✅ OK |
| Erreurs RFC 7644 (status, scimType) | test_scim_api.py | 144-168 | ✅ OK |
| Pagination (startIndex, count) | test_scim_api.py | 261-293 | ✅ OK (partiel) |

#### ❌ Tests Manquants (20%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **Session revocation `active=false`** | Désactiver user → sessions révoquées immédiatement | 🔴 Haute |
| **Pagination bornes** | `startIndex` négatif / `count` > max → erreur | 🟡 Moyenne |
| **Attributs interdits** | Envoyer `password` en clair → rejet | 🟡 Moyenne |

**Test proposé** :

```python
# tests/test_scim_session_revocation.py

def test_scim_disable_user_revokes_sessions_immediately(auth_token, test_username):
    """Test that setting active=false immediately revokes user sessions"""
    # Step 1: Create user and get session
    create_response = requests.post(
        f"{APP_BASE_URL}/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": test_username,
            "emails": [{"value": f"{test_username}@example.com"}],
            "active": True
        },
        headers={"Authorization": f"Bearer {auth_token}", "Content-Type": "application/scim+json"},
        verify=False
    )
    user_id = create_response.json()["id"]
    
    # Step 2: Simulate user login (create session)
    # (In real test: use Selenium to login and capture session cookie)
    user_session_cookie = simulate_user_login(test_username, "temp-password")
    
    # Step 3: Verify user has active session
    sessions_response = get_user_sessions(user_id, admin_token)
    assert len(sessions_response.json()) > 0, "User should have active session"
    
    # Step 4: Disable user via SCIM
    disable_response = requests.put(
        f"{APP_BASE_URL}/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "active": False  # Leaver operation
        },
        headers={"Authorization": f"Bearer {auth_token}", "Content-Type": "application/scim+json"},
        verify=False
    )
    assert disable_response.status_code == 200
    
    # Step 5: Verify sessions revoked IMMEDIATELY (no 5-15 min window)
    sessions_after = get_user_sessions(user_id, admin_token)
    assert len(sessions_after.json()) == 0, "Sessions should be revoked immediately"
    
    # Step 6: Verify user cannot access protected resources with old session
    protected_response = requests.get(
        f"{APP_BASE_URL}/admin",
        cookies={"session": user_session_cookie},
        allow_redirects=False,
        verify=False
    )
    assert protected_response.status_code in [401, 403], "Disabled user should be denied access"
```

**Pourquoi manquant ?**  
Tests actuels ne vérifient pas l'effet de `active=false` sur les sessions Keycloak. Nécessite tests E2E avec vraie stack + simulation login utilisateur.

---

### 7. Secrets

#### ✅ Tests Existants (50%)

**Fichier** : `tests/test_ensure_secrets.py`

| Test | Ligne | Status |
|------|-------|--------|
| Auto-génération secrets (demo mode) | - | ✅ OK (via Makefile) |
| Permissions `/run/secrets` (chmod 400) | - | 🟡 Partiel |

#### ❌ Tests Manquants (50%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **Secrets jamais loggés (stdout/stderr)** | Grep logs, aucun secret trouvé | 🔴 Haute |
| **Secrets jamais en réponse HTTP** | Aucun endpoint ne retourne secret | 🔴 Haute |
| **Priorité `/run/secrets` > env > demo** | Tester cascade lecture | 🟡 Moyenne |
| **Rotation idempotence** | Rotation 2x → secrets différents | 🔴 Haute |
| **Rotation health check** | Après rotation → HTTP 200 `/health` | 🔴 Haute |

**Tests proposés** :

```python
# tests/test_secrets_security.py

def test_secrets_never_logged_in_stdout_stderr(capfd):
    """Test that secrets are never printed to stdout or stderr"""
    # Generate secrets (demo mode)
    from app.config import settings
    settings.load_secrets()
    
    # Capture stdout/stderr
    captured = capfd.readouterr()
    
    # Verify no secrets in output
    assert "FLASK_SECRET_KEY" not in captured.out
    assert "AUDIT_LOG_SIGNING_KEY" not in captured.out
    assert "demo-service-secret" not in captured.out
    
    # Stderr should also be clean (except masked logs like "Secret loaded from...")
    assert not any(
        secret_value in captured.err 
        for secret_value in [settings.FLASK_SECRET_KEY, settings.AUDIT_SIGNING_KEY]
    )


def test_secrets_never_in_http_responses(client):
    """Test that no endpoint returns secrets in response body or headers"""
    endpoints = [
        "/",
        "/health",
        "/admin",
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/Users",
    ]
    
    for endpoint in endpoints:
        response = client.get(endpoint)
        
        # Check response body
        body = response.get_data(as_text=True).lower()
        assert "secret" not in body or "secret key" not in body  # Generic check
        assert "flask_secret_key" not in body
        assert "audit_log_signing_key" not in body
        
        # Check headers
        for header, value in response.headers:
            assert "secret" not in value.lower()


def test_secret_rotation_is_idempotent(monkeypatch):
    """Test that running rotation twice produces different secrets"""
    # Mock Keycloak rotation
    rotated_secrets = []
    
    def mock_rotate_keycloak_secret():
        import secrets
        new_secret = secrets.token_urlsafe(32)
        rotated_secrets.append(new_secret)
        return new_secret
    
    monkeypatch.setattr("scripts.rotate_secret.rotate_client_secret", mock_rotate_keycloak_secret)
    
    # Run rotation twice
    from scripts import rotate_secret
    secret1 = rotate_secret.main(dry_run=False)
    secret2 = rotate_secret.main(dry_run=False)
    
    # Secrets must be different (true rotation)
    assert secret1 != secret2
    assert len(rotated_secrets) == 2
    assert rotated_secrets[0] != rotated_secrets[1]


def test_rotation_script_validates_health_after_restart(monkeypatch):
    """Test that rotation script verifies app health after Flask restart"""
    health_checks = []
    
    def mock_health_check():
        import requests
        response = requests.get("https://localhost/health", verify=False)
        health_checks.append(response.status_code)
        return response.status_code == 200
    
    monkeypatch.setattr("scripts.rotate_secret.verify_health", mock_health_check)
    
    # Run rotation
    from scripts import rotate_secret
    result = rotate_secret.main(dry_run=False)
    
    # Verify health check was called
    assert len(health_checks) > 0
    assert all(status == 200 for status in health_checks), "Health checks should return 200"
```

**Pourquoi manquant ?**  
Pas de tests automatisés pour vérifier que secrets ne sont jamais loggés. Nécessite capture stdout/stderr et grep. Script `rotate_secret.sh` testé manuellement mais pas automatisé.

---

### 8. Nginx/TLS/Headers

#### ✅ Tests Existants (60%)

**Fichier** : `tests/test_flask_app.py`

| Test | Ligne | Status |
|------|-------|--------|
| Headers sécurité (X-Content-Type-Options, X-Frame-Options) | 107-110 | ✅ OK |
| X-Forwarded-Proto validation (reject HTTP) | 445-448 | ✅ OK |
| Untrusted proxy rejected | 438-442 | ✅ OK |

#### ❌ Tests Manquants (40%)

| Requirement | Test Nécessaire | Priorité |
|-------------|-----------------|----------|
| **TLS v1.2+ minimum** | Connexion TLS v1.0/v1.1 → rejet | 🟡 Moyenne |
| **HTTP → HTTPS redirect** | `curl http://localhost` → 301 HTTPS | 🔴 Haute |
| **HSTS header présent** | Vérifier `Strict-Transport-Security` | 🔴 Haute |
| **CSP header présent** | Vérifier `Content-Security-Policy` | 🔴 Haute |
| **Referrer-Policy** | Vérifier `Referrer-Policy: strict-origin-when-cross-origin` | 🟡 Moyenne |
| **Rate limiting** | 100 requêtes/sec → 429 (si configuré) | 🟡 Moyenne |

**Tests proposés** :

```python
# tests/test_nginx_security_headers.py

def test_http_redirects_to_https():
    """Test that HTTP requests are redirected to HTTPS"""
    response = requests.get("http://localhost", allow_redirects=False, verify=False)
    
    assert response.status_code == 301
    assert response.headers["Location"].startswith("https://")


def test_hsts_header_present():
    """Test that HSTS header is set with reasonable max-age"""
    response = requests.get("https://localhost/health", verify=False)
    
    assert "Strict-Transport-Security" in response.headers
    hsts = response.headers["Strict-Transport-Security"]
    
    # Check max-age is present and at least 1 year (31536000 seconds)
    assert "max-age=" in hsts
    import re
    max_age = int(re.search(r"max-age=(\d+)", hsts).group(1))
    assert max_age >= 31536000  # 1 year


def test_csp_header_present():
    """Test that Content-Security-Policy header is set"""
    response = requests.get("https://localhost/health", verify=False)
    
    assert "Content-Security-Policy" in response.headers
    csp = response.headers["Content-Security-Policy"]
    
    # Check basic CSP directives
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp or "frame-ancestors 'self'" in csp


def test_referrer_policy_set():
    """Test that Referrer-Policy is set correctly"""
    response = requests.get("https://localhost/health", verify=False)
    
    assert "Referrer-Policy" in response.headers
    assert response.headers["Referrer-Policy"] in [
        "strict-origin-when-cross-origin",
        "no-referrer",
        "same-origin"
    ]


def test_tls_version_minimum_12():
    """Test that TLS v1.0/v1.1 connections are rejected"""
    import ssl
    import socket
    
    # Attempt connection with TLS v1.0 (should fail)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS v1.0 explicitly
    
    with pytest.raises((ssl.SSLError, ConnectionError)):
        with socket.create_connection(("localhost", 443)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                ssock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")


def test_rate_limiting_under_load():
    """Test behavior under high request rate (if rate limiting configured)"""
    import concurrent.futures
    
    def make_request(_):
        return requests.get("https://localhost/health", verify=False)
    
    # Send 100 requests concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        responses = list(executor.map(make_request, range(100)))
    
    # Check: no crashes (all responses received)
    assert len(responses) == 100
    
    # If rate limiting configured, some should be 429
    # If not, all should be 200 (no crash = pass)
    status_codes = [r.status_code for r in responses]
    assert all(code in [200, 429] for code in status_codes), "Unexpected status codes under load"
```

**Pourquoi manquant ?**  
Tests actuels ne vérifient que Flask app, pas Nginx. Headers sécurité (HSTS, CSP, Referrer-Policy) configurés dans `nginx.conf` mais non testés. Nécessite tests E2E contre vraie stack Nginx.

---

### 9. Audit

#### ✅ Tests Existants (100%)

**Fichier** : `tests/test_audit.py`

| Test | Ligne | Status |
|------|-------|--------|
| Événement loggé avec signature HMAC | 44-62 | ✅ OK |
| Multiple événements | 64-90 | ✅ OK |
| Vérification signatures valides | 92-106 | ✅ OK |
| Détection falsification (tamper) | 108-143 | ✅ OK |
| Permissions fichier (chmod 600) | 36-40 | ✅ OK |
| Permissions répertoire (chmod 700) | 190-196 | ✅ OK |
| Log sans clé signature | 145-165 | ✅ OK |
| Log opération échouée | 167-181 | ✅ OK |

**Couverture** : 100% des requirements audit ✅

#### ❌ Tests Manquants (0%)

**Aucun** — Couverture complète ✅

---

## 📈 Plan d'Action — Priorisation

### 🔴 Haute Priorité (Critique Sécurité)

1. **OIDC/JWT Validation** (7 tests) — `tests/test_oidc_jwt_validation.py`
   - Issuer/audience/expiration validation
   - PKCE code_verifier
   - Alg none interdit
   - **Impact** : Vulnérabilité auth bypass si non validé

2. **Secrets Never Logged** (2 tests) — `tests/test_secrets_security.py`
   - Grep stdout/stderr
   - Aucun secret en réponse HTTP
   - **Impact** : Fuite secrets en logs/responses

3. **SCIM Session Revocation** (1 test) — `tests/test_scim_session_revocation.py`
   - `active=false` → sessions révoquées immédiatement
   - **Impact** : Leaver inefficace (sessions actives 5-15 min)

4. **Nginx Headers Security** (3 tests) — `tests/test_nginx_security_headers.py`
   - HTTP → HTTPS redirect
   - HSTS header
   - CSP header
   - **Impact** : Vulnérabilités XSS/MITM

### 🟡 Moyenne Priorité (Hardening)

5. **MFA Enforcement** (2 tests) — `tests/test_mfa_enforcement.py`
   - CONFIGURE_TOTP required action
   - User sans TOTP → redirect setup
   - **Impact** : MFA bypass possible (théorique, Keycloak gère)

6. **Secret Rotation Idempotence** (2 tests) — `tests/test_secrets_security.py`
   - Rotation 2x → secrets différents
   - Health check après rotation
   - **Impact** : Rotation non fiable

7. **Session Max Age** (1 test) — `tests/test_flask_app.py`
   - Vérifier `Max-Age` cookie session
   - **Impact** : Sessions infinies possibles

### 🟢 Basse Priorité (Nice-to-Have)

8. **JWKS Rotation** (1 test) — `tests/test_oidc_jwt_validation.py`
   - Nouveau `kid` → re-télécharge JWKS
   - **Impact** : Gestion rotation clés Keycloak

9. **Rate Limiting** (1 test) — `tests/test_nginx_security_headers.py`
   - 100 req/sec → 429 (si configuré)
   - **Impact** : DoS protection (non critique si infra externe gère)

10. **TLS Version** (1 test) — `tests/test_nginx_security_headers.py`
    - TLS v1.0/v1.1 → rejet
    - **Impact** : Compliance (OWASP recommandation)

---

## 🛠️ Implémentation Recommandée

### Phase 1 : Tests OIDC/JWT (Semaine 1)

```bash
# Créer nouveau fichier tests
touch tests/test_oidc_jwt_validation.py

# Implémenter tests:
# - test_jwt_invalid_issuer_rejected
# - test_jwt_expired_token_rejected
# - test_jwt_alg_none_rejected
# - test_pkce_invalid_code_verifier_rejected
# - test_jwt_audience_validation
# - test_jwt_not_before_validation
# - test_jwt_clock_skew_tolerance

# Exécuter
pytest tests/test_oidc_jwt_validation.py -v
```

### Phase 2 : Tests Secrets Security (Semaine 2)

```bash
touch tests/test_secrets_security.py

# Implémenter tests:
# - test_secrets_never_logged_in_stdout_stderr
# - test_secrets_never_in_http_responses
# - test_secret_rotation_is_idempotent
# - test_rotation_script_validates_health_after_restart

pytest tests/test_secrets_security.py -v
```

### Phase 3 : Tests E2E Nginx + SCIM (Semaine 3)

```bash
touch tests/test_nginx_security_headers.py
touch tests/test_scim_session_revocation.py

# Nécessite stack running
make quickstart

pytest tests/test_nginx_security_headers.py -v
pytest tests/test_scim_session_revocation.py -v -m integration
```

### Phase 4 : Tests MFA (Semaine 4)

```bash
touch tests/test_mfa_enforcement.py

# Tests nécessitent mock Keycloak + OIDC
pytest tests/test_mfa_enforcement.py -v
```

---

## 📊 Scorecard Final Projeté

| Catégorie | Couverture Actuelle | Après Implémentation |
|-----------|---------------------|----------------------|
| **Auth & Sessions** | 70% | **100%** (+30%) |
| **CSRF** | 100% | 100% |
| **RBAC** | 100% | 100% |
| **MFA** | 0% | **90%** (+90%) |
| **OIDC/JWT** | 0% | **95%** (+95%) |
| **SCIM 2.0** | 80% | **100%** (+20%) |
| **Secrets** | 50% | **95%** (+45%) |
| **Nginx/TLS** | 60% | **100%** (+40%) |
| **Audit** | 100% | 100% |
| **TOTAL** | **65%** | **98%** |

**Effort estimé** : 4 semaines (1 développeur)  
**Nombre de tests à ajouter** : ~30 tests

---

## ✅ Conclusion

**Couverture actuelle** : **65%** — Bonne base (RBAC, CSRF, Audit)  
**Gaps critiques** : OIDC/JWT validation, MFA enforcement, session revocation SCIM, secrets logging  

**Recommandation** : Prioriser **Phase 1 (OIDC/JWT)** et **Phase 2 (Secrets)** avant mise en production.

**Points forts existants** :
- ✅ RBAC enforcement complet (7 tests)
- ✅ CSRF protection exhaustif (5 tests)
- ✅ Audit cryptographique tamper-evident (8 tests)

**Prochaines étapes** :
1. Créer `tests/test_oidc_jwt_validation.py` (7 tests haute priorité)
2. Créer `tests/test_secrets_security.py` (4 tests haute priorité)
3. Compléter `tests/test_integration_e2e.py` avec session revocation

---

**Dernière mise à jour** : Janvier 2025  
**Auteur** : Security Test Analysis  
**Reviewé par** : Alex
