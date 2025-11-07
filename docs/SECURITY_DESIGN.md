# Security Design — Mini IAM Lab

> **Swiss Compliance Positioning**: nLPD, GDPR, FINMA compliant architecture  
> **Standards**: OWASP ASVS L2, RFC 7644 (SCIM 2.0), RFC 6749 (OAuth 2.0), NIST 800-63B

Authoritative view of the security controls implemented in this SCIM PoC. Derived from `app/api/*`, `app/core/*`, `app/flask_app.py`, `proxy/nginx.conf`, and tests under `tests/test_api_*`.

---

## Swiss Compliance Context

### nLPD (new Swiss Data Protection Act)
- **Traceability**: HMAC-SHA256 audit trail with ISO 8601 timestamps
- **Retention**: Logs with restrictive permissions (400), planned rotation
- **Transparency**: SCIM API for data portability

### GDPR (General Data Protection Regulation)
- **Right to erasure**: Soft-delete via `PATCH .../Users/{id}` (`active=false`)
- **Portability**: JSON export via `GET /scim/v2/Users` (RFC 7644 standard)
- **Consent**: Audit log traces all modifications (`jml-events.jsonl`)

### FINMA (Swiss Financial Market Supervisory Authority)
- **Non-repudiation**: HMAC-SHA256 signatures on each JML event
- **Integrity**: Tampering detection via `make verify-audit`
- **Auditability**: Correlation-ID, timestamps, actor tracking

---

## 🚨 Known TODO (Temporary Scope Bypass)

**Current**: `automation-cli` service account is allowed without explicit scopes (`is_service_account` check in `app/api/scim.py`).  
**Intent**: Will be removed once service client scopes are finalized in Keycloak configuration.  
**Mitigation**: Service account tokens are still validated for signature, issuer, and expiration.

## Guiding principles
- Secrets never live in the repo (`/run/secrets`, Azure Key Vault in production).
- Every SCIM call must authenticate (OAuth bearer token).
- Audit trail must be tamper-evident (HMAC-SHA256 per event).
- HTTP surface hardened with TLS 1.2+, HSTS, CSP, and secure cookies.
- Minimal scope exposure: `scim:read` vs `scim:write` enforced per verb.

## Implemented controls
| Category | Control | Evidence |
|----------|---------|----------|
| Transport | TLS 1.2/1.3, HSTS (1y), CSP deny-all | `proxy/nginx.conf` |
| AuthN | OAuth 2.0 bearer (`Authorization: Bearer …`) | `app/api/scim.py` before_request |
| AuthZ | Scope checks (`scim:read`, `scim:write`) | `app/api/scim.py` lines 70-110 |
| Service account bypass | `automation-cli` allowed even without scopes (temporary) | `app/api/scim.py` (`is_service_account`) |
| Input validation | Content-Type enforcement (`application/scim+json`), schema checks | `app/api/scim.py::validate_request`, `patch_user` |
| Filtering guard | Only `userName eq "value"` accepted | `app/core/provisioning_service.list_users_scim` |
| Secrets | `/run/secrets` + Azure Key Vault loader | `app/core/provisioning_service._load_secret_from_file`, `settings.service_client_secret_resolved` |
| Password security | Temp passwords NEVER returned in API/UI (production) | RFC 7644 § 7.7, `app/core/keycloak.send_password_reset_email` |
| Password reset | Keycloak native flow (secure token + email) | NIST SP 800-63B § 5.1.1.2, OWASP ASVS V2.1.12 |
| Audit | `scripts/audit.log_jml_event` HMAC signature + chmod 600 | `scripts/audit.py` |
| CSRF/UI hardening | CSRF tokens for admin UI, cookies `Secure`/`HttpOnly`/`SameSite=Lax` | `app/flask_app.py::_register_middleware` |
| Session security | Flask session secret key with rotation support (SECRET_KEY_FALLBACKS) | `app/flask_app.py:35-43` |

## Threat considerations
- **Bearer theft**: tokens are required on every request; expired/invalid tokens yield 401 with SCIM error payload.
- **Scope abuse**: write methods refuse tokens missing `scim:write`. Service account exception noted above; rotate secrets regularly.
- **Payload tampering**: PATCH handler only allows `replace active` with boolean value; malformed JSON returns 400.
- **Password exposure** ✅ **OWASP A07:2021 / RFC 7644 § 7.7**: Temporary passwords NEVER returned in SCIM responses or UI flash messages in production mode (`DEMO_MODE=false`). Demo mode displays passwords with prominent warning (`⚠️ DEMO MODE`). Production uses email-based password reset links. **Test**: `tests/unit/test_admin_password_security.py` validates no leakage.
- **Audit repudiation** ✅ **nLPD/FINMA compliance**: each JML event is signed with HMAC-SHA256; `make verify-audit` recomputes hashes to detect tampering (non-repudiation requirement for financial sector).
- **Secrets leakage**: production mode loads secrets from Azure Key Vault (soft-delete + purge protection recommended). Demo mode generates ephemeral secrets (printed to stdout).
- **Rate limiting**: not applied in code; rely on reverse proxy/WAF (TODO: add nginx `limit_req` or App Gateway policy).
- **Data portability** ✅ **RGPD compliance**: SCIM standard enables data export via `GET /Users` (RFC 7644).
- **Right to erasure** ✅ **RGPD compliance**: Soft-delete via `PATCH .../Users/{id}` with `active=false` (reversible, audit-logged).

## Error handling model
`ScimError` guarantees RFC 7644 compliant responses:
- Body always includes `schemas`, `status`, `detail`, optional `scimType`.
- Common detail strings:
  - Missing header → `"Authorization header missing. Provide 'Authorization: Bearer <token>'."`
  - Wrong scheme → `"Authorization header must use Bearer token scheme: 'Authorization: Bearer <token>'."`
  - Empty token → `"Bearer token is empty."`
  - Wrong media type → `"Content-Type must be application/scim+json"`
  - Unimplemented feature → `"Requested SCIM feature is not available in this PoC."`

## Open gaps / TODO
- Remove service-account scope bypass once Keycloak client scopes are configured.
- Add automated rate limiting / WAF rules for SCIM endpoints.
- **Swiss Compliance Roadmap** :
  - [ ] Archive audit logs to Azure Blob Storage with immutability policy (nLPD retention)
  - [ ] Implement GDPR data subject access request (DSAR) endpoint
  - [ ] Add audit log export to SIEM (Azure Sentinel) for FINMA compliance
  - [ ] Document data residency strategy (Swiss data center availability)

---

## 🔗 Related Documentation
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis, MITRE ATT&CK mapping
- [API Reference](API_REFERENCE.md) — SCIM 2.0 endpoints, OAuth scopes
- [Deployment Guide](DEPLOYMENT_GUIDE.md) — Azure Key Vault, Managed Identity
- [Swiss Hiring Pack](Hiring_Pack.md) — CV ↔ Repo skills mapping
- Extend audit shipping to immutable storage (Azure Blob immutability policy).
- Instrument Flask with OpenTelemetry/App Insights for centralised monitoring.

## 🎓 Why This Matters (Security Learning)

### Minimal Scope Principle (OWASP / NIST)
- **read vs write segregation**: Prevents privilege escalation - listing users doesn't grant modification rights
- **Service account isolation**: Dedicated client for automation, separate from user accounts

### Secret Rotation & Management
- **Azure Key Vault**: Centralized secret storage with access policies and audit trail
- **No secrets in repo**: Development secrets auto-generated, production secrets externally managed

### Defense in Depth
- **Multiple layers**: TLS (transport) + OAuth (application) + RBAC (business logic)
- **Fail secure**: Invalid tokens → 401, wrong content type → 415, unsupported operations → 501

## Verification checklist
- `make load-secrets` (Azure) → `/run/secrets/*` populated.
- `make verify-audit` → tamper check succeeds.
- `pytest tests/test_scim_oauth_validation.py` → confirms OAuth failures/successes.
- `pytest tests/unit/test_admin_password_security.py` → validates password security.
- `curl` without `Authorization` → `401 unauthorized` SCIM error.
- `curl -H "Content-Type: application/json"` on POST → `415 invalidSyntax`.

---

## 🔐 Password Management Architecture

### Design Decision: Keycloak Native Flow

**We use Keycloak's `execute-actions-email` endpoint instead of custom token generation.**

**Rationale**:
- ✅ **Security**: Keycloak is SOC2/ISO 27001 certified, audited by security experts
- ✅ **Standards**: Implements NIST SP 800-63B password reset guidelines
- ✅ **Crypto**: Uses cryptographically secure token generation (256 bits entropy)
- ✅ **Maintenance**: Zero custom crypto code to maintain
- ✅ **Audit**: Built-in event logging (who reset password, when, from where)
- ✅ **One-time use**: Tokens automatically invalidated after use
- ✅ **Expiration**: Default 5-minute token lifetime (configurable)

**Compliance**:
- **OWASP ASVS V2.1.12**: Password reset via secure tokenized link
- **RFC 7644 § 7.7**: "The password attribute MUST NOT be returned by default"
- **NIST SP 800-63B § 5.1.1.2**: Reset via out-of-band channel (email)

### Production Flow

```
1. Admin creates user via UI (/admin/joiner)
   ↓
2. provisioning_service.create_user_scim_like()
   ├── Creates user in Keycloak (temporary=True)
   ├── If DEMO_MODE=false:
   │   └── Calls keycloak.send_password_reset_email()
   │       ├── Keycloak generates secure token
   │       ├── Sends email with reset link
   │       └── Logs event in Keycloak audit trail
   └── Returns SCIM User (no _tempPassword field)
   ↓
3. User receives email:
   Subject: Welcome to IAM Platform - Set Your Password
   Link: https://keycloak.domain.com/.../reset-credentials?key=<TOKEN>
   ↓
4. User clicks → Keycloak reset password page
   ↓
5. User sets password → redirect to /auth/login
```

### Demo Mode (Local Testing)

```
1. Admin creates user via UI
   ↓
2. If DEMO_MODE=true:
   ├── Password included in SCIM response (_tempPassword field)
   ├── Flash message: "⚠️ DEMO MODE: Temporary password: XYZ"
   └── Red warning banner in UI
```

**Security Safeguards**:
- ⚠️ Default `.env.production` has `DEMO_MODE=false`
- ⚠️ Automated tests verify password NOT in response when `DEMO_MODE=false`
- ⚠️ Visual warning banner in UI when demo mode active

### SMTP Configuration

Password reset emails require SMTP configuration in Keycloak:

**Via Keycloak Admin Console**:
1. Realm Settings → Email
2. Configure:
   - From: `noreply@domain.com`
   - Host: `smtp.office365.com` (or Gmail, SendGrid, etc.)
   - Port: `587`
   - Enable StartTLS: ✅
   - Enable Authentication: ✅
   - Username: SMTP user
   - Password: SMTP password

**Via Script**:
```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=noreply@example.com
export SMTP_PASSWORD='app-specific-password'
python scripts/configure_smtp.py
```

**Test**:
```bash
# Set production mode
echo "DEMO_MODE=false" >> .env

# Create user via UI
# → User should receive email with reset link
```

### Error Handling

If email delivery fails:
- User is still created in Keycloak
- SCIM response includes `meta.emailDeliveryFailed=true`
- Admin can manually send reset email via Keycloak Admin UI:
  - Users → Select user → Actions → Send Reset Email

### Implementation

**Core function** (`app/core/keycloak/users.py`):
```python
def send_password_reset_email(kc_url, token, realm, user_id, redirect_uri):
    """Trigger Keycloak to send password reset email."""
    response = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/execute-actions-email",
        headers={"Authorization": f"Bearer {token}"},
        json=["UPDATE_PASSWORD"],
        params={"redirect_uri": redirect_uri, "client_id": "flask-app"}
    )
    response.raise_for_status()
```

**Used by** (`app/core/provisioning_service.py`):
```python
def create_user_scim_like(payload, correlation_id=None):
    # ... create user in Keycloak ...
    
    if DEMO_MODE:
        scim_user["_tempPassword"] = temp_password
    else:
        send_password_reset_email(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, user_id)
    
    return scim_user
```

**Test coverage**:
- `tests/unit/test_admin_password_security.py::test_joiner_no_password_in_flash_when_production_mode`
- `tests/unit/test_admin_password_security.py::test_joiner_password_visible_in_demo_mode`


