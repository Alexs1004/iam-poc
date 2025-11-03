# Security Design — Mini IAM Lab

Authoritative view of the security controls implemented in this SCIM PoC. Derived from `app/api/*`, `app/core/*`, `app/flask_app.py`, `proxy/nginx.conf`, and tests under `tests/test_api_*`.

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
| Audit | `scripts/audit.log_jml_event` HMAC signature + chmod 600 | `scripts/audit.py` |
| CSRF/UI hardening | CSRF tokens for admin UI, cookies `Secure`/`HttpOnly`/`SameSite=Lax` | `app/flask_app.py::_register_middleware` |
| Session security | Flask session secret key with rotation support (SECRET_KEY_FALLBACKS) | `app/flask_app.py:35-43` |

## Threat considerations
- **Bearer theft**: tokens are required on every request; expired/invalid tokens yield 401 with SCIM error payload.
- **Scope abuse**: write methods refuse tokens missing `scim:write`. Service account exception noted above; rotate secrets regularly.
- **Payload tampering**: PATCH handler only allows `replace active` with boolean value; malformed JSON returns 400.
- **Audit repudiation**: each JML event is signed; `make verify-audit` recomputes hashes to detect tampering.
- **Secrets leakage**: production mode loads secrets from Azure Key Vault (soft-delete + purge protection recommended). Demo mode generates ephemeral secrets (printed to stdout).
- **Rate limiting**: not applied in code; rely on reverse proxy/WAF (TODO: add nginx `limit_req` or App Gateway policy).

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
- `curl` without `Authorization` → `401 unauthorized` SCIM error.
- `curl -H "Content-Type: application/json"` on POST → `415 invalidSyntax`.
