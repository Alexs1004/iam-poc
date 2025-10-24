# IAM PoC - AI Coding Agent Instructions

## Project Overview
Enterprise IAM demonstration showcasing Keycloak-based identity management with Flask UI, SCIM 2.0 API, and Azure Key Vault integration. Docker Compose stack with HTTPS reverse proxy (nginx), implementing OIDC + PKCE, RBAC, and JML (Joiner/Mover/Leaver) automation.

## Architecture & Data Flow

### Service Boundaries
```
Browser → Nginx (TLS) → Flask/Gunicorn → Keycloak (OIDC)
                              ↓
                    provisioning_service.py → scripts/jml.py → Keycloak Admin API
                              ↓
                         audit.py (HMAC-SHA256 signed logs)
```

**Critical:** Both Flask admin UI (`/admin/*`) and SCIM API (`/scim/v2/*`) share `app/core/provisioning_service.py` for all JML operations. Never duplicate business logic across interfaces.

### Configuration Priority
1. **Demo mode** (`DEMO_MODE=true`): Auto-generates secrets, uses hardcoded defaults (service secret: `demo-service-secret`)
2. **Production mode** (`DEMO_MODE=false`): Loads from Azure Key Vault → `/run/secrets` (Docker secrets pattern)
3. Secret resolution: `/run/secrets/{name}` → env var → demo fallback (see `app/config/settings.py`)

**Guards:** `DEMO_MODE=true` + `AZURE_USE_KEYVAULT=true` is invalid. Runtime guards in `flask_app.py` and `provisioning_service.py` force correction. Permanent fix: `make validate-env`.

## Essential Developer Workflows

### Zero-Config Start (Recommended)
```bash
make quickstart   # Auto-generates .env from .env.demo, starts stack + JML demo
make demo-jml     # Rerun JML automation against running stack
make fresh-demo   # Full reset: volumes + secrets + certificates + demo
```

**Idempotency:** `make quickstart` is safe to run repeatedly. Secrets preserved, no duplicate containers.

### Testing Workflow
```bash
make pytest       # Unit tests (mocked Keycloak)
make pytest-e2e   # Integration tests (requires running stack)
```

**Critical:** Tests set `DEMO_MODE=true` in fixtures. Never run tests against production Key Vault.

### Secret Rotation (Production Only)
```bash
make rotate-secret      # Orchestrated: Keycloak → Key Vault → Restart Flask → Health-check
make rotate-secret-dry  # Dry-run validation
```

Refuses to run if `DEMO_MODE=true`. Updates Keycloak client credential, syncs to Key Vault, restarts Flask.

## Code Conventions

### Module Structure (Post-Refactoring)
- `app/config/settings.py` — Centralized config loader (Azure KV, env vars, validation)
- `app/core/` — Business logic (provisioning, RBAC, validators) - **pure Python, no Flask dependencies**
- `app/api/` — Thin Flask blueprints (routes only, delegate to `core/`)
- `scripts/jml.py` — Keycloak Admin API client (realm/user/role CRUD)

**Pattern:** Routes validate input → Call `provisioning_service.py` → Service calls `jml.py` → Keycloak Admin API

### RBAC Enforcement
```python
from app.core.rbac import user_has_role, is_authenticated, current_user_context

# Decorators in app/api/admin.py
@require_jml_operator  # Requires iam-operator or realm-admin roles
@require_admin_view    # Allows analyst, manager, iam-operator, realm-admin
```

**Role hierarchy:**
- `realm-admin` / `iam-operator`: Full JML operations
- `manager` / `analyst`: View-only (audit logs, user statuses)

### SCIM API Patterns
- Use `ScimError(status, detail, scim_type)` for all errors (RFC 7644 compliant)
- All mutating ops (`POST`, `PUT`, `DELETE`) require `Content-Type: application/scim+json`
- Transformations: `keycloak_to_scim()` / `scim_to_keycloak()` in `provisioning_service.py`
- Session revocation on user disable: `jml.revoke_user_sessions()` called automatically

### Audit Logging
```python
from scripts import audit

audit.log_jml_event(
    event_type="mover",  # joiner|mover|leaver|scim_*
    username="alice",
    operator="admin",
    realm="demo",
    details={"from_role": "analyst", "to_role": "manager"},
    success=True
)
```

**Security:** HMAC-SHA256 signature on every event using `AUDIT_LOG_SIGNING_KEY`. Append-only `.runtime/audit/jml-events.jsonl`.

## Integration Points

### Keycloak Communication
- **Internal URL:** `http://keycloak:8080` (Docker network)
- **Public URL:** `https://localhost/keycloak` (via nginx proxy)
- **Admin API:** Requires bearer token from `jml.get_admin_token()` or `jml.get_service_account_token()`
- **Service account:** `automation-cli` client (secret: `demo-service-secret` in demo mode)

### Nginx Reverse Proxy
- All traffic flows through nginx (enforces TLS)
- Flask validates `X-Forwarded-*` headers against `TRUSTED_PROXY_IPS` (default: `127.0.0.1/32, ::1/128`)
- ProxyFix middleware configured with `x_for=1, x_proto=1, x_host=1`

### Azure Key Vault
- **Authentication:** `DefaultAzureCredential` (requires `az login` or managed identity)
- **Loading:** `scripts/load_secrets_from_keyvault.sh` → `.runtime/secrets/`
- **Mapping:** `AZURE_SECRET_*` env vars map to Key Vault secret names (e.g., `AZURE_SECRET_FLASK_SECRET_KEY=flask-secret-key`)

## Debugging & Troubleshooting

### Environment Validation
```bash
make validate-env   # Auto-corrects DEMO_MODE/AZURE_USE_KEYVAULT conflicts
make doctor         # Checks az CLI, Key Vault access, docker compose
```

### Secret Issues
- **Demo mode:** Secrets auto-generated by `make ensure-secrets` (stored in `.env`, gitignored)
- **Production mode:** Check `.runtime/secrets/keycloak-service-client-secret` exists and is readable
- **Azure cache:** Clear with `make clean-secrets` if `DefaultAzureCredential` fails

### Service Health
```bash
make ps     # Container status
make logs   # Tail all logs
docker compose exec flask-app curl http://localhost:8000/health  # Flask health check
```

### Common Gotchas
1. **"Service secret not found"**: Run `make quickstart` to bootstrap automation-cli client in Keycloak
2. **"Forbidden" in admin UI**: User needs `iam-operator` or `realm-admin` role (assigned via JML script)
3. **SCIM 401 errors**: OAuth token missing or expired (obtain from Keycloak `/token` endpoint)
4. **Certificate warnings**: Self-signed certs regenerated by `scripts/run_https.sh` (valid 30 days)

## Testing Patterns

### Mocking Keycloak
```python
@patch('scripts.jml.requests.post')
@patch('scripts.jml.requests.get')
def test_create_user(mock_get, mock_post):
    mock_post.return_value.status_code = 201
    # Test provisioning_service logic without real Keycloak
```

### E2E Tests
Require running stack (`make up`). Test real OIDC flows, JML operations, SCIM API.

## File References

### Key Entry Points
- `app/flask_app.py` — Flask application factory (`create_app()`)
- `scripts/jml.py` — Keycloak provisioning CLI (realm/user/role management)
- `scripts/demo_jml.sh` — Full JML demonstration script (used by `make quickstart`)

### Configuration
- `.env.demo` — Demo mode defaults (copy to `.env` to start)
- `docker-compose.yml` — Service orchestration (Keycloak, Flask, Nginx)
- `Makefile` — All developer workflows (30+ targets)

### Documentation
- `README.md` — Comprehensive guide (quickstart, secret management, production notes)
- `docs/REFACTORING_GUIDE.md` — Explains modular architecture refactoring
- `docs/ADMIN_DASHBOARD_FEATURES.md` — Admin UI capabilities

## Security Reminders
- Never commit `.env` (gitignored)
- Demo credentials (`admin/admin`, `demo-service-secret`) printed at startup — **never use in production**
- Audit logs contain PII (usernames, emails) — treat as sensitive
- Self-signed certificates acceptable for local dev only — use CA-signed certs in production
