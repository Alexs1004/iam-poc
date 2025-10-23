# Mini IAM Lab — Azure-First Identity Demo

> TODO: CI badge · TODO: Documentation link

## 🎯 Quick Demo Mode (Zero Configuration)

Try the complete IAM stack in 3 commands — no Azure setup required:

```bash
make quickstart    # Auto-generates secrets, starts stack, runs JML demo
make demo-jml      # Rerun Joiner/Mover/Leaver demo anytime
make reset-demo    # Reset to clean slate (requires confirmation)
```

**What happens:**
- `make quickstart` copies `.env.demo` → `.env` if `.env` doesn't exist
- Detects `DEMO_MODE=true` and auto-generates strong secrets **only in demo mode**
- Generates `FLASK_SECRET_KEY` (32 bytes) and `AUDIT_LOG_SIGNING_KEY` (48 bytes) using Python `secrets.token_urlsafe()`
- **Idempotent**: safe to run multiple times (no duplicate changes, secrets preserved)
- **Security**: Secrets never printed to console (logs to stderr only)
- **Production-safe**: When `DEMO_MODE=false`, skips local generation and loads from Azure Key Vault
- JML automation runs at startup to show provisioning workflows

**Access the stack:**
- Admin UI: https://localhost/admin (alice/alice, enable MFA)
- Keycloak: https://localhost/keycloak (admin/admin)
- SCIM API: https://localhost/scim/v2 (OAuth 2.0 bearer token)

**Secret Management:**
- **Demo mode** (`DEMO_MODE=true`): Secrets auto-generated in `.env` (gitignored)
- **Production mode** (`DEMO_MODE=false`): Secrets loaded from Azure Key Vault → `.runtime/secrets/` (read-only mount)
- `.env` file is **never committed** to git (protected by `.gitignore`)

To switch to production mode with Azure Key Vault, see [🔐 Configuration & Secrets](#-configuration--secrets).

## Table of Contents
1. [🚀 Elevator Pitch](#-elevator-pitch)
2. [💡 Project Highlights](#-project-highlights)
3. [🧱 Architecture (dev)](#-architecture-dev)
4. [⚙️ Quickstart (2 minutes)](#️-quickstart-2-minutes)
5. [🛠️ Make Commands — Quick Reference](#️-make-commands--quick-reference)
6. [🔐 Configuration & Secrets](#-configuration--secrets)
7. [🧰 Security Guardrails](#-security-guardrails)
8. [🧪 Tests](#-tests)
9. [🚧 Troubleshooting](#-troubleshooting)
10. [☁️ Production Notes](#️-production-notes)
11. [🗺️ Roadmap](#️-roadmap)
12. [📄 License & Credits](#-license--credits)
13. [🔗 Badges & Useful Links](#-badges--useful-links)

## 🚀 Elevator Pitch
Modern IAM lab that showcases how I design, secure, and automate identity workloads with Keycloak, Flask, and Azure services.  
Implements OIDC Authorization Code + PKCE, TOTP MFA, RBAC, and Joiner/Mover/Leaver automation across a Docker Compose stack.  
Azure Key Vault (DefaultAzureCredential) keeps secrets out of source control while an HTTPS reverse proxy protects every request.  
Automation scripts rebuild containers on source hash changes, rotate secrets, and validate readiness before exposing endpoints.  
Ideal for enterprise teams evaluating my approach to IAM architecture, DevSecOps, and Azure-first operations.

## 💡 Project Highlights

### Zero-Config Demo Mode
- **Instant startup**: `make quickstart` works without any Azure setup
- **Auto-generated secrets**: Strong cryptographic keys (256-384 bits) generated automatically
- **Idempotent workflow**: Safe to run multiple times, secrets preserved
- **Production guard**: `DEMO_MODE=false` disables local generation, enforces Azure Key Vault

### Enterprise-Grade Secret Management
- **Azure Key Vault integration**: Production secrets via `DefaultAzureCredential`
- **Docker Secrets pattern**: Secrets mounted read-only in `/run/secrets` (chmod 400)
- **Orchestrated rotation**: Automated Keycloak → Key Vault → restart → health-check workflow
- **No console leaks**: Secrets never printed to stdout/stderr
- **Audit trail**: All Key Vault access logged in Azure Activity Log

### Production-Ready SCIM 2.0 API
- **RFC 7644 compliant**: Standard schemas, error responses, filtering, pagination
- **OAuth 2.0 authentication**: Bearer token validation with Keycloak
- **Unified architecture**: Shared service layer between UI and API (no code duplication)
- **Cryptographic audit trails**: HMAC-SHA256 signatures on all JML events
- **Session revocation**: Immediate effect when disabling users

### Security & Compliance
- **HTTPS by default**: Self-signed certificates regenerated automatically
- **Hardened Flask app**: Server-side sessions, CSRF tokens, strict proxy validation
- **RBAC enforcement**: `iam-operator` and `realm-admin` roles at route level
- **Mandatory MFA**: TOTP required action enforced in Keycloak
- **Immutable audit logs**: Append-only JSON Lines with signature verification

### Developer Experience
- **Operational Makefile**: 30+ targets with guard clauses and clear documentation
- **Reproducible automation**: `scripts/jml.py` provisions realms, roles, and JML workflows
- **Testable sandbox**: pytest coverage for auth controls, RBAC, and SCIM API
- **DOGFOOD mode**: UI can call SCIM API via HTTP for real-world testing
- **Health checks**: Liveness probes on all services with retry logic

## 🧱 Architecture (dev)
```
              +---------------------+
              |   Azure Key Vault   |
              |   (<VAULT_NAME>)    |
              +----------+----------+
                         ^
                         | secrets (DefaultAzureCredential)
+-----------+   HTTPS    |                      +----------------+
|  Browser  | <--------> |  Reverse Proxy (NGINX)| self-signed TLS|
+-----------+            v                      +-------+--------+
                        443                             |
                                                     proxy_pass
                                                      |
                                              +-------v--------+
                                              | Flask App      |
                                              | (Gunicorn)     |
                                              +-------+--------+
                                                      |
                                                      | OIDC / REST
                                                      v
                                              +-------+--------+
                                              | Keycloak 24    |
                                              | realm: demo    |
                                              +----------------+
```
Docker Compose orchestrates three services (Keycloak, Flask/Gunicorn, Nginx). Azure Key Vault remains external, providing secrets to automation and runtime via environment injection.

## ⚙️ Quickstart (2 minutes)
```bash
cp .env.demo .env                                    # enable DEMO_MODE defaults
make fresh-demo                                      # Clean start: HTTPS certs + stack + scripted JML demo
open https://localhost                              # trust the self-signed certificate once
```
Shutdown:
```bash
make down
```

**What happens during `make fresh-demo`:**
1. ✅ Removes old containers and volumes for a clean state
2. ✅ Clears runtime secrets and Azure cache
3. ✅ Generates self-signed HTTPS certificates (valid 30 days)
4. ✅ Starts Keycloak, Flask, and Nginx with health checks
5. ✅ Bootstraps `automation-cli` service account with **fixed demo secret** (`demo-service-secret`)
6. ✅ Creates demo realm with roles, users (alice, bob, carol, joe), and required actions
7. ✅ Demonstrates JML workflows: alice promoted, bob disabled

**No Azure Key Vault required!** Demo mode uses hardcoded secrets from `.env` for rapid local development.

### What gets provisioned
- **OIDC demo login** with Alice / Bob / Carol / Joe (pre-seeded passwords from `.env`).
- **Joiner/Mover/Leaver UI** at `https://localhost/admin` (requires roles, see table below).
- **Keycloak consoles**  
  - Realm-scoped: `https://localhost/admin/demo/console/` (works with Joe).  
  - Master: `https://localhost/admin/master/console/` (use the global `admin` account).
- **Automation storyline** via `scripts/demo_jml.sh` (rerun with `make demo` or `make fresh-demo` for a clean state).
- **Demo Mode Secret Management**: In `DEMO_MODE=true`, the automation bootstrap automatically restores the service client secret to `demo-service-secret` after rotation, ensuring Flask and scripts stay synchronized without manual restarts.

## 🛠️ Make Commands — Quick Reference

### Essential Commands
- `make quickstart` — **Zero-config start**: Auto-setup `.env`, generate secrets (demo mode only), start stack + JML demo
- `make fresh-demo` — **Clean slate**: Reset volumes, clear secrets, regenerate certs, rerun full demo
- `make reset-demo` — **Reset configuration**: Restore `.env` to `.env.demo` defaults (requires typing `yes` confirmation)
- `make down` — Stop containers (add `-v` flag manually to purge volumes)

### Secret Management
- `make ensure-env` — Copy `.env.demo` → `.env` if `.env` doesn't exist
- `make ensure-secrets` — Auto-generate `FLASK_SECRET_KEY` and `AUDIT_LOG_SIGNING_KEY` (demo mode only, skips in production)
- `make load-secrets` — Load secrets from Azure Key Vault → `.runtime/secrets/` (production mode)
- `make clean-secrets` — Remove `.runtime/secrets/` and `.runtime/azure/` caches (keeps audit logs)
- `make clean-all` — Remove all runtime data (secrets + audit logs)
- `make archive-audit` — Archive current audit log with timestamp

### Testing & Validation
- `make pytest` — Execute unit tests in managed Python virtual environment
- `make pytest-e2e` — Run end-to-end integration tests against live stack (requires running containers)
- `make validate-env` — Validate `.env` configuration (auto-corrects `DEMO_MODE=true` + `AZURE_USE_KEYVAULT=true` conflict)
- `make doctor` — Validate `az login`, Key Vault permissions, and docker compose availability

### Production Operations
- `make rotate-secret` — Orchestrated secret rotation: Keycloak → Azure Key Vault → Restart Flask → Health-check (production only)
- `make rotate-secret-dry` — Dry-run rotation test without making changes
- `make demo` — Replay Joiner/Mover/Leaver script against running stack (no rebuild)

### Utilities
- `make help` — Display all available targets with inline descriptions
- `make ps` — Display service status
- `make logs` — Tail logs for all services
- `make restart-flask` — Restart Flask container to reload secrets

## 🔐 Configuration & Secrets

### Demo Mode (without Azure Key Vault) — **Recommended for Local Development**
Copy `.env.demo` to `.env` for local development:
```bash
cp .env.demo .env
```

Key settings for demo mode:
- `DEMO_MODE=true` — Auto-generates missing secrets and uses hardcoded demo values
- `AZURE_USE_KEYVAULT=false` — Uses environment variables directly instead of Key Vault
- Set passwords directly in `.env`:
  ```bash
  KEYCLOAK_ADMIN_PASSWORD=admin
  ALICE_TEMP_PASSWORD=Passw0rd!
  BOB_TEMP_PASSWORD=Passw0rd!
  CAROL_TEMP_PASSWORD=Passw0rd!
  JOE_TEMP_PASSWORD=Passw0rd!
  ```

**Smart Secret Management in Demo Mode:**
- Service client secret (`automation-cli`) is automatically set to `demo-service-secret` after bootstrap
- Flask and automation scripts stay synchronized without manual restarts
- No Azure Key Vault setup required — instant local development
- Scripts detect `DEMO_MODE=true` and apply demo defaults automatically

⚠️ **Warning**: Demo credentials are printed at startup. Never deploy with these defaults in production.

### Production Mode (with Azure Key Vault)
For production deployments:
- Set `DEMO_MODE=false` — Enforces production-grade secret checks
- Set `AZURE_USE_KEYVAULT=true` — Loads secrets from Azure Key Vault using `DefaultAzureCredential`
- Map secret names in `.env` (e.g., `AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET=keycloak-service-client-secret`)
- `scripts/run_https.sh` syncs `~/.azure` → `.runtime/azure` for container auth
- Service secrets are rotated and stored in `.runtime/secrets/keycloak-service-client-secret`
- Clear caches with `make clean-secrets` if needed

**Production Secret Workflow:**
```bash
# 1. Set production mode
DEMO_MODE=false
AZURE_USE_KEYVAULT=true

# 2. Initial setup - Bootstrap automatically updates Key Vault
./scripts/demo_jml.sh
# ✅ Service account created
# ✅ Secret automatically stored in Azure Key Vault
# ✅ NO secret exposed in terminal logs

# 3. Orchestrated secret rotation (production only)
make rotate-secret          # Full rotation: Keycloak → Key Vault → Restart Flask → Health-check
make rotate-secret-dry      # Dry-run to test without making changes

# 4. Verify Flask can authenticate
curl -sk https://localhost/admin
```

**Security Best Practices:**
- ✅ **Automated Key Vault updates**: Secrets are written directly to Key Vault, never printed to terminal
- ✅ **Zero manual copy/paste**: Eliminates risk of secrets in shell history or logs
- ✅ **Audit trail**: All Key Vault changes are logged in Azure Activity Log
- ✅ **Fail-fast**: Script exits if Key Vault update fails, preventing mismatched secrets

**Secret Rotation Details:**
The `scripts/rotate_secret.sh` script performs an **orchestrated secret rotation**:
1. ✅ Generates a new secret in Keycloak (client credential rotation)
2. ✅ Updates Azure Key Vault with the new secret
3. ✅ Restarts Flask container to reload the secret
4. ✅ Verifies application health with retry logic

Features:
- 🔒 **Production-only**: Refuses to run in `DEMO_MODE=true`
- 🧪 **Dry-run support**: Test with `--dry-run` flag
- 🔄 **Idempotent**: Safe to run multiple times
- 📊 **Observable**: Clear logging and health-check validation
- ⚡ **Zero-downtime**: Docker restart is graceful

This is the recommended approach for periodic secret rotation in production environments.

### Auto-Generated Secrets (Demo Mode Only)

When `DEMO_MODE=true`, `make quickstart` automatically generates secure secrets using Python's `secrets` module:

| Secret | Algorithm | Length | Purpose |
|--------|-----------|--------|---------|
| `FLASK_SECRET_KEY` | `secrets.token_urlsafe(32)` | 43 chars (256 bits) | Flask session encryption + CSRF tokens |
| `AUDIT_LOG_SIGNING_KEY` | `secrets.token_urlsafe(48)` | 64 chars (384 bits) | HMAC-SHA256 audit trail signatures |

**Key Features:**
- ✅ **Idempotent**: Secrets generated only if empty or missing in `.env`
- ✅ **No duplication**: Detects existing values with regex `^KEY=[^[:space:]#]+`
- ✅ **No console leaks**: Secrets never printed to stdout (logs to stderr only)
- ✅ **Production-safe**: When `DEMO_MODE=false`, generation is **skipped** entirely
- ✅ **Git-safe**: `.env` is in `.gitignore`, secrets never committed

**Priority Order for Secrets (Demo Mode):**
1. Explicitly set values in `.env` (preserved, never overwritten)
2. Auto-generated values for `FLASK_SECRET_KEY` and `AUDIT_LOG_SIGNING_KEY`
3. Demo default fallbacks (`*_DEMO` variables, e.g., `KEYCLOAK_ADMIN_PASSWORD_DEMO=admin`)

**Service Secrets:**
- Service client secret (`automation-cli`) is set to `demo-service-secret` in demo mode
- User passwords default to `Passw0rd!` if not explicitly set
- Keycloak admin password defaults to `admin`

**Production Mode Behavior:**
When `DEMO_MODE=false`, `make ensure-secrets` outputs:
```
[ensure-secrets] Production mode detected (DEMO_MODE=false)
[ensure-secrets] Secrets will be loaded from Azure Key Vault via /run/secrets
[ensure-secrets] Skipping local secret generation
```

This separation ensures:
- **Demo mode**: Fast zero-config local development with auto-generated secrets
- **Production mode**: Secrets always loaded from Azure Key Vault, never stored in `.env`

### Production Secret Pattern: `/run/secrets`

In production mode, the project follows Docker Swarm/Kubernetes secret patterns:

```bash
# 1. Load secrets from Azure Key Vault
make load-secrets

# This creates:
.runtime/secrets/
├── flask_secret_key (chmod 400)
├── keycloak_admin_password (chmod 400)
├── keycloak_service_client_secret (chmod 400)
├── audit_log_signing_key (chmod 400)
└── *_temp_password (chmod 400, optional)

# 2. Secrets mounted read-only in containers
docker-compose.yml:
  volumes:
    - ./.runtime/secrets:/run/secrets:ro  # Read-only mount
```

**Application reads secrets from files:**

```python
# app/config/settings.py
def _load_secret_from_file(secret_name: str) -> str | None:
    """Load secret from /run/secrets (Docker secrets pattern)."""
    secret_file = Path("/run/secrets") / secret_name
    
    if secret_file.exists() and secret_file.is_file():
        return secret_file.read_text().strip()
    
    return None

# Priority: /run/secrets > environment variable > demo fallback
flask_secret_key = _load_secret_from_file("flask_secret_key", "FLASK_SECRET_KEY")
```

**Security Benefits:**
- ✅ **No secrets in `.env`**: Environment file can be safely versioned
- ✅ **Read-only mount**: Containers cannot modify secrets
- ✅ **File permissions**: `chmod 400` (owner read-only)
- ✅ **Centralized rotation**: Update Azure Key Vault → `make load-secrets` → restart
- ✅ **Audit trail**: Azure Key Vault logs all access
- ✅ **Kubernetes-ready**: Same pattern works with Kubernetes secrets

**Workflow:**
```bash
# Production deployment
DEMO_MODE=false
AZURE_USE_KEYVAULT=true

# 1. Authenticate to Azure
az login

# 2. Load secrets (called automatically by make quickstart)
make load-secrets

# 3. Start stack (secrets mounted from .runtime/secrets/)
make up

# 4. Rotate a secret (orchestrated workflow)
make rotate-secret
```

## 🔄 SCIM 2.0 API Integration

This project implements a **production-ready SCIM 2.0 API** (RFC 7644) for standardized user provisioning. The API enables integration with enterprise Identity Providers like Okta, Azure AD, and others.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM capability discovery |
| `GET` | `/scim/v2/ResourceTypes` | Advertises supported resource types |
| `GET` | `/scim/v2/Schemas` | Returns User schema definition |
| `POST` | `/scim/v2/Users` | Create user (joiner) |
| `GET` | `/scim/v2/Users` | List users with filtering/pagination |
| `GET` | `/scim/v2/Users/{id}` | Retrieve specific user |
| `PUT` | `/scim/v2/Users/{id}` | Update user (supports `active=false` for leaver) |
| `DELETE` | `/scim/v2/Users/{id}` | Soft delete user via disable |

### Authentication

All SCIM endpoints require OAuth 2.0 Bearer token authentication:

```bash
# Get service account token
TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=${KEYCLOAK_SERVICE_CLIENT_SECRET}" \
  | jq -r '.access_token')

# Create user via SCIM
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "newuser",
    "emails": [{"value": "newuser@example.com", "primary": true}],
    "name": {"givenName": "New", "familyName": "User"},
    "active": true
  }'
```

### Features

- ✅ **RFC 7644 Compliant**: Standard SCIM schemas, error responses, filtering
- ✅ **Filtering Support**: `filter=userName eq "alice"` for targeted queries
- ✅ **Pagination**: `startIndex` and `count` parameters
- ✅ **Audit Trail**: All SCIM operations logged with HMAC-SHA256 signatures
- ✅ **Session Revocation**: Immediate effect when disabling users
- ✅ **Input Validation**: Strict username/email/name sanitization

### Integration Examples

For detailed integration guides with Okta, Azure AD, and curl examples, see:
- **[SCIM API Guide](docs/SCIM_API_GUIDE.md)** — Complete usage documentation
- **[SCIM Compliance Analysis](docs/SCIM_COMPLIANCE_ANALYSIS.md)** — Conformance details

---

## 🔄 Secret Rotation (Production)

The project includes an **orchestrated secret rotation script** for production environments. This script automates the complete rotation workflow: Keycloak credential regeneration → Azure Key Vault update → application restart → health verification.

### Quick Start

```bash
# Dry-run (safe test without making changes)
make rotate-secret-dry

# Production rotation (requires DEMO_MODE=false + AZURE_USE_KEYVAULT=true)
make rotate-secret
```

For complete documentation, troubleshooting, and CI/CD integration examples, see:
- **[Secret Rotation Guide](docs/SECRET_ROTATION.md)** — Complete rotation documentation

### What the Script Does

1. ✅ **Validates context**: Refuses to run in demo mode, checks Azure CLI login
2. ✅ **Generates new secret**: Calls Keycloak Admin API to rotate the `automation-cli` client secret
3. ✅ **Updates Key Vault**: Synchronizes the new secret to Azure Key Vault
4. ✅ **Restarts Flask**: Gracefully restarts the Flask container to reload secrets
5. ✅ **Health check**: Verifies application availability with retry logic (10 attempts, 2s interval)

### Prerequisites

- `DEMO_MODE=false` and `AZURE_USE_KEYVAULT=true` in `.env`
- Active Azure CLI session (`az login`)
- Required tools: `curl`, `jq`, `docker`, `az`
- Running stack (Keycloak + Flask)

### Example Output

```bash
$ make rotate-secret
[INFO] Variables chargées depuis /home/alex/iam-poc/.env
[INFO] Obtention d'un token admin Keycloak…
[INFO] Recherche du client 'automation-cli' dans le realm 'demo'…
[INFO] Régénération du secret Keycloak pour le client automation-cli…
[INFO] Nouveau secret obtenu (longueur 36 chars).
[INFO] Mise à jour du secret dans Azure Key Vault: demo-key-vault-alex/keycloak-service-client-secret
[INFO] Key Vault synchronisé.
[INFO] Redémarrage du service Docker 'flask-app'…
[INFO] Health-check sur https://localhost/health…
[INFO] ✅ Application OK (HTTP 200).
[INFO] ✅ Rotation orchestrée terminée avec succès.
```

### Why This Matters for Security Roles

- **Zero-trust compliance**: Regular credential rotation without manual intervention
- **Audit trail**: All rotation events logged with timestamps
- **Idempotent operations**: Safe to re-run, no side effects
- **Separation of concerns**: Rotation is external to the application
- **Observable**: Clear logging and health validation
- **Production-ready**: Dry-run mode for CI/CD testing

### Testing

```bash
# Run integration tests (requires running stack)
./scripts/test_scim_api.sh

# Run unit tests
make pytest tests/test_scim_api.py

# Run E2E integration tests
make pytest tests/test_integration_e2e.py -v
```

---

## 🏗️ Unified Service Architecture (Version 2.0)

**Version 2.0** introduces a **unified provisioning service layer** that eliminates code duplication between the Flask UI and SCIM API. Both interfaces now share identical business logic, validation, and error handling.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP Clients                               │
│  (Browser UI, Okta, Azure AD, curl)                            │
└────────────┬─────────────────────────┬────────────────────────┘
             │                          │
             ▼                          ▼
  ┌──────────────────────┐   ┌──────────────────────┐
  │  Flask UI Routes     │   │  SCIM 2.0 API        │
  │  /admin/joiner       │   │  /scim/v2/Users      │
  │  /admin/mover        │   │  POST, GET, PUT      │
  │  /admin/leaver       │   │  DELETE              │
  └──────────┬───────────┘   └──────────┬───────────┘
             │                          │
             │    ✅ UNIFIED LOGIC     │
             │                          │
             └────────────┬─────────────┘
                          │
                          ▼
  ┌────────────────────────────────────────────────────────┐
  │  app/provisioning_service.py (NEW)                     │
  │  • create_user_scim_like()                            │
  │  • get_user_scim(), list_users_scim()                 │
  │  • replace_user_scim(), delete_user_scim()            │
  │  • change_user_role()                                 │
  │  • ScimError exception handling                       │
  │  • Input validation (username, email, names)          │
  │  • Session revocation helper                          │
  └────────────────────────┬───────────────────────────────┘
                           │
                           ▼
  ┌────────────────────────────────────────────────────────┐
  │  scripts/jml.py + scripts/audit.py                     │
  │  Keycloak Admin API wrapper + Audit logging           │
  └────────────────────────┬───────────────────────────────┘
                           │
                           ▼
  ┌────────────────────────────────────────────────────────┐
  │  Keycloak Admin API                                    │
  │  /users, /roles, /sessions                             │
  └────────────────────────────────────────────────────────┘
```

### Key Benefits

- ✅ **Single Source of Truth**: All JML logic in one place (`provisioning_service.py`)
- ✅ **Consistent Validation**: Username, email, name validation shared across UI and API
- ✅ **Standardized Errors**: ScimError exception with RFC 7644-compliant format
- ✅ **Easy Testing**: Mock service layer instead of Keycloak
- ✅ **DOGFOOD Mode**: Optional UI → SCIM API testing via HTTP

### DOGFOOD Mode (Optional Testing Feature)

Set `DOGFOOD_SCIM=true` to make the Flask UI call the SCIM API via HTTP instead of using the service layer directly. This enables real-world testing of your SCIM API through production UI workflows.

```bash
# Enable DOGFOOD mode
export DOGFOOD_SCIM=true
export APP_BASE_URL=https://localhost

# Start stack
make quickstart

# Use admin UI - logs will show:
# [dogfood] Created user via SCIM API: alice (HTTP 201)
```

**Use cases:**
- 🧪 Test SCIM API with real UI workflows
- 🔍 Validate OAuth token flow end-to-end
- 📊 Monitor SCIM API performance under production conditions
- 🐛 Debug SCIM issues with familiar UI interface

**⚠️ Performance Impact:** DOGFOOD mode adds +20-50ms latency per request (HTTP overhead). Use only for testing, not production.

### New Files

| File | Description | Lines |
|------|-------------|-------|
| `app/provisioning_service.py` | ✨ Unified service layer with SCIM-like operations | ~600 |
| `app/admin_ui_helpers.py` | ✨ UI helper functions with DOGFOOD mode support | ~200 |
| `tests/test_service_scim.py` | ✨ Unit tests for service layer (mocked) | ~650 |
| `tests/test_integration_e2e.py` | ✨ E2E integration tests (real Keycloak) | ~400 |
| `CHANGELOG.md` | ✨ Version 2.0.0 release notes | ~400 |
| `docs/UNIFIED_SERVICE_ARCHITECTURE.md` | ✨ Technical documentation | ~600 |

### Modified Files

| File | Change | Impact |
|------|--------|--------|
| `app/scim_api.py` | Refactored to thin HTTP layer | 616 → 300 lines (-52%) |
| `app/flask_app.py` | UI routes use `admin_ui_helpers` | +30 lines |
| `pytest.ini` | Added `integration` marker | +5 lines |

### Configuration

Add to your `.env`:

```bash
# Optional: Enable DOGFOOD mode (UI calls SCIM API via HTTP)
DOGFOOD_SCIM=false

# Required for DOGFOOD mode
APP_BASE_URL=https://localhost

# Temp password visibility (demo only)
DEMO_MODE=true  # Shows _tempPassword in SCIM responses
```

### Documentation

For detailed technical documentation, see:
- **[Unified Service Architecture](docs/UNIFIED_SERVICE_ARCHITECTURE.md)** — Architecture diagrams, API reference, examples
- **[CHANGELOG.md](CHANGELOG.md)** — Version 2.0.0 migration guide, breaking changes
- **[Integration Tests](tests/test_integration_e2e.py)** — E2E test suite with real Keycloak

### Migration Notes

**Breaking Changes in 2.0:**
- SCIM error format now strictly RFC 7644 compliant
- Temp passwords only returned in `POST /scim/v2/Users` (not in `GET`)
- UI routes now return ScimError exceptions (catch in error handlers)

**No Action Required If:**
- You only use the UI (transparent upgrade)
- You use SCIM API with standard clients (Okta, Azure AD)

**Action Required If:**
- Custom SCIM clients: Update error parsing to expect `scimType` field
- Direct `scripts/jml.py` imports: Use `provisioning_service` instead

---

## 🧰 Security Guardrails

### Transport & Network Security
- ✅ **HTTPS Enforcement**: Nginx reverse proxy with self-signed certificates (regenerated on `make quickstart`)
- ✅ **Strict Proxy Validation**: Flask validates `X-Forwarded-*` headers against `TRUSTED_PROXY_IPS` whitelist
- ✅ **TLS Configuration**: Modern cipher suites, HTTP/2 support

### Authentication & Authorization
- ✅ **OIDC Authorization Code + PKCE**: Prevents authorization code interception attacks
- ✅ **Role-Based Access Control**: `iam-operator` and `realm-admin` roles enforced at route level
- ✅ **Mandatory TOTP/MFA**: Required action enforced in Keycloak realm
- ✅ **Session Validation**: Server-side session storage with secure cookies

### Secret Management (Production)
- ✅ **Azure Key Vault Integration**: Secrets loaded via `DefaultAzureCredential` (never in `.env`)
- ✅ **Docker Secrets Pattern**: Secrets mounted read-only in `/run/secrets` (chmod 400)
- ✅ **Secret Rotation**: Orchestrated rotation with `make rotate-secret` (Keycloak → Key Vault → Restart → Health-check)
- ✅ **Audit Trail**: All Key Vault access logged in Azure Activity Log
- ✅ **No Console Leaks**: Secrets never printed to stdout/stderr during rotation

### Secret Management (Demo Mode)
- ✅ **Auto-Generation**: Strong secrets generated with Python `secrets.token_urlsafe()` (256-384 bits)
- ✅ **Idempotent**: Secrets generated only once, never overwritten
- ✅ **Git-Safe**: `.env` file in `.gitignore`, secrets never committed
- ✅ **Production Guard**: `DEMO_MODE=false` disables local generation, enforces Azure Key Vault
- ✅ **Clear Warnings**: Demo mode displays warnings at startup

### Application Security
- ✅ **Hardened Session Cookies**: `Secure`, `HttpOnly`, `SameSite=Lax` flags
- ✅ **CSRF Protection**: Tokens validated on all state-changing routes
- ✅ **Input Validation**: Strict regex validation for usernames, emails, names
- ✅ **SQL Injection Protection**: ORM-based queries (Keycloak REST API)
- ✅ **XSS Prevention**: Jinja2 auto-escaping, CSP headers

### Audit & Compliance
- ✅ **Cryptographic Audit Trail**: HMAC-SHA256 signatures on all JML events
- ✅ **Immutable Logs**: Append-only JSON Lines format (`.runtime/audit/jml-events.jsonl`)
- ✅ **Signature Verification**: `make verify-audit` validates log integrity
- ✅ **Separate Signing Keys**: Demo vs production keys (`AUDIT_LOG_SIGNING_KEY_DEMO`)
- ✅ **Tamper Detection**: Modified events fail signature verification

### Defense in Depth
- ✅ **Principle of Least Privilege**: Service accounts with minimal scopes
- ✅ **Session Revocation**: Immediate effect when disabling users (Keycloak API)
- ✅ **Health Checks**: Liveness probes on all services (Docker Compose)
- ✅ **Graceful Degradation**: Fallback to environment variables if `/run/secrets` unavailable
- ✅ **Error Handling**: No sensitive data in error messages (production mode)
- Restrict proxy forwarding with trusted IP allow lists and reject non-HTTPS `X-Forwarded-Proto` headers.
- **SCIM 2.0 Provisioning API** (`/scim/v2`) for standardized user lifecycle management (RFC 7644)
- **Immediate session revocation** on user disable (prevents 5-15 minute token validity window)
- **Input validation** with strict username/email/name sanitization (XSS/SQLi protection)
- **Cryptographic audit trail** with HMAC-SHA256 signatures for tamper detection
- Capture structured audit logs from `scripts/jml.py`, redacting tokens and surfacing failed admin calls.
- Deny missing environment variables in non-demo mode, preventing accidental startup without required secrets.

## 🧪 Tests
- `tests/test_flask_app.py` validates RBAC enforcement, admin-only routes, hardened headers, CSRF protection, secure cookies, and proxy trust logic.
- `tests/test_jml.py` exercises the automation CLI, ensuring service-account tokens, bootstrap safeguards, and secret rotations behave as expected.
- `tests/test_audit.py` verifies cryptographic signature generation, tamper detection, and JSONL audit log integrity.
- `tests/test_scim_api.py` validates SCIM 2.0 RFC 7644 compliance (schema endpoints, CRUD operations, filtering).
- `scripts/test_scim_api.sh` provides end-to-end integration testing for SCIM API with real OAuth tokens.
- The suite runs under `DEMO_MODE=true`, keeping tests self-contained while mimicking Keycloak token payloads.

## 🚧 Troubleshooting
- **Flask unhealthy** → missing `az login` → run `make doctor` then rerun `scripts/run_https.sh`.
- **404 on automation calls** → stack not running → execute `make fresh-demo` to bootstrap services.
- **Key Vault denied** → insufficient RBAC → assign **Key Vault Secrets User** on `<VAULT_NAME>`.
- **Browser TLS warning** → stale cert trust → accept the new self-signed cert or clear old certificate caches.
- **Service secret empty** → skipped bootstrap → run `make bootstrap-service-account` or `make fresh-demo`.
- **"Invalid client credentials" error on /admin** → In demo mode, secret mismatch between Flask and Keycloak → run `make fresh-demo` to reset to demo defaults.
- **Automation CLI unauthorized** → In production mode, stale service secret → rerun `make rotate-secret` then `make quickstart`.
- **Compose rebuild loop** → bind mount stale → remove `.runtime/azure` via `make clean-secrets` and retry.
- **pytest import error** → missing deps → run `make pytest` to create venv and install requirements.
- **Keycloak 401** → admin credentials absent → confirm `KEYCLOAK_ADMIN` plus Key Vault secret mappings or demo defaults in `.env`.
- **Demo mode not working** → Check `.env` has `DEMO_MODE=true` and `AZURE_USE_KEYVAULT=false` → passwords should be set directly in file.
- **Stack starts but demo script fails** → Run `./scripts/demo_jml.sh` manually to see detailed error messages → check `KEYCLOAK_URL=http://127.0.0.1:8080` (not localhost).

## ☁️ Production Notes
- Remove development bind mounts (`.:/srv/app`, `./.runtime/azure:/root/.azure`) and bake source into container images.
- Replace Azure CLI credential sync with Managed Identity or workload identity federation in production environments.
- Disable `DEMO_MODE`, supply real secrets via Key Vault, and ensure automation guards against missing values.
- Swap self-signed certs for managed certificates (Azure Application Gateway, Front Door, or cert manager).
- Tighten Nginx security policies (CSP, HSTS max-age, referrer policies) to align with enterprise standards.
- Keep logs centralised (Azure Monitor, App Insights) and enforce retention/alerting policies.
- Integrate container scanning and IaC validation into CI/CD (e.g., GitHub Actions + Trivy/Terraform Validate).

## 🗺️ Roadmap
- ✅ **Phase 1 — Core IAM Stack** (Completed)
  - Keycloak + Flask + OIDC with PKCE
  - Azure Key Vault integration
  - JML automation scripts
- ✅ **Phase 2.0 — SCIM 2.0 Provisioning** (Completed)
  - Full RFC 7644 compliant REST API at `/scim/v2`
  - Support for Okta, Azure AD, and other IdP integrations
  - Cryptographically signed audit trail (HMAC-SHA256)
  - Session revocation on user disable (immediate effect)
  - Input validation and security guardrails
- ✅ **Phase 2.1 — Unified Service Architecture** (Completed)
  - Consolidated business logic in `provisioning_service.py`
  - DOGFOOD mode for testing SCIM API via UI
  - Comprehensive E2E integration tests
- ✅ **Phase 2.2 — Demo Mode Improvements** (Completed - Current)
  - Zero Azure Key Vault dependency for local development
  - Automatic secret synchronization in demo mode
  - Smart fallback: demo defaults → environment → Key Vault
  - `make fresh-demo` works out-of-the-box
- Phase 3 — Add Microsoft Entra ID (Azure AD) support with configuration switches and consent automation.
- Phase 4 — Deliver webhook provisioning to extend real-time JML workflows.
- Phase 5 — Package `scripts/jml.py` as a versioned CLI with documentation and release automation.
- Phase 6 — Layer in observability (structured logging, metrics, distributed tracing) across services.
- Phase 7 — Automate certificate management (ACME/Let's Encrypt) and key rotation pipelines.
- Phase 8 — Add policy-as-code guardrails (OPA/Azure Policy) for configuration drift detection.

## 👥 Demo Identities & RBAC Cheatsheet

| Identity | Realm | Roles | `/admin` Access | JML Operations | Keycloak Console | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `alice` | demo | `analyst` → `iam-operator` (after mover) | ✅ View (snapshot + audit) | ✅ (after promotion) | ❌ | Illustrates joiner → mover path |
| `bob` | demo | `analyst` (disabled as leaver) | ✅ View (snapshot + audit) | ❌ | ❌ | Used to demonstrate leaver |
| `carol` | demo | `manager` → `iam-operator` (after mover) | ✅ View (snapshot + audit, **no JML forms**) | ✅ (after promotion) | ❌ | Manager persona with oversight-only access initially |
| `joe` | demo | `iam-operator`, `realm-admin`, client `realm-management/realm-admin` | ✅ Full (snapshot + audit + JML forms) | ✅ | ✅ `https://localhost/admin/demo/console/` | Operator persona: can perform JML and configure the demo realm |
| `admin` | master | built-in admin | ✅ Full (snapshot + audit + JML forms) | ✅ | ✅ `https://localhost/admin/master/console/` | Full cross-realm control |

### Role-Based Access Control (RBAC) Model

```
analyst      → /admin (view user snapshot + audit, NO JML forms)
manager      → /admin (view user snapshot + audit, NO JML forms, oversight role)
iam-operator → /admin (FULL access: snapshot + audit + JML automation forms)
realm-admin  → /admin + Keycloak Console (FULL access + realm configuration)
```

**Governance Principle**: Visibility is separated from modification rights. Analysts and managers can see the user snapshot and audit trail for oversight, but only IAM operators can perform lifecycle changes (Joiner/Mover/Leaver). Managers see the **current state** (snapshot) and **historical actions** (audit) without being distracted by operational forms. This demonstrates the **principle of least privilege** in action.

**UI Behavior**:
- **Analyst/Manager**: `/admin` shows only "Realm user snapshot" tab — clean oversight interface
- **Operator/Admin**: `/admin` shows both "Automation forms" and "Realm user snapshot" tabs — full operational capability

Joe is the operator persona in the demo. He can reach `/admin` (JML) and the Keycloak console for the *demo* realm, but he has no visibility into other realms. The master `admin` user remains available for cross-realm tasks.

## 🧰 Automation CLI (`scripts/jml.py`)

- `init`, `joiner`, `mover`, `leaver`, `delete-realm` – commandes historiques.
- `client-role` – assigne des rôles clients (ex. `realm-management/realm-admin`) avec repli automatique sur l’admin master si le service account manque de privilèges.
- `grant-role` – **nouveau** pour ajouter un rôle realm sans retirer les autres (utilisé pour donner `realm-admin` à Joe après le joiner).

`scripts/demo_jml.sh` orchestrates the storyline end-to-end: création du realm, provision des identités, ajout des rôles `iam-operator` + `realm-admin` à Joe, promotion d’Alice, désactivation de Bob, etc. Rerun `make demo` ou `make fresh-demo` pour rejouer la séquence.

## 📄 License & Credits
> TODO: Add license details and acknowledgements.

## 🔗 Badges & Useful Links
- TODO: CI status badge
- TODO: Architecture / documentation portal
- TODO: Demo walkthrough recording
