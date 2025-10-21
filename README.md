# Mini IAM Lab — Azure-First Identity Demo

> TODO: CI badge · TODO: Documentation link

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
- **Zero-friction demo mode**: `make fresh-demo` works instantly without Azure setup — smart secret fallbacks and automatic synchronization.
- Azure-first secret management via Key Vault and `DefaultAzureCredential` with device-code fallback (production mode).
- Reproducible automation: `scripts/jml.py` provisions realms, roles, and JML workflows with clear logging.
- Hardened Flask app: server-side sessions, CSRF tokens, strict proxy validation, and RBAC-protected admin routes.
- Fine-grained demo roles: `iam-operator` handles JML workflows while `realm-admin` is required for realm-level changes and console access.
- HTTPS by default: `scripts/run_https.sh` mints certs, rebuilds Gunicorn images, and wires health checks end to end.
- Operational Makefile: guard clauses highlight missing secrets, enabling safe rotations and demos (`make doctor`, `make rotate-secret`).
- Testable sandbox: pytest coverage for auth controls, ensuring "trust but verify" on cookies, headers, and RBAC.
- **Production-ready SCIM 2.0 API** with RFC 7644 compliance, OAuth 2.0 authentication, and cryptographic audit trails.

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
- `make fresh-demo` — **Recommended**: Reset volumes, clear secrets, regenerate certs, and rerun full demo (clean slate).
- `make quickstart` — Start stack, bootstrap service account, and replay JML storyline (reuses existing volumes).
- `make demo` — Replay the Joiner/Mover/Leaver script against a running stack (no rebuild).
- `make down` — Stop containers (manually add `docker compose down -v` to purge data).
- `make clean-secrets` — Remove `.runtime/secrets` and `.runtime/azure` caches.
- `make pytest` — Execute unit tests inside a managed Python virtual environment.
- `make pytest-e2e` — Run end-to-end integration tests against live stack (requires running containers).
- `make rotate-secret` — Rotate Keycloak service client secret in Key Vault and restart stack (production mode only).
- `make doctor` — Validate `az login`, Key Vault permissions, and docker compose availability.
- `make help` — Display all available targets with inline descriptions.

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
When `DEMO_MODE=true`, the following secrets are auto-generated if not provided:
- `FLASK_SECRET_KEY` — Flask session encryption key (48-byte token)
- `AUDIT_LOG_SIGNING_KEY` — HMAC key for audit trail signatures (48-byte token)
- Service passwords default to demo values (`admin`, `Passw0rd!`) if not explicitly set
- Service client secret (`automation-cli`) is automatically restored to `demo-service-secret` after bootstrap
- These are regenerated on each restart unless explicitly set in `.env`
- Generated Keycloak secrets land in `.runtime/secrets` but are overwritten with demo defaults

**Priority Order for Secrets (Demo Mode):**
1. Environment variables explicitly set in `.env`
2. Demo default values (e.g., `admin`, `demo-service-secret`)
3. Auto-generated values for Flask/audit keys

This ensures `make fresh-demo` works out-of-the-box without any Azure setup.

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
- Enforce HTTPS through Nginx with self-signed certificates regenerated on every quickstart.
- Require Authorization Code + PKCE, role checks, and mandatory TOTP enrollment in the Keycloak realm.
- Rotate secrets via Key Vault-backed automation (`make rotate-secret`); never store credentials in plaintext.
- Harden session cookies (`Secure`, `HttpOnly`, `SameSite=Lax`) and validate CSRF tokens on every state-changing route.
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
