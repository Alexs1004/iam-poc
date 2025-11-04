# Scripts Directory

Utility scripts for IAM PoC automation, infrastructure, and secret management.

> **📚 Documentation complète** : Voir [docs/README.md](../docs/README.md) pour la documentation détaillée du projet

---

## 📁 Script Inventory

### Automation & Provisioning
| Script | Purpose | Used By |
|--------|---------|---------|
| **[jml.py](jml.py)** | JML CLI (Joiner/Mover/Leaver automation) | `provisioning_service.py`, `Makefile` |
| **[audit.py](audit.py)** | Audit logging with HMAC-SHA256 signatures | `provisioning_service.py`, `Makefile` |
| **[demo_jml.sh](demo_jml.sh)** | Complete JML workflow demonstration | `make quickstart`, `make demo` |

### Infrastructure & Deployment
| Script | Purpose | Used By |
|--------|---------|---------|
| **[run_https.sh](run_https.sh)** | Start Docker stack with HTTPS (nginx + certs) | `make up`, `make quickstart` |
| **[rotate_secret.sh](rotate_secret.sh)** | **Secure secret rotation** (Keycloak → Key Vault → Flask) | `make rotate-secret` |
| **[load_secrets_from_keyvault.sh](load_secrets_from_keyvault.sh)** | Load secrets from Azure Key Vault | `make load-secrets` |
| **[keycloak_entrypoint.sh](keycloak_entrypoint.sh)** | Keycloak Docker container entrypoint | `docker-compose.yml` |

### Configuration & Validation
| Script | Purpose | Used By |
|--------|---------|---------|
| **[validate_env.sh](validate_env.sh)** | Validate `.env` configuration (DEMO_MODE guards) | `make validate-env` |
| **[validate_config.sh](validate_config.sh)** | Validate project setup and dependencies | Manual validation |

### Utilities
| Script | Purpose | Used By |
|--------|---------|---------|
| **[update_env.py](update_env.py)** | Update key=value in `.env` files | Internal scripts |

---

## 🚀 Quick Command Reference

### Common Workflows
```bash
# Zero-config demo
make quickstart              # Auto-generates .env, starts stack, runs demo

# Testing
make test                    # Unit tests (328 tests, 92% coverage, ~3.5s)
make test-e2e                # Integration tests (requires running stack)
make test-coverage           # Coverage report (HTML + terminal)

# Infrastructure
make up                      # Start Docker stack
make down                    # Stop services
make restart                 # Full restart
make logs                    # Tail all services

# Validation
make validate-env            # Check .env configuration
make doctor                  # Azure + Docker health check
make verify-audit            # Verify HMAC signatures

# Production
make rotate-secret           # Secret rotation (zero-downtime)
make rotate-secret-dry       # Dry-run simulation
```

**📖 Full workflow documentation:** [docs/DEPLOYMENT_GUIDE.md](../docs/DEPLOYMENT_GUIDE.md)

---

## 🔒 Script-Specific Security Notes

### `rotate_secret.sh` — Production Secret Rotation

**Workflow (7 steps):**
1. Authenticate to Keycloak (master realm admin)
2. Regenerate client secret (POST `/client-secret`)
3. Update Azure Key Vault (versioned)
4. Record audit entry (HMAC-SHA256 signed)
5. Sync local cache (`.runtime/secrets/`)
6. Restart Flask (reload configuration)
7. Health-check (automatic rollback on failure)

**Security features:**
- ✅ Zero-downtime (health-check with retry + rollback)
- ✅ Audit trail (operator + timestamp + version + HMAC signature)
- ✅ Atomic file updates (mktemp + umask 077)
- ✅ Minimum 16 chars validation (OWASP ASVS 2.7.1)
- ✅ Zero secret exposure (never logged)

**Environment variables used:**
- `AZURE_KEY_VAULT_NAME` — Key Vault name
- `AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET` — Secret name in Key Vault
- `AZURE_SECRET_AUDIT_LOG_SIGNING_KEY` — HMAC key for audit
- `FLASK_SERVICE` — Docker service name (default: `flask-app`)
- `HEALTHCHECK_URL` — Health endpoint (default: `https://localhost/health`)

**Compliance:** NIST SP 800-53 (IA-5, AU-10, CP-10), OWASP ASVS L2 (2.7.1, 6.2.1), CIS (5.2.1, 5.5.1)

**📖 Full security analysis:** [docs/SECRET_ROTATION_SECURITY.md](../docs/SECRET_ROTATION_SECURITY.md)

---

### `load_secrets_from_keyvault.sh` — Azure Key Vault Integration

**Behavior:**
- Fetches secrets from Azure Key Vault
- Caches in `.runtime/secrets/` (chmod 600)
- Docker mounts as `/run/secrets/` (read-only)

**Why local cache?**
- **Performance:** No Azure API calls at runtime
- **Resilience:** Works if Key Vault temporarily unavailable
- **Cost:** Reduces Key Vault access charges

**Security:**
- Secrets never in `.env` (only Key Vault names)
- Cached files: `chmod 600` (owner read/write only)
- Directory: `chmod 700` (owner access only)

---

### `jml.py` — Keycloak Admin CLI

**Standalone CLI** for Keycloak automation (Joiner/Mover/Leaver operations).

**Features:**
- Service account authentication (client credentials flow)
- User lifecycle management (create, disable, role changes)
- Audit logging (HMAC-SHA256 signed events)
- Dry-run mode for testing

**Usage:**
```bash
python scripts/jml.py --help

# Or via Makefile
make joiner-alice    # Create user
make mover-alice     # Promote to admin
make leaver-bob      # Disable account
```

**Design choice:** Direct CLI (not via Flask app context) for use in automation pipelines.

---

### `audit.py` — Tamper-Proof Audit Trail

**Implementation:**
- HMAC-SHA256 signatures (key from Azure Key Vault)
- JSONL format (one event per line, easy parsing)
- Operator tracking (Azure AD identity)
- Timestamp (ISO 8601 UTC)

**Verification:**
```bash
make verify-audit
# Checks all HMAC signatures in .runtime/audit/jml-events.jsonl
```

**Compliance:** NIST SP 800-53 AU-10 (non-repudiation), GDPR Art. 5 (accountability)

---

## 🗂️ Runtime Directory Structure

Scripts manage the `.runtime/` directory for secrets, audit logs, and Azure cache:

```
.runtime/
├── secrets/                # Local secret cache (chmod 600)
│   ├── flask_secret_key
│   ├── keycloak_service_client_secret
│   ├── keycloak_admin_password
│   └── audit_log_signing_key
├── audit/                  # Tamper-proof logs (chmod 600)
│   ├── jml-events.jsonl            # JML operations (HMAC signed)
│   ├── secret-rotation.log         # Secret rotations (HMAC signed)
│   └── archive/                    # Historical snapshots
└── azure/                  # Azure CLI token cache (chmod 700)
```

**Docker mounts:** `.runtime/secrets/` → `/run/secrets/` (read-only in containers)

---

## 📚 Documentation References

| Topic | Document | Description |
|-------|----------|-------------|
| **Project Overview** | [README.md](../README.md) | Quickstart, demo mode, credentials |
| **Testing Strategy** | [docs/TESTING.md](../docs/TESTING.md) | Unit, integration, coverage workflows |
| **Production Deployment** | [docs/DEPLOYMENT_GUIDE.md](../docs/DEPLOYMENT_GUIDE.md) | Azure setup, Key Vault, Managed Identity |
| **Secret Rotation** | [docs/SECRET_ROTATION_SECURITY.md](../docs/SECRET_ROTATION_SECURITY.md) | Security analysis, NIST/OWASP compliance |
| **Security Design** | [docs/SECURITY_DESIGN.md](../docs/SECURITY_DESIGN.md) | Threat model, controls, OAuth flows |
| **API Reference** | [docs/API_REFERENCE.md](../docs/API_REFERENCE.md) | SCIM endpoints, JML operations |

**📖 Documentation Hub:** [docs/README.md](../docs/README.md)

---

**Last Updated**: November 2025  
**Maintainer**: Alex  
**Project**: IAM PoC (Keycloak + Flask + SCIM 2.0 + Azure Key Vault)
