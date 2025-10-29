# Scripts Directory

Utility scripts for IAM PoC automation, infrastructure, and testing.

## 📁 Organization

### Automation & Provisioning
| Script | Purpose | Used By |
|--------|---------|---------|
| **[jml.py](jml.py)** | JML CLI (Joiner/Mover/Leaver automation) | `provisioning_service.py`, `Makefile` |
| **[audit.py](audit.py)** | Audit logging with HMAC-SHA256 signatures | `provisioning_service.py`, `Makefile` |
| **[demo_jml.sh](demo_jml.sh)** | Complete JML workflow demonstration | `make quickstart`, `make demo-jml` |

### Infrastructure & Deployment
| Script | Purpose | Used By |
|--------|---------|---------|
| **[run_https.sh](run_https.sh)** | Start Docker stack with HTTPS (nginx + certs) | `make up`, `make quickstart` |
| **[rotate_secret.sh](rotate_secret.sh)** | Rotate Keycloak service account secret | `make rotate-secret` |
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

## 🚀 Quick Reference

### JML Automation
```bash
# Create user
python scripts/jml.py create-user --username alice --email alice@example.com

# Change role (Mover)
python scripts/jml.py change-role --username alice --from-role analyst --to-role manager

# Disable user (Leaver)
python scripts/jml.py disable-user --username alice

# Full demo
./scripts/demo_jml.sh
```

### Infrastructure
```bash
# Start stack with HTTPS
./scripts/run_https.sh

# Rotate service account secret (production)
./scripts/rotate_secret.sh

# Load secrets from Azure Key Vault
./scripts/load_secrets_from_keyvault.sh
```

### Validation
```bash
# Validate environment configuration
./scripts/validate_env.sh

# Validate project setup
./scripts/validate_config.sh
```

### Testing
```bash
# Core pytest suites
make test             # Unit tests (Keycloak mocked)
make test-e2e         # Integration tests (requires running stack)
make test/security    # Critical security smoke tests
```

---

## 🔒 Security Notes

### Production Secrets
- **NEVER commit `.env`** (gitignored)
- Use `DEMO_MODE=false` + Azure Key Vault in production
- Service account secret: `/run/secrets/keycloak-service-client-secret`
- Audit logs signed with HMAC-SHA256 (`AUDIT_LOG_SIGNING_KEY`)

### Secret Rotation
```bash
# Dry-run validation
make rotate-secret-dry

# Execute rotation (updates Keycloak + Key Vault + restarts Flask)
make rotate-secret
```

### Demo Mode Warnings
- `DEMO_MODE=true` auto-generates secrets (printed at startup)
- Demo credentials: `admin/admin`, `demo-service-secret`
- **DO NOT deploy with demo credentials**

---

## 📖 Architecture Integration

### Data Flow
```
1. JML Operations:
   Admin UI → provisioning_service.py → jml.py → Keycloak Admin API
   
2. SCIM API:
   HTTP Client → scim.py (OAuth) → provisioning_service.py → jml.py → Keycloak
   
3. Audit Logging:
   All JML ops → audit.py → .runtime/audit/jml-events.jsonl (HMAC signed)
```

### Module Dependencies
```python
# app/core/provisioning_service.py
from scripts import jml      # Keycloak Admin API
from scripts import audit    # Audit logging

# Direct imports (NOT via Flask app context)
```

---

## 🧪 Testing Strategy

### Unit Tests (pytest)
- **Command**: `make test`
- **Scope**: 190+ fast tests with mocked Keycloak API
- **Highlights**: Config validation, JML flows, SCIM transformers, OAuth validators

### Integration Tests (pytest)
- **Command**: `make test-e2e`
- **Scope**: Real Keycloak tokens, SCIM CRUD, filtering, error handling
- **Prerequisites**: Running stack (`make up` or `make ensure-stack`)

### Security Regression Suite
- **Command**: `make test/security`
- **Scope**: TLS headers, JWT rejection paths, secret hygiene, rotation sanity checks
- **Prerequisites**: Production-style secrets (Key Vault or `.runtime/secrets`)

---

## 🗂️ Removed Scripts

**January 2025**
- ❌ `validate_refactoring.sh`: Obsolete (referenced deleted `flask_app_new.py`)
- ❌ `test_scim_oauth.sh`: Superseded by `tests/test_scim_oauth_validation.py`

**February 2025**
- ❌ `test_scim_api.sh`: Redundant with `tests/test_scim_api.py`
- ❌ `fix_automation_cli_secret.py`: Bootstrap now restores the demo secret automatically

---

## 📚 Documentation

- **Main Guide**: [../README.md](../README.md)
- **Architecture & flux**: [../docs/OVERVIEW.md](../docs/OVERVIEW.md)
- **Setup & dépannage**: [../docs/SETUP_GUIDE.md](../docs/SETUP_GUIDE.md)
- **Sécurité & OAuth SCIM**: [../docs/SECURITY_DESIGN.md](../docs/SECURITY_DESIGN.md)
- **API détaillée**: [../docs/API_REFERENCE.md](../docs/API_REFERENCE.md)

---

## 🛠️ Development Workflow

```bash
# 1. Zero-config quickstart
make quickstart   # Auto-generates .env, starts stack, runs demo

# 2. Run tests
make test         # Unit tests (mocked)
make test-e2e     # Integration tests (requires stack)
# (Optional) Production smoke tests
make test/security

# 3. Manual JML operations
python scripts/jml.py --help

# 4. Validate changes
make validate-env
pytest tests/ -v

# 5. Clean restart
make clean-all
make quickstart
```

---

**Last Updated**: February 2025  
**Maintainer**: Alex  
**Project**: IAM PoC (Keycloak + Flask + SCIM 2.0)
