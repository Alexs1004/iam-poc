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

### Testing
| Script | Purpose | Used By |
|--------|---------|---------|
| **[test_scim_api.sh](test_scim_api.sh)** | Integration tests with real Keycloak tokens | Manual testing, CI/CD |

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
# Integration tests with real OAuth tokens
./scripts/test_scim_api.sh

# Unit tests (Python)
pytest tests/test_scim_api.py -v              # SCIM API routes
pytest tests/test_scim_oauth_validation.py -v # OAuth validation
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
- **Location**: `tests/test_*.py`
- **Coverage**: 128 tests, 98.5% pass rate
- **Mocking**: Keycloak API mocked, provisioning_service tested
- **OAuth**: 17 dedicated tests in `test_scim_oauth_validation.py`

### Integration Tests (Shell)
- **Location**: `scripts/test_scim_api.sh`
- **Coverage**: Real Keycloak tokens, full CRUD workflow
- **Prerequisites**: Running stack (`make up`)

### End-to-End Tests (pytest)
- **Location**: `tests/test_integration_e2e.py`
- **Coverage**: Full user lifecycle (joiner → mover → leaver)
- **Prerequisites**: Running stack + real Keycloak

---

## 🗂️ Removed Scripts

**Commit f57e9d5** (2025-01-XX):
- ❌ `validate_refactoring.sh`: Obsolete (referenced deleted `flask_app_new.py`)
- ❌ `test_scim_oauth.sh`: Superseded by `tests/test_scim_oauth_validation.py` (17 pytest tests)

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
make pytest       # Unit tests (mocked)
make pytest-e2e   # Integration tests (requires stack)

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

**Last Updated**: January 2025  
**Maintainer**: Alex  
**Project**: IAM PoC (Keycloak + Flask + SCIM 2.0)
