# 📚 Documentation Hub — Mini IAM Lab

> **Smart navigation**: Documentation organized by profile (Recruiters · Security · DevOps)

---

## 🎯 For Recruiters & HR Screening

**Reading time: 5-10 minutes**

| Document | Objective | Audience |
|----------|----------|--------|
| **[Swiss Hiring Pack](Hiring_Pack.md)** | Resume ↔ Repo mapping, ATS keywords, quick validation | HR Recruiters, Hiring Managers |
| **[RBAC Demo Scenarios](RBAC_DEMO_SCENARIOS.md)** | Detailed Joiner/Mover/Leaver workflows, RBAC matrix, manual tests | HR Recruiters, Tech Leads |
| **[Main README](../README.md)** | Cloud Security Engineer positioning (Swiss), 2-min start | All (initial screening) |

**What recruiters should remember**:
- **Azure Entra ID SCIM 2.0 provisioning** (production-ready, RFC 7644 compliant)
- Operational Azure Key Vault (production-ready secrets management)
- Swiss compliance: nLPD, GDPR, FINMA (non-repudiable audit trail)
- 346 automated tests, 91% coverage (verifiable code quality)
- Security pipeline: Gitleaks, Trivy, Syft, Grype (CI/CD + local)
- Azure-native integration: Entra ID SCIM provisioning operational

---

## 🔐 For Security Engineers & CISO

**Reading time: 30-60 minutes**

| Document | Content | Standards |
|----------|---------|-----------|
| **[Security Design](SECURITY_DESIGN.md)** | Implemented controls, threat mitigation, secrets management | OWASP ASVS L2, nLPD, GDPR |
| **[Security Scanning](SECURITY_SCANNING.md)** | Gitleaks, Trivy, Syft, Grype (local + CI/CD), troubleshooting | NIST SP 800-190, EO 14028 |
| **[Threat Model](THREAT_MODEL.md)** | STRIDE analysis, MITRE ATT&CK, FINMA compliance | RFC 7644, NIST 800-63B |
| **[API Reference](API_REFERENCE.md)** | SCIM endpoints, OAuth authentication, rate limiting | RFC 7644, RFC 6749 |

**Key security points**:
- **AuthN/AuthZ**: OAuth 2.0 Bearer tokens, PKCE, MFA enforcement
- **Audit Trail**: HMAC-SHA256 signatures (non-repudiation), `make verify-audit`
- **Secrets**: Azure Key Vault (prod), automated rotation (`make rotate-secret`)
- **Transport**: TLS 1.3, HSTS, CSP, Secure/HttpOnly cookies
- **Security Scanning**: Gitleaks (secrets), Trivy (CVE), Syft (SBOM), Grype (vulnerabilities)
- **Compliance**: nLPD (traceability), GDPR (portability), FINMA (non-repudiation)

---

## 🛠️ For DevOps & Cloud Engineers

**Reading time: 45-90 minutes**

| Document | Content | Technologies |
|----------|---------|--------------|
| **[Deployment Guide](DEPLOYMENT_GUIDE.md)** | Azure App Service, Key Vault, Managed Identity, CI/CD | Azure, Docker, Nginx |
| **[Testing Guide](TESTING.md)** | Test strategy, coverage, CI/CD workflow, troubleshooting | pytest, coverage, xdist |
| **[Local SCIM Testing](LOCAL_SCIM_TESTING.md)** | Local tests, curl examples, troubleshooting | SCIM 2.0, OAuth 2.0 |

**Key commands**:
```bash
make quickstart              # 2-minute demo start
make doctor                  # Azure + Docker health check
make test-all                # Full suite (346 tests, 91% coverage)
make test-coverage           # Tests with HTML coverage report
make test-coverage-vscode    # Open report in VS Code
make verify-audit            # HMAC signature verification
make rotate-secret-dry       # Key Vault rotation simulation
make security-check          # Run all security scans
make scan-secrets            # Detect exposed secrets (Gitleaks)
make scan-vulns              # Scan HIGH/CRITICAL CVE (Trivy)
```

**Code coverage workflow**:
- `make test-coverage`: Runs all tests and generates `htmlcov/index.html`
- `make test-coverage-report`: Shows viewing options
- `make test-coverage-vscode`: Opens report in VS Code (recommended)
- `make test-coverage-open`: Attempts to open in system browser
- `make test-coverage-serve`: Starts HTTP server on `localhost:8888`

---

## 📋 Références Techniques (Core References)

| Document | Description |
|----------|-------------|
| [Security Scanning](SECURITY_SCANNING.md) | Gitleaks, Trivy, Syft, Grype — Guide complet local + CI/CD |
| [API Reference](API_REFERENCE.md) | Endpoints SCIM 2.0, OAuth, OpenAPI spec |
| [Security Design](SECURITY_DESIGN.md) | Contrôles sécurité, OWASP ASVS L2, threat mitigation |
| [Threat Model](THREAT_MODEL.md) | Analyse STRIDE, MITRE ATT&CK, conformité Swiss |
| [Deployment Guide](DEPLOYMENT_GUIDE.md) | Azure Key Vault, Managed Identity, App Service |
| [Testing Guide](TESTING.md) | Stratégie de test, couverture 91%, workflow CI/CD |
| [Local SCIM Testing](LOCAL_SCIM_TESTING.md) | Tests curl, troubleshooting, exemples |
| [RBAC Demo Scenarios](RBAC_DEMO_SCENARIOS.md) | Workflows JML complets, matrice utilisateurs, tests manuels |

---

## 🧪 Validation Interactive (UI Verification)

**Accès** : `https://localhost/verification` (après `make quickstart`)

| Test | Action UI |
|-------|-----------|
| OpenAPI responds 200 | `/verification` → **Check OpenAPI** |
| OAuth unauthenticated yields 401 | `/verification` → **Check OAuth 401** |
| Wrong media type returns 415 | `/verification` → **Check Media Type** |
| PATCH active toggle is idempotent (200/200) | `/verification` → **Check PATCH Idempotence** |
| PUT returns 501 with guidance message | `/verification` → **Check PUT 501** |
| Security headers enforced | `/verification` → **Check Security Headers** |

## Navigation
- [Documentation Hub (this page)](README.md)
- [Main README](../README.md)

## 📖 Glossary

| Term | Definition |
|------|------------|
| **SCIM Resource** | JSON representation of identity data (User, Group) conforming to RFC 7644 |
| **JWKS** | JSON Web Key Set - public keys used to verify JWT signatures |
| **Managed Identity** | Azure AD identity for Azure resources, eliminates credential management |
| **PKCE** | Proof Key for Code Exchange - OAuth security extension for public clients |
| **Bearer Token** | OAuth access token passed in Authorization header: `Bearer <token>` |
| **JML** | Joiner-Mover-Leaver - IAM workflow for user lifecycle management |
| **HMAC-SHA256** | Hash-based Message Authentication Code for audit log integrity |
| **OIDC** | OpenID Connect - identity layer on top of OAuth 2.0 |
| **CSP** | Content Security Policy - browser security header preventing XSS |
| **HSTS** | HTTP Strict Transport Security - enforces HTTPS connections |

## ✅ Quick Validation Checklist

```bash
# 1. Environment health check
make doctor

# 2. Unauthenticated SCIM access should return 401
curl -k https://localhost/scim/v2/Users
# Expected: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401",...}

# 3. Wrong content type should return 415
curl -k -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
# Expected: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"415",...}

# 4. Audit log integrity
make verify-audit
# Expected: ✅ All audit signatures valid

# 5. Rate limiting protection
for i in {1..12}; do curl -k https://localhost/verification; done
# Expected: First ~6 requests succeed, then 429 Too Many Requests
```
# Infrastructure Terraform - IAM POC

**Azure-native infrastructure** déployée avec Terraform pour l'IAM Security PoC.

---

## 🚀 Quick Start

```bash
# 1. Setup Azure backend (première fois uniquement)
./scripts/infra/setup-backend.sh

# 2. Initialize Terraform
make infra/init

# 3. Preview changes
make infra/plan

# 4. Deploy to Azure
make infra/apply
```

---

## 📋 Prérequis

### Docker (requis)
```bash
docker --version       # Docker Desktop ou Docker Engine
docker compose version # Docker Compose v2
```

### Azure CLI (requis)
```bash
az login
az account show  # Vérifier la souscription active
```

> **Note**: Terraform s'exécute via Docker pour garantir la reproductibilité.
> Vos credentials Azure (`~/.azure`) sont montées automatiquement.

### Terraform local (optionnel - fallback)
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
```

---

## 🔧 Commandes Terraform

### Via Makefile (recommandé)
```bash
make infra/init       # Initialize Terraform
make infra/validate   # Validate configuration
make infra/plan       # Show execution plan
make infra/apply      # Apply changes
make infra/destroy    # Destroy infrastructure
make infra/fmt        # Format Terraform files
make infra/clean      # Remove cache
```

### Via Docker directement
```bash
docker compose run --rm terraform init -backend-config=infra/backend.hcl
docker compose run --rm terraform plan
docker compose run --rm terraform apply
```

---

## 📂 Infrastructure Actuelle (Phase C2)

### Ressources Déployées
- ✅ **Resource Group**: `rg-iam-demo` (Switzerland North)
- ✅ **Log Analytics Workspace**: `iam-poc-law-dev`
  - Retention: 30 jours (compliance FINMA)
  - SKU: PerGB2018
  - Tags: `Compliance=LPD-FINMA`, `Purpose=Observability`

### Backend Azure Storage
- **Storage Account**: Auto-généré (`tfstateiam<random>`)
- **Container**: `tfstate`
- **Security**:
  - ✅ Encryption at rest (AES-256)
  - ✅ Versioning (rollback capability)
  - ✅ Soft delete (30 jours)
  - ✅ HTTPS only (TLS 1.2+)
  - ✅ Public access disabled

---

## 🔐 Configuration Backend (Première fois)

### 1. Créer le backend Azure Storage

```bash
./scripts/infra/setup-backend.sh
```

**Ce script va**:
- Créer un Resource Group dédié (`tfstate-rg`)
- Créer un Storage Account sécurisé (nom unique)
- Activer versioning, soft delete, encryption
- Générer `infra/backend.hcl` automatiquement

### 2. Initialiser Terraform

```bash
make infra/init
```

**Alternative (mode local - dev uniquement)**:
```bash
./scripts/infra/setup-local-mode.sh
```

---

## 📝 Variables Terraform

| Variable | Description | Défaut | Requis |
|----------|-------------|--------|--------|
| `prefix` | Préfixe pour nommer les ressources | `iam-poc` | Non |
| `location` | Région Azure | `switzerlandnorth` | Non |
| `rg_name` | Nom du Resource Group | `rg-iam-demo` | Non |
| `subnet_id` | ID du subnet pour Private Endpoints | `""` | Non |
| `environment` | Environnement (dev/staging/prod) | `dev` | Non |
| `tags` | Tags communs | `{Project, ManagedBy}` | Non |

**Note**: `tenant_id` est auto-détecté via `data.azurerm_client_config`

### Exemple avec variables personnalisées

Créez `infra/terraform.tfvars`:
```hcl
prefix      = "mon-iam"
location    = "switzerlandnorth"
environment = "prod"

tags = {
  Project   = "IAM-POC"
  Owner     = "VotreNom"
  ManagedBy = "Terraform"
}
```

---

## 🗺️ Roadmap Infrastructure

### ✅ Phase C1: Skeleton (Completed)
- Providers configuration (azurerm ~>3)
- Azure Storage backend
- Variables + outputs structure
- Docker containerization

### ✅ Phase C2: Foundation (Completed)
- Resource Group (imported existing `rg-iam-demo`)
- Log Analytics Workspace (30d retention)
- Service Principal authentication
- Auto-detection `tenant_id`

### 🔄 Phase C3: Network (In Progress)
- VNet (10.0.0.0/16)
- Subnet for Private Endpoints
- Network Security Group (NSG)

### 📋 Phase C4: Key Vault
- Azure Key Vault with Private Endpoint
- Network isolation (no public access)
- RBAC policies

### 📋 Phase C5: App Service
- Azure App Service Plan (Linux)
- Web App with Managed Identity
- VNet integration

### 📋 Phase C6: Monitoring
- Diagnostic settings to Log Analytics
- Alerts + dashboards
- Cost monitoring

---

## 📂 Structure du Projet

```
infra/
├── providers.tf         # Configuration azurerm provider
├── variables.tf         # Variables d'entrée
├── outputs.tf           # Outputs Terraform
├── main.tf              # Auto-detection tenant_id
├── log_analytics.tf     # Resource Group + Log Analytics
├── backend.tf           # Backend Azure Storage
├── backend.hcl          # Configuration backend (généré par script)
├── .gitignore           # Protection secrets/state
└── README.md            # Ce fichier
```

---

## 🔒 Sécurité & Bonnes Pratiques

### Backend Terraform State
⚠️ **Le state Terraform contient des données sensibles**:
- IPs publiques
- Identifiants de déploiement
- Metadata de configuration

**Bonnes pratiques**:
1. ✅ Toujours utiliser un backend distant (Azure Storage)
2. ✅ Activer versioning (rollback possible)
3. ✅ Activer soft delete (30 jours - compliance FINMA)
4. ✅ Utiliser Azure CLI auth (éviter access keys en clair)
5. ❌ **Ne jamais commiter** `terraform.tfstate`, `backend.hcl`, `*.tfvars`

### Fichiers à ne jamais commiter
```gitignore
**/.terraform/
**/.terraform.lock.hcl
**/terraform.tfstate
**/terraform.tfstate.backup
**/*.tfvars
**/*.tfvars.json
**/backend.hcl
```

---

## 🛠️ Scripts d'Infrastructure

Disponibles dans `scripts/infra/`:

| Script | Description |
|--------|-------------|
| `setup-backend.sh` | Créer backend Azure Storage (première fois) |
| `register-providers.sh` | Enregistrer providers Azure (si nécessaire) |
| `setup-local-mode.sh` | Mode local sans backend distant (dev) |
| `upload-terraform-secret.sh` | Upload ARM_CLIENT_SECRET dans Key Vault |

---

## 📘 Documentation Complémentaire

- **[Main README](../README.md)**: Vue d'ensemble du projet
- **[Deployment Guide](../docs/DEPLOYMENT_GUIDE.md)**: Déploiement Azure App Service
- **[Security Design](../docs/SECURITY_DESIGN.md)**: Architecture de sécurité

---

**Note**: Cette infrastructure suit les bonnes pratiques Azure et les exigences de conformité suisses (LPD/FINMA).
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
| **[infra/setup-backend.sh](infra/setup-backend.sh)** | Create Azure Storage backend for Terraform state | `make infra/init` |
| **[infra/register-providers.sh](infra/register-providers.sh)** | Register Azure resource providers | `infra/setup-backend.sh` |
| **[infra/setup-local-mode.sh](infra/setup-local-mode.sh)** | Configure Terraform local backend (no Azure) | Manual setup |
| **[infra/upload-terraform-secret.sh](infra/upload-terraform-secret.sh)** | Upload ARM_CLIENT_SECRET to Azure Key Vault | Manual setup |

### Configuration & Validation
| Script | Purpose | Used By |
|--------|---------|---------|
| **[configure_smtp.py](configure_smtp.py)** | Configure Keycloak SMTP settings | `make quickstart`, Docker entrypoint |
| **[check_smtp.py](check_smtp.py)** | Test SMTP connection and credentials | Manual validation |
| **[validate_env.sh](validate_env.sh)** | Validate `.env` configuration (DEMO_MODE guards) | `make validate-env` |
| **[validate_config.sh](validate_config.sh)** | Validate project setup and dependencies | Manual validation |

### Utilities
| Script | Purpose | Used By |
|--------|---------|---------|
| **[update_env.py](update_env.py)** | Update key=value in `.env` files | Internal scripts |

---

## ⚠️ Important: Script Naming Convention

**Why some scripts don't follow `test_*.py` pattern:**

Scripts in this directory are **standalone utilities**, not pytest tests. To avoid pytest collection errors:

- ✅ **Use descriptive names**: `check_smtp.py`, `audit.py`, `configure_smtp.py`  
- ❌ **Avoid `test_*.py`**: Would be collected by pytest and cause `INTERNALERROR` if they call `sys.exit()`

**Pytest configuration** (`pytest.ini`) explicitly excludes this directory:
```ini
[pytest]
testpaths = tests
norecursedirs = scripts htmlcov .git .github certs docs openapi proxy
```

**Example error if misconfigured:**
```python
# ❌ Bad: scripts/test_smtp.py (collected by pytest)
sys.exit(1)  # → INTERNALERROR: SystemExit: 1

# ✅ Good: scripts/check_smtp.py (ignored by pytest)
sys.exit(1)  # → Works as expected standalone script
```

**Running scripts:**
```bash
# Inside Docker (recommended)
docker compose exec flask-app python3 scripts/check_smtp.py

# On host (requires Python 3.12 + dependencies)
python3 scripts/check_smtp.py
```

---

## 🚀 Quick Command Reference

### Common Workflows
```bash
# Zero-config demo
make quickstart              # Auto-generates .env, starts stack, runs demo

# Testing
make test                    # Unit tests (346 tests, 91% coverage, ~3.5s)
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
