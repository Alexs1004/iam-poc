# IAM Security PoC — Azure-Native Architecture
### SCIM 2.0 · OIDC/MFA · Azure Key Vault · Terraform IaC · Cryptographic Audit

![Azure](https://img.shields.io/badge/Azure-Key%20Vault%20%7C%20Entra%20ID%20%7C%20Terraform-0078D4?logo=microsoft-azure&logoColor=white)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests 91%](https://img.shields.io/badge/Coverage-91%25-brightgreen?logo=codecov)
![Security](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![Compliance](https://img.shields.io/badge/Compliance-nLPD%20%7C%20FINMA-red)

> **🎯 Production-ready IAM platform · Infrastructure as Code · Swiss compliance by design**

---

## 🎯 What This Demonstrates

**Azure Cloud Infrastructure**
- **Terraform IaC**: Resource Group, Log Analytics, automated backend setup
- **Azure Key Vault**: Centralized secrets management with rotation
- **Infrastructure automation**: `make infra/init`, `infra/plan`, `infra/apply`
- **Secure state management**: Azure Storage backend with encryption

**Identity & Access Management**
- **SCIM 2.0 RFC 7644**: Entra ID provisioning-ready API
- **OIDC/OAuth 2.0**: Federated authentication with MFA enforcement
- **RBAC**: Role-based access control (admin, operator, verifier)
- **JML automation**: Joiner/Mover/Leaver lifecycle management

**Security & Compliance**
- **Cryptographic audit**: HMAC-SHA256 signatures, non-repudiation
- **Security scans**: Gitleaks (secrets), Trivy (CVE), SBOM generation
- **Swiss compliance**: nLPD/FINMA-compliant architecture
- **Production-grade**: 91% test coverage, CI/CD automation

---

## ⚡ Quick Start (2 minutes)

```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart          # Auto-setup + demo
open https://localhost   # Interactive verification page
```

**What you'll see**:
- OIDC login with MFA (TOTP)
- SCIM 2.0 API ([ReDoc docs](https://localhost/scim/docs))
- Admin dashboard with audit trail
- Automated security validation

---

## 🏗️ Infrastructure as Code (Terraform)

### Quick Commands
```bash
# Initialize Terraform with Azure backend
make infra/init

# Preview infrastructure changes
make infra/plan

# Deploy to Azure
make infra/apply

# Destroy resources
make infra/destroy
```

### Current Infrastructure (Phase C2)
- ✅ **Resource Group** (`rg-iam-demo`)
- ✅ **Log Analytics Workspace** (30-day retention, PerGB2018 SKU)
- ✅ **Azure Storage backend** (encrypted state with versioning)
- ✅ **Service Principal auth** (auto-detected tenant_id)

**Location**: Switzerland North (LPD/FINMA compliance)  
**Tags**: `Compliance=LPD-FINMA`, `ManagedBy=Terraform`

### Roadmap
- 🔄 **Phase C3**: VNet + Private Endpoints
- 📋 **Phase C4**: Azure Key Vault with network isolation
- 📋 **Phase C5**: App Service + Managed Identity
- 📋 **Phase C6**: Diagnostic settings to Log Analytics

📘 **Full documentation**: [`infra/README.md`](infra/README.md)

---

## 👥 Demo Users & RBAC

| User | Role | Password | Access | Scenario |
|------|------|----------|--------|----------|
| **joe** | `iam-operator` + `realm-admin` | `Temp123!` | Full admin + JML operations | Stable operator |
| **alice** | `analyst` → **`iam-operator`** | `Temp123!` | Promoted to admin | **Mover** (promotion) |
| **bob** | `analyst` → ~~disabled~~ | `Temp123!` | Account disabled | **Leaver** (soft-delete) |
| **carol** | `manager` | `Temp123!` | Read-only dashboard | Stable manager |

**Test workflow**:
```bash
# 1. Login as joe (full admin)
open https://localhost
# Username: joe | Password: Temp123!

# 2. Access admin dashboard
open https://localhost/admin

# 3. Check audit trail
open https://localhost/admin/audit
make verify-audit  # Verify HMAC signatures
```

---

## 🔧 Essential Commands

```bash
# Application
make quickstart          # Zero-config: .env + stack + JML demo
make fresh-demo          # Complete reset: volumes + secrets + audit
make up                  # Start services
make logs                # View logs

# Infrastructure
make infra/init          # Initialize Terraform
make infra/plan          # Preview changes
make infra/apply         # Deploy to Azure
make infra/destroy       # Destroy resources

# Tests & Quality
make test                # Unit tests (346 tests, 91% coverage)
make test-e2e            # Integration tests (requires stack)
make test-coverage       # Tests with HTML coverage report

# Security
make security-check      # Run all scans (secrets, CVE, SBOM)
make scan-secrets        # Gitleaks (exposed secrets)
make scan-vulns          # Trivy (CVE vulnerabilities)
make verify-audit        # Verify HMAC signatures
make rotate-secret       # Azure Key Vault secret rotation
```

📘 **Full reference**: `make help-all` (40+ commands)

---

## 📋 Documentation

### 🎯 For Recruiters
- **[Hiring Pack](docs/Hiring_Pack.md)** — Resume ↔ Repo mapping, keywords
- **[RBAC Demo](docs/RBAC_DEMO_SCENARIOS.md)** — Joiner/Mover/Leaver workflows

### 🔐 For Security Engineers
- **[Security Design](docs/SECURITY_DESIGN.md)** — OWASP ASVS L2, JWT validation
- **[Threat Model](docs/THREAT_MODEL.md)** — STRIDE analysis, non-repudiation
- **[Security Scanning](docs/SECURITY_SCANNING.md)** — Gitleaks, Trivy, SBOM

### 🛠️ For DevOps
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** — Azure App Service, CI/CD
- **[Testing Strategy](docs/TESTING.md)** — 91% coverage, pytest config
- **[API Reference](docs/API_REFERENCE.md)** — SCIM 2.0 endpoints, curl examples

### 🏗️ For Infrastructure
- **[Terraform Guide](infra/README.md)** — IaC setup, backend configuration
- **[Entra ID SCIM](docs/ENTRA_SCIM_HOWTO.md)** — Microsoft provisioning setup

**📂 Documentation hub**: [docs/README.md](docs/README.md)

---

## 📊 SCIM 2.0 Support Matrix

| Method | Endpoint | Status | Description |
|--------|----------|--------|-------------|
| **GET** | `/scim/v2/Users` | ✅ | List users (pagination) |
| **POST** | `/scim/v2/Users` | ✅ | Create user + audit |
| **GET** | `/scim/v2/Users/{id}` | ✅ | Retrieve by ID |
| **PATCH** | `/scim/v2/Users/{id}` | ✅ | Update (multi-operation) |
| **DELETE** | `/scim/v2/Users/{id}` | ✅ | Soft-delete (idempotent) |
| **PUT** | `/scim/v2/Users/{id}` | ⚠️ 501 | Not supported (use PATCH) |

**Interactive validation**: https://localhost/verification  
**OpenAPI docs**: https://localhost/scim/docs

---

## 🛡️ Security & Rate Limiting

### DoS Protection (Nginx)
| Endpoint | Limit | Burst | Purpose |
|----------|-------|-------|---------|
| `/verification` | 10 req/min | +5 | Testing endpoint |
| `/scim/v2/*` | 60 req/min | +10 | Provisioning API |
| `/admin/*` | 30 req/min | +8 | Admin interface |

**Test**: `./scripts/test_rate_limiting.sh`

### Security Standards
- **OWASP ASVS Level 2**: A01-A08 protection
- **RFC 7636 (PKCE)**: Authorization code flow
- **RFC 7644 (SCIM 2.0)**: Strict schema validation
- **NIST 800-63B**: MFA for privileged accounts
- **nLPD/FINMA**: Cryptographic audit trail

### Password Management
**Production** (SMTP-based):
- ✅ Secure reset email with one-time token (256-bit, 5-minute expiration)
- ✅ User sets own password (zero knowledge)
- ✅ RFC 7644 § 7.7: Password never returned in responses

**Demo Mode** (local testing):
- ⚠️ `DEMO_MODE=true`: Password visible in flash message (red warning)
- ⚠️ Disabled in production (`.env.production` has `DEMO_MODE=false`)

---

## 🚀 Azure-Native Roadmap

### ✅ Phase C1-C2: Foundation (Completed)
- [x] Terraform skeleton with Azure backend
- [x] Resource Group + Log Analytics Workspace
- [x] Service Principal authentication
- [x] Infrastructure automation (`make infra/*`)

### 🔄 Phase C3-C6: Network & Isolation (In Progress)
- [ ] VNet + Subnet for Private Endpoints
- [ ] Azure Key Vault with network isolation
- [ ] App Service + Managed Identity
- [ ] Diagnostic settings to Log Analytics

### 📋 Phase Z1: Entra ID Migration (Planned)
- [x] SCIM 2.0 provisioning API (completed)
- [ ] Replace Keycloak with Azure AD B2C
- [ ] Conditional Access Policies (MFA, device compliance)

---

## 📈 Skills Demonstrated

| Resume Skill | Evidence | File/Command |
|--------------|----------|--------------|
| **Azure Terraform** | IaC with encrypted backend | `make infra/plan`, `infra/*.tf` |
| **Azure Key Vault** | Secrets + rotation | `make rotate-secret`, `scripts/load_secrets_from_keyvault.sh` |
| **SCIM 2.0** | RFC 7644 API | `app/api/scim.py`, `tests/test_api_scim.py` |
| **OIDC/OAuth 2.0** | PKCE, MFA, JWT | `app/api/auth.py`, `app/api/decorators.py` |
| **RBAC** | 3 roles (admin/operator/verifier) | `app/core/rbac.py` |
| **Cryptographic Audit** | HMAC-SHA256, non-repudiation | `scripts/audit.py`, `make verify-audit` |
| **DevSecOps** | CI/CD (5 security jobs), 91% tests | `.github/workflows/security-scans.yml` |
| **Security Scanning** | Gitleaks, Trivy, SBOM | `make security-check` |
| **Python 3.12** | Flask, pytest, type hints | All `.py` files |
| **Docker** | Multi-service Compose | `docker-compose.yml` |
| **Nginx** | TLS, rate limiting, headers | `proxy/nginx.conf` |

---

## 🎓 Target Roles (Romandy)

- **Cloud Security Engineer (Azure)**: Infrastructure security, compliance
- **IAM Engineer**: Entra ID provisioning, SCIM, SSO
- **DevSecOps Cloud**: Secure pipelines, IaC, monitoring
- **Identity & Access Management Specialist**: RBAC, MFA policies, audit

**Regulatory Context**: nLPD (Swiss Data Protection Act), FINMA (financial sector)

---

## 📜 Current Limitations

- **SCIM Filtering**: Only `userName eq "value"` supported (extensible)
- **PATCH**: Multi-operation support (add/replace on emails, phones, name, active)
- **PUT**: Intentionally 501 (RFC compliance: use PATCH/DELETE)
- **Content-Type**: `application/scim+json` mandatory (RFC 7644)

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.
