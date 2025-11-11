# Mini IAM Lab — Azure Security PoC
### SCIM 2.0 · OIDC/MFA · Azure Key Vault · Cryptographic Audit Trail

![Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4?logo=microsoft-azure&logoColor=white)
![Entra ID Ready](https://img.shields.io/badge/Entra%20ID-SCIM%20Provisioning%20Ready-brightgreen?logo=microsoft-azure&logoColor=white)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests 91%](https://img.shields.io/badge/Coverage-91%25-brightgreen?logo=codecov)
![Security OWASP](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![Security Scans](https://img.shields.io/badge/Security-Trivy%20%7C%20Gitleaks%20%7C%20SBOM-green?logo=github-actions)
![Swiss Compliance](https://img.shields.io/badge/Compliance-nLPD%20%7C%20RGPD%20%7C%20FINMA-red)
![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> **🎯 2-minute demo · Production-ready mindset · Swiss compliance focus**

---

## Positioning: Cloud Security Engineer (Romandy)

This project demonstrates **operational mastery of modern IAM standards** in an **Azure-first** context, **compliant with Swiss regulations** (nLPD, GDPR, FINMA). It targets cloud security recruiters seeking profiles capable of designing, securing, and auditing identity environments in Microsoft Azure Cloud.

**Recruiter keywords**: Azure Entra ID (ex-Azure AD) · SCIM 2.0 Provisioning · OIDC/OAuth 2.0 · MFA Policy · RBAC · Azure Key Vault · Managed Identity · Secret Rotation · Non-Repudiation · DevSecOps · Cryptographic Audit · Compliance (nLPD/GDPR/FINMA)

**Target roles**: Junior Cloud Security Engineer (Azure) · IAM Engineer · DevSecOps Cloud · Identity & Access Management Specialist

---

## ⚡ Quick Start (2 minutes)

```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart
open https://localhost
```

**What you'll see**:
- OIDC authentication with MFA (Keycloak → Entra ID migration in progress)
- **Azure Entra ID SCIM 2.0 provisioning** (RFC 7644-compliant, production-ready)
- Secrets loaded from Azure Key Vault (zero-config demo mode available)
- Cryptographic audit trail with verifiable HMAC-SHA256 signatures
- Interactive verification page: https://localhost/verification

**🎯 Entra ID Integration Status** (Phase Z1 - SCIM Provisioning):
- SCIM 2.0 endpoints (`/scim/v2/Users`, `/Schemas`, `/ServiceProviderConfig`)
- Static Bearer token authentication (stored in Azure Key Vault)
- Multi-operation PATCH support (RFC 7644 compliant)
- UPN format support (`alice@domain.com`)
- Active attribute synchronization (soft-delete for Leavers)
- Public ngrok endpoint for Entra ID provisioning agent
- See [`docs/ENTRA_SCIM_HOWTO.md`](docs/ENTRA_SCIM_HOWTO.md) for Azure Enterprise App configuration

### 👥 Demo Users & RBAC Matrix

`make demo` provisions **4 users** with different access levels (full JML demonstration):

| User | Initial Role | Final Role | Password | Admin UI Access | JML Operations | Scenario |
|------|--------------|------------|----------|-----------------|----------------|----------|
| **alice** | `analyst` | **`iam-operator`** ⬆️ | `Temp123!` | ❌ → ✅ Full admin | ❌ → ✅ Joiner/Mover/Leaver | **Mover**: Promotion analyst → operator |
| **bob** | `analyst` | ~~`disabled`~~ ❌ | `Temp123!` | ❌ 403 Forbidden | ❌ None | **Leaver**: Account disabled |
| **carol** | `manager` | `manager` | `Temp123!` | ✅ Read-only | ❌ None | **Stable**: Manager (read access) |
| **joe** | `iam-operator` | `iam-operator`<br>+ `realm-admin` | `Temp123!` | ✅ Full admin | ✅ Joiner/Mover/Leaver | **Stable**: Full IAM operator |

**Role Hierarchy (RBAC)**:
- **`realm-admin`**: Full control (Keycloak realm management)
- **`iam-operator`**: JML operations (create/modify/disable users) + dashboard read
- **`manager`**: Admin dashboard read-only, no operations
- **`analyst`**: No admin UI access (403 Forbidden)

**Quick Test**:
```bash
# 1. Login with joe (iam-operator + realm-admin)
open https://localhost
# Username: joe | Password: Temp123! | MFA: Configure TOTP on first login

# 2. Access admin dashboard
open https://localhost/admin

# 3. Check JML operations audit trail
open https://localhost/admin/audit

# 4. Verify HMAC signature integrity
make verify-audit
```

**💡 Key Points**:
- **Privilege separation**: 4 role levels (least privilege principle)
- **Complete lifecycle**: Joiner (alice), Mover (alice → operator), Leaver (bob disabled)
- **Traceability**: Every JML operation cryptographically signed (`/admin/audit`)
- **Mandatory MFA**: TOTP required for all accounts (NIST 800-63B standard)

---

## 🏗️ Architecture Azure-First

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Browser    │───▶│    Nginx     │───▶│    Flask     │───▶│   Keycloak      │
│   (HTTPS)    │    │  (TLS, WAF,  │    │  (SCIM 2.0)  │    │ (OIDC/JWT/MFA)  │
└──────────────┘    │ Rate Limit)  │    └──────────────┘    └─────────────────┘
                    └──────────────┘            │                     │
                                                ▼                     ▼
                                   ┌──────────────────┐    ┌─────────────────┐
                                   │  Azure Key Vault │    │  Audit Trail    │
                                   │  (Secrets Mgmt)  │    │ (HMAC Signed)   │
                                   │  + Rotation      │    │ Non-Repudiation │
                                   └──────────────────┘    └─────────────────┘
```

**Technical Stack**:
- **Identity Provider**: Keycloak 24 (OIDC + MFA) + **Azure Entra ID** (SCIM 2.0 provisioning)
- **API Backend**: Flask (Python 3.12) + SCIM 2.0 RFC 7644
- **Secrets Management**: Azure Key Vault SDK (azure-keyvault-secrets)
- **Reverse Proxy**: Nginx (TLS 1.3, rate limiting, security headers)
- **Audit**: HMAC-SHA256 signatures for non-repudiation

---

## 🎯 What This Project Demonstrates

### Azure Cloud Security
- **Azure Entra ID integration**: SCIM 2.0 provisioning with Enterprise App (see [setup guide](docs/ENTRA_SCIM_HOWTO.md))
- **Azure Key Vault** as single source of truth for secrets (KEYCLOAK_SERVICE_CLIENT_SECRET, FLASK_SECRET_KEY, AUDIT_LOG_SIGNING_KEY, SCIM_STATIC_TOKEN)
- **Automated secret rotation** with integrity validation (dry-run available)
- **Managed Identity-ready architecture** (eliminates Service Principals)
- **Security headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Rate limiting**: DoS protection on critical endpoints (SCIM, admin, verification)

### Identity & Access Management (IAM)
- **Azure Entra ID SCIM 2.0 provisioning**: Production-ready integration with Enterprise App
- **SCIM 2.0 RFC 7644**: Standardized identity provisioning API (multi-operation PATCH, upsert semantics)
- **OIDC/OAuth 2.0**: Federated authentication with PKCE (RFC 7636)
- **Multi-Factor Authentication**: Mandatory TOTP for admin accounts
- **Granular RBAC**: realm-admin, iam-operator, iam-verifier (privilege separation)
- **Joiner/Mover/Leaver (JML)**: User lifecycle automation with soft-delete (active=false) for Leavers

### Compliance & Audit
- **Immutable audit trail**: HMAC-SHA256 signatures for every SCIM operation
- **Non-repudiation**: Correlation-id, timestamp, username, hashed payload
- **Integrity verification**: Automatic tampering detection (dedicated page)
- **nLPD/GDPR**: Personal data access traceability
- **FINMA**: Cryptographic proof retention

### DevSecOps
- **Automated tests**: 346 tests (91% coverage), secure CI/CD
- **Security scans**: Gitleaks (secrets), Trivy (CVE), Syft (SBOM), Grype (vulnerabilities)
- **CI/CD pipeline**: GitHub Actions with 5 security jobs (secrets, vulns, SBOM, dependency-review)
- **Zero-config demo**: Ephemeral secrets generated automatically (DEMO mode)
- **Production-ready**: Strict demo/prod separation, secrets never in cleartext
- **Infrastructure as Code**: Makefile with 35+ commands (quickstart, rotate-secret, verify-audit, scan-secrets)

---

---

## 🔧 Essential Commands

```bash
# Startup
make quickstart          # Zero-config: .env + stack + JML demo (2 min)
make fresh-demo          # Complete reset: volumes + secrets + certificates

# Tests & Quality
make test                    # Unit tests (346 tests, 91% coverage)
make test-e2e                # Integration tests (requires running stack)
make test-coverage           # Full tests with HTML coverage report
make test-coverage-vscode    # Open coverage report in VS Code
make verify-audit            # Verify HMAC signatures in audit trail

# Security
make security-check          # Run all security scans (secrets, CVE, SBOM)
make scan-secrets            # Detect exposed secrets with Gitleaks
make scan-vulns              # Scan CVE with Trivy (HIGH/CRITICAL)
make sbom                    # Generate Software Bill of Materials (SPDX + CycloneDX)
make scan-sbom               # Analyze SBOM vulnerabilities with Grype

# Production
make rotate-secret       # Azure Key Vault secret rotation (with validation)
make doctor              # Health check: Azure CLI, Key Vault, Docker

# Monitoring
make logs SERVICE=flask-app   # Application logs
make ps                       # Container status
```

📘 **Full reference**: `make help-all` (35+ commands available)

---

## 📋 Documentation Technique

### 🎯 For Recruiters (HR + Technical Screening)
- **[Swiss Hiring Pack](docs/Hiring_Pack.md)** — Resume ↔ Repo mapping, recruiter keywords
- **[RBAC Demo Scenarios](docs/RBAC_DEMO_SCENARIOS.md)** — Detailed Joiner/Mover/Leaver workflows, user matrix
- **[Security Design](docs/SECURITY_DESIGN.md)** — OWASP ASVS L2, CSRF/XSS protection, JWT validation
- **[Threat Model](docs/THREAT_MODEL.md)** — STRIDE analysis, non-repudiation, audit trail

### 🔐 For Security Engineers
- **[Security Scanning](docs/SECURITY_SCANNING.md)** — Gitleaks, Trivy, Syft, Grype (local + CI/CD)
- **[API Reference](docs/API_REFERENCE.md)** — SCIM 2.0 endpoints, curl examples, error codes
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** — Azure App Service, Key Vault setup, CI/CD
- **[Testing Strategy](docs/TESTING.md)** — 91% coverage, critical tests, pytest configuration

### 🛠️ For DevOps & Integration
- **[Local SCIM Testing](docs/LOCAL_SCIM_TESTING.md)** — Manual testing with curl/Postman
- **[Entra ID SCIM Setup](docs/ENTRA_SCIM_HOWTO.md)** — Microsoft Entra ID provisioning configuration
- **[RBAC Demo Scenarios](docs/RBAC_DEMO_SCENARIOS.md)** — Manual JML workflow tests

**📂 Documentation hub**: [docs/README.md](docs/README.md)  
**💡 Quick troubleshooting**: See `make help-all` and [TESTING.md](docs/TESTING.md#troubleshooting)


## ✅ PoC Validation (Interactive Page)

**URL**: https://localhost/verification

This page automatically executes a validation test suite covering:

### SCIM RFC 7644 Compliance
- POST/GET/PATCH/DELETE on `/scim/v2/Users`
- `userName eq` filtering (guards against injections)
- PUT returns 501 with explicit message
- `application/scim+json` Content-Type mandatory (415 otherwise)

### OAuth 2.0 Security
- 401 Unauthorized without token or invalid token
- 403 Forbidden with insufficient scope
- JWT validation: signature, issuer, audience, expiration

### Audit Integrity
- HMAC-SHA256 signature verification of audit trail
- Tampering detection (alert if signature invalid)
- Correlation-id, timestamp, username, payload in each event

### Network Protection
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Operational rate limiting (Nginx: 10-60 req/min per endpoint)

**CLI alternative**: `make verify-audit`  
**OpenAPI documentation**: https://localhost/scim/docs

---

## 📊 SCIM 2.0 Support Matrix

| Method | Endpoint | Status | Comment |
|--------|----------|--------|---------|
| **GET** | `/scim/v2/Users` | ✅ OK | List with pagination |
| **POST** | `/scim/v2/Users` | ✅ OK | User creation + audit |
| **GET** | `/scim/v2/Users/{id}` | ✅ OK | Retrieval by ID |
| **PATCH** | `/scim/v2/Users/{id}` | ✅ OK | `active` attribute only (idempotent) |
| **DELETE** | `/scim/v2/Users/{id}` | ✅ OK | Soft-delete (disable, idempotent) |
| **PUT** | `/scim/v2/Users/{id}` | ⚠️ 501 | Not supported (use PATCH/DELETE) |

**Intentional limitation**: PUT returns `501 Not Implemented` with explicit message:  
`"Full replace is not supported. Use PATCH (active) or DELETE."`

---

## 🛡️ Security & Rate Limiting

### DoS Protection (Nginx)
| Endpoint | Limit | Burst | Purpose |
|----------|-------|-------|---------|
| `/verification` | 10 req/min | +5 | Testing endpoint |
| `/scim/v2/*` | 60 req/min | +10 | Provisioning API |
| `/admin/*` | 30 req/min | +8 | Admin interface |

**Test**: `./scripts/test_rate_limiting.sh` (demonstrates 429 responses)  
**Configuration**: See `proxy/nginx.conf` for rate limiting rules

### Security Standards
- **OWASP ASVS Level 2**: A01-A08 protection (injection, broken access, misconfiguration)
- **NIST SP 800-190**: Container security (Trivy scans, SBOM with Syft)
- **EO 14028 (SBOM)**: Software Bill of Materials SPDX + CycloneDX
- **RFC 7636 (PKCE)**: Authorization code interception protection
- **RFC 7644 (SCIM 2.0)**: Strict schema + error handling implementation
- **NIST 800-63B**: Strong password policy, MFA for privileged accounts

### Password Management (Keycloak Native)
**Production Flow** : Passwords are **NEVER** returned in API responses or displayed in UI.
- ✅ User created → Keycloak sends secure reset email
- ✅ Token: 256-bit entropy, one-time use, 5-minute expiration
- ✅ User clicks link → sets own password → redirects to login

**Demo Mode** : For local testing without SMTP configuration
- ⚠️ `DEMO_MODE=true` : Password visible in flash message (red warning banner)
- ⚠️ Default `.env.production` has `DEMO_MODE=false`
- ⚠️ Automated tests verify no password leaks in production

**SMTP Configuration** (Production):
```bash
# 1. Configure variables in .env
SMTP_HOST=smtp.gmail.com  # or Office365, SendGrid, etc.
SMTP_PORT=587
SMTP_USER=noreply@domain.com
SMTP_FROM=noreply@domain.com

# 2. Store password in Azure Key Vault
az keyvault secret set \
  --vault-name your-keyvault \
  --name smtp-password \
  --value "your-app-password"

# 3. SMTP is automatically configured during bootstrap
make quickstart  # or make fresh-demo

# Or configure manually:
docker compose exec flask-app python3 scripts/configure_smtp.py
```

**Gmail App Password Setup**:
1. Enable 2FA: https://myaccount.google.com/signinoptions/two-step-verification
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Store in Key Vault: `az keyvault secret set --vault-name ... --name smtp-password --value "xxxx xxxx xxxx xxxx"`

**Compliance**:
- **OWASP ASVS V2.1.12**: Password reset via secure tokenized link
- **RFC 7644 § 7.7**: Password attribute MUST NOT be returned by default
- **NIST SP 800-63B § 5.1.1.2**: Reset via out-of-band channel (email)

📘 **Full Documentation**: [docs/SECURITY_DESIGN.md#password-management-architecture](docs/SECURITY_DESIGN.md)

**Security pipeline**:
- **Gitleaks**: Secret detection (0 false positives, configured allowlist)
- **Trivy**: HIGH/CRITICAL CVE scan (Python dependencies)
- **Syft**: SBOM generation (SPDX + CycloneDX)
- **Grype**: SBOM vulnerability analysis (CRITICAL threshold)

📘 **Complete guide**: [docs/SECURITY_SCANNING.md](docs/SECURITY_SCANNING.md)

---

## 🧪 Tests & Quality

```bash
# Tests
make test                    # Unit tests (pytest -n auto, ~91% coverage)
make test-e2e                # Integration tests (requires stack)
make test-coverage           # All tests with HTML coverage report

# Visualize coverage (multiple options)
make test-coverage-report    # Display viewing options
make test-coverage-vscode    # Open in VS Code (recommended)
make test-coverage-open      # Open in system browser (if available)
make test-coverage-serve     # Serve via HTTP on localhost:8888

# Full suite
SKIP_E2E=true make test-all  # Full suite without integration
```

**Coverage**: 346 passing tests, 91% coverage on business code  
**CI/CD**: GitHub Actions with security validation (5 jobs: Trivy, Gitleaks, SBOM, dependency-review, summary)  
**Critical tests**: JWT validation, RBAC, rate limiting, audit signatures, secret scanning

**💡 Tip**: `test-coverage` automatically checks that Docker stack is started and generates detailed HTML report in `htmlcov/`. Integration tests gracefully disable (skip) if infrastructure is unavailable.

---

## 🚀 Roadmap Azure-Native

### Phase 1: Entra ID Migration 🔄 In Progress
- [ ] Replace Keycloak with **Azure AD B2C** (cloud-native OIDC)
- [ ] Implement **Conditional Access Policies** (MFA, device compliance)
- [x] **Entra ID SCIM 2.0 Provisioning** (RFC 7644 compliant, production-ready)
- [x] **Static Bearer token authentication** (stored in Azure Key Vault)
- [x] **Multi-operation PATCH support** (add/replace, upsert semantics)
- [x] **UPN format support** (alice@domain.com)
- [x] **Active attribute sync** (soft-delete for Leavers)

### Phase 2: Secrets & Identity ✅ Completed
- [x] **Azure Key Vault** for secrets (implemented)
- [x] Automated **secret rotation** (implemented)
- [x] **SCIM static token** stored in Key Vault (implemented)
- [ ] **Managed Identity** to eliminate Service Principals
- [ ] **Azure Key Vault RBAC** (replace access policies)

### Phase 3: Monitoring & Compliance 📋 Planned
- [ ] **Azure Monitor**: Centralize logs in Log Analytics
- [ ] **Application Insights**: Real-time APM + alerts
- [ ] **Azure Policy**: Enforce TLS 1.2+, mandatory MFA
- [ ] **Microsoft Defender for Cloud**: Posture management

### Phase 4: Production Readiness 🎯 Vision
- [ ] **Azure App Service**: PaaS deployment without infrastructure management
- [ ] **Azure SQL Database**: Replace SQLite (HA + backups)
- [ ] **Azure Cache for Redis**: Distributed sessions
- [ ] **Azure Front Door**: Global CDN + WAF

---

## Romandy Context

### Regulatory Compliance
- **nLPD (new Swiss Data Protection Act)**: Timestamped audit trail, personal data access traceability
- **GDPR**: Consent management, right to be forgotten, data portability
- **FINMA**: Non-repudiation via cryptographic signatures (financial sector)

### Valued Skills
- **Azure Entra ID** (ex-Azure AD): Cloud-native identity management
- **SCIM 2.0 Provisioning**: JML automation
- **Azure Key Vault**: Production-grade secrets management
- **Compliance-by-design**: Audited architecture, secure by default
- **DevSecOps**: Secure CI/CD, automated testing, secret rotation

### Target Roles (Romandy)
- **Junior Cloud Security Engineer (Azure)**: Cloud environment security
- **IAM Engineer**: Entra ID provisioning, SCIM, SSO
- **DevSecOps Cloud**: Secure pipelines, secrets management, monitoring
- **Identity & Access Management Specialist**: RBAC, MFA policies, audit trails

---

## 📈 Resume ↔ Repository Mapping

| Resume Skill | Repository Evidence | File/Command |
|--------------|---------------------|--------------|
| **Azure Key Vault** | Full integration, secret rotation | `make rotate-secret`, `scripts/load_secrets_from_keyvault.sh` |
| **SCIM 2.0** | RFC 7644 API, compliance tests | `app/api/scim.py`, `tests/test_api_scim.py` |
| **OIDC/OAuth 2.0** | PKCE, MFA, JWT validation | `app/api/auth.py`, `app/api/decorators.py` |
| **RBAC** | 3 roles (admin/operator/verifier) | `app/core/rbac.py` |
| **Audit Trail** | HMAC-SHA256, non-repudiation | `scripts/audit.py`, `make verify-audit` |
| **DevSecOps** | CI/CD (5 security jobs), 91% tests, SBOM | `.github/workflows/security-scans.yml`, `Makefile` |
| **Security Scanning** | Gitleaks, Trivy, Syft, Grype | `make security-check`, `docs/SECURITY_SCANNING.md` |
| **Python 3.12** | Flask, pytest, type hints | All `.py` files |
| **Docker** | Multi-service Compose, health checks | `docker-compose.yml` |
| **Nginx** | TLS, rate limiting, security headers | `proxy/nginx.conf` |
| **Compliance** | nLPD/GDPR/FINMA design | `docs/THREAT_MODEL.md`, `docs/SECURITY_DESIGN.md` |

---

## 🎓 What This Project Demonstrates

**For Cloud Security Recruiters**:
- Ability to design complete and auditable IAM system
- Mastery of Azure standards (Key Vault, Entra ID roadmap, Managed Identity)
- Understanding of compliance issues (nLPD, GDPR, FINMA)
- DevSecOps approach (automated testing, secret rotation, secure CI/CD)

**For CISO/SOC**:
- Defensible architecture (RBAC, MFA, cryptographic audit)
- Complete traceability (correlation-id, timestamps, hashed payloads)
- Tampering detection (HMAC-SHA256 signature verification)
- Industry standards (OWASP ASVS L2, RFC 7644/7636, NIST 800-63B)

**For Cloud Engineers**:
- Production-ready code (90% tests, zero-config demo, complete documentation)
- Strict demo/prod separation, secrets never in cleartext
- Comprehensive Makefile (30+ commands), health checks, monitoring
- Scalable architecture (Entra ID roadmap, App Service, Monitor)

---

## 📜 Current Limitations

- **SCIM Filtering**: Only `userName eq "value"` supported (extensible)
- **PATCH**: Limited to `active` attribute (idempotence guaranteed)
- **PUT**: Intentionally 501 (use PATCH/DELETE, RFC compliance)
- **Content-Type**: `application/scim+json` mandatory (RFC 7644)

These limitations are **intentional** to guarantee security and operation idempotence.

---

## 📞 Contact & Portfolio

**Author**: Alexs1004
**Seeking roles**: Cloud Security Engineer · IAM Engineer · DevSecOps (Azure)  
**Location**: Romandy  

**GitHub**: [github.com/Alexs1004/iam-poc](https://github.com/Alexs1004/iam-poc)  
**Full documentation**: [docs/README.md](docs/README.md)  
**Hiring Pack**: [docs/Hiring_Pack.md](docs/Hiring_Pack.md)

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Azure Key Vault** for production-grade secrets management
- **Keycloak** for OIDC/MFA implementation (pending Entra ID migration)
- **SCIM RFC 7644** pour le standard de provisioning d'identités
- **OWASP** pour les guidelines de sécurité applicative
