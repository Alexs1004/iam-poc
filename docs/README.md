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
- Operational Azure Key Vault (production-ready secrets management)
- SCIM 2.0 RFC 7644 compliant (inter-enterprise IAM standard)
- Swiss compliance: nLPD, GDPR, FINMA (non-repudiable audit trail)
- 346 automated tests, 91% coverage (verifiable code quality)
- Security pipeline: Gitleaks, Trivy, Syft, Grype (CI/CD + local)
- Azure-native roadmap: Entra ID migration planned

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
