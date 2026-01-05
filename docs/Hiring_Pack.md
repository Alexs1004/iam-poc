# Swiss Hiring Pack — Mini IAM Lab

> **Recipients**: Cloud Security / IAM Recruiters · Tech Leads · Hiring Managers  
> **Objective**: Facilitate technical candidate evaluation via Resume ↔ Repository mapping

---

## 📋 Overview

This document establishes direct correspondence between **skills listed on CV** and **technical evidence in this repository**. It allows recruiters to quickly validate candidate expertise on Azure technologies and cloud security.

---

## 🎯 Target Profile

**Target roles**:
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Identity & Access Management Specialist

**Location**: Romandy

**Experience**: 0-3 years in cloud security, continuous training in Azure/IAM

---

## 🔑 Mots-Clés Recruteurs (ATS-Friendly)

### Cloud & Azure
`Azure Key Vault` · `Azure Entra ID` · `Azure AD B2C` · `Managed Identity` · `Azure Monitor` · `Application Insights` · `Azure Policy` · `Azure App Service` · `Azure SQL Database` · `Azure Cache for Redis` · `Azure Front Door` · `Microsoft Defender for Cloud`

### IAM & Authentification
`SCIM 2.0` · `OpenID Connect (OIDC)` · `OAuth 2.0` · `PKCE` · `Multi-Factor Authentication (MFA)` · `Role-Based Access Control (RBAC)` · `JWT Validation` · `SSO (Single Sign-On)` · `Provisioning Automation` · `Joiner/Mover/Leaver (JML)`

### Sécurité & Conformité
`OWASP ASVS` · `nLPD` · `RGPD` · `FINMA` · `Non-Repudiation` · `Cryptographic Audit Trail` · `HMAC-SHA256` · `Secret Rotation` · `Zero Trust` · `Rate Limiting` · `Security Headers` · `TLS 1.3`

### DevSecOps
`CI/CD` · `GitHub Actions` · `pytest` · `Docker` · `Docker Compose` · `Nginx` · `Makefile` · `Infrastructure as Code` · `Secret Management` · `Health Checks` · `Monitoring`

### Standards & RFC
`RFC 7644 (SCIM 2.0)` · `RFC 7636 (PKCE)` · `RFC 6749 (OAuth 2.0)` · `RFC 7519 (JWT)` · `NIST 800-63B`

---

## 📊 Resume ↔ Repository Mapping

| CV Skill | Level | Repository Evidence | File/Command | Validation |
|---------------|--------|---------------------|------------------|------------|
| **Azure Key Vault** | ⭐⭐⭐⭐ | Full integration, automated rotation, dry-run | `make rotate-secret`<br>`scripts/load_secrets_from_keyvault.sh`<br>`scripts/rotate_secret.sh` | ✅ Functional |
| **SCIM 2.0** | ⭐⭐⭐⭐ | RFC 7644-compliant API, compliance tests | `app/api/scim.py`<br>`tests/test_api_scim.py`<br>`openapi/scim_openapi.yaml` | ✅ 300+ tests |
| **OIDC/OAuth 2.0** | ⭐⭐⭐⭐ | PKCE, MFA, RSA-SHA256 JWT validation | `app/api/auth.py`<br>`app/api/decorators.py`<br>`app/core/rbac.py` | ✅ JWT tests |
| **RBAC** | ⭐⭐⭐ | 3 granular roles (admin/operator/verifier) | `app/core/rbac.py`<br>`tests/test_core_rbac.py` | ✅ RBAC tests |
| **Audit Trail** | ⭐⭐⭐⭐ | HMAC-SHA256, non-repudiation, integrity verification | `scripts/audit.py`<br>`make verify-audit`<br>`.runtime/audit/jml-events.jsonl` | ✅ 22/22 valid signatures |
| **Secret Rotation** | ⭐⭐⭐ | Full orchestration, pre-deployment validation | `scripts/rotate_secret.sh`<br>`make rotate-secret-dry` | ✅ Dry-run OK |
| **DevSecOps** | ⭐⭐⭐ | CI/CD, 91% tests, secrets management | `.github/workflows/`<br>`Makefile` (30+ commands)<br>`pytest.ini` | ✅ 346 tests |
| **Python 3.12** | ⭐⭐⭐⭐ | Flask, pytest, type hints, async | All `.py` files<br>`requirements.txt` | ✅ Type-safe |
| **Docker** | ⭐⭐⭐ | Multi-service Compose, health checks, volumes | `docker-compose.yml`<br>`Dockerfile.flask` | ✅ 3 healthy services |
| **Nginx** | ⭐⭐⭐ | TLS 1.3, rate limiting, security headers | `proxy/nginx.conf`<br>`scripts/test_rate_limiting.sh` | ✅ Rate limit tests |
| **Compliance** | ⭐⭐⭐ | nLPD/GDPR/FINMA by design | `docs/THREAT_MODEL.md`<br>`docs/SECURITY_DESIGN.md` | ✅ Audited architecture |

**Legend**:  
⭐⭐⭐⭐ = Confirmed mastery (production-ready code)  
⭐⭐⭐ = Good knowledge (functional implementation)  
⭐⭐ = Basic understanding (documentation + tests)

---

## 🧪 Quick Validation (30 seconds)

### Option 1: Web Interface
```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart  # 2 minutes
open https://localhost/verification  # Automatic tests
```

### Option 2: CLI
```bash
make test          # Unit tests (346 tests, 91% coverage)
make verify-audit  # HMAC signature verification
make doctor        # Azure + Docker health check
```

### Option 3: Code Review
Key files to examine (15 min):
- `app/api/scim.py` — SCIM RFC 7644 implementation
- `app/api/auth.py` — OIDC with PKCE
- `scripts/rotate_secret.sh` — Azure Key Vault rotation
- `Makefile` — Infrastructure as Code (30+ commands)

---

## 📈 Quality Metrics

| Indicator | Value | Target | Status |
|------------|--------|-------|--------|
| **Tests** | 346 | >200 | ✅ Exceeded |
| **Coverage** | 91% | >80% | ✅ Exceeded |
| **Azure Integration** | Key Vault + Entra ID Roadmap | Cloud-native | ✅ Operational |
| **Security Standards** | OWASP ASVS L2 | L1 minimum | ✅ Exceeded |
| **Documentation** | 10 docs/ files | 5 minimum | ✅ Complete |
| **Audit Trail** | 22/22 valid signatures | 100% | ✅ Perfect |

---

## Romandy Context

### Implemented Regulatory Compliance
- **nLPD (new Swiss Data Protection Act)**:
  - ✅ Timestamped audit trail with correlation-id
  - ✅ Personal data access traceability
  - ✅ Secure log retention (400 permissions)

- **GDPR**:
  - ✅ Consent tracked via audit trail
  - ✅ Right to be forgotten (soft-delete)
  - ✅ Portability (standard SCIM API)

- **FINMA (financial sector)**:
  - ✅ Non-repudiation via cryptographic signatures
  - ✅ Immutable audit log (tamper detection)
  - ✅ Evidence retention (immutable audit log)

### Valued Skills in Switzerland
1. **Azure Entra ID**: Microsoft cloud-native identity management
2. **SCIM 2.0 Provisioning**: Inter-enterprise IAM standard
3. **Compliance-by-design**: Architecture compliant from conception
4. **DevSecOps**: Automated tests, secret rotation, secure CI/CD
5. **Technical multilingualism**: FR/EN documentation, international standards

### Target Sectors
- **Finance** (Banks, Insurance): FINMA compliance, audit trail
- **Healthcare**: Strict nLPD/GDPR, traceability
- **Tech**: SaaS, Identity Providers, Cloud Security
- **Consulting**: Azure integration, Entra ID migrations

---

## 🎓 Training & Certifications (Recommended)

**Target Azure certifications**:
- [ ] **AZ-900**: Azure Fundamentals (foundation)
- [ ] **AZ-500**: Azure Security Engineer Associate (main target)
- [ ] **SC-300**: Microsoft Identity and Access Administrator (IAM focus)

**Complementary training**:
- OWASP Top 10 & ASVS
- SCIM 2.0 Protocol (RFC 7644)
- OAuth 2.0 & OIDC (RFC 6749, 6750, 7636)

---

## 📞 Frequently Asked Questions from Recruiters

### Q1: "Why Keycloak and not directly Entra ID?"
**A**: Pedagogical choice to demonstrate mastery of OIDC/MFA standards independently. The **Azure-native roadmap** is documented (Phase 1: Entra ID migration planned) with already compatible architecture.

### Q2: "Is the project production-ready?"
**A**: **Yes for security**, no for scalability:
- ✅ Azure Key Vault secrets management (production-grade)
- ✅ Non-repudiable cryptographic audit
- ✅ 91% tests, CI/CD, automated rotation
- ⚠️ SQLite → Azure SQL Database required for HA
- ⚠️ Local sessions → Azure Cache for Redis for distribution

### Q3: "What is the real Azure experience?"
**A**: **Learning project with functional implementation**:
- Operational Azure Key Vault integration (az cli, Python SDK)
- Understanding cloud-native architecture (Managed Identity, App Service, Monitor)
- Compliance-by-design approach (nLPD/GDPR/FINMA)
- **Seeking internship/apprenticeship** for large-scale production experience

### Q4: "Estimated ramp-up time?"
**A**: On existing Azure environment:
- **Week 1**: Familiarization with Entra ID, SCIM provisioning
- **Week 2-3**: API integration, conditional access policies
- **Month 2**: Autonomy on routine IAM (JML, MFA, RBAC)
- **Month 3-6**: Expertise on advanced topics (B2B/B2C, compliance audits)

### Q5: "Interview availability?"
**A**: Immediate. Notice period: none (active job search).

---

## 📂 Documentation Navigation

| Document | Audience | Content |
|----------|----------|---------|
| **[README.md](../README.md)** | All | General presentation, quickstart, roadmap |
| **[Hiring_Pack.md](Hiring_Pack.md)** | Recruiters | This document (Resume ↔ Repo mapping) |
| **[RBAC_DEMO_SCENARIOS.md](RBAC_DEMO_SCENARIOS.md)** | Tech Leads | Detailed JML workflows, user matrix, scenarios |
| **[SECURITY_DESIGN.md](SECURITY_DESIGN.md)** | CISO/SOC | Threat model, OWASP ASVS L2, protection |
| **[API_REFERENCE.md](API_REFERENCE.md)** | Engineers | SCIM endpoints, curl examples, error codes |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | DevOps | Azure App Service, CI/CD, monitoring |
| **[THREAT_MODEL.md](THREAT_MODEL.md)** | Security | Risk analysis, mitigations, audit |

---

## ✅ Technical Evaluation Checklist

**For HR recruiter** (5 minutes):
- [ ] Verify GitHub badges (tests, coverage, security)
- [ ] Consult Resume ↔ Repo mapping table
- [ ] Validate Azure Key Vault presence (production-ready)
- [ ] Verify nLPD/GDPR/FINMA compliance mentioned

**For Tech Lead** (30 minutes):
- [ ] Launch `make quickstart` → verify functional demo
- [ ] Test `/verification` page → validate automatic tests
- [ ] Examine `make rotate-secret-dry` → verify orchestration
- [ ] Code review `app/api/scim.py` → evaluate code quality
- [ ] Read `docs/SECURITY_DESIGN.md` → validate architecture

**For CISO** (1 hour):
- [ ] Audit trail: `make verify-audit` → 22/22 signatures OK
- [ ] Threat model: `docs/THREAT_MODEL.md` → identified risks
- [ ] Standards: OWASP ASVS L2, RFC 7644/7636, NIST 800-63B
- [ ] Compliance: nLPD (traceability), GDPR (portability), FINMA (non-repudiation)
- [ ] Roadmap: Entra ID migration, Managed Identity, Monitor

---

## 📧 Contact

**Candidate**: Alex (Romandy)  
**Email**: [See GitHub Profile](https://github.com/Alexs1004)  
**LinkedIn**: https://www.linkedin.com/in/alexandre-stutz/ 
**Availability**: Immediate  
**Mobility**: Romandy

**Target roles**:
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Stage/Alternance Cloud Security

---

## 🙏 Why This Project?

This repository demonstrates my ability to:
1. **Design** a complete and auditable IAM system
2. **Implement** security standards (OWASP, RFC, NIST)
3. **Integrate** Azure services (Key Vault, Entra ID roadmap)
4. **Document** professionally (recruiters + engineers)
5. **Think compliance** from inception (nLPD, GDPR, FINMA)

**In summary**: I know how to build secure, auditable, and compliant cloud environments. I am now seeking to **apply these skills within a Romandy-based team**.
