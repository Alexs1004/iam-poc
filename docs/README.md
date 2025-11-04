# 📚 Documentation Hub — Mini IAM Lab

> **Navigation intelligente** : Documentation organisée par profil (Recruteurs · Sécurité · DevOps)

---

## 🎯 Pour Recruteurs & Screening RH

**Temps de lecture : 5-10 minutes**

| Document | Objectif | Public |
|----------|----------|--------|
| **[Swiss Hiring Pack](Hiring_Pack.md)** | Correspondance CV ↔ Repo, mots-clés ATS, validation rapide | Recruteurs RH, Hiring Managers |
| **[RBAC Demo Scenarios](RBAC_DEMO_SCENARIOS.md)** | Workflows Joiner/Mover/Leaver détaillés, matrice RBAC, tests manuels | Recruteurs RH, Tech Leads |
| **[README Principal](../README.md)** | Positionnement Cloud Security Engineer (Swiss), démarrage 2 min | Tous (screening initial) |

**Ce qu'un recruteur doit retenir** :
- Azure Key Vault opérationnel (production-ready secrets management)
- SCIM 2.0 RFC 7644 compliant (standard IAM inter-entreprises)
- Conformité Swiss : nLPD, RGPD, FINMA (audit trail non-répudiable)
- 328 tests automatisés, 92% coverage (qualité code vérifiable)
- Roadmap Azure-native : Migration Entra ID planifiée

---

## 🔐 Pour Ingénieurs Sécurité & CISO

**Temps de lecture : 30-60 minutes**

| Document | Contenu | Standards |
|----------|---------|-----------|
| **[Security Design](SECURITY_DESIGN.md)** | Contrôles implémentés, threat mitigation, secrets management | OWASP ASVS L2, nLPD, RGPD |
| **[Threat Model](THREAT_MODEL.md)** | Analyse STRIDE, MITRE ATT&CK, conformité FINMA | RFC 7644, NIST 800-63B |
| **[API Reference](API_REFERENCE.md)** | Endpoints SCIM, authentification OAuth, rate limiting | RFC 7644, RFC 6749 |

**Points clés sécurité** :
- **AuthN/AuthZ** : OAuth 2.0 Bearer tokens, PKCE, MFA enforcement
- **Audit Trail** : HMAC-SHA256 signatures (non-repudiation), `make verify-audit`
- **Secrets** : Azure Key Vault (prod), rotation automatisée (`make rotate-secret`)
- **Transport** : TLS 1.3, HSTS, CSP, Secure/HttpOnly cookies
- **Compliance** : nLPD (traçabilité), RGPD (portabilité), FINMA (non-répudiation)

---

## 🛠️ Pour DevOps & Ingénieurs Cloud

**Temps de lecture : 45-90 minutes**

| Document | Contenu | Technologies |
|----------|---------|--------------|
| **[Deployment Guide](DEPLOYMENT_GUIDE.md)** | Azure App Service, Key Vault, Managed Identity, CI/CD | Azure, Docker, Nginx |
| **[Testing Guide](TESTING.md)** | Stratégie de test, couverture, workflow CI/CD, troubleshooting | pytest, coverage, xdist |
| **[Local SCIM Testing](LOCAL_SCIM_TESTING.md)** | Tests locaux, curl examples, troubleshooting | SCIM 2.0, OAuth 2.0 |

**Commandes clés** :
```bash
make quickstart              # Démarrage démo 2 minutes
make doctor                  # Health check Azure + Docker
make test-all                # Suite complète (328 tests, 92% coverage)
make test-coverage           # Tests avec rapport HTML de couverture
make test-coverage-vscode    # Ouvrir rapport dans VS Code
make verify-audit            # Vérification signatures HMAC
make rotate-secret-dry       # Simulation rotation Key Vault
```

**Workflow de couverture de code** :
- `make test-coverage` : Lance tous les tests et génère `htmlcov/index.html`
- `make test-coverage-report` : Affiche les options de visualisation
- `make test-coverage-vscode` : Ouvre le rapport dans VS Code (recommandé)
- `make test-coverage-open` : Tente d'ouvrir dans le navigateur système
- `make test-coverage-serve` : Démarre un serveur HTTP sur `localhost:8888`

---

## 📋 Références Techniques (Core References)

| Document | Description |
|----------|-------------|
| [API Reference](API_REFERENCE.md) | Endpoints SCIM 2.0, OAuth, OpenAPI spec |
| [Security Design](SECURITY_DESIGN.md) | Contrôles sécurité, OWASP ASVS L2, threat mitigation |
| [Threat Model](THREAT_MODEL.md) | Analyse STRIDE, MITRE ATT&CK, conformité Swiss |
| [Deployment Guide](DEPLOYMENT_GUIDE.md) | Azure Key Vault, Managed Identity, App Service |
| [Testing Guide](TESTING.md) | Stratégie de test, couverture 92%, workflow CI/CD |
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
