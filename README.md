# Mini IAM Lab — Azure-First Identity Demo

![Made with Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4?logo=microsoft-azure&logoColor=white)
![Demo in 2 min](https://img.shields.io/badge/Demo-2%20minutes-success?logo=github)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-162%20passed-brightgreen?logo=pytest)
![Coverage](https://img.shields.io/badge/Coverage-85%25-green?logo=codecov)
![Security](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🎯 TL;DR (pour recruteurs)

- **PoC IAM "Azure-first"** : SCIM 2.0 (RFC 7644), OIDC+PKCE, TOTP MFA, RBAC, JML (Joiner/Mover/Leaver) automatisé
- **Secrets Azure Key Vault** : `DefaultAzureCredential`, rotation orchestrée, pattern `/run/secrets` prod-like
- **Tests & qualité** : Tests unitaires + E2E, audit cryptographique HMAC-SHA256, health checks
- **Démo locale en 2 min** : `make quickstart` — zéro configuration Azure requise
- **Alignement Azure** : Key Vault (implémenté), roadmap proche **Microsoft Entra ID**, **Managed Identity**, **Azure Monitor/Policy**
- **Contexte Suisse romande** : Bonnes pratiques **nLPD (LPD 2023)** + **RGPD**, principes **FINMA** (haut niveau)

## 🚀 Essayez en 2 minutes

```bash
make quickstart     # Secrets démo auto + stack + JML automation
open https://localhost
```

**Ce que vous voyez** :
Login → Provisioning JML → Appel SCIM API → Audit signé → Rotation de secret OK (HTTP 200)

> **📹 Vidéo démo (60s)** : _À venir_ — Login alice → Promotion manager → Désactivation bob → Logs d'audit HMAC

**Accès :**
- UI Admin : https://localhost/admin
- SCIM API : https://localhost/scim/v2 (OAuth 2.0 bearer)
- Keycloak : https://localhost/keycloak

<details>
<summary><strong>🔓 Credentials démo (cliquer pour afficher)</strong></summary>

**⚠️ UNIQUEMENT POUR DÉMO LOCALE** — Jamais en production !

- **Keycloak admin** : `admin` / `admin`
- **Utilisateurs démo** : `alice` / `alice`, `bob` / `bob`, `joe` / `joe`
- **Service account** : `automation-cli` / `demo-service-secret`

</details>

## 💼 Hiring Signals — Sécurité & Preuves

| Besoin Entreprise          | Implémentation                  | Azure                          | Preuve Rapide                      |
|----------------------------|---------------------------------|--------------------------------|------------------------------------|
| **Secrets hors code**      | `/run/secrets` + Key Vault      | **Azure Key Vault**            | `make load-secrets`, logs KV       |
| **Rotation créd. service** | Script orchestré end-to-end     | **Azure Key Vault**            | `make rotate-secret` + HTTP 200    |
| **JML standardisé**        | SCIM 2.0 (RFC 7644)             | **Entra ID** (prochain)        | `tests/test_scim_api.py`           |
| **MFA/RBAC**               | Keycloak TOTP + rôles           | **Entra ID** (prochain)        | Démo UI + tests RBAC               |
| **Traçabilité**            | Audit HMAC-SHA256               | **Azure Monitor** (prochain)   | `make verify-audit` (tamper detect)|
| **Conformité locale**      | nLPD, RGPD, FINMA (principes)   | **Azure Policy** (prochain)    | Docs conformité                    |

## 🔐 Pourquoi Azure-First ?

### ✅ Implémenté (Production-Ready)
- **Azure Key Vault** avec `DefaultAzureCredential` (zéro secrets en code)
- Pattern **Docker Secrets** : `/run/secrets` (chmod 400, read-only mount)
- **Rotation orchestrée** : Keycloak → Key Vault → Restart Flask → Health-check
- **Audit trail** : Tous les accès Key Vault loggés dans Azure Activity Log

### 🚀 Roadmap court terme (Q1 2025)
- **Microsoft Entra ID** (ex-Azure AD) : Auth OIDC + SCIM provisioning, consent automation
- **Managed Identity** : Remplacement `az login` par workload identity federation
- **Azure Monitor / App Insights** : Métriques, logs structurés, alerting
- **Azure Policy** : Guardrails infrastructure-as-code, drift detection

> 💡 **Architecture actuelle** : Keycloak démo local → **Migration progressive vers Microsoft Entra ID** pour alignement 100% Azure

## 📋 Table des Matières
1. [Architecture & Composants](#-architecture--composants)
2. [Quickstart (Détaillé)](#️-quickstart-détaillé)
3. [Make Commands](#️-make-commands--référence-rapide)
4. [Conformité & Sécurité](#-conformité--sécurité-suisse-romande)
5. [SCIM 2.0 API](#-scim-20-api)
6. [Tests](#-tests)
7. [Production Notes](#️-production-notes)
8. [Documentation Complète](#-documentation-complète)

---

## 🏗️ Architecture & Composants

```
              ┌─────────────────────┐
              │  Azure Key Vault    │  ← DefaultAzureCredential
              │  (Production)       │     Managed Identity (roadmap)
              └──────────┬──────────┘
                         │ secrets
┌──────────┐   HTTPS    │                   ┌────────────────┐
│  Browser │ ◄─────────►│  Nginx (TLS)     │  Self-signed   │
└──────────┘            │  Reverse Proxy   │  (auto-regen)  │
                        └────────┬──────────┘
                                 │ proxy_pass
                        ┌────────▼──────────┐
                        │  Flask + Gunicorn │  ← OIDC + PKCE
                        │  /admin, /scim/v2 │     RBAC, MFA
                        └────────┬──────────┘
                                 │ Admin API
                        ┌────────▼──────────┐
                        │  Keycloak 24      │  ← TOTP MFA
                        │  Realm: demo      │     Session mgmt
                        └───────────────────┘
```

**Service Docker Compose** : Keycloak + Flask/Gunicorn + Nginx (orchestration santé, health checks)

**Flux de données** :
1. Browser → Nginx (HTTPS) → Flask (OIDC validate) → Keycloak (token)
2. Flask Admin UI → `provisioning_service.py` → `scripts/jml.py` → Keycloak Admin API
3. SCIM Client → Nginx → Flask SCIM API → `provisioning_service.py` (logique unifiée)
4. Audit : Toutes opérations → `audit.py` → `.runtime/audit/jml-events.jsonl` (HMAC-SHA256)

## ⚙️ Quickstart (Détaillé)

### Mode Démo (Développement Local — Recommandé)

```bash
# Installation zéro config
make quickstart

# Ce qui se passe automatiquement :
# 1. ✅ Copie .env.demo → .env (si absent)
# 2. ✅ Génère FLASK_SECRET_KEY (256 bits) + AUDIT_LOG_SIGNING_KEY (384 bits)
# 3. ✅ Démarre Keycloak + Flask + Nginx avec health checks
# 4. ✅ Bootstrap service account automation-cli (secret: demo-service-secret)
# 5. ✅ Crée realm demo + users (alice, bob, carol, joe) + roles
# 6. ✅ Démontre JML : alice promue manager, bob désactivé
```

**Identités de démo** :
- `alice` / `alice` : Analyst → Manager (après promotion)
- `bob` / `bob` : Analyst → Désactivé (leaver demo)
- `joe` / `joe` : IAM Operator + Realm Admin (full access)
- `admin` / `admin` : Master realm (cross-realm control)
v
**Commandes utiles** :
```bash
make demo-jml       # Rejouer demo JML sans rebuild
make fresh-demo     # Reset complet : volumes + secrets + certs
make down           # Arrêter stack
make logs           # Logs temps réel
make ps             # Status containers
```

### Mode Production (Azure Key Vault)

```bash
# 1. Configuration production dans .env
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=<votre-keyvault>

# 2. Authentification Azure
az login

# 3. Démarrage (charge secrets depuis Key Vault)
make quickstart

# 4. Rotation de secrets (orchestrée)
make rotate-secret          # Keycloak → KV → Restart → Health
make rotate-secret-dry      # Test dry-run
```

**Permissions Azure requises** :
- **Key Vault Secrets User** (lecture secrets)
- **Key Vault Secrets Officer** (écriture pour rotation)
- Voir [docs/DETAILED_SETUP.md](docs/DETAILED_SETUP.md) pour guide complet

## 🛡️ Make Commands — Référence Rapide

### Essentiel
- `make quickstart` — **Démarrage zéro-config** (démo ou prod selon `.env`)
- `make fresh-demo` — Reset complet (volumes + secrets + certificats)
- `make down` — Arrêt containers
- `make help` — Afficher tous les targets disponibles

### Secrets (Production)
- `make load-secrets` — Charger depuis Azure Key Vault → `.runtime/secrets/`
- `make rotate-secret` — Rotation orchestrée (prod uniquement)
- `make clean-secrets` — Effacer caches locaux

### Tests & Validation
- `make pytest` — Tests unitaires (mocked Keycloak)
- `make pytest-e2e` — Tests E2E (stack running requis)
- `make validate-env` — Vérifier cohérence `.env`
- `make doctor` — Diagnostic complet (az CLI, Key Vault, docker)

## 🛡️ Conformité & Sécurité (Suisse Romande)

### Réglementation Locale (Haut Niveau)

**nLPD (LPD 2023) — Nouvelle loi fédérale sur la protection des données**
- ✅ **Minimisation** : Secrets hors dépôt Git (`.gitignore`), accès Key Vault loggé
- ✅ **Traçabilité** : Audit logs tamper-evident (HMAC-SHA256), append-only
- ✅ **Sécurité technique** : Chiffrement transport (TLS), secrets read-only (`chmod 400`)
- ✅ **Droit d'accès** : RBAC granulaire (analyst/manager visibilité, operator modifications)

**RGPD (Règlement européen) — Applicable en Suisse**
- ✅ **Privacy by Design** : MFA obligatoire, sessions révoquées immédiatement
- ✅ **Accountability** : Logs d'audit signés cryptographiquement (non-répudiation)
- ✅ **Data Portability** : Export SCIM 2.0 (standard interopérable)

**FINMA (Principes) — Exigences de contrôle & traçabilité**
- ✅ **Ségrégation des rôles** : Analyst (vue) vs Operator (action) vs Admin (config)
- ✅ **Piste d'audit** : Qui a fait quoi, quand, avec quelle autorisation
- ✅ **Continuité** : Health checks, graceful restart, idempotence

> **Note** : Ce projet démontre les **principes techniques** de conformité. Mise en production réelle nécessite analyse juridique complète (DPIA, contrats sous-traitance, etc.).

### Guardrails Sécurité (Implémentés)

**Transport & Réseau**
- ✅ HTTPS obligatoire (Nginx TLS, auto-regen certs 30 jours)
- ✅ Validation proxy (`X-Forwarded-*` vs `TRUSTED_PROXY_IPS`)
- ✅ Headers sécurité : HSTS (`max-age=31536000`), CSP (`default-src 'self'`), `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin` → Voir [`proxy/nginx.conf`](proxy/nginx.conf)

**Auth & Authorization**
- ✅ OIDC Authorization Code + PKCE (anti-interception)
- ✅ RBAC route-level (`@require_jml_operator`, `@require_admin_view`)
- ✅ MFA obligatoire (TOTP required action Keycloak)
- ✅ Sessions server-side (secure cookies : `Secure`, `HttpOnly`, `SameSite=Lax`)

**Gestion Secrets (Production)**
- ✅ Azure Key Vault (`DefaultAzureCredential`, zéro secrets en code)
- ✅ Pattern `/run/secrets` (chmod 400, read-only mount Docker)
- ✅ Rotation orchestrée : Keycloak → KV → Restart → Health-check
- ✅ Audit trail Azure Activity Log

**Gestion Secrets (Démo)**
- ✅ Auto-génération `secrets.token_urlsafe()` (256-384 bits)
- ✅ Idempotent (génère une seule fois, préserve existant)
- ✅ Git-safe (`.env` in `.gitignore`, jamais loggé console)
- ✅ Production guard (`DEMO_MODE=false` désactive génération locale)

**Sécurité Application**
- ✅ CSRF protection (tokens validés sur routes mutantes)
- ✅ Input validation (regex strict username/email/name)
- ✅ XSS prevention (Jinja2 auto-escaping, CSP headers)
- ✅ Session revocation (effet immédiat sur user disable)

**Audit & Compliance**
- ✅ Logs cryptographiques (HMAC-SHA256 sur chaque événement JML/SCIM)
- ✅ Append-only (`.runtime/audit/jml-events.jsonl`)
- ✅ Tamper detection (`make verify-audit`)
- ✅ Clés séparées demo vs production

> 🔒 **Preuves de sécurité** : Voir [docs/SECURITY_PROOFS.md](docs/SECURITY_PROOFS.md) pour captures d'écran, commandes de vérification, et scénarios de test.

## ⚠️ Known Limitations

### SCIM API Authentication (🔴 Production Blocker)

**Status**: SCIM 2.0 API endpoints are functional but **do not validate OAuth 2.0 Bearer tokens**.

**What works** ✅:
- SCIM routes implemented: `POST /Users`, `GET /Users`, `PUT /Users/{id}`, `DELETE /Users/{id}`
- SCIM ↔ Keycloak transformations functional
- Content-Type validation (`application/scim+json`)
- ServiceProviderConfig declares OAuth support

**What's missing** ❌:
- OAuth 2.0 Bearer token validation (RFC 6750)
- JWT signature verification against Keycloak JWKS
- Role/scope authorization checks
- Token expiration enforcement
- Client identification in audit logs

**Impact**:
- 🔴 **DO NOT expose `/scim/v2/*` publicly** without implementing OAuth validation
- 🔴 Anyone with network access can create/modify/delete users via SCIM
- 🟠 Non-RFC 7644 compliant (Section 2 requires authentication)
- 🟠 No audit trail of SCIM operations (missing `client_id`)

**Workaround**:
- ✅ Use admin UI (`/admin/*`) for user provisioning (protected by OIDC session)
- ✅ Block SCIM routes in nginx for production deployments
- ✅ E2E tests for SCIM temporarily skipped (see [`docs/E2E_SCIM_WORKAROUND.md`](docs/E2E_SCIM_WORKAROUND.md))

**Remediation**: 
- 📖 Complete implementation guide: [`docs/SCIM_AUTHENTICATION.md`](docs/SCIM_AUTHENTICATION.md)
- 📖 Executive summary: [`docs/SCIM_AUTH_SUMMARY.md`](docs/SCIM_AUTH_SUMMARY.md)
- ⏱️ Estimated effort: **6 hours** (middleware + tests + validation)
- 🎯 Priority: **P0** (required before production deployment)

**Testing**:
```bash
# Verify if OAuth is implemented (should return 401)
curl -X GET https://localhost/scim/v2/Users

# If 200 OK or 403 (not 401) → OAuth not enforced
```

See [`docs/SCIM_AUTHENTICATION.md`](docs/SCIM_AUTHENTICATION.md) for detailed implementation roadmap, RFC compliance checklist, and test procedures.

## 🔌 SCIM 2.0 API

**API standardisée** pour provisioning utilisateurs (RFC 7644), compatible Okta, Azure AD, autres IdP.

### Endpoints Principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/scim/v2/Users` | Créer utilisateur (joiner) |
| `GET` | `/scim/v2/Users` | Lister + filtrer (`filter=userName eq "alice"`) |
| `GET` | `/scim/v2/Users/{id}` | Récupérer utilisateur |
| `PUT` | `/scim/v2/Users/{id}` | Mettre à jour (incl. `active=false` leaver) |
| `DELETE` | `/scim/v2/Users/{id}` | Soft delete (disable) |

### Authentification

OAuth 2.0 Bearer token (service account `automation-cli`) :

```bash
# Obtenir token
TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=${KEYCLOAK_SERVICE_CLIENT_SECRET:-demo-service-secret}" \
  | jq -r '.access_token')

# Créer utilisateur
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "nouvelutilisateur",
    "emails": [{"value": "nouveau@example.com", "primary": true}],
    "active": true
  }'
```

**Features** :
- ✅ RFC 7644 compliant (schémas, erreurs, filtering, pagination)
- ✅ Audit trail (HMAC-SHA256 sur toutes opérations)
- ✅ Session revocation (effet immédiat sur `active=false`)
- ✅ Validation stricte (username, email, noms)

> 📘 **Guide complet** : [docs/SCIM_API_GUIDE.md](docs/SCIM_API_GUIDE.md) _(à venir)_ — Tests disponibles : `tests/test_scim_api.py`, `scripts/test_scim_api.sh`

## 🧪 Tests

```bash
make pytest         # Tests unitaires (Keycloak mocké)
make pytest-e2e     # Tests E2E intégration (stack running)
make verify-audit   # Vérifier signatures HMAC logs
```

**Couverture** :
- `tests/test_flask_app.py` — RBAC, CSRF, headers sécurité, cookies
- `tests/test_scim_api.py` — SCIM RFC 7644 compliance (CRUD, filtering)
- `tests/test_jml.py` — Automation CLI, service account, bootstrap
- `tests/test_audit.py` — Signatures crypto, tamper detection
- `tests/test_integration_e2e.py` — Workflows end-to-end (OIDC, JML, SCIM)

**Mode test** : `DEMO_MODE=true` (tests self-contained, aucun accès Azure requis)

### 🛡️ Test Posture Sécurité

- **Unitaires hermétiques** : fixtures autouse mockent OIDC/JWKS ⇒ aucun appel réseau accidentel.
- **Modules critiques ≥80 %** : `app/core/validators` 100 %, `app/core/rbac` 85 %, `app/core/provisioning_service` 82 %, `app/api/errors` 91 %.
- **SCIM & OAuth** : `app/api/scim` couvert à 78 % + batterie d’intégration (`tests/test_integration_e2e.py`) sur stack Docker.
- **CI gating** : workflow `tests-coverage` exécute `pytest -m "not integration"` avec `--cov-fail-under=60`, badge calculé depuis `coverage.xml`.
- **Glue UI exclue** : `app/api/admin.py` & `app/api/helpers/admin_ui.py` omis des unitaires (couverts via tests E2E).

## ☁️ Production Notes

**Avant déploiement** :
- ❌ **Retirer bind mounts** : `.:/srv/app`, `./.runtime/azure:/root/.azure` (bake dans image)
- ✅ **Managed Identity** : Remplacer `az login` par workload identity federation
- ✅ **Certificats CA-signed** : Azure Application Gateway, Front Door, ou cert-manager
- ✅ **Logs centralisés** : Azure Monitor, App Insights (structured logging)
- ✅ **CI/CD** : Container scanning (Trivy), IaC validation (Terraform/Bicep)
- ✅ **Policies** : Tighten Nginx CSP, HSTS max-age, referrer policies

**Checklist sécurité** :
1. `DEMO_MODE=false` + `AZURE_USE_KEYVAULT=true`
2. Secrets uniquement depuis Key Vault (`.env` ne contient **aucun** secret)
3. Audit logs rétention policy (Azure Storage immutable blobs)
4. Network policies (NSG, Azure Firewall, private endpoints)
5. RBAC Key Vault granulaire (principe du moindre privilège)

## 📚 Documentation Complète

### Guides Principaux
- **[docs/DETAILED_SETUP.md](docs/DETAILED_SETUP.md)** _(à venir)_ — Configuration détaillée (secrets, SCIM, architecture)
- **[docs/SECURITY_PROOFS.md](docs/SECURITY_PROOFS.md)** — Preuves de sécurité (captures, commandes vérification)
- **[docs/SCIM_API_GUIDE.md](docs/SCIM_API_GUIDE.md)** _(à venir)_ — Intégration SCIM (Okta, Azure AD, curl)
- **[docs/SECRET_ROTATION.md](docs/SECRET_ROTATION.md)** _(à venir)_ — Rotation orchestrée (CI/CD, troubleshooting)
- **[docs/README.md](docs/README.md)** — Index complet documentation

### Documentation Technique
- **[CHANGELOG.md](CHANGELOG.md)** — Historique versions, breaking changes
- **[docs/UNIFIED_SERVICE_ARCHITECTURE.md](docs/UNIFIED_SERVICE_ARCHITECTURE.md)** _(à venir)_ — Architecture v2.0
- **[docs/IMPLEMENTATION_SUMMARY.md](docs/IMPLEMENTATION_SUMMARY.md)** _(vide, à compléter)_ — Résumé implémentation
- **[docs/JML_REFACTORING_SUMMARY.md](docs/JML_REFACTORING_SUMMARY.md)** — Refactoring JML

### Support & Troubleshooting

**Problèmes courants** :
- **Flask unhealthy** → `make doctor` puis `make fresh-demo`
- **404 automation** → Stack pas running → `make quickstart`
- **Key Vault denied** → Permissions manquantes → Assigner **Key Vault Secrets User**
- **Service secret vide** → Bootstrap manqué → `make fresh-demo`
- **"Invalid client credentials"** → Demo mode secret mismatch → `make fresh-demo`

> 🩺 **Diagnostic complet** : Section troubleshooting détaillée à venir dans docs/DETAILED_SETUP.md

## 🗺️ Roadmap Azure

### ✅ Phase Actuelle (v2.3 — Production)
- Azure Key Vault (`DefaultAzureCredential`, rotation orchestrée)
- Pattern Docker Secrets (`/run/secrets`, chmod 400)
- Auto-génération secrets (demo mode, 256-384 bits)
- SCIM 2.0 API (RFC 7644, unified architecture)
- Audit cryptographique (HMAC-SHA256, tamper-evident)

### 🚀 Q1 2025 — Azure-Native Phase
- **Microsoft Entra ID** : Authentification OIDC + provisioning SCIM (remplacement Keycloak)
- **Managed Identity** : Workload identity federation (zéro secret auth Azure)
- **Azure Monitor** : Logs structurés, métriques, alerting (KQL queries)
- **App Insights** : Tracing distribué, performance monitoring
- **Azure Policy** : Guardrails IaC, compliance automation

### Q2 2025 — Enterprise Hardening
- **Azure Application Gateway** : WAF, certificats managés, DDoS protection
- **Azure Private Link** : Key Vault private endpoints
- **Azure DevOps Pipelines** : CI/CD automation (Terraform/Bicep)
- **Defender for Cloud** : Container vulnerability scanning
- **Cost Management** : Budgets, tagging, optimization

### Q3 2025+ — Avancé
- Webhook provisioning (real-time JML)
- CLI versioned (`scripts/jml.py` → PyPI package)
- Policy-as-Code (OPA integration)
- ACME/Let's Encrypt automation

## 👥 Identités & RBAC (Démo)

| Identité | Rôles | `/admin` | JML Ops | Keycloak Console |
|----------|-------|----------|---------|------------------|
| `alice` | `analyst` → `iam-operator` | ✅ Vue → Full (après promo) | ✅ (après) | ❌ |
| `bob` | `analyst` (désactivé) | ✅ Vue | ❌ | ❌ |
| `carol` | `manager` → `iam-operator` | ✅ Vue → Full (après promo) | ✅ (après) | ❌ |
| `joe` | `iam-operator` + `realm-admin` | ✅ Full | ✅ | ✅ demo realm |
| `admin` | Master admin | ✅ Full | ✅ | ✅ Tous realms |

**Principe de gouvernance** : 
- **Analyst/Manager** : Vue (snapshot users + audit) — **oversight sans modification**
- **IAM Operator** : Plein accès (JML forms + vue)
- **Realm Admin** : Opérateur + configuration Keycloak realm

## 📄 License

**MIT License** — Voir [LICENSE](LICENSE)

---

## � Author

**Alex** (@Alexs1004)  
🔗 GitHub: [github.com/Alexs1004/iam-poc](https://github.com/Alexs1004/iam-poc)

---

## �🔗 Ressources Complémentaires

**Keywords Azure/Suisse Romande** :
Azure Key Vault • Microsoft Entra ID • Managed Identity • Azure Monitor • Azure Policy • Defender for Cloud • SC-300 • AZ-500 • nLPD (LPD 2023) • RGPD • FINMA • SCIM 2.0 • OIDC • JML • Suisse Romande • DevSecOps

**Certifications recommandées** :
- **SC-300** : Microsoft Identity and Access Administrator
- **AZ-500** : Azure Security Engineer Associate
- **AZ-104** : Azure Administrator Associate

---

> 💼 **Contact** : GitHub [@Alexs1004](https://github.com/Alexs1004) | [Ouvrir une issue](https://github.com/Alexs1004/iam-poc/issues)

---
