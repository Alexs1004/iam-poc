# Mini IAM Lab — Azure Security PoC
### SCIM 2.0 · OIDC/MFA · Azure Key Vault · Cryptographic Audit Trail

![Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4?logo=microsoft-azure&logoColor=white)
![Entra ID Ready](https://img.shields.io/badge/Migration-Entra%20ID%20Ready-0078D4?logo=microsoft-azure)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests 92%](https://img.shields.io/badge/Coverage-92%25-brightgreen?logo=codecov)
![Security OWASP](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![Swiss Compliance](https://img.shields.io/badge/Compliance-nLPD%20%7C%20RGPD%20%7C%20FINMA-red)
![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> **🎯 Démo en 2 minutes · Production-ready mindset · Swiss compliance focus**

---

## Positionnement : Cloud Security Engineer (Suisse Romande)

Ce projet démontre une **maîtrise opérationnelle des standards IAM modernes** dans un contexte **Azure-first** et **conforme aux exigences suisses** (nLPD, RGPD, FINMA). Il s'adresse aux recruteurs en sécurité cloud recherchant des profils capables de concevoir, sécuriser et auditer des environnements d'identité dans le cloud Microsoft Azure.

**Mots-clés recruteurs** : Azure Entra ID (ex-Azure AD) · SCIM 2.0 Provisioning · OIDC/OAuth 2.0 · MFA Policy · RBAC · Azure Key Vault · Managed Identity · Secret Rotation · Non-Repudiation · DevSecOps · Cryptographic Audit · Compliance (nLPD/RGPD/FINMA)

**Rôles cibles** : Junior Cloud Security Engineer (Azure) · IAM Engineer · DevSecOps Cloud · Identity & Access Management Specialist

---

## ⚡ Démarrage Rapide (2 minutes)

```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart
open https://localhost
```

**Ce que vous verrez** :
- Authentification OIDC avec MFA (Keycloak → migration Entra ID prévue)
- API SCIM 2.0 RFC 7644-compliant (Joiner/Mover/Leaver automation)
- Secrets chargés depuis Azure Key Vault (zero-config demo mode disponible)
- Trail d'audit cryptographique avec signatures HMAC-SHA256 vérifiables
- Page de vérification interactive : https://localhost/verification

### 👥 Utilisateurs de Démo & Matrice RBAC

Le `make demo` provisionne **4 utilisateurs** avec différents niveaux d'accès (démonstration complète JML) :

| Utilisateur | Rôle Initial | Rôle Final | Mot de passe | Accès Admin UI | Opérations JML | Scénario |
|-------------|--------------|------------|--------------|----------------|----------------|----------|
| **alice** | `analyst` | **`iam-operator`** ⬆️ | `Temp123!` | ❌ → ✅ Admin complet | ❌ → ✅ Joiner/Mover/Leaver | **Mover** : Promotion analyst → operator |
| **bob** | `analyst` | ~~`disabled`~~ ❌ | `Temp123!` | ❌ 403 Forbidden | ❌ Aucune | **Leaver** : Compte désactivé |
| **carol** | `manager` | `manager` | `Temp123!` | ✅ Lecture seule | ❌ Aucune | **Stable** : Manager (lecture) |
| **joe** | `iam-operator` | `iam-operator`<br>+ `realm-admin` | `Temp123!` | ✅ Admin complet | ✅ Joiner/Mover/Leaver | **Stable** : Opérateur IAM complet |

**Hiérarchie des Rôles (RBAC)** :
- **`realm-admin`** : Contrôle total (Keycloak realm management)
- **`iam-operator`** : Opérations JML (créer/modifier/désactiver utilisateurs) + lecture dashboard
- **`manager`** : Lecture dashboard admin, pas d'opérations
- **`analyst`** : Aucun accès admin UI (403 Forbidden)

**Test Rapide** :
```bash
# 1. Se connecter avec joe (iam-operator + realm-admin)
open https://localhost
# Username: joe | Password: Temp123! | MFA: Configure TOTP à la première connexion

# 2. Accéder au dashboard admin
open https://localhost/admin

# 3. Vérifier l'audit trail des opérations JML
open https://localhost/admin/audit

# 4. Vérifier intégrité signatures HMAC
make verify-audit
```

**💡 Points Clés** :
- **Séparation des privilèges** : 4 niveaux de rôles (principe du moindre privilège)
- **Cycle de vie complet** : Joiner (alice), Mover (alice → operator), Leaver (bob disabled)
- **Traçabilité** : Chaque opération JML signée cryptographiquement (`/admin/audit`)
- **MFA obligatoire** : TOTP requis pour tous les comptes (standard NIST 800-63B)

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

**Stack Technique** :
- **Identity Provider** : Keycloak 24 (OIDC + MFA) → **Migration Entra ID prévue**
- **API Backend** : Flask (Python 3.12) + SCIM 2.0 RFC 7644
- **Secrets Management** : Azure Key Vault SDK (azure-keyvault-secrets)
- **Reverse Proxy** : Nginx (TLS 1.3, rate limiting, security headers)
- **Audit** : HMAC-SHA256 signatures pour non-répudiation

---

## 🎯 Ce Projet Démontre

### Sécurité Cloud Azure
- **Azure Key Vault** comme source unique de vérité pour secrets (KEYCLOAK_SERVICE_CLIENT_SECRET, FLASK_SECRET_KEY, AUDIT_LOG_SIGNING_KEY)
- **Rotation automatisée** des secrets avec validation d'intégrité (dry-run disponible)
- **Architecture prête pour Managed Identity** (élimination des Service Principals)
- **Security headers** : HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Rate limiting** : Protection DoS sur endpoints critiques (SCIM, admin, verification)

### Gestion d'Identités (IAM)
- **SCIM 2.0 RFC 7644** : API standardisée de provisioning d'identités
- **OIDC/OAuth 2.0** : Authentification fédérée avec PKCE (RFC 7636)
- **Multi-Factor Authentication** : OTP obligatoire pour comptes admin
- **RBAC granulaire** : realm-admin, iam-operator, iam-verifier (séparation des privilèges)
- **Joiner/Mover/Leaver (JML)** : Automatisation du cycle de vie utilisateurs

### Conformité & Audit
- **Trail d'audit inaltérable** : Signatures HMAC-SHA256 pour chaque opération SCIM
- **Non-répudiation** : Corrélation-id, timestamp, username, payload hashé
- **Vérification d'intégrité** : Détection automatique des modifications (page dédiée)
- **nLPD/RGPD** : Traçabilité des accès aux données personnelles
- **FINMA** : Conservation des preuves cryptographiques

### DevSecOps
- **Tests automatisés** : 300+ tests (90% coverage), CI/CD sécurisé
- **Zero-config demo** : Secrets éphémères générés automatiquement (mode DEMO)
- **Production-ready** : Séparation stricte demo/prod, secrets jamais en clair
- **Infrastructure as Code** : Makefile 30+ commandes (quickstart, rotate-secret, verify-audit)

---

---

## 🔧 Commandes Essentielles

```bash
# Démarrage
make quickstart          # Zero-config : .env + stack + démo JML (2 min)
make fresh-demo          # Reset complet : volumes + secrets + certificats

# Tests & Qualité
make test                # Tests unitaires (328 tests, 92% coverage)
make test-e2e            # Tests d'intégration (nécessite stack démarrée)
make test-coverage       # Tests complets avec rapport de couverture HTML
make test-coverage-vscode # Ouvrir le rapport de couverture dans VS Code
make verify-audit        # Vérification signatures HMAC du trail d'audit

# Production
make rotate-secret       # Rotation secrets Azure Key Vault (avec validation)
make doctor              # Health check : Azure CLI, Key Vault, Docker

# Monitoring
make logs SERVICE=flask-app   # Logs applicatifs
make ps                       # État des conteneurs
```

📘 **Référence complète** : `make help-all` (30+ commandes disponibles)

---

## 📋 Documentation Technique

### 🎯 Pour Recruteurs (Screening RH + Technique)
- **[🇨🇭 Swiss Hiring Pack](docs/Hiring_Pack.md)** — Correspondance CV ↔ Repo, mots-clés recruteurs
- **[👥 RBAC Demo Scenarios](docs/RBAC_DEMO_SCENARIOS.md)** — Workflows Joiner/Mover/Leaver détaillés, matrice utilisateurs
- **[Vue d'ensemble](docs/OVERVIEW.md)** — Architecture, décisions techniques, Azure roadmap
- **[Sécurité](docs/SECURITY_DESIGN.md)** — OWASP ASVS L2, protection CSRF/XSS, validation JWT
- **[Conformité](docs/THREAT_MODEL.md)** — Threat model, non-répudiation, audit trail

### 🔐 Pour Ingénieurs Sécurité
- **[API Reference](docs/API_REFERENCE.md)** — Endpoints SCIM 2.0, exemples curl, codes d'erreur
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** — Azure App Service, Key Vault setup, CI/CD
- **[Rate Limiting](docs/RATE_LIMITING.md)** — Configuration Nginx, tests de charge
- **[Testing Strategy](docs/TESTING.md)** — Couverture 90%, tests critiques

### 🛠️ Pour DevOps
- **[Setup Guide](docs/SETUP_GUIDE.md)** — Installation locale, troubleshooting
- **[Local SCIM Testing](docs/LOCAL_SCIM_TESTING.md)** — Tests manuels avec curl/Postman
- **[RBAC Demo Scenarios](docs/RBAC_DEMO_SCENARIOS.md)** — Tests manuels workflows JML
- **[Error Handling](docs/ERROR_HANDLING_SECURITY.md)** — Gestion des erreurs SCIM RFC 7644

**📂 Hub documentation** : [docs/README.md](docs/README.md)


## ✅ Validation du PoC (Page Interactive)

**URL** : https://localhost/verification

Cette page exécute automatiquement une suite de tests de validation couvrant :

### Conformité SCIM RFC 7644
- POST/GET/PATCH/DELETE sur `/scim/v2/Users`
- Filtrage `userName eq` (garde contre injections)
- PUT retourne 501 avec message explicite
- Content-Type `application/scim+json` obligatoire (415 sinon)

### Sécurité OAuth 2.0
- 401 Unauthorized sans token ou token invalide
- 403 Forbidden avec scope insuffisant
- Validation JWT : signature, émetteur, audience, expiration

### Intégrité Audit
- Vérification signatures HMAC-SHA256 du trail d'audit
- Détection des modifications (alerte si signature invalide)
- Corrélation-id, timestamp, username, payload dans chaque événement

### Protection Réseau
- Security headers : HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Rate limiting opérationnel (Nginx : 10-60 req/min selon endpoint)

**Commande CLI alternative** : `make verify-audit`  
**Documentation OpenAPI** : https://localhost/scim/docs

---

## 📊 Matrice de Support SCIM 2.0

| Méthode | Endpoint | Statut | Commentaire |
|---------|----------|--------|-------------|
| **GET** | `/scim/v2/Users` | ✅ OK | Liste avec pagination |
| **POST** | `/scim/v2/Users` | ✅ OK | Création utilisateur + audit |
| **GET** | `/scim/v2/Users/{id}` | ✅ OK | Récupération par ID |
| **PATCH** | `/scim/v2/Users/{id}` | ✅ OK | Modification `active` uniquement (idempotent) |
| **DELETE** | `/scim/v2/Users/{id}` | ✅ OK | Soft-delete (disable, idempotent) |
| **PUT** | `/scim/v2/Users/{id}` | ⚠️ 501 | Non supporté (use PATCH/DELETE) |

**Limitation intentionnelle** : PUT retourne `501 Not Implemented` avec message explicite :  
`"Full replace is not supported. Use PATCH (active) or DELETE."`

---

## 🛡️ Sécurité & Rate Limiting

### Protection DoS (Nginx)
| Endpoint | Limite | Burst | Objectif |
|----------|--------|-------|----------|
| `/verification` | 10 req/min | +5 | Endpoint de test |
| `/scim/v2/*` | 60 req/min | +10 | API provisioning |
| `/admin/*` | 30 req/min | +8 | Interface admin |

**Test** : `./scripts/test_rate_limiting.sh` (démontre réponses 429)  
**Documentation** : [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md)

### Standards de Sécurité
- **OWASP ASVS Level 2** : Protection A01-A08 (injection, broken access, misconfiguration)
- **RFC 7636 (PKCE)** : Protection contre interception code d'autorisation
- **RFC 7644 (SCIM 2.0)** : Implémentation stricte schemas + error handling
- **NIST 800-63B** : Politique mots de passe robuste, MFA comptes privilégiés

---

## 🧪 Tests & Qualité

```bash
# Tests
make test                    # Tests unitaires (pytest -n auto, ~92% coverage)
make test-e2e                # Tests d'intégration (nécessite stack)
make test-coverage           # Tous les tests avec rapport de couverture HTML

# Visualiser la couverture (plusieurs options)
make test-coverage-report    # Afficher les options d'affichage
make test-coverage-vscode    # Ouvrir dans VS Code (recommandé)
make test-coverage-open      # Ouvrir dans navigateur système (si disponible)
make test-coverage-serve     # Servir via HTTP sur localhost:8888

# Suite complète
SKIP_E2E=true make test-all  # Suite complète sans intégration
```

**Couverture** : 328 tests passants, 92% de couverture sur code métier  
**CI/CD** : GitHub Actions avec validation sécurité + rapport coverage  
**Tests critiques** : JWT validation, RBAC, rate limiting, audit signatures

**💡 Astuce** : `test-coverage` vérifie automatiquement que le stack Docker est démarré et génère un rapport HTML détaillé dans `htmlcov/`. Les tests d'intégration se désactivent proprement (skip) si l'infrastructure n'est pas disponible.

---

## 🚀 Roadmap Azure-Native

### Phase 1 : Migration Entra ID ✅ Préparée
- [ ] Remplacer Keycloak par **Azure AD B2C** (OIDC cloud-native)
- [ ] Implémenter **Conditional Access Policies** (MFA, device compliance)
- [ ] Migrer SCIM vers **Entra ID Provisioning API**

### Phase 2 : Secrets & Identity 🔄 En cours
- [x] **Azure Key Vault** pour secrets (implémenté)
- [x] **Secret rotation** automatisée (implémenté)
- [ ] **Managed Identity** pour éliminer Service Principals
- [ ] **Azure Key Vault RBAC** (remplacer access policies)

### Phase 3 : Monitoring & Compliance 📋 Planifiée
- [ ] **Azure Monitor** : Centraliser logs dans Log Analytics
- [ ] **Application Insights** : APM temps réel + alertes
- [ ] **Azure Policy** : Enforcer TLS 1.2+, MFA obligatoire
- [ ] **Microsoft Defender for Cloud** : Posture management

### Phase 4 : Production Readiness 🎯 Vision
- [ ] **Azure App Service** : Déploiement PaaS sans gestion infra
- [ ] **Azure SQL Database** : Remplacer SQLite (HA + backups)
- [ ] **Azure Cache for Redis** : Sessions distribuées
- [ ] **Azure Front Door** : CDN + WAF global

---

## Contexte Suisse Romande

### Conformité Réglementaire
- **nLPD (nouvelle Loi sur la Protection des Données)** : Trail d'audit horodaté, traçabilité accès données personnelles
- **RGPD** : Conservation des consentements, droit à l'oubli, portabilité
- **FINMA** : Non-répudiation via signatures cryptographiques (secteur financier)

### Compétences Valorisées
- **Azure Entra ID** (ex-Azure AD) : Gestion identités cloud-native
- **SCIM 2.0 Provisioning** : Automatisation JML
- **Azure Key Vault** : Secrets management production-grade
- **Compliance-by-design** : Architecture auditée, sécurisée par défaut
- **DevSecOps** : CI/CD sécurisé, tests automatisés, rotation secrets

### Rôles Ciblés (Genève · Lausanne · Berne)
- **Junior Cloud Security Engineer (Azure)** : Sécurisation environnements cloud
- **IAM Engineer** : Provisioning Entra ID, SCIM, SSO
- **DevSecOps Cloud** : Pipelines sécurisés, secrets management, monitoring
- **Identity & Access Management Specialist** : RBAC, MFA policies, audit trails

---

## 📈 Correspondance CV ↔ Repository

| Compétence CV | Preuve dans le Repo | Fichier/Commande |
|---------------|---------------------|------------------|
| **Azure Key Vault** | Intégration complète, rotation secrets | `make rotate-secret`, `scripts/load_secrets_from_keyvault.sh` |
| **SCIM 2.0** | API RFC 7644, tests conformité | `app/api/scim.py`, `tests/test_api_scim.py` |
| **OIDC/OAuth 2.0** | PKCE, MFA, JWT validation | `app/api/auth.py`, `app/api/decorators.py` |
| **RBAC** | 3 rôles (admin/operator/verifier) | `app/core/rbac.py` |
| **Audit Trail** | HMAC-SHA256, non-répudiation | `scripts/audit.py`, `make verify-audit` |
| **DevSecOps** | CI/CD, tests 90%, secrets management | `.github/workflows/`, `Makefile` |
| **Python 3.12** | Flask, pytest, type hints | Tous fichiers `.py` |
| **Docker** | Compose multi-services, health checks | `docker-compose.yml` |
| **Nginx** | TLS, rate limiting, security headers | `proxy/nginx.conf` |
| **Conformité** | nLPD/RGPD/FINMA design | `docs/THREAT_MODEL.md`, `docs/SECURITY_DESIGN.md` |

---

## 🎓 Ce Que Ce Projet Démontre

**Pour un recruteur Cloud Security** :
- Capacité à concevoir un système IAM complet et auditable
- Maîtrise des standards Azure (Key Vault, Entra ID roadmap, Managed Identity)
- Compréhension des enjeux conformité (nLPD, RGPD, FINMA)
- Approche DevSecOps (tests automatisés, rotation secrets, CI/CD sécurisé)

**Pour un CISO/SOC** :
- Architecture défendable (RBAC, MFA, audit cryptographique)
- Traçabilité complète (correlation-id, timestamps, payloads hashés)
- Détection d'altération (vérification signatures HMAC-SHA256)
- Standards de l'industrie (OWASP ASVS L2, RFC 7644/7636, NIST 800-63B)

**Pour un ingénieur cloud** :
- Code production-ready (90% tests, zero-config demo, documentation complète)
- Séparation stricte demo/prod, secrets jamais en clair
- Makefile exhaustif (30+ commandes), health checks, monitoring
- Architecture évolutive (roadmap Entra ID, App Service, Monitor)

---

## 📜 Limitations Actuelles

- **Filtrage SCIM** : Seul `userName eq "value"` supporté (extensible)
- **PATCH** : Limité à l'attribut `active` (idempotence garantie)
- **PUT** : Volontairement 501 (use PATCH/DELETE, conformité RFC)
- **Content-Type** : `application/scim+json` obligatoire (RFC 7644)

Ces limitations sont **intentionnelles** pour garantir la sécurité et l'idempotence des opérations.

---

## 📞 Contact & Portfolio

**Auteur** : Alexs1004
**Rôles recherchés** : Cloud Security Engineer · IAM Engineer · DevSecOps (Azure)  
**Localisation** : Suisse Romande  

**GitHub** : [github.com/Alexs1004/iam-poc](https://github.com/Alexs1004/iam-poc)  
**Documentation complète** : [docs/README.md](docs/README.md)  
**Hiring Pack** : [docs/Hiring_Pack.md](docs/Hiring_Pack.md)

---

## 📄 Licence

MIT License — Voir [LICENSE](LICENSE) pour détails.

---

## 🙏 Remerciements

- **Azure Key Vault** pour le secrets management production-grade
- **Keycloak** pour l'implémentation OIDC/MFA (en attendant migration Entra ID)
- **SCIM RFC 7644** pour le standard de provisioning d'identités
- **OWASP** pour les guidelines de sécurité applicative
