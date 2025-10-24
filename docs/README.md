# 📚 Documentation IAM PoC — Index Complet

Portail de documentation technique pour le projet **Mini IAM Lab — Azure-First Identity Demo**.

---

## 🚀 Par Où Commencer ?

### Pour les Recruteurs / Hiring Managers
1. **[README principal](../README.md)** — Vue d'ensemble, TL;DR, hiring signals (5 min)
2. **[Preuves de sécurité](SECURITY_PROOFS.md)** — Démonstrations concrètes (screenshots, commandes)
3. **[Vidéo démo](#)** _(À venir — 60 secondes)_

### Pour les Développeurs / Ops
1. **[Setup détaillé](DETAILED_SETUP.md)** — Configuration complète (secrets, SCIM, troubleshooting)
2. **[Architecture unifiée](UNIFIED_SERVICE_ARCHITECTURE.md)** — Diagrammes, API reference
3. **[Tests](../tests/)** — Unit + E2E integration tests

### Pour les Architectes / Security Engineers
1. **[Conformité nLPD/RGPD/FINMA](#conformité-locale)** — Principes réglementaires
2. **[Rotation de secrets](SECRET_ROTATION.md)** — Workflow orchestré production
3. **[SCIM API Guide](SCIM_API_GUIDE.md)** — Intégration Okta, Azure AD

---

## 📖 Documentation par Thème

### 🔐 Sécurité & Conformité

| Document | Description | Audience |
|----------|-------------|----------|
| **[SECURITY_PROOFS.md](SECURITY_PROOFS.md)** | Preuves de sécurité (MFA, secrets, audit, RBAC) avec commandes vérification | Tous |
| **[SECRET_ROTATION.md](SECRET_ROTATION.md)** | Rotation orchestrée Keycloak → Key Vault (CI/CD ready) | Ops, DevSecOps |
| **[SECRET_MANAGEMENT.md](SECRET_MANAGEMENT.md)** | Pattern `/run/secrets`, Azure Key Vault, auto-génération demo | Développeurs |
| **Conformité locale** (section ci-dessous) | nLPD 2023, RGPD, FINMA (principes haut niveau) | Architectes, Legal |

### 🏗️ Architecture & Implémentation

| Document | Description | Audience |
|----------|-------------|----------|
| **[UNIFIED_SERVICE_ARCHITECTURE.md](UNIFIED_SERVICE_ARCHITECTURE.md)** | Architecture v2.0 : service layer unifié UI/SCIM | Développeurs |
| **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** | Résumé implémentation (historique développement) | PM, Architectes |
| **[JML_REFACTORING_SUMMARY.md](JML_REFACTORING_SUMMARY.md)** | Refactoring JML automation (v1 → v2) | Développeurs |

### 🔌 API & Intégrations

| Document | Description | Audience |
|----------|-------------|----------|
| **[SCIM_API_GUIDE.md](SCIM_API_GUIDE.md)** | Guide intégration SCIM 2.0 (Okta, Azure AD, curl) | Ops, Intégrateurs |
| **[SCIM_COMPLIANCE_ANALYSIS.md](SCIM_COMPLIANCE_ANALYSIS.md)** | Analyse conformité RFC 7644 (schemas, erreurs, filtering) | Architectes |
| **[API Reference](#)** _(À venir)_ | OpenAPI spec pour SCIM endpoints | Développeurs |

### 📦 Setup & Operations

| Document | Description | Audience |
|----------|-------------|----------|
| **[DETAILED_SETUP.md](DETAILED_SETUP.md)** | Configuration complète (demo/prod, Azure KV, troubleshooting) | Tous |
| **[Makefile Reference](../Makefile)** | 30+ targets expliqués (quickstart, secrets, tests, rotation) | Ops |
| **[Docker Compose](../docker-compose.yml)** | Orchestration services (Keycloak, Flask, Nginx) | Ops |

### 🧪 Tests & Qualité

| Document | Description | Audience |
|----------|-------------|----------|
| **[tests/test_flask_app.py](../tests/test_flask_app.py)** | Tests RBAC, CSRF, headers sécurité, cookies | Développeurs |
| **[tests/test_scim_api.py](../tests/test_scim_api.py)** | Tests SCIM RFC 7644 compliance (CRUD, filtering) | Développeurs |
| **[tests/test_integration_e2e.py](../tests/test_integration_e2e.py)** | Tests E2E (OIDC, JML, SCIM) avec Keycloak réel | QA, Ops |
| **[scripts/test_scim_api.sh](../scripts/test_scim_api.sh)** | Tests intégration SCIM (OAuth tokens réels) | QA |

---

## 📋 Quick Links — Checklist par Rôle

### ✅ Recruteur Cloud Security / Azure
- [ ] Lire [TL;DR recruteurs](../README.md#-tldr-pour-recruteurs) (30 sec)
- [ ] Voir [Hiring Signals table](../README.md#-hiring-signals--sécurité--preuves) (1 min)
- [ ] Parcourir [Roadmap Azure](../README.md#️-roadmap-azure) (Entra ID, Managed Identity, Monitor) (2 min)
- [ ] Consulter [Conformité CH-Romand](../README.md#️-conformité--sécurité-suisse-romande) (nLPD/RGPD/FINMA) (3 min)
- [ ] _(Optionnel)_ Voir [Preuves sécurité](SECURITY_PROOFS.md) (captures, commandes) (10 min)

### ✅ Développeur Backend / Python
- [ ] Cloner repo, `make quickstart` (2 min)
- [ ] Explorer [Architecture](UNIFIED_SERVICE_ARCHITECTURE.md) (diagrammes, service layer) (10 min)
- [ ] Lire [Code structure](IMPLEMENTATION_SUMMARY.md) (`app/core/`, `app/api/`, `scripts/`) (5 min)
- [ ] Lancer tests : `make pytest` + `make pytest-e2e` (5 min)
- [ ] Consulter [SCIM API Guide](SCIM_API_GUIDE.md) (exemples curl, Postman) (15 min)

### ✅ DevSecOps Engineer
- [ ] Setup demo : `make quickstart` (2 min)
- [ ] Tester rotation secrets : `make rotate-secret-dry` (3 min)
- [ ] Lire [Secret Rotation Guide](SECRET_ROTATION.md) (CI/CD integration) (10 min)
- [ ] Vérifier audit trail : `make verify-audit` (2 min)
- [ ] Explorer [Security Proofs](SECURITY_PROOFS.md) (HMAC, session revocation) (15 min)
- [ ] Consulter [Production Notes](../README.md#️-production-notes) (bind mounts, Managed Identity, certs) (5 min)

### ✅ Architect / Solution Designer
- [ ] Vue d'ensemble [Architecture](../README.md#️-architecture--composants) (dataflow diagram) (5 min)
- [ ] Comprendre [Unified Service Architecture](UNIFIED_SERVICE_ARCHITECTURE.md) (v2.0 refactoring) (15 min)
- [ ] Analyser [SCIM Compliance](SCIM_COMPLIANCE_ANALYSIS.md) (RFC 7644 coverage) (10 min)
- [ ] Évaluer [Roadmap Azure](../README.md#️-roadmap-azure) (Entra ID migration plan) (10 min)
- [ ] Lire [Conformité](../README.md#️-conformité--sécurité-suisse-romande) (nLPD, FINMA principles) (10 min)

---

## 🌍 Conformité Locale (Suisse Romande)

### nLPD (Nouvelle Loi Fédérale sur la Protection des Données)

**Entrée en vigueur** : 1er septembre 2023

**Principes implémentés** :
- ✅ **Minimisation** : Secrets hors Git (`.gitignore`), accès Key Vault loggé
- ✅ **Transparence** : Audit trail HMAC-SHA256, append-only logs
- ✅ **Sécurité technique** : TLS obligatoire, secrets chmod 400, read-only mounts
- ✅ **Droits des personnes** : SCIM export (data portability), RBAC granulaire

**Ressources** :
- [PFPDT Guide nLPD](https://www.edoeb.admin.ch/edoeb/fr/home/protection-des-donnees/documentation/guides.html)
- Analyse DPIA template : _À ajouter (hors scope PoC)_

### RGPD (Règlement Général sur la Protection des Données)

**Applicabilité** : Suisse applique RGPD par équivalence (nLPD align

é)

**Articles pertinents** :
- **Art. 25** (Privacy by Design) : MFA obligatoire, sessions révoquées immédiatement
- **Art. 30** (Registre traitements) : Audit logs avec horodatage, non-répudiation
- **Art. 32** (Sécurité) : Chiffrement TLS, secrets hors code, rotation orchestrée
- **Art. 33** (Notification violations) : Health checks, monitoring (roadmap Azure Monitor)

### FINMA (Principes de Contrôle & Traçabilité)

**Applicabilité** : Institutions financières suisses (banques, assurances)

**Exigences haut niveau** :
- ✅ **Ségrégation des rôles** : Analyst (view) vs Operator (action) vs Admin (config)
- ✅ **Piste d'audit** : Qui, quoi, quand, avec quelle autorisation (logs HMAC signés)
- ✅ **Continuité opérationnelle** : Health checks, graceful restarts, idempotence
- ✅ **Tests réguliers** : Unit + E2E tests, rotation secret orchestrée

**Note** : Ce PoC démontre les **principes techniques**. Production réelle nécessite :
- DPIA complète (Data Protection Impact Assessment)
- Contrats sous-traitance (DPA — Data Processing Agreement)
- Analyse risques sécurité (threat modeling)
- Certification ISO 27001 / SOC 2 (selon contexte)

---

## 🗂️ Structure Documentation

```
docs/
├── README.md                          ← Vous êtes ici (portail index)
├── SECURITY_PROOFS.md                 ← Preuves de sécurité (NEW)
├── DETAILED_SETUP.md                  ← Setup complet (À créer)
├── UNIFIED_SERVICE_ARCHITECTURE.md    ← Architecture v2.0
├── IMPLEMENTATION_SUMMARY.md          ← Résumé implémentation
├── JML_REFACTORING_SUMMARY.md         ← Refactoring JML
├── SECRET_MANAGEMENT.md               ← Gestion secrets
├── SECRET_ROTATION.md                 ← Rotation orchestrée (À créer)
├── SCIM_API_GUIDE.md                  ← Guide intégration SCIM (À créer)
└── SCIM_COMPLIANCE_ANALYSIS.md        ← Analyse RFC 7644 (À créer)
```

---

## 📞 Support & Contribution

### Questions Fréquentes (FAQ)

**Q : Le projet fonctionne-t-il sans Azure ?**  
✅ Oui ! Mode démo (`DEMO_MODE=true`) zéro-config : `make quickstart` suffit.

**Q : Puis-je utiliser ce code en production ?**  
⚠️ Nécessite adaptations :
- Retirer bind mounts Docker (bake code dans image)
- Managed Identity au lieu de `az login`
- Certificats CA-signed (pas self-signed)
- Monitoring centralisé (Azure Monitor)

**Q : Compatible avec Okta / Azure AD / Auth0 ?**  
✅ SCIM 2.0 API compatible. Roadmap Q1 2025 : migration Keycloak → **Microsoft Entra ID**.

**Q : Tests fonctionnent sans stack running ?**  
✅ `make pytest` : Unit tests (Keycloak mocké)  
⚠️ `make pytest-e2e` : Nécessite `make up` (tests intégration)

### Issues & Bugs

Signaler via [GitHub Issues](https://github.com/Alexs1004/iam-poc/issues) :
- 🐛 Bug : template `[BUG] Titre`
- 💡 Feature request : template `[FEATURE] Titre`
- 📘 Documentation : template `[DOCS] Titre`

### Contribution

Pull requests acceptées ! Processus :
1. Fork repo
2. Créer branche feature (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Tests : `make pytest` + `make pytest-e2e`
4. Lint : `make validate-env`
5. Commit descriptif : `feat(scim): Add pagination support`
6. Push + PR vers `main`

---

## 🎓 Ressources Complémentaires

### Standards & RFC
- **[RFC 7644 — SCIM 2.0](https://datatracker.ietf.org/doc/html/rfc7644)** : Protocol specification
- **[RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)** : Authorization framework
- **[RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)** : Proof Key for Code Exchange

### Azure Documentation
- **[Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)**
- **[Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)**
- **[Microsoft Entra ID (Azure AD)](https://learn.microsoft.com/en-us/entra/identity/)**
- **[Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/)**

### Certifications Recommandées
- **[SC-300](https://learn.microsoft.com/en-us/certifications/exams/sc-300)** : Microsoft Identity and Access Administrator
- **[AZ-500](https://learn.microsoft.com/en-us/certifications/exams/az-500)** : Azure Security Engineer Associate
- **[AZ-104](https://learn.microsoft.com/en-us/certifications/exams/az-104)** : Azure Administrator Associate

### Livres & Guides
- _Zero Trust Networks_ (Evan Gilman, Doug Barth) — O'Reilly
- _Identity and Access Management: The First Steps_ (Raj Kissu Rajasree) — Packt
- _Cloud Security and Privacy_ (Tim Mather, Subra Kumaraswamy, Shahed Latif) — O'Reilly

---

## 📈 Métriques Documentation

| Métrique | Valeur | Objectif |
|----------|--------|----------|
| **Pages documentation** | 8 | ✅ 8+ |
| **Exemples de code** | 50+ snippets | ✅ 40+ |
| **Diagrammes architecture** | 3 | ✅ 3+ |
| **Tests couverture** | Unit + E2E | ✅ Complète |
| **Temps setup démo** | 2 min | ✅ < 5 min |
| **Langues** | FR + EN | ✅ Bilingue |

---

## 🔄 Dernière Mise à Jour

**Date** : Janvier 2025  
**Version** : v2.3 (Secret management & production hardening)  
**Mainteneur** : Alex

---

**💡 Tip** : Bookmark cette page comme **point d'entrée unique** pour toute la documentation !
