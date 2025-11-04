# 🇨🇭 Swiss Hiring Pack — Mini IAM Lab

> **Destinataires** : Recruteurs Cloud Security / IAM · Tech Leads · Hiring Managers  
> **Objectif** : Faciliter l'évaluation technique du candidat via correspondance CV ↔ Repository

---

## 📋 Vue d'ensemble

Ce document établit la correspondance directe entre les **compétences annoncées sur le CV** et les **preuves techniques dans ce repository**. Il permet aux recruteurs de valider rapidement l'expertise du candidat sur des technologies Azure et sécurité cloud.

---

## 🎯 Profil Recherché

**Rôles ciblés** :
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Identity & Access Management Specialist

**Localisation** : Suisse Romande (Genève, Lausanne, Berne)

**Expérience** : 0-3 ans en sécurité cloud, formation continue en Azure/IAM

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

## 📊 Table de Correspondance CV ↔ Repo

| Compétence CV | Niveau | Preuve dans le Repo | Fichier/Commande | Validation |
|---------------|--------|---------------------|------------------|------------|
| **Azure Key Vault** | ⭐⭐⭐⭐ | Intégration complète, rotation automatisée, dry-run | `make rotate-secret`<br>`scripts/load_secrets_from_keyvault.sh`<br>`scripts/rotate_secret.sh` | ✅ Fonctionnel |
| **SCIM 2.0** | ⭐⭐⭐⭐ | API RFC 7644-compliant, tests conformité | `app/api/scim.py`<br>`tests/test_api_scim.py`<br>`openapi/scim_openapi.yaml` | ✅ 300+ tests |
| **OIDC/OAuth 2.0** | ⭐⭐⭐⭐ | PKCE, MFA, JWT validation RSA-SHA256 | `app/api/auth.py`<br>`app/api/decorators.py`<br>`app/core/rbac.py` | ✅ Tests JWT |
| **RBAC** | ⭐⭐⭐ | 3 rôles granulaires (admin/operator/verifier) | `app/core/rbac.py`<br>`tests/test_core_rbac.py` | ✅ Tests RBAC |
| **Audit Trail** | ⭐⭐⭐⭐ | HMAC-SHA256, non-répudiation, vérification intégrité | `scripts/audit.py`<br>`make verify-audit`<br>`.runtime/audit/jml-events.jsonl` | ✅ 22/22 signatures valides |
| **Secret Rotation** | ⭐⭐⭐ | Orchestration complète, validation avant déploiement | `scripts/rotate_secret.sh`<br>`make rotate-secret-dry` | ✅ Dry-run OK |
| **DevSecOps** | ⭐⭐⭐ | CI/CD, tests 90%, secrets management | `.github/workflows/`<br>`Makefile` (30+ commandes)<br>`pytest.ini` | ✅ 300+ tests |
| **Python 3.12** | ⭐⭐⭐⭐ | Flask, pytest, type hints, async | Tous fichiers `.py`<br>`requirements.txt` | ✅ Type-safe |
| **Docker** | ⭐⭐⭐ | Compose multi-services, health checks, volumes | `docker-compose.yml`<br>`Dockerfile.flask` | ✅ 3 services healthy |
| **Nginx** | ⭐⭐⭐ | TLS 1.3, rate limiting, security headers | `proxy/nginx.conf`<br>`docs/RATE_LIMITING.md` | ✅ Tests rate limit |
| **Conformité** | ⭐⭐⭐ | nLPD/RGPD/FINMA by design | `docs/THREAT_MODEL.md`<br>`docs/SECURITY_DESIGN.md` | ✅ Architecture auditée |

**Légende** :  
⭐⭐⭐⭐ = Maîtrise confirmée (code production-ready)  
⭐⭐⭐ = Bonne connaissance (implémentation fonctionnelle)  
⭐⭐ = Notions de base (documentation + tests)

---

## 🧪 Validation Rapide (30 secondes)

### Option 1 : Interface Web
```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart  # 2 minutes
open https://localhost/verification  # Tests automatiques
```

### Option 2 : CLI
```bash
make test          # Tests unitaires (300+ tests, 90% coverage)
make verify-audit  # Vérification signatures HMAC
make doctor        # Health check Azure + Docker
```

### Option 3 : Code Review
Fichiers clés à examiner (15 min) :
- `app/api/scim.py` — Implémentation SCIM RFC 7644
- `app/api/auth.py` — OIDC avec PKCE
- `scripts/rotate_secret.sh` — Rotation Azure Key Vault
- `Makefile` — Infrastructure as Code (30+ commandes)

---

## 📈 Métriques Qualité

| Indicateur | Valeur | Cible | Statut |
|------------|--------|-------|--------|
| **Tests** | 300+ | >200 | ✅ Dépassée |
| **Coverage** | 90% | >80% | ✅ Dépassée |
| **Azure Integration** | Key Vault + Roadmap Entra ID | Cloud-native | ✅ Opérationnel |
| **Security Standards** | OWASP ASVS L2 | L1 minimum | ✅ Dépassé |
| **Documentation** | 10 fichiers docs/ | 5 minimum | ✅ Complète |
| **Audit Trail** | 22/22 signatures valides | 100% | ✅ Parfait |

---

## 🇨🇭 Contexte Suisse Romande

### Conformité Réglementaire Implémentée
- **nLPD (nouvelle Loi sur la Protection des Données)** :
  - ✅ Trail d'audit horodaté avec corrélation-id
  - ✅ Traçabilité des accès aux données personnelles
  - ✅ Conservation sécurisée des logs (permissions 400)

- **RGPD** :
  - ✅ Consentement tracé via audit trail
  - ✅ Droit à l'oubli (soft-delete SCIM)
  - ✅ Portabilité (API SCIM standard)

- **FINMA (secteur financier)** :
  - ✅ Non-répudiation via signatures cryptographiques
  - ✅ Détection d'altération (vérification HMAC)
  - ✅ Conservation des preuves (audit log immuable)

### Compétences Valorisées en CH
1. **Azure Entra ID** : Gestion identités cloud-native Microsoft
2. **SCIM 2.0 Provisioning** : Standard IAM inter-entreprises
3. **Compliance-by-design** : Architecture conforme dès la conception
4. **DevSecOps** : Tests automatisés, rotation secrets, CI/CD sécurisé
5. **Multilinguisme technique** : Documentation FR/EN, standards internationaux

### Secteurs Cibles
- **Finance** (Banques, Assurances) : FINMA compliance, audit trail
- **Healthcare** : nLPD/RGPD strict, traçabilité
- **Tech** : SaaS, Identity Providers, Cloud Security
- **Conseil** : Intégration Azure, migrations Entra ID

---

## 🎓 Formation & Certifications (Recommandées)

**Certifications Azure visées** :
- [ ] **AZ-900** : Azure Fundamentals (base)
- [ ] **AZ-500** : Azure Security Engineer Associate (cible principale)
- [ ] **SC-300** : Microsoft Identity and Access Administrator (IAM focus)

**Formations complémentaires** :
- OWASP Top 10 & ASVS
- SCIM 2.0 Protocol (RFC 7644)
- OAuth 2.0 & OIDC (RFC 6749, 6750, 7636)

---

## 📞 Questions Fréquentes des Recruteurs

### Q1 : "Pourquoi Keycloak et pas directement Entra ID ?"
**R** : Choix pédagogique pour démontrer la maîtrise des standards OIDC/MFA de manière indépendante. La **roadmap Azure-native** est documentée (Phase 1 : Migration Entra ID prévue) avec architecture déjà compatible.

### Q2 : "Le projet est-il production-ready ?"
**R** : **Oui pour la sécurité**, non pour la scalabilité :
- ✅ Secrets management Azure Key Vault (production-grade)
- ✅ Audit cryptographique non-répudiable
- ✅ Tests 90%, CI/CD, rotation automatisée
- ⚠️ SQLite → Azure SQL Database requise pour HA
- ⚠️ Sessions locales → Azure Cache for Redis pour distribution

### Q3 : "Quelle est l'expérience réelle Azure ?"
**R** : **Projet d'apprentissage avec implémentation fonctionnelle** :
- Intégration Azure Key Vault opérationnelle (az cli, SDK Python)
- Compréhension architecture cloud-native (Managed Identity, App Service, Monitor)
- Approche compliance-by-design (nLPD/RGPD/FINMA)
- **Recherche stage/alternance** pour expérience production à grande échelle

### Q4 : "Temps de montée en compétence estimé ?"
**R** : Sur environnement Azure existant :
- **Semaine 1** : Familiarisation Entra ID, provisioning SCIM
- **Semaine 2-3** : Intégration API, conditional access policies
- **Mois 2** : Autonomie sur IAM routine (JML, MFA, RBAC)
- **Mois 3-6** : Expertise sur sujets avancés (B2B/B2C, compliance audits)

### Q5 : "Disponibilité pour entretien ?"
**R** : Immédiate. Préavis : aucun (recherche active).

---

## 📂 Navigation Documentation

| Document | Audience | Contenu |
|----------|----------|---------|
| **[README.md](../README.md)** | Tous | Présentation générale, quickstart, roadmap |
| **[Hiring_Pack.md](Hiring_Pack.md)** | Recruteurs | Ce document (correspondance CV ↔ Repo) |
| **[OVERVIEW.md](OVERVIEW.md)** | Tech Leads | Architecture détaillée, décisions techniques |
| **[SECURITY_DESIGN.md](SECURITY_DESIGN.md)** | CISO/SOC | Threat model, OWASP ASVS L2, protection |
| **[API_REFERENCE.md](API_REFERENCE.md)** | Ingénieurs | Endpoints SCIM, exemples curl, codes erreur |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | DevOps | Azure App Service, CI/CD, monitoring |
| **[THREAT_MODEL.md](THREAT_MODEL.md)** | Sécurité | Analyse risques, mitigations, audit |

---

## ✅ Checklist Évaluation Technique

**Pour un recruteur RH** (5 minutes) :
- [ ] Vérifier badges GitHub (tests, coverage, security)
- [ ] Consulter table de correspondance CV ↔ Repo
- [ ] Valider présence Azure Key Vault (production-ready)
- [ ] Vérifier conformité nLPD/RGPD/FINMA mentionnée

**Pour un Tech Lead** (30 minutes) :
- [ ] Lancer `make quickstart` → vérifier démo fonctionnelle
- [ ] Tester page `/verification` → valider tests automatiques
- [ ] Examiner `make rotate-secret-dry` → vérifier orchestration
- [ ] Code review `app/api/scim.py` → évaluer qualité code
- [ ] Lire `docs/SECURITY_DESIGN.md` → valider architecture

**Pour un CISO** (1 heure) :
- [ ] Audit trail : `make verify-audit` → 22/22 signatures OK
- [ ] Threat model : `docs/THREAT_MODEL.md` → risques identifiés
- [ ] Standards : OWASP ASVS L2, RFC 7644/7636, NIST 800-63B
- [ ] Compliance : nLPD (traçabilité), RGPD (portabilité), FINMA (non-répudiation)
- [ ] Roadmap : Migration Entra ID, Managed Identity, Monitor

---

## 📧 Contact

**Candidat** : Alex (Suisse Romande)  
**Email** : [Voir GitHub Profile](https://github.com/Alexs1004)  
**LinkedIn** : [À ajouter si applicable]  
**Disponibilité** : Immédiate  
**Mobilité** : Genève, Lausanne, Berne

**Rôles recherchés** :
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Stage/Alternance Cloud Security

---

## 🙏 Pourquoi Ce Projet ?

Ce repository démontre ma capacité à :
1. **Concevoir** un système IAM complet et auditable
2. **Implémenter** des standards de sécurité (OWASP, RFC, NIST)
3. **Intégrer** des services Azure (Key Vault, roadmap Entra ID)
4. **Documenter** de manière professionnelle (recruteurs + ingénieurs)
5. **Penser conformité** dès la conception (nLPD, RGPD, FINMA)

**En résumé** : Je sais construire des environnements cloud sécurisés, auditables et conformes. Je cherche maintenant à **mettre ces compétences au service d'une équipe en Suisse romande**.
