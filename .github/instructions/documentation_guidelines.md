---
applyTo: 'docs/**'
priority: high
---

# Documentation Guidelines — Swiss Cloud Security Focus

> **Objectif** : Maintenir une documentation alignée avec le positionnement Swiss Cloud Security recruitment

---

## 🎯 Principes Directeurs

### 1. Swiss Compliance First
Chaque document technique doit mentionner au moins un des trois piliers :
- **nLPD** (nouvelle Loi sur la Protection des Données) : Traçabilité, conservation, transparence
- **RGPD** (Règlement Général sur la Protection des Données) : Portabilité, droit à l'oubli, consentement
- **FINMA** (Autorité de surveillance des marchés financiers) : Non-répudiation, intégrité, audit

### 2. Azure-Native Messaging
- Toujours mentionner la roadmap Azure (Entra ID, Managed Identity, Monitor, App Service)
- Privilégier les services Azure natifs dans les exemples (Key Vault > HashiCorp Vault)
- Documenter les Azure Swiss regions (Switzerland North/West) pour data residency

### 3. Multi-Audience Navigation
Chaque document doit clairement indiquer son public cible :
- **Recruteurs RH** : 5-10 minutes, focus hiring keywords
- **Ingénieurs Sécurité** : 30-60 minutes, standards OWASP/RFC/NIST
- **DevOps** : 45-90 minutes, commandes pratiques, troubleshooting

---

## 📝 Structure Recommandée par Type de Document

### Security Design / Threat Model
```markdown
# [Titre] — [Sujet]

> **Swiss Compliance Focus** : [nLPD/RGPD/FINMA relevance]
> **Standards** : [OWASP ASVS, RFC, NIST references]

[Introduction avec contexte Swiss]

## Swiss Regulatory Context
### nLPD
- **Requirements** : [liste]
- **Implementation** : [preuves avec fichiers]

### RGPD
- ...

### FINMA
- ...

[Contenu technique standard]

## 🔗 Related Documentation
- [liens vers autres docs avec contexte Swiss]
```

### Deployment / Operations Guide
```markdown
# [Titre] — Azure-Native Roadmap

> **Current State** : [état actuel avec Azure]
> **Target State** : [vision Azure-native complète]

## 🚀 Azure-Native Evolution ([N] Phases)
### Phase 1 : [Priorité]
**Objective** : [description]
**Actions** : [checklist]
**Benefits** : [bénéfices Swiss market]

[Contenu technique standard]

## Swiss Azure Regions
[Table des régions avec latence et use cases]
```

### API Reference / Technical Specs
```markdown
# [Titre] — [Standard]

> **Standards** : [RFC/OWASP references]
> **Swiss Compliance** : [relevance nLPD/RGPD/FINMA]

[Contenu technique standard]
```

---

## ✅ Checklist Avant Commit Documentation

### Pour Tout Document
- [ ] Mention au moins 1 standard Swiss (nLPD/RGPD/FINMA) si applicable
- [ ] Azure services mentionnés (Key Vault, Entra ID, Monitor)
- [ ] Public cible explicite (Recruteurs/Sécurité/DevOps)
- [ ] Liens vers docs/Hiring_Pack.md si relevant
- [ ] Temps de lecture estimé (5min/30min/90min)

### Pour Security Documents
- [ ] OWASP ASVS L2 référencé
- [ ] RFC standards cités (7644/6749/7636/7519)
- [ ] NIST 800-63B si authentification
- [ ] STRIDE ou MITRE ATT&CK si threat model
- [ ] Swiss compliance column dans tables

### Pour Deployment Guides
- [ ] Azure-native roadmap présente
- [ ] Swiss Azure regions documentées (Switzerland North/West)
- [ ] Managed Identity evolution mentionnée
- [ ] Post-deployment checklist Swiss compliance
- [ ] Data residency requirements addressed

### Pour API Documentation
- [ ] OpenAPI spec référencée
- [ ] OAuth 2.0 scopes documentés
- [ ] SCIM 2.0 compliance explicite (RFC 7644)
- [ ] Swiss compliance context dans intro
- [ ] Error handling SCIM-compliant

---

## 🔑 Mots-Clés à Intégrer Naturellement

### Swiss Compliance (minimum 2-3 par doc technique)
`nLPD` · `RGPD` · `FINMA` · `non-répudiation` · `traçabilité` · `portabilité` · `droit à l'oubli` · `data residency` · `Swiss regulations` · `financial sector` · `audit trail`

### Azure Services (minimum 3-5 par doc deployment)
`Azure Key Vault` · `Azure Entra ID` · `Managed Identity` · `Azure Monitor` · `Application Insights` · `Azure Sentinel` · `Azure Policy` · `Azure App Service` · `Azure SQL Database` · `Azure Cache for Redis` · `Azure Front Door` · `Log Analytics` · `Switzerland North` · `Switzerland West`

### Security Standards (minimum 2-3 par doc security)
`OWASP ASVS L2` · `RFC 7644` · `RFC 6749` · `RFC 7636` · `RFC 7519` · `NIST 800-63B` · `STRIDE` · `MITRE ATT&CK` · `Zero Trust` · `Defense in Depth` · `Least Privilege`

### IAM / Identity (minimum 3-4 par doc IAM)
`SCIM 2.0` · `OpenID Connect` · `OAuth 2.0` · `PKCE` · `MFA` · `RBAC` · `JWT` · `SSO` · `Provisioning` · `JML` · `Joiner-Mover-Leaver` · `Conditional Access`

---

## 🚫 À Éviter

### ❌ Generic Cloud Terms
Remplacer "cloud provider" par "Azure"
Remplacer "identity provider" par "Azure Entra ID"
Remplacer "secret manager" par "Azure Key Vault"

### ❌ Compliance Vague
❌ "GDPR compliant"
✅ "RGPD-compliant : droit à l'oubli via SCIM soft-delete (RFC 7644)"

❌ "Secure audit log"
✅ "Audit trail HMAC-SHA256 non-répudiable (FINMA requirement)"

### ❌ Technical Without Context
❌ "Uses JWT tokens"
✅ "JWT validation RSA-SHA256 (RFC 7519) avec JWKS rotation Azure Entra ID"

---

## 📊 Métriques de Qualité Documentation

### Cibles par Document
| Type Document | Swiss Keywords | Azure Mentions | Standards | Liens Internes |
|---------------|----------------|----------------|-----------|----------------|
| Security Design | 5-8 | 3-5 | 4-6 | 3-4 |
| Threat Model | 6-10 | 2-4 | 3-5 | 3-4 |
| Deployment Guide | 4-6 | 8-12 | 2-3 | 3-4 |
| API Reference | 2-4 | 2-3 | 5-8 | 2-3 |
| README/Hub | 3-5 | 4-6 | 2-3 | 5-8 |

### Validation Automatique (idéal)
```bash
# Vérifier présence Swiss compliance keywords
grep -E "nLPD|RGPD|FINMA" docs/*.md | wc -l  # Minimum 30 occurrences

# Vérifier Azure mentions
grep -iE "azure|entra" docs/*.md | wc -l  # Minimum 50 occurrences

# Vérifier standards
grep -E "RFC [0-9]{4}|OWASP|NIST" docs/*.md | wc -l  # Minimum 25 occurrences
```

---

## 🎓 Exemples de Bonnes Pratiques

### ✅ Bon Exemple (SECURITY_DESIGN.md)
```markdown
## Swiss Compliance Context

### nLPD (nouvelle Loi sur la Protection des Données)
- **Traçabilité** : Audit trail HMAC-SHA256 avec timestamps ISO 8601
- **Conservation** : Logs avec permissions restrictives (400), rotation planifiée
- **Transparence** : API SCIM pour portabilité des données

### FINMA (Autorité fédérale de surveillance des marchés financiers)
- **Non-répudiation** : Signatures HMAC-SHA256 sur chaque événement JML
- **Intégrité** : Détection altération via `make verify-audit`
- **Auditabilité** : Corrélation-ID, timestamps, actor tracking
```

### ✅ Bon Exemple (DEPLOYMENT_GUIDE.md)
```markdown
## 🚀 Azure-Native Evolution (4 Phases)

### Phase 1 : Identity Provider Migration ✅ **Next Priority**
**Objective** : Replace Keycloak with Azure Entra ID (ex-Azure AD)

**Actions** :
- [ ] Configure Entra ID App Registration (SCIM client)
- [ ] Enable Conditional Access Policies (MFA, device compliance)
- [ ] Migrate OIDC/OAuth flows to Entra ID endpoints

**Benefits** :
- Cloud-native authentication (no self-hosted Keycloak)
- Advanced MFA policies (Authenticator, FIDO2)
- Integration with Microsoft 365 identities
```

---

## 🔗 Ressources Externes

### Swiss Compliance
- [nLPD Official](https://www.edoeb.admin.ch/edoeb/fr/home/protection-des-donnees/Internet_und_Computer/services-en-ligne.html)
- [RGPD/GDPR Guide](https://www.cnil.fr/fr/reglement-europeen-protection-donnees)
- [FINMA Circulaires](https://www.finma.ch/fr/surveillance/banques/)

### Azure Documentation
- [Azure Entra ID](https://learn.microsoft.com/en-us/azure/active-directory/)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [Azure Switzerland Regions](https://azure.microsoft.com/en-us/explore/global-infrastructure/geographies/#geographies)

### Security Standards
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [RFC 7644 (SCIM 2.0)](https://datatracker.ietf.org/doc/html/rfc7644)
- [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## 🤝 Contribution

Quand tu ajoutes un nouveau document :
1. Copier le template approprié (ci-dessus)
2. Remplir les sections Swiss Compliance (nLPD/RGPD/FINMA)
3. Mentionner au moins 3 services Azure
4. Citer les standards applicables (OWASP, RFC, NIST)
5. Ajouter liens vers docs/Hiring_Pack.md si relevant
6. Exécuter checklist avant commit

**Objectif final** : Chaque document doit pouvoir être montré à un recruteur Swiss Cloud Security et démontrer immédiatement la maîtrise des standards de conformité et Azure.
