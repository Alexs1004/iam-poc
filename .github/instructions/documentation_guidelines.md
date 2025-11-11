# [Nom du document] — [Type: Security / Deployment / API / Architecture]

> **Audience** : [Recruteur / Ingénieur Sécurité / DevOps]  
> **Temps de lecture** : ~[5 / 30 / 60] min  
> **Swiss Compliance Focus** : [nLPD / RGPD / FINMA]  
> **Azure Services** : [Entra ID, Key Vault, Managed Identity, Monitor]  

---

## 🎯 Objectif

[1 à 3 phrases : pourquoi ce document existe, contexte suisse, valeur business]

---

## 🇨🇭 Swiss Compliance Context

### nLPD (Protection des données Suisse)
- Point clé : [traçabilité / transparence / data residency]
- Implémentation : [ex. logs tracés, accès restreints]

### RGPD (UE)
- Point clé : [portabilité / consentement / droit à l’oubli]
- Implémentation : [SCIM soft-delete, export API]

### FINMA (Marché financier CH) *(si applicable)*
- Point clé : [non-répudiation / auditabilité]
- Implémentation : [audit trail immuable, signatures HMAC]

---

## ☁️ Azure Architecture / Vision

### Azure Services Utilisés
- Azure Entra ID
- Azure Key Vault
- Managed Identity
- Azure Monitor / Log Analytics
- [Autres : App Service / Front Door / SQL…]

### Roadmap Azure Native (si applicable)
| Phase | Objectif | Actions |
|---|---|---|
| Phase 1 | [ex. identité] | SCIM → Entra ID, Conditional Access |
| Phase 2 | [ex. secrets] | Migration secrets → Key Vault |
| Phase 3 | [ex. observabilité] | Logs → Monitor + Sentinel |

---

## 🛡️ Standards Sécurité

| Standard | Usage |
|---|---|
OWASP ASVS L2 | Authentification / sessions |
NIST 800-63B | MFA / Identity Assurance |
RFC 7519 | JWT signing/validation |
RFC 7644 | SCIM 2.0 provisioning |
MITRE / STRIDE | Threat model |

---

## 🧩 Architecture / Workflow

[Diagramme / Description]

