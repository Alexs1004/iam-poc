# Roadmap — Mini IAM Lab

## Vision
Positionner le PoC comme un mini-laboratoire Azure IAM aligné sur les attentes production : sécurité vérifiable, automatisation, conformité locale.

## Historique
- **v2.3 (actuel)** — Azure Key Vault intégré, audit HMAC, tests E2E stabilisés.
- **v2.2** — SCIM 2.0 complet (CRUD + filtering), refonte UI admin.
- **v2.1** — Intégration MFA TOTP + renforcement CSP/HSTS.
- **v2.0** — Passage à Flask modulaire + séparation core/api.

## Roadmap 2025
| Trimestre | Objectif | Résultat attendu |
|-----------|----------|------------------|
| **Q1** | Migration Keycloak → Microsoft Entra ID | SCIM natif, Conditional Access, suppression maintenance Keycloak. |
| **Q1** | Implémenter OAuth SCIM côté API | Middleware JWT complet, tests négatifs, logs d’audit enrichis. |
| **Q2** | Managed Identity + Azure Monitor | Fin du `az login`, logs centralisés, alertes IAM. |
| **Q2** | Azure Policy & Defender for Cloud | Baseline sécurité, déploiement IaC récurrent. |
| **Q3** | Policy-as-Code & SCIM CLI | Terraform/Bicep, tests compliance, CLI de provisioning sécurisé. |
| **Q4** | Production hardening | HA (multi-zone), scaling, playbooks incident response. |

## Sujets d'étude en cours
- **Zero Trust** : segmentation réseau, mutual TLS interne.
- **Supply chain** : SBOM, signatures container (cosign).
- **Compliance** : DPIA, alignement ISO 27001/SOC 2 (documentation).

## Suivi & feedback
- Issues & idées : GitHub Issues (`[DOCS]`, `[SECURITY]`, `[FEATURE]`).
- Démonstrations : planifier sessions live (20 min) pour recruteurs/architectes.
- Revues trimestrielles : mise à jour de cette roadmap + revues des métriques tests/sécurité.

👉 Besoin d’une info supplémentaire ? Ouvrir une issue ou proposer un PR pour enrichir le plan.
