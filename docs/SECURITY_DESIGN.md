# Security Design — Mini IAM Lab

## Principes de référence
- **Least privilege** : séparation analyst/operator/admin, scopes SCIM dédiés, secrets servis par rôle.
- **Zero trust mindset** : chaque requête SCIM doit être authentifiée (objectif à court terme), proxies et headers stricts.
- **Secrets hors code** : aucun secret en dépôt, `/run/secrets` + Azure Key Vault pour la production.
- **Non-répudiation** : audit append-only signé HMAC-SHA256.
- **MFA & durcissement** : TOTP obligatoire, CSP stricte, cookies sécurisés, headers OWASP ASVS L2.

## Contrôles implémentés
| Catégorie | Contrôle | Mécanisme | Référence |
|-----------|----------|-----------|-----------|
| **AuthN** | OIDC Code + PKCE | Keycloak realm `demo`, secrets rotatifs | `app/api/auth.py` |
| **MFA** | TOTP required actions | Politique Keycloak, enforcement UI | `scripts/bootstrap_realm.py` |
| **AuthZ** | RBAC route-level | Décorateurs Flask (`require_jml_operator`) | `app/security/rbac.py` |
| **Secrets** | `/run/secrets` + KV | `make load-secrets`, `DefaultAzureCredential` | [Setup Guide](SETUP_GUIDE.md) |
| **Audit** | HMAC-SHA256 par événement | `audit.sign_event()`, stockage JSONL append-only | `app/core/audit.py` |
| **Transport** | TLS + CSP + HSTS | Nginx reverse proxy, certificats auto-regen | `proxy/nginx.conf` |
| **Sécurité appli** | CSRF, XSS, sessions | Flask-WTF CSRF, CSP strict, cookies `Secure`/`HttpOnly`/`SameSite=Lax` | `app/api/admin.py` |
| **Conformité** | nLPD/RGPD/FINMA (principes) | Minimisation données, audit traçable, séparation rôles | [README](../README.md#-conformité--sécurité-suisse-romande) |

## Threat model (vue rapide)
- **Acteurs** : utilisateur interne malveillant, client SCIM compromis, attaquant réseau local.
- **Menaces adressées** :
  - Usurpation session : cookies sécurisés + rotation tokens + disable user immédiat.
  - CSRF / XSS : tokens CSRF, CSP, escaping Jinja.
  - Altération audit : HMAC sur chaque ligne + vérification via `make verify-audit`.
  - Secrets exposés : stockage hors code, rotation orchestrée, journaux Azure.
- **Non-objectifs actuels** :
  - Tampering physique sur host Docker (hors scope PoC).
  - BYOK/HSM pour Key Vault (prévu si production réelle).
  - Haute disponibilité multi-région.

## Preuves & validation
- **Audit** : `make verify-audit` détecte toute modification de log.
- **Secrets** : `make ensure-secrets` + `make load-secrets` démontrent l’absence de secrets locaux en production.
- **Tests sécurité** : `tests/test_api_auth.py`, `tests/test_api_scim_negatives.py`, `tests/test_integration_e2e.py` couvrent CSRF, JWT, scénarios SCIM.
- **CI** : workflow `.github/workflows/tests-coverage.yml` exécute les tests, génère `coverage.xml`, gate à `--cov-fail-under=80`.

## Road to Azure-native
1. **Entra ID** : remplacer Keycloak (SCIM & OIDC natifs, Conditional Access).
2. **Managed Identity** : supprimer la dépendance `az login` pour Key Vault.
3. **Azure Monitor / App Insights** : collecter logs structurés, alertes, dashboards IAM.
4. **Azure Policy & Defender for Cloud** : guardrails, posture compliance.
5. **Automation** : pipeline IaC (Bicep/Terraform) + Policy-as-Code + scanning container (Trivy/Azure Security Benchmark).

## Liens utiles
- Mise en route & rotation secrets : [Setup Guide](SETUP_GUIDE.md)
- Couverture de tests & CI : [Test Strategy](TEST_STRATEGY.md)
- Détails endpoints sécurisés : [API Reference](API_REFERENCE.md)
