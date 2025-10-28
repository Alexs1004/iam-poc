# Test Strategy — Mini IAM Lab

## Objectifs
- Prouver la solidité des contrôles sécurité (OAuth, CSRF, MFA, audit).
- Garantir une régression minimale avant chaque démonstration.
- Offrir une vision claire aux recruteurs sur la rigueur QA/security engineering.

## Pyramide de tests
| Niveau | Contenu | Outils |
|--------|---------|--------|
| **Static checks** | `pip-audit`, formatters, lint | Make targets dédiés (TBD) |
| **Unit tests** | Validation SCIM, RBAC, audit HMAC, helpers Key Vault | `pytest`, fixtures isolées, Keycloak mocké |
| **Integration tests** | API SCIM end-to-end avec Keycloak réel, rotation secrets | `pytest -m integration`, Docker stack |
| **Manual drills** | `make demo-jml`, test MFA/TOTP, rotation manuelle | Runbook dans README |

## Couverture attendue
- **Global** : ≥ 90 % (objectif interne, gate CI à 80 % dans le pipeline GitHub).
- **Modules critiques** : `app/core/provisioning_service`, `app/security/rbac`, `app/core/audit` ≥ 80 %.
- **Tests sécurité** : `tests/test_api_scim_negatives.py` (JWT invalide, scopes manquants), `tests/test_api_auth.py` (headers, CSRF, cookie security).

## Commandes principales
```bash
# Unitaires (rapides, mock Keycloak)
pytest -m "not integration"

# Intégration (nécessite stack)
pytest -m integration

# Couverture + rapport HTML
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

## Intégration continue
- Workflow GitHub Actions : `.github/workflows/tests-coverage.yml`.
- Étapes clés :
  1. Installation dépendances (cache pip).
  2. Exécution `pytest -m "not integration"` avec `--cov`.
  3. Upload `coverage.xml` pour badge.
  4. Conditions d’échec si couverture < 80 % ou tests en échec.
- Extension prévue : matrix Python, ajout `pip-audit` et `bandit`.

## Tests à haute valeur sécurité
- **JWT validation** : vérifie signature, audience, expiration (PyJWKClient).
- **CSRF** : ensures `X-CSRF-Token` obligatoire pour actions sensibles.
- **Audit integrity** : recalcul HMAC et détection tampering (`tests/test_audit.py`).
- **Secret rotation** : tests `tests/test_secret_rotation.py` (à ajouter) pour s’assurer que `make rotate-secret` reste idempotent.

## Liens utiles
- Architecture et flux : [Overview](OVERVIEW.md)
- Contrôles sécurité : [Security Design](SECURITY_DESIGN.md)
- Exemples API SCIM : [API Reference](API_REFERENCE.md)
