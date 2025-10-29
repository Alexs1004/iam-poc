# Mini IAM Lab — SCIM 2.0 · Azure Key Vault · JML

![Made with Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4?logo=microsoft-azure&logoColor=white)
![Demo in 2 min](https://img.shields.io/badge/Demo-2%20minutes-success?logo=github)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-160%2B%20passed-brightgreen?logo=pytest)
![Coverage](https://img.shields.io/badge/Coverage-90%25-brightgreen?logo=codecov)
![Security](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## Why / What / Proof
- Pourquoi : démontrer des réflexes sécurité Azure (Key Vault, secrets hors code, rotation).
- Quoi : SCIM 2.0 (RFC 7644) + Key Vault + audit HMAC-SHA256 (JML automatisé via Keycloak 24).
- Preuve : >160 tests pytest (~90 %), `make quickstart` opérationnel en 2 min.

## Try
```bash
make quickstart
open https://localhost
```

- Ce que vous voyez : login Keycloak, workflow JML, appels SCIM, audit signé.

## Preuves vérifiables
- [OpenAPI SCIM (ReDoc)](https://localhost/scim/docs) — spécification 3.0 et exemples CRUD.
- [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) — chargement Key Vault (`make load-secrets`) et rotation (`make rotate-secret`).
- `make verify-audit` + [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — journaux JML signés HMAC-SHA256.

## Limitations actuelles
- Filtrage SCIM limité à `userName eq` (pas d’opérateurs avancés).
- PATCH SCIM non supporté (`patch.supported=false` dans ServiceProviderConfig).
- Les requêtes POST/PUT/DELETE doivent utiliser `Content-Type: application/scim+json` (sinon 415).

## Ciblage poste
Cloud Security / IAM (Azure).

## Où trouver la suite
- [Documentation Hub](docs/README.md)
- [Référence SCIM](docs/API_REFERENCE.md)
- [Security Design & conformité](docs/SECURITY_DESIGN.md)
- [Test Strategy](docs/TEST_STRATEGY.md)
- [Local SCIM Testing](docs/LOCAL_SCIM_TESTING.md)
