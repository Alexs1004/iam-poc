# Setup Guide — Mini IAM Lab (Archived)

> Archived copy of the original setup instructions. Current getting-started workflow lives in `../README.md` and `../LOCAL_SCIM_TESTING.md`.

# Setup Guide — Mini IAM Lab

## Audience & Pré-requis
- **Cible** : développeur / DevSecOps qui veut lancer la démo ou tester des scénarios.
- **Pré-requis** : Docker, Docker Compose, Python 3.12+, Make, `az` CLI (pour mode Azure).
- **Configuration** : cloner le repo, copier `.env.example` en `.env` si besoin, ou laisser `make` générer les secrets.

## Démarrage express (mode démo)
```bash
make quickstart
open https://localhost
```
Ce que la commande réalise :
1. Génération sécurisée des secrets demo (`secrets.token_urlsafe()`).
2. Build & start des conteneurs Nginx, Flask, Keycloak.
3. Bootstrap du realm demo (comptes Alice/Bob/Joe, rôles, TOTP requis).
4. Lancement du scénario JML (promotion + désactivation) pour démonstration + semis du secret service-account dans Azure Key Vault (production).

### Comptes utiles
- Admin UI : `alice/alice` (Analyst → Manager après promo), `bob/bob` (désactivé).
- Keycloak : `admin/admin`.
- Service SCIM : client `automation-cli` / secret `demo-service-secret` *(démo uniquement — en production se référer au secret `keycloak-service-client-secret` dans Azure Key Vault)*.

## Mode production (Azure Key Vault)
```bash
# 1. Préparer .env
cp .env.production .env        # si disponible, sinon éditer manuellement
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=<votre-coffre>

# 2. Authentifier Azure
az login                       # privilégier Workload Identity ensuite

# 3. Charger les secrets
make ensure-secrets            # vide les valeurs locales s'il faut
make load-secrets              # récupère depuis Key Vault vers .runtime/secrets/

# 4. Lancer la stack
make quickstart
```
Garanties apportées :
- Aucun secret persistant dans `.env`.
- Secrets montés en lecture seule (`chmod 400`) via `/run/secrets`.
- Secret `automation-cli` stocké et maintenu dans Azure Key Vault (`keycloak-service-client-secret`), synchronisé sur `/run/secrets`.
- Journalisation Azure Activity Log pour toute action Key Vault.
- `KEYCLOAK_URL_HOST` doit pointer vers l'URL accessible depuis la machine locale (ex. `http://127.0.0.1:8080`) pour permettre `scripts/rotate_secret.sh` de contacter l'API admin.

## Commandes courantes
| Commande | Description |
|----------|-------------|
| `make up` | Démarrer sans bootstrap complet (pour tests manuels). |
| `make down` | Arrêter la stack et libérer les ports. |
| `make logs` | Suivre les conteneurs en temps réel. |
| `make demo-jml` | Rejouer le scénario JML contre la stack en cours. |
| `make pytest` | Lancer les tests unitaires (Keycloak mocké). |
| `make pytest-e2e` | Tests d'intégration (stack obligatoire). |
| `make rotate-secret` | Rotation orchestrée du secret SCIM (prod uniquement). |
| `make doctor` | Diagnostic (Docker, az CLI, Key Vault). |

## Dépannage rapide
| Symptom | Cause probable | Résolution |
|---------|----------------|------------|
| `Invalid client credentials` après `make fresh-demo` | Secret Keycloak hors sync | Relancer `make demo-jml` (réapplique le secret `demo-service-secret`); si besoin, refaire `make fresh-demo`. |
| Erreurs JWT signature | Token expiré ou mauvais issuer | Regénérer le token via Keycloak, vérifier URL issuer dans `.env`. |
| `DefaultAzureCredential` failed | `az login` manquant ou pas de Managed Identity | Lancer `az login` ou configurer Workload Identity Federation. |
| Containers `unhealthy` | Keycloak pas prêt ou secrets manquants | Patienter 60s, vérifier `.runtime/secrets`, relancer `make quickstart`. |
| SCIM retourne 403 | OAuth non implémenté côté API | Bloquer l'accès externe, utiliser UI admin, suivre [Security Design](../SECURITY_DESIGN.md#road-to-azure-native). |

## Prochaines lectures
- Comprendre les contrôles sécurité : [Security Design](../SECURITY_DESIGN.md)
- Voir la stratégie de tests : [Test Strategy](../TEST_STRATEGY.md)
- Explorer l’API SCIM : [API Reference](../API_REFERENCE.md)
