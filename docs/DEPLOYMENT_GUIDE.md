# Deployment Guide (Azure-First, Swiss Enterprise)

Ce guide décrit la mise en production d’une instance IAM PoC sur Azure avec un accent sécurité (FINMA/nLPD).

## 1. Prérequis

- Azure subscription (region Swiss North/West recommandée).
- Azure CLI ≥ 2.54 + `az login` (ou workload identity).
- Container Registry (ACR) provisionné.
- Managed Identity (User Assigned) pour les workloads applicatifs.

## 2. Key Vault & Secrets

```bash
# Variables de travail
RESOURCE_GROUP=rg-iam-poc
LOCATION=s witzerlandnorth
KV_NAME=kv-iam-poc-prod

# Création
az keyvault create \
  --name "$KV_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --enable-soft-delete true \
  --enable-purge-protection true

# Secrets requis
az keyvault secret set --vault-name "$KV_NAME" --name keycloak-service-client-secret --value "<prod-secret>"
az keyvault secret set --vault-name "$KV_NAME" --name keycloak-admin-password --value "<complex-password>"
az keyvault secret set --vault-name "$KV_NAME" --name flask-secret-key --value "$(python - <<'PY'\nimport secrets;print(secrets.token_urlsafe(64))\nPY)"
az keyvault secret set --vault-name "$KV_NAME" --name audit-log-signing-key --value "$(python - <<'PY'\nimport secrets;print(secrets.token_urlsafe(72))\nPY)"
```

> 🛡️ Activer `RBAC` et n’accorder qu’un rôle `Key Vault Secrets User` à la managed identity.

## 3. Managed Identity & Access

```bash
IDENTITY_NAME=msi-iam-poc
az identity create \
  --name "$IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"

IDENTITY_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)

# Autoriser l’identité sur Key Vault
az keyvault set-policy \
  --name "$KV_NAME" \
  --object-id $(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv) \
  --secret-permissions get list
```

Dans Kubernetes (AKS) : configurer `aad-pod-identity` ou Workload Identity Federation pour lier le pod Flask à cette identité.

## 4. Conteneurs & ACR

1. `docker build -t <acr>.azurecr.io/iam-poc/flask:prod .`
2. `az acr login --name <acr>`
3. `docker push <acr>.azurecr.io/iam-poc/flask:prod`

Keycloak peut rester externe (managed service) ou déployé comme conteneur (prévoir volume Azure Files + base Postgres managée).

## 5. Infrastructure Réseau

- **Frontend** : Azure Application Gateway (WAF) ou Azure Front Door.
- **TLS** : certificats signés (Key Vault managed certs ou DigiCert).
- **Back-end** : AKS ou Azure Container Apps. Restreindre accès Keycloak via NSG.
- **Logs** : Azure Monitor + App Insights (export GDPR/FINMA compliant).

## 6. Configuration Application

Mettre à jour `.env.production` avant build :

```
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=$KV_NAME
KEYCLOAK_URL_HOST=https://keycloak.<company>.ch
OAUTH_ISSUER=https://keycloak.<company>.ch/realms/prod
```

Dans la pipeline (GitHub Actions/Azure DevOps) :

- Injecter variables (Key Vault actions, `azure/login` + `azure/keyvault`).
- Exécuter `make validate-env`.
- Lancer `make rotate-secret` après déploiement si rotation nécessaire.

## 7. Observabilité & Sécurité

- **App Insights** : instrumentation Flask (OpenTelemetry).
- **Azure Monitor** : alertes sur erreurs 5xx, temps réponse SCIM.
- **Security Center** : activer Defender for Cloud (SQL, containers).
- **Geo-réplication** : Key Vault (soft-delete/purge-protection déjà activés).

## 8. Opérations

- **Rotation secret** : `make rotate-secret` (exécuté depuis runner Azure avec Managed Identity).
- **Audit log** : exporter `.runtime/audit` vers Azure Storage immutable (WORM).
- **Patching** : automatiser update images (Dependabot + `az acr task`).

## 9. Conformité Suisse

- FINMA Circ. 08/21 – Tenir un registre d’accès Key Vault (Activity Logs).
- nLPD art. 8-12 – Minimisation des données, transparence (documenter SCIM mapping).
- OFCOM/OFIT – Sécurité réseau (TLS 1.2+, HSTS 1 an, cipher suites restreintes).
- Revue annuelle des droits (RBAC Key Vault, Keycloak admin).

---

## 10. Check-list Go-Live

- [ ] `DEMO_MODE=false`, `AZURE_USE_KEYVAULT=true`
- [ ] `/openapi.json` et `/scim/docs` protégés (auth + IP filtering)
- [ ] Backup restauration testée (Key Vault, base Keycloak)
- [ ] Journaux audités (Azure Monitor + archivage)
- [ ] DR runbook documenté (RTO/RPO < 4h)
