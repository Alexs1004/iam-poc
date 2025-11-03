# Deployment Guide — Azure

This guide documents the Azure deployment path supported by `app/config/settings.py` and `app/core/provisioning_service.py`. Adjust values to match your environment; add TODO markers where additional work is required.

## Prerequisites
- Azure subscription with rights to create resource groups, Key Vault, and Managed Identities.
- Azure CLI ≥ 2.54 (`az login` or workload identity federation).
- Azure Container Registry (or equivalent) for Docker images.
- TLS certificates (Key Vault managed or external).

## Provision Azure Key Vault
```bash
RESOURCE_GROUP=rg-iam-poc
LOCATION=westeurope    # adjust region
KV_NAME=kv-iam-poc-prod

az keyvault create \
  --name "$KV_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --enable-soft-delete true \
  --enable-purge-protection true

az keyvault secret set --vault-name "$KV_NAME" --name keycloak-service-client-secret --value "<prod-secret>"
az keyvault secret set --vault-name "$KV_NAME" --name keycloak-admin-password --value "<complex-password>"
az keyvault secret set --vault-name "$KV_NAME" --name flask-secret-key --value "$(python - <<'PY'
import secrets; print(secrets.token_urlsafe(64))
PY)"
az keyvault secret set --vault-name "$KV_NAME" --name audit-log-signing-key --value "$(python - <<'PY'
import secrets; print(secrets.token_urlsafe(72))
PY)"
```

Restrict access to the managed identity (next section) with `get`/`list` permissions only. Enable Key Vault diagnostics and Activity Logs retention.

## Managed Identity
```bash
IDENTITY_NAME=msi-iam-poc
az identity create \
  --name "$IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"

PRINCIPAL_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv)
az keyvault set-policy --name "$KV_NAME" --object-id "$PRINCIPAL_ID" --secret-permissions get list
```

Use Azure Workload Identity (AKS) or Container Apps managed identity to fetch secrets without storing credentials locally.

## Build and push images
```bash
ACR_NAME=<your_acr>
docker build -t $ACR_NAME.azurecr.io/iam-poc/flask:prod .
az acr login --name $ACR_NAME
docker push $ACR_NAME.azurecr.io/iam-poc/flask:prod
```

Keycloak can run as a managed service or container. For production, back it with managed Postgres and persistent storage.

## Configure environment variables
Supply the following via `.env.production`, Kubernetes secrets, or Azure App Configuration:
```
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=$KV_NAME
KEYCLOAK_URL_HOST=https://keycloak.<company>.com
KEYCLOAK_ISSUER=https://keycloak.<company>.com/realms/prod
APP_BASE_URL=https://iam.<company>.com
```

Validate Key Vault access locally:
```bash
make ensure-secrets   # clears demo values
make load-secrets     # fetches secrets into .runtime/secrets/
```

## Deploy platform components
- Reverse proxy: Azure Application Gateway (WAF) or Azure Front Door in front of nginx.
- Workload: AKS or Azure Container Apps with the managed identity assigned to the Flask service.
- Secrets: CSI Secret Store driver (AKS) or container app environment variables from managed identity.
- Observability: Azure Monitor + Application Insights (TODO: wire OpenTelemetry exporter in Flask).
- Certificates: Key Vault managed certificates or external provider with auto-rotation.

## Post-deployment checklist
- [ ] `make rotate-secret` succeeds using managed identity (no `az login` on build agents).
- [ ] `make verify-audit` passes; archive audit logs to immutable storage (TODO: Azure Blob immutability policy).
- [ ] `/scim/v2/*` rejects unauthenticated requests (curl without header → `401`).
- [ ] `/scim/docs` protected (VPN, auth proxy, or IP allowlist) — TODO enforce via gateway policy.
- [ ] TLS 1.2+/HSTS/CSP confirmed at the edge.
- [ ] Azure Monitor alerts cover 5xx spikes and Key Vault access anomalies.

## Recovery
- Snapshot or backup the Keycloak database and volume.
- Retain audit logs offsite (`make verify-audit` + immutable storage).
- Maintain staging reset procedure (`make fresh-demo` equivalent) and production rollback playbooks.
