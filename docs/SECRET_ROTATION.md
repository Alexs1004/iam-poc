# Secret Rotation Guide

## Overview

This project implements **orchestrated secret rotation** for production environments. The rotation process is fully automated and follows security best practices for zero-trust architectures.

## Quick Reference

```bash
# Dry-run (test without making changes)
make rotate-secret-dry

# Production rotation
make rotate-secret
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Secret Rotation Workflow                   │
└─────────────────────────────────────────────────────────────┘

1. Generate New Secret
   ├─ Obtain Keycloak admin token
   ├─ Find automation-cli client UUID
   └─ POST /admin/realms/{realm}/clients/{uuid}/client-secret

2. Update Azure Key Vault
   └─ az keyvault secret set --vault-name {vault} --name {secret}

3. Restart Application
   └─ docker compose restart flask-app

4. Verify Health
   ├─ curl https://localhost/health (10 retries, 2s interval)
   └─ Exit 1 if health check fails
```

## Prerequisites

### Environment Configuration

```bash
# .env (production mode)
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=your-key-vault
AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET=keycloak-service-client-secret

# Keycloak admin credentials
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=<secure-password>

# Docker service name
FLASK_SERVICE=flask-app

# Health check endpoint
HEALTHCHECK_URL=https://localhost/health
```

### Required Tools

- `bash` (4.0+)
- `curl` (with HTTPS support)
- `jq` (JSON processor)
- `docker` with Docker Compose v2
- `az` (Azure CLI, authenticated)

### Azure Permissions

The Azure identity must have:
- **Key Vault Secrets Officer** or **Key Vault Administrator** role
- Permissions: `Get`, `Set` on secrets

Verify with:
```bash
make doctor
```

## Usage

### Dry-Run Mode (Recommended for Testing)

```bash
./scripts/rotate_secret.sh --dry-run
```

**What it does:**
- ✅ Validates all prerequisites
- ✅ Obtains Keycloak admin token
- ✅ Finds client UUID
- ❌ Does NOT generate new secret
- ❌ Does NOT update Key Vault
- ❌ Does NOT restart application

**Use cases:**
- CI/CD pipeline testing
- Validating Azure credentials
- Checking Keycloak connectivity
- Pre-deployment verification

### Production Rotation

```bash
make rotate-secret
# or
./scripts/rotate_secret.sh
```

**Output example:**
```
[INFO] Variables chargées depuis /home/alex/iam-poc/.env
[INFO] Obtention d'un token admin Keycloak…
[INFO] Recherche du client 'automation-cli' dans le realm 'demo'…
[INFO] Régénération du secret Keycloak pour le client automation-cli (a1b2c3d4-...)
[INFO] Nouveau secret obtenu (longueur 36 chars).
[INFO] Mise à jour du secret dans Azure Key Vault: my-vault/keycloak-service-client-secret
[INFO] Key Vault synchronisé.
[INFO] Redémarrage du service Docker 'flask-app'…
[INFO] Health-check sur https://localhost/health…
[INFO] ✅ Application OK (HTTP 200).
[INFO] ✅ Rotation orchestrée terminée avec succès.
```

## Safety Features

### Demo Mode Protection

The script **refuses to run** in demo mode:

```bash
$ DEMO_MODE=true make rotate-secret
[WARN] DEMO_MODE=true → On ne fait pas de rotation réelle en démo.
[WARN] Astuce: conservez un secret stable (demo-service-secret) et testez la rotation seulement en PROD.
```

**Rationale:** Demo mode uses a fixed secret (`demo-service-secret`) for developer convenience. Rotation would break local development workflows.

### Idempotency

The script is safe to run multiple times:
- If Keycloak is unreachable → fails early
- If Key Vault update fails → application still uses old secret
- If health check fails → exits with error code 1

### Error Handling

All operations use `set -euo pipefail`:
- **`-e`**: Exit on any command failure
- **`-u`**: Error on undefined variables
- **`-o pipefail`**: Catch errors in pipelines

### Health Check Retry Logic

```bash
# 10 attempts, 2 seconds apart
for i in {1..10}; do
  HTTP_CODE=$(curl -k -o /dev/null -w "%{http_code}" https://localhost/health)
  if [[ "${HTTP_CODE}" =~ ^2[0-9][0-9]$ ]]; then
    break  # Success
  fi
  sleep 2
done
```

## Automation & CI/CD

### GitHub Actions Example

```yaml
name: Rotate Keycloak Secret

on:
  schedule:
    - cron: '0 2 * * 0'  # Every Sunday at 2 AM UTC
  workflow_dispatch:       # Manual trigger

jobs:
  rotate:
    runs-on: ubuntu-latest
    environment: production
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Install Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq
      
      - name: Rotate Secret
        run: |
          make rotate-secret
        env:
          DEMO_MODE: false
          AZURE_USE_KEYVAULT: true
          AZURE_KEY_VAULT_NAME: ${{ secrets.AZURE_KEY_VAULT_NAME }}
      
      - name: Notify on Failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ Secret rotation failed in production"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Azure DevOps Pipeline

```yaml
trigger: none

schedules:
- cron: "0 2 * * 0"
  displayName: Weekly secret rotation
  branches:
    include:
    - main

pool:
  vmImage: ubuntu-latest

steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: 'Production-ServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      apt-get update && apt-get install -y jq
      make rotate-secret
  env:
    DEMO_MODE: false
    AZURE_USE_KEYVAULT: true
    AZURE_KEY_VAULT_NAME: $(AZURE_KEY_VAULT_NAME)
```

## Troubleshooting

### Error: "Impossible d'obtenir un access token admin"

**Cause:** Keycloak is not reachable or admin credentials are incorrect.

**Solution:**
```bash
# Check Keycloak availability
curl -I http://127.0.0.1:8080/health

# Verify credentials
docker compose logs keycloak | grep -i "admin"

# Check .env file
grep KEYCLOAK_ADMIN .env
```

### Error: "Client 'automation-cli' introuvable"

**Cause:** Service account client doesn't exist in the realm.

**Solution:**
```bash
# Bootstrap the service account first
./scripts/demo_jml.sh
```

### Error: "Cannot list secrets; check Key Vault permissions"

**Cause:** Azure identity lacks Key Vault access.

**Solution:**
```bash
# Verify login
az account show

# Check Key Vault access
az keyvault secret list --vault-name YOUR_VAULT_NAME

# Grant permissions
az keyvault set-policy \
  --name YOUR_VAULT_NAME \
  --object-id $(az ad signed-in-user show --query id -o tsv) \
  --secret-permissions get set list
```

### Error: "Health-check KO après 10 tentatives"

**Cause:** Application failed to restart or is not healthy.

**Solution:**
```bash
# Check container status
docker compose ps

# View Flask logs
docker compose logs flask-app

# Check health endpoint manually
curl -k https://localhost/health
```

## Advanced Configuration

### Custom Health Check Endpoint

If you have a custom health endpoint:

```bash
# .env
HEALTHCHECK_URL=https://localhost/api/health/ready

# Or pass directly
HEALTHCHECK_URL=https://my-app.example.com/health ./scripts/rotate_secret.sh
```

### Custom Docker Service Name

If your Flask service has a different name:

```bash
# docker-compose.yml
services:
  my-flask-app:  # Custom name
    # ...

# .env
FLASK_SERVICE=my-flask-app
```

### Self-Signed Certificates

The script automatically uses `-k` (insecure) flag for HTTPS health checks on `localhost`. For production domains with valid certificates, modify the script:

```bash
# Line 182 in rotate_secret.sh
if [[ "${HEALTHCHECK_URL}" == https://localhost* ]]; then
  CURL_FLAGS="${CURL_FLAGS} -k"
fi
```

## Security Considerations

### Credential Rotation Frequency

**Recommended schedule:**
- **Development**: Manual rotation only
- **Staging**: Monthly rotation
- **Production**: Weekly or bi-weekly rotation

### Audit Logging

All rotation events are logged to:
1. **Script output** (stdout/stderr)
2. **Docker logs** (Flask restart events)
3. **Azure Activity Log** (Key Vault secret updates)

Collect these logs in your SIEM:
```bash
# Export Azure audit logs
az monitor activity-log list \
  --resource-id /subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault} \
  --start-time 2024-01-01 \
  --query "[?contains(operationName.value, 'SECRET')]"
```

### Zero-Downtime Considerations

- **Flask restart**: Graceful shutdown (SIGTERM → SIGKILL after 10s)
- **Active sessions**: Preserved via server-side session storage
- **New connections**: Briefly rejected during restart (~1-2s)

For true zero-downtime, use:
1. Blue-green deployment
2. Rolling updates (Kubernetes)
3. Load balancer with health checks

### Emergency Rollback

If rotation causes issues:

```bash
# 1. Get previous secret version
OLD_SECRET=$(az keyvault secret show \
  --vault-name YOUR_VAULT \
  --name keycloak-service-client-secret \
  --version PREVIOUS_VERSION_ID \
  --query value -o tsv)

# 2. Manually restore in Keycloak
# (Use Keycloak Admin Console → Clients → automation-cli → Credentials tab)

# 3. Update Key Vault to match
az keyvault secret set \
  --vault-name YOUR_VAULT \
  --name keycloak-service-client-secret \
  --value "${OLD_SECRET}"

# 4. Restart Flask
docker compose restart flask-app
```

## Performance Metrics

Typical rotation duration (on Azure VM Standard_B2s):
- Token acquisition: ~200ms
- Secret generation: ~150ms
- Key Vault update: ~300ms
- Flask restart: ~5s (includes health check retries)
- **Total**: ~6-7 seconds

## See Also

- [Demo vs Production Modes](../README.md#demo-mode-vs-production)
- [Azure Key Vault Integration](../README.md#production-mode-with-azure-key-vault)
- [Troubleshooting Guide](../README.md#troubleshooting)
