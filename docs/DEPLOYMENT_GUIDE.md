# Deployment Guide — Azure-Native Roadmap

> **Current State**: Azure Key Vault integrated, production-ready secrets management  
> **Target State**: Full Azure-native (Entra ID, Managed Identity, App Service, Monitor)

This guide documents the Azure deployment path supported by `app/config/settings.py` and `app/core/provisioning_service.py`. Adjust values to match your environment; add TODO markers where additional work is required.

---

## 🚀 Azure-Native Evolution (4 Phases)

### Phase 1: Identity Provider Migration ✅ **Next Priority**
**Objective**: Replace Keycloak with Azure Entra ID (ex-Azure AD)

**Actions**:
- [ ] Configure Entra ID App Registration (SCIM client)
- [ ] Enable Conditional Access Policies (MFA, device compliance)
- [ ] Migrate OIDC/OAuth flows to Entra ID endpoints
- [ ] Update JWT validation to Entra ID JWKS
- [ ] Test B2B guest access (inter-organization SCIM)

**Benefits**:
- Cloud-native authentication (no self-hosted Keycloak)
- Advanced MFA policies (Authenticator, FIDO2)
- Integration with Microsoft 365 identities

### Phase 2: Secrets & Identity Management ✅ **Partially Complete**
**Objective**: Eliminate Service Principals, adopt Managed Identity

**Actions**:
- [x] Azure Key Vault integration (completed)
- [x] Secret rotation automation (`make rotate-secret`)
- [ ] Replace Service Principal with Managed Identity
- [ ] Implement Workload Identity for AKS/Container Apps
- [ ] Remove `.env` dependency (full Key Vault migration)

**Benefits**:
- Zero credentials in code/config
- Automatic credential rotation
- RBAC-based access control

### Phase 3: Observability & Compliance
**Objective**: Production-grade monitoring and audit

**Actions**:
- [ ] Azure Monitor Application Insights integration
- [ ] Log Analytics workspace for centralized logs
- [ ] Azure Sentinel SIEM for FINMA compliance
- [ ] Immutable Blob Storage for audit logs (nLPD retention)
- [ ] Alerting rules for security events (failed auth, privilege escalation)

**Benefits**:
- Real-time threat detection
- Compliance audit trails (FINMA)
- Performance monitoring

### Phase 4: Production Infrastructure
**Objective**: Scalable, resilient deployment

**Actions**:
- [ ] Azure App Service with auto-scaling
- [ ] Azure SQL Database (replace SQLite)
- [ ] Azure Cache for Redis (distributed sessions)
- [ ] Azure Front Door (global load balancing, WAF)
- [ ] Azure Policy enforcement (compliance guardrails)

**Benefits**:
- High availability (99.9% SLA)
- Global distribution
- Built-in DDoS protection

---

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

# SMTP password for Keycloak email delivery (password reset, account verification)
az keyvault secret set --vault-name "$KV_NAME" --name smtp-password --value "<gmail-app-password>"
```

**📧 Email Configuration (Password Reset)**

Password reset functionality requires SMTP configuration in Keycloak:

```bash
# 1. Generate Gmail App Password (or use Office365/SendGrid credentials)
# Gmail: https://myaccount.google.com/apppasswords
# Office365: Use app password or OAuth2 (recommended for production)

# 2. Store SMTP password in Azure Key Vault
az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name smtp-password \
  --value "xxxx xxxx xxxx xxxx"  # Gmail app password (remove spaces)

# 3. Configure environment variables (.env.production or Azure App Configuration)
SMTP_HOST=smtp.gmail.com       # or smtp.office365.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_FROM=noreply@yourdomain.com

# 4. SMTP is automatically configured during stack bootstrap
# Or configure manually:
docker compose exec flask-app python3 scripts/configure_smtp.py

# 5. Test SMTP connectivity
docker compose exec flask-app python3 scripts/check_smtp.py
```

**Supported SMTP Providers**:
- ✅ **Gmail**: `smtp.gmail.com:587` (requires App Password with 2FA enabled)
- ✅ **Office 365**: `smtp.office365.com:587` (app password or OAuth2)
- ✅ **SendGrid**: `smtp.sendgrid.net:587` (API key as password)
- ✅ **Azure Communication Services**: Email service with managed identity

**Security Notes**:
- ✅ Never store SMTP password in `.env` or code — always use Azure Key Vault
- ✅ Use TLS (port 587 with STARTTLS) or SSL (port 465)
- ✅ Restrict SMTP credentials to least privilege (send-only permissions)
- ✅ Monitor email delivery logs for abuse detection

**Production Recommendation**: Use **Azure Communication Services** Email with Managed Identity (eliminates SMTP credentials entirely).

---

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

# SMTP Configuration (password reset emails)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_FROM=noreply@yourdomain.com
# SMTP_PASSWORD loaded from Azure Key Vault secret 'smtp-password'
```

**📧 Email Delivery**: See [SMTP Configuration](#email-configuration-password-reset) section above.  
**🔒 Password Security**: See [SECURITY_DESIGN.md](SECURITY_DESIGN.md#password-management-architecture) for details.

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
- [ ] **Swiss Compliance** :
  - [ ] Data residency: Confirm Azure region (Switzerland North/West for Swiss data)
  - [ ] nLPD: Audit log retention ≥ 12 months (Azure Log Analytics)
  - [ ] FINMA: Export audit trail to SIEM (Azure Sentinel)
  - [ ] GDPR: Document data processing activities (DPIA if needed)

## Recovery
- Snapshot or backup the Keycloak database and volume.
- Retain audit logs offsite (`make verify-audit` + immutable storage).
- Maintain staging reset procedure (`make fresh-demo` equivalent) and production rollback playbooks.

---

## � Troubleshooting

### SMTP Email Not Delivered

**Symptoms**: Password reset emails not received by users

**Solutions**:
1. **Test SMTP connectivity**:
   ```bash
   docker compose exec flask-app python3 scripts/check_smtp.py
   ```
   Expected output: "✅ SMTP test email sent successfully"

2. **Check Keycloak SMTP configuration**:
   - Login to Keycloak Admin Console: `http://localhost:8080/admin/demo/console`
   - Navigate to: Realm Settings → Email
   - Verify: Host, Port, From, Authentication enabled

3. **Verify Azure Key Vault secret**:
   ```bash
   az keyvault secret show --vault-name "$KV_NAME" --name smtp-password --query value -o tsv
   ```

4. **Common Issues**:
   - ❌ Gmail without App Password → Enable 2FA + generate App Password
   - ❌ Office365 with MFA → Use app-specific password or OAuth2
   - ❌ Firewall blocking port 587 → Check network security groups
   - ❌ "Invalid credentials" → Verify SMTP_USER matches email provider

5. **Check Keycloak logs**:
   ```bash
   docker compose logs keycloak | grep -i "email\|smtp"
   ```

### Azure Key Vault Access Denied

**Symptoms**: `make load-secrets` fails with "Forbidden"

**Solutions**:
1. Verify Managed Identity has correct permissions:
   ```bash
   az keyvault set-policy --name "$KV_NAME" \
     --object-id "$PRINCIPAL_ID" \
     --secret-permissions get list
   ```

2. Check Azure CLI authentication:
   ```bash
   az account show  # Verify correct subscription
   az keyvault list  # Verify access
   ```

### Password Reset Link Expired

**Symptoms**: User clicks password reset link and sees "Token expired"

**Solutions**:
- Default Keycloak token lifetime: 5 minutes
- Configure in Keycloak: Realm Settings → Tokens → Action Token Lifespan
- Recommended: 15-30 minutes for production

---

## �🔗 Related Documentation
- [Security Design](SECURITY_DESIGN.md) — OWASP ASVS L2, nLPD/RGPD/FINMA controls
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis, Swiss compliance threats
- [API Reference](API_REFERENCE.md) — SCIM 2.0 endpoints, OAuth scopes
- [Swiss Hiring Pack](Hiring_Pack.md) — Azure skills demonstration for recruiters

---

## Swiss Azure Regions

For Swiss data residency requirements (nLPD, financial sector):

| Region | Code | Latency (Geneva) | Use Case |
|--------|------|------------------|----------|
| **Switzerland North** | `switzerlandnorth` | <5ms | Primary (Zurich datacenter) |
| **Switzerland West** | `switzerlandwest` | <10ms | DR/backup (Geneva datacenter) |
| West Europe | `westeurope` | ~15ms | Non-critical workloads |

**Recommendation** : Deploy production in `switzerlandnorth` with geo-replication to `switzerlandwest` for FINMA compliance.
