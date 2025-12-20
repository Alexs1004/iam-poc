# API Reference — SCIM 2.0

> **Standards**: RFC 7644 (SCIM 2.0), RFC 6749 (OAuth 2.0), RFC 7519 (JWT)  
> **Swiss Compliance**: nLPD (data portability), GDPR (right to erasure), FINMA (audit trail)

Authoritative description of the `/scim/v2` surface exposed by `app/api/scim.py`. All requests are served over HTTPS and return JSON bodies using the SCIM error schema (`schemas`, `status`, `detail`, optional `scimType`).

## Interactive Documentation
- **OpenAPI Specification**: [scim_openapi.yaml](../openapi/scim_openapi.yaml)
- **ReDoc Interface**: https://localhost/scim/docs (read-only, production-safe)
- **Raw OpenAPI JSON**: https://localhost/openapi.json

## Base URLs
- Reverse proxy (default demo stack): `https://localhost/scim/v2`
- Direct Flask access (bypass nginx): `http://localhost:8000/scim/v2`

## Authentication & headers
- **Authorization**: `Bearer <token>` issued by Keycloak (`automation-cli` client in demo).
- **Scopes**:
  - `scim:read` for `GET`
  - `scim:write` for `POST`, `PATCH`, `DELETE` (and `POST /Users/.search`)
- **Content-Type**: `application/scim+json` mandatory for `POST`, `PATCH`, `PUT` (non-compliant content types → `415 invalidSyntax`).
- Discovery endpoints (`/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`) are public; every other path enforces OAuth.
- Service account `automation-cli` is allowed without explicit scopes (temporary bypass noted in code).

**🔐 Service Secrets**: The service client secret is generated at runtime and stored under `.runtime/secrets/` locally, or retrieved from Azure Key Vault in production.

## Endpoints

### `GET /Users`
List users with optional pagination or filter.

Parameters:
- `startIndex` (default `1`)
- `count` (default `10`, capped at 200)
- `filter` (only `userName eq "value"` supported; any other expression returns `501 notImplemented`)

Responses:
- `200` — SCIM ListResponse (`Resources`, `totalResults`, `startIndex`, `itemsPerPage`)
- `400` — invalid pagination values
- `401` / `403` — missing token or scope
- `500` — Keycloak fetch failure
- `501` — unsupported filter operator

### `POST /Users`
Create a user (joiner flow).

Body must include:
- `schemas` with `urn:ietf:params:scim:schemas:core:2.0:User`
- `userName`, `emails[0].value`, `name.givenName`, `name.familyName`
- Optional `active` (defaults `true`), `role`

Responses:
- `201` — returns SCIM User + `Location` header
- `400` — malformed payload / missing fields
- `401` / `403` — auth failures
- `409` — duplicate `userName`
- `413` — request payload too large (>64 KB)
- `415` — wrong media type
- `500` — provisioning failure

### `GET /Users/{id}`
Retrieve user by SCIM `id`.

Responses:
- `200` — SCIM User
- `401` / `403`
- `404` — unknown id
- `500` — Keycloak error

### `PATCH /Users/{id}`
Toggle `active` flag (idempotent).

Body must strictly equal:
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "replace", "path": "active", "value": true|false }
  ]
}
```

Responses:
- `200` — updated SCIM User
- `400` — invalid JSON, missing keys, non-boolean value
- `401` / `403`
- `404` — unknown id
- `413` — request payload too large (>64 KB)
- `415` — wrong content type
- `500` — Keycloak failure
- `501` — unsupported `op` or `path`

### `DELETE /Users/{id}`
Soft-delete user (disables account + revokes sessions).

Responses:
- `204` — success or already disabled
- `401` / `403`
- `404` — unknown id
- `500` — Keycloak failure

### `PUT /Users/{id}`
Full replace not supported.

Always returns:
- `501 notImplemented` with detail `Full replace is not supported. Use PATCH (active) or DELETE.`

### `POST /Users/.search`
Functional equivalent of `GET /Users` but accepts filter/pagination in the body. Treated as a write operation ⇒ requires `scim:write`.

Body (all fields optional):
```json
{
  "startIndex": 1,
  "count": 10,
  "filter": "userName eq \"value\""
}
```

Responses mirror `GET /Users`.

**Note**: This endpoint provides Azure AD/Okta compatibility for complex filter expressions via POST body.

### Discovery endpoints
- `GET /ServiceProviderConfig` — advertises `patch.supported=true`, `filter.supported=true`, `bulk=false`, `sort=false`, `etag=false`, OAuth bearer authentication.
- `GET /Schemas` — returns SCIM User schema (userName, emails, active).
- `GET /ResourceTypes` — exposes `User` resource metadata.

**Note**: Discovery endpoints are public (no OAuth required) per RFC 7644 specification.

## Error responses
All errors use:
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "401",
  "detail": "...",
  "scimType": "unauthorized"
}
```

Key detail strings (from `app/api/scim.py`):
- Missing header: `"Authorization header missing. Provide 'Authorization: Bearer <token>'."`
- Non-Bearer scheme: `"Authorization header must use Bearer token scheme: 'Authorization: Bearer <token>'."`
- Empty token: `"Bearer token is empty."`
- Content-Type failure: `"Content-Type must be application/scim+json"`
- Filter unsupported: `"Requested SCIM feature is not available in this PoC."` (SCIM error helper)

## OAuth example (demo realm)
```bash
TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=<service-secret>" \
  | jq -r '.access_token')
```

**Note**: The service secret is loaded from `.runtime/secrets/keycloak-service-client-secret` (demo mode) or Azure Key Vault (production).

## Sample SCIM calls
```bash
# Create user
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "demo.scim",
    "name": {"givenName": "Demo", "familyName": "SCIM"},
    "emails": [{"value": "demo.scim@example.com", "primary": true}],
    "active": true
  }'

# Filter by userName
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22demo.scim%22" \
  -H "Authorization: Bearer $TOKEN"

# Disable account (PATCH)
curl -sk -X PATCH "https://localhost/scim/v2/Users/<userId>" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "path": "active",
      "value": false
    }]
  }'
```

---

## 🛡️ Security & Common Pitfalls

### Why (Security)
- **Validate `iss`, `aud`, `exp`, `nbf`**: JWT validation prevents token forgery and ensures tokens are from trusted issuer
- **Enforce Content-Type: application/scim+json**: Prevents CSRF attacks and ensures proper parsing
- **Only PATCH active allowed (safe joiner/leaver)**: Prevents accidental data corruption by limiting operations to safe state changes

### Common Mistakes
- **Wrong media type → 415**: Missing `Content-Type: application/scim+json` header
- **Unsupported SCIM filter → 501**: Only `userName eq "value"` is supported
- **Using PUT → 501**: Use PATCH for updates or DELETE for removal (PUT not supported)
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

## Troubleshooting

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

## Related Documentation
- [Security Design](SECURITY_DESIGN.md) — OWASP ASVS L2, nLPD/RGPD/FINMA controls
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis, Swiss compliance threats
- [API Reference](API_REFERENCE.md) — SCIM 2.0 endpoints, OAuth scopes
- [Swiss Hiring Pack](Hiring_Pack.md) — Azure skills demonstration for recruiters
# Microsoft Entra ID App Registration Guide

This guide covers configuring Microsoft Entra ID (Azure AD) as an OIDC provider for the IAM PoC application.

## Prerequisites

- Azure subscription with Entra ID (Azure AD) tenant
- Global Administrator or Application Administrator role
- Azure CLI installed and authenticated (`az login`)

## 1. Create App Registration

### Azure Portal

1. Navigate to **Microsoft Entra ID** → **App registrations** → **New registration**
2. Configure:
   - **Name**: `iam-poc-flask` (or your preferred name)
   - **Supported account types**: Single tenant (your org only)
   - **Redirect URI**: Web → `https://localhost/callback`

3. Click **Register**

### Azure CLI

```bash
az ad app create \
  --display-name "iam-poc-flask" \
  --sign-in-audience "AzureADMyOrg" \
  --web-redirect-uris "https://localhost/callback" \
  --enable-id-token-issuance true
```

## 2. Enable ID Tokens

**Why?** OIDC authentication requires ID tokens to identify users.

1. Go to **Authentication** tab
2. Under **Implicit grant and hybrid flows**, check:
   - ✅ **ID tokens** (used for implicit and hybrid flows)
3. Click **Save**

> ⚠️ **Security Note**: We use Authorization Code Flow with PKCE (not implicit). ID tokens are returned via the token endpoint, not the authorize endpoint.

## 3. Configure Redirect URIs

Add all environments where the app will run:

| Environment | Redirect URI |
|-------------|--------------|
| Local dev   | `https://localhost/callback` |
| Staging     | `https://staging.example.com/callback` |
| Production  | `https://app.example.com/callback` |

### Post-Logout Redirect URI

1. Go to **Authentication** → **Front-channel logout URL**
2. Add: `https://localhost/` (or your domain)

## 4. Define App Roles

App Roles map to internal RBAC roles. Define them in the app manifest.

### Azure Portal

1. Go to **App roles** → **Create app role**
2. Create these roles:

| Display Name | Value | Description | Allowed members |
|--------------|-------|-------------|-----------------|
| Administrator | `admin` | Full access to admin dashboard | Users/Groups |
| Viewer | `viewer` | Read-only access | Users/Groups |
| IAM Operator | `iam-operator` | Can manage users and roles | Users/Groups |
| Manager | `manager` | Can view team members | Users/Groups |

### Manifest JSON

Alternatively, edit the manifest directly:

```json
"appRoles": [
  {
    "allowedMemberTypes": ["User"],
    "description": "Full access to admin dashboard and all operations",
    "displayName": "Administrator",
    "id": "generate-unique-guid",
    "isEnabled": true,
    "value": "admin"
  },
  {
    "allowedMemberTypes": ["User"],
    "description": "Read-only access to dashboards",
    "displayName": "Viewer",
    "id": "generate-unique-guid",
    "isEnabled": true,
    "value": "viewer"
  },
  {
    "allowedMemberTypes": ["User"],
    "description": "Can manage users, groups, and role assignments",
    "displayName": "IAM Operator",
    "id": "generate-unique-guid",
    "isEnabled": true,
    "value": "iam-operator"
  },
  {
    "allowedMemberTypes": ["User"],
    "description": "Can view and manage team members",
    "displayName": "Manager",
    "id": "generate-unique-guid",
    "isEnabled": true,
    "value": "manager"
  }
]
```

> 💡 Generate GUIDs: `uuidgen` (Linux/Mac) or `[guid]::NewGuid()` (PowerShell)

### Assign Roles to Users

1. Go to **Enterprise applications** → Select your app
2. **Users and groups** → **Add user/group**
3. Select user(s) and assign role(s)

## 5. Create Client Secret

**⚠️ Critical Security Step**: The client secret authenticates the application to Entra ID.

### Generate Secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Add description: `iam-poc-production`
3. Set expiration: 12 months (or per your policy)
4. Click **Add**
5. **Copy the VALUE immediately** (shown only once!)

> ⚠️ **Copy the VALUE, not the Secret ID!** The Value looks like: `abc123~xyz789...`

### Store in Azure Key Vault

**Never store secrets in `.env` or code!**

```bash
# Store the secret in Key Vault
az keyvault secret set \
  --vault-name YOUR_VAULT_NAME \
  --name entra-client-secret \
  --value "PASTE_SECRET_VALUE_HERE"
```

### Verify Storage

```bash
# Verify it was stored (shows metadata only)
az keyvault secret show \
  --vault-name YOUR_VAULT_NAME \
  --name entra-client-secret \
  --query "name"
```

## 6. Configure Environment Variables

Add to your `.env` file:

```bash
# Multi-IdP Configuration
OIDC_PROVIDER=entra

# Entra ID Configuration
ENTRA_ISSUER=https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
ENTRA_CLIENT_ID=YOUR_APPLICATION_CLIENT_ID
ENTRA_CLIENT_SECRET=  # Loaded from Key Vault
ENTRA_REDIRECT_URI=https://localhost/callback
ENTRA_POST_LOGOUT_REDIRECT_URI=https://localhost/

# Key Vault mapping
AZURE_SECRET_ENTRA_CLIENT_SECRET=entra-client-secret
```

### Find Your Values

| Variable | Where to find |
|----------|---------------|
| `ENTRA_ISSUER` | Overview → Directory (tenant) ID → Format as URL |
| `ENTRA_CLIENT_ID` | Overview → Application (client) ID |

## 7. Load Secrets and Restart

```bash
# Load secrets from Key Vault
make load-secrets

# Restart application
docker-compose up -d --force-recreate flask-app

# Verify Entra config is loaded
docker logs flask-app 2>&1 | grep -i entra
```

## 8. Test Authentication

1. Open `https://localhost/login`
2. Should redirect to Microsoft login page
3. After login, check roles are correctly mapped:

```bash
# In browser console or via curl
curl -k https://localhost/admin/me
```

## Role Mapping

The application normalizes Entra ID roles to internal roles:

| Entra App Role | Internal Role | Access Level |
|----------------|---------------|--------------|
| `admin` | `admin` | Full admin access |
| `viewer` | `viewer` | Read-only (denied /admin) |
| `iam-operator` | `iam-operator` | User/role management |
| `manager` | `manager` | Team view access |

## Troubleshooting

### Error: AADSTS7000215 - Invalid client secret

**Cause**: Wrong secret or Secret ID used instead of Value.

**Fix**:
1. Create a new client secret in Azure Portal
2. Copy the **VALUE** (not the ID)
3. Update Key Vault: `az keyvault secret set --vault-name ... --name entra-client-secret --value "NEW_VALUE"`
4. Reload: `make load-secrets && docker-compose up -d --force-recreate flask-app`

### Error: AADSTS50011 - Reply URL mismatch

**Cause**: Redirect URI doesn't match registration.

**Fix**: Add exact URI in App Registration → Authentication → Redirect URIs

### Roles not appearing in token

**Cause**: User not assigned to App Role.

**Fix**:
1. Enterprise applications → Your app → Users and groups
2. Add user and assign role
3. User must re-login to get new token

## Security Best Practices

1. **Rotate secrets regularly** - Set calendar reminders for expiration
2. **Use managed identities** in production Azure deployments
3. **Audit role assignments** - Review who has admin/operator roles
4. **Enable Conditional Access** - Require MFA for admin roles
5. **Monitor sign-in logs** - Entra ID → Sign-in logs

## References

- [Microsoft identity platform documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/)
- [App roles in Microsoft Entra ID](https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps)
- [OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
# Microsoft Entra ID SCIM Provisioning - Integration Guide

## 📋 Overview

This guide describes the integration of **Microsoft Entra ID (workforce identities)** with this application via **SCIM 2.0** for automated user provisioning.

**Authentication flow:** Static Bearer token (demo/development mode) or OAuth2 (production).

---

## 🎯 Objectives

- ✅ Create a **non-gallery Enterprise Application** in Entra ID
- ✅ Configure **automatic SCIM provisioning**
- ✅ Test connection with **Test connection** (GET `/scim/v2/ServiceProviderConfig`)
- ✅ Define **attribute mappings** (userPrincipalName, objectId, mail, accountEnabled)
- ✅ Validate creation/deactivation with **Provision on demand**
- ✅ Review application-side HMAC audit logs

---

## 🔧 Entra ID Configuration

### 1. Create Enterprise Application

1. Login to [Azure portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** → **Enterprise Applications**
3. Click **+ New application**
4. Select **+ Create your own application**
5. Name the application (ex: `IAM PoC SCIM`) and choose **Integrate any other application you don't find in the gallery (Non-gallery)**
6. Click **Create**

**Screenshot:**  
![Enterprise App Creation](images/entra_provisioning_create_app.png)  

---

### 2. Configure Provisioning

1. In the created application, go to **Provisioning** (side menu)
2. Click **Get started**
3. Select **Provisioning Mode: Automatic**
4. Fill in **Admin Credentials** fields:

   | Field | Value |
   |-------|--------|
   | **Tenant URL** | `https://<your-domain>/scim/v2` |
   | **Secret Token** | See [Authentication](#authentication) section below |

5. Click **Test Connection** → Must return **200 OK**
   - Entra ID calls `GET /scim/v2/ServiceProviderConfig`
   - Verifies endpoint responds with SCIM schema

6. If successful → **Save**

**Screenshot:**  
![Test connection successful](images/entra_provisioning_test_connection.png)  

---

### 3. Define Attribute Mappings

1. In **Provisioning** → **Mappings** → **Provision Azure Active Directory Users**
2. Configure the following mappings:

   | Entra ID Attribute | SCIM Attribute | Required | Notes |
   |-------------------|---------------|-------------|-------|
   | `userPrincipalName` | `userName` | ✅ | Unique identifier (ex: `alice@contoso.com`) |
   | `objectId` | `externalId` | ✅ | Entra ID GUID for correlation |
   | `mail` | `emails[type eq "work"].value` | ✅ | Professional email |
   | `displayName` | `displayName` | ✅ | User full name |
   | `Switch([IsSoftDeleted], , "False", "True", "True", "False")` | `active` | ⚠️ | Soft deactivation (see note) |

   **Note on `active`:**  
   - The `accountEnabled → active` mapping may require adjustment based on your Entra ID configuration.
   - Use the expression `Switch([IsSoftDeleted], , "False", "True", "True", "False")` to map deactivation.
   - Alternative: directly map `accountEnabled` if exposed in your tenant.

3. **Disable** unsupported mappings (groups, complex roles) if present.
4. **Save** changes.

**Screenshot:**  
![Attribute mappings](images/entra_provisioning_mappings.png)  

---

### 4. Test with "Provision on demand"

Before enabling full provisioning, test with a specific user:

1. In **Provisioning** → **Provision on demand**
2. Select a test user (ex: `alice@contoso.com`)
3. Click **Provision**
4. Verify steps:
   - ✅ **Import**: Entra ID reads the user
   - ✅ **Match**: Checks if user exists (via `userName`)
   - ✅ **Action**: Decides to create (POST) or update (PATCH)
   - ✅ **Create**: Calls `POST /scim/v2/Users`

5. **Expected result:** `201 Created` with returned SCIM user

**Screenshot:**  
![Provision on demand](images/entra_provisioning_on_demand.png)  

---

### 5. Enable Provisioning

1. In **Provisioning** → **Settings**
2. Change **Provisioning Status** from `Off` to `On`
3. **Save**
4. Entra ID launches initial sync cycle (may take 20-40 min)

**Screenshot:**  
![Provisioning enabled](images/entra_provisioning_enabled.png)

---

### 6. Test Deactivation

1. In Entra ID, **disable a user**:
   - Go to **Users** → Select user → **Block sign-in**
2. Wait for next sync cycle (or force with **Restart provisioning**)
3. Verify that `PATCH /scim/v2/Users/{id}` is called with `{ "active": false }`
4. Check **audit logs** in application (endpoint `/admin/audit`)

**Screenshot:**  
![Visible deactivation](images/entra_provisioning_deactivate.png)  

---

## 🔐 Authentication

### Static Token Mode (Demo/Development)

**Activation:**
- `DEMO_MODE=true` **OR** `SCIM_STATIC_TOKEN_SOURCE=keyvault`
- Endpoint: `/scim/v2/*` only

**Secret configuration:**

| Priority | Source | Variable |
|----------|--------|----------|
| 1 | Azure Key Vault | Secret `scim-static-token` (if `AZURE_USE_KEYVAULT=true`) |
| 2 | Environment | `SCIM_STATIC_TOKEN` |

**Example `.env` (development):**
```bash
DEMO_MODE=true
AZURE_USE_KEYVAULT=false
SCIM_STATIC_TOKEN=demo-scim-token-change-me
SCIM_STATIC_TOKEN_SOURCE=  # Empty = use SCIM_STATIC_TOKEN
```

**Example Azure Key Vault (production):**
```bash
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=my-keyvault
SCIM_STATIC_TOKEN_SOURCE=keyvault
# Secret 'scim-static-token' will be loaded from Key Vault
```

**⚠️ Security:**
- **NEVER** use static token in production without Key Vault.
- Static token is rejected on non-SCIM endpoints (`/admin`, `/scim/docs`).
- **Constant-time** comparison (`hmac.compare_digest`) to avoid timing attacks.

**Header in Entra ID:**
```
Authorization: Bearer demo-scim-token-change-me
```

### OAuth2 Mode (Recommended Production)

For enhanced security, use OAuth2 client credentials:

1. Configure a dedicated client in Keycloak with scopes `scim:read` and `scim:write`
2. Entra ID obtains token via `POST /realms/demo/protocol/openid-connect/token`
3. Token is validated on each request (RSA-SHA256 signature, expiration, issuer)

**See:** [SECURITY_DESIGN.md](SECURITY_DESIGN.md) for OAuth2 details

---

## 📡 SCIM Endpoints

| Method | Endpoint | Description | Auth required |
|---------|----------|-------------|--------------|
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM capabilities discovery | ❌ Public |
| `GET` | `/scim/v2/ResourceTypes` | Supported resource types | ❌ Public |
| `GET` | `/scim/v2/Schemas` | Available SCIM schemas | ❌ Public |
| `GET` | `/scim/v2/Users` | User list (with filtering) | ✅ Bearer |
| `GET` | `/scim/v2/Users/{id}` | User details | ✅ Bearer |
| `POST` | `/scim/v2/Users` | Create user | ✅ Bearer |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update | ✅ Bearer |
| `DELETE` | `/scim/v2/Users/{id}` | Delete user | ✅ Bearer |

---

## 🚫 Current Limitations

| Operation | Status | Notes |
|-----------|--------|-------|
| `PUT /scim/v2/Users/{id}` | ❌ **501 Not Implemented** | Use `PATCH` instead |
| Group provisioning | ❌ Not supported | User mappings only |
| Complex filters | ⚠️ Partial | Supported: `userName eq "alice@contoso.com"`<br>Not supported: nested AND/OR filters |
| Bulk operations | ❌ Not supported | `ServiceProviderConfig.bulk.supported = false` |
| Change password | ❌ Not supported | Passwords must be set in Keycloak |

**Required Content-Type:** `application/scim+json` (Entra ID sends automatically)

---

## 📊 Verification and Audit

### HMAC Audit Logs

Each SCIM operation generates an HMAC-SHA256 signed audit entry:

**Endpoint:** `GET /admin/audit` (authentication required)

**Event example:**
```json
{
  "timestamp": "2025-11-05T14:23:10Z",
  "event_type": "user.created",
  "actor": "automation-cli",
  "target_user": "alice@contoso.com",
  "auth_method": "static",
  "client_ip": "20.190.160.5",
  "correlation_id": "abc123",
  "signature": "hmac-sha256:a3f4e8..."
}
```

**Important fields:**
- `auth_method`: `static` (static token) or `oauth` (OAuth2)
- `client_ip`: Entra ID source IP
- `correlation_id`: Traceability ID (header `X-Correlation-Id`)

### Response Header

Each SCIM response includes `X-Auth-Method` for transparency:

```http
HTTP/1.1 200 OK
X-Auth-Method: static
X-Correlation-Id: abc123
Content-Type: application/scim+json
```

---

## 🔍 Troubleshooting

### "Test Connection" Fails

**Symptoms:** Entra ID returns "Failed to connect" during test.

**Solutions:**
1. Verify URL is accessible from Internet (or configure VPN/Private Link).
2. Test manually with `curl`:
   ```bash
   curl -H "Authorization: Bearer <token>" \
        https://your-domain/scim/v2/ServiceProviderConfig
   ```
3. Check application logs for authentication errors.

### Users Not Created

**Symptoms:** Provisioning cycle completes without creating users.

**Solutions:**
1. Check **Scoping filters** in Entra ID (Provisioning → Settings → Scope).
2. Ensure users are **assigned to the application** (Users and groups).
3. Review **Provisioning logs** (Entra ID → Enterprise App → Provisioning logs).

### 401 Unauthorized Error

**Symptoms:** All SCIM requests return `401`.

**Solutions:**
1. Verify **Secret Token** in Entra ID matches `SCIM_STATIC_TOKEN` (or Key Vault secret).
2. Ensure static mode is enabled (`DEMO_MODE=true` or `SCIM_STATIC_TOKEN_SOURCE=keyvault`).
3. Check logs for received token hash (truncated SHA256, not full token).

### 403 Forbidden Error (scope)

**Symptoms:** Authentication succeeds but Entra ID receives `403`.

**Solutions:**
1. Static token is accepted only on `/scim/v2/*`.
2. If using OAuth2, verify Keycloak client has `scim:read` and `scim:write` scopes.

### Deactivation Not Detected

**Symptoms:** User blocked in Entra ID remains active in application.

**Solutions:**
1. Verify `accountEnabled → active` mapping (see Attribute Mappings section).
2. Force sync cycle with **Restart provisioning**.
3. Review Entra ID logs to see if `PATCH` is sent.

---

## 🎓 Security Best Practices

### In Development

- ✅ Use `DEMO_MODE=true` with `SCIM_STATIC_TOKEN` in `.env`
- ✅ Test on localhost with HTTPS (self-signed certificates OK)
- ✅ Limit static token scope to `/scim/v2/*` (already implemented)

### In Production

- ✅ **Mandatory:** Store `scim-static-token` in Azure Key Vault
- ✅ Set `SCIM_STATIC_TOKEN_SOURCE=keyvault` and `AZURE_USE_KEYVAULT=true`
- ✅ Use long random token (minimum 32 characters): `openssl rand -base64 32`
- ✅ Configure **IP whitelisting** if possible (Entra ID IP ranges)
- ✅ Enable **Provisioning logs** in Entra ID (90-day retention)
- ✅ Monitor `auth_method=static` events in audit logs

**Secret rotation:**
1. Generate new token: `openssl rand -base64 32`
2. Add to Key Vault with name `scim-static-token`
3. Update **Secret Token** in Entra ID (without stopping provisioning)
4. Restart services: `make load-secrets && make restart`

---

## 📚 References

- [RFC 7644 - SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- [RFC 7643 - SCIM Core Schema](https://datatracker.ietf.org/doc/html/rfc7643)
- [Microsoft Entra ID SCIM Documentation](https://learn.microsoft.com/en-us/azure/active-directory/app-provisioning/use-scim-to-provision-users-and-groups)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)

# Swiss Hiring Pack — Mini IAM Lab

> **Recipients**: Cloud Security / IAM Recruiters · Tech Leads · Hiring Managers  
> **Objective**: Facilitate technical candidate evaluation via Resume ↔ Repository mapping

---

## 📋 Overview

This document establishes direct correspondence between **skills listed on CV** and **technical evidence in this repository**. It allows recruiters to quickly validate candidate expertise on Azure technologies and cloud security.

---

## 🎯 Target Profile

**Target roles**:
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Identity & Access Management Specialist

**Location**: Romandy

**Experience**: 0-3 years in cloud security, continuous training in Azure/IAM

---

## 🔑 Mots-Clés Recruteurs (ATS-Friendly)

### Cloud & Azure
`Azure Key Vault` · `Azure Entra ID` · `Azure AD B2C` · `Managed Identity` · `Azure Monitor` · `Application Insights` · `Azure Policy` · `Azure App Service` · `Azure SQL Database` · `Azure Cache for Redis` · `Azure Front Door` · `Microsoft Defender for Cloud`

### IAM & Authentification
`SCIM 2.0` · `OpenID Connect (OIDC)` · `OAuth 2.0` · `PKCE` · `Multi-Factor Authentication (MFA)` · `Role-Based Access Control (RBAC)` · `JWT Validation` · `SSO (Single Sign-On)` · `Provisioning Automation` · `Joiner/Mover/Leaver (JML)`

### Sécurité & Conformité
`OWASP ASVS` · `nLPD` · `RGPD` · `FINMA` · `Non-Repudiation` · `Cryptographic Audit Trail` · `HMAC-SHA256` · `Secret Rotation` · `Zero Trust` · `Rate Limiting` · `Security Headers` · `TLS 1.3`

### DevSecOps
`CI/CD` · `GitHub Actions` · `pytest` · `Docker` · `Docker Compose` · `Nginx` · `Makefile` · `Infrastructure as Code` · `Secret Management` · `Health Checks` · `Monitoring`

### Standards & RFC
`RFC 7644 (SCIM 2.0)` · `RFC 7636 (PKCE)` · `RFC 6749 (OAuth 2.0)` · `RFC 7519 (JWT)` · `NIST 800-63B`

---

## 📊 Resume ↔ Repository Mapping

| CV Skill | Level | Repository Evidence | File/Command | Validation |
|---------------|--------|---------------------|------------------|------------|
| **Azure Key Vault** | ⭐⭐⭐⭐ | Full integration, automated rotation, dry-run | `make rotate-secret`<br>`scripts/load_secrets_from_keyvault.sh`<br>`scripts/rotate_secret.sh` | ✅ Functional |
| **SCIM 2.0** | ⭐⭐⭐⭐ | RFC 7644-compliant API, compliance tests | `app/api/scim.py`<br>`tests/test_api_scim.py`<br>`openapi/scim_openapi.yaml` | ✅ 300+ tests |
| **OIDC/OAuth 2.0** | ⭐⭐⭐⭐ | PKCE, MFA, RSA-SHA256 JWT validation | `app/api/auth.py`<br>`app/api/decorators.py`<br>`app/core/rbac.py` | ✅ JWT tests |
| **RBAC** | ⭐⭐⭐ | 3 granular roles (admin/operator/verifier) | `app/core/rbac.py`<br>`tests/test_core_rbac.py` | ✅ RBAC tests |
| **Audit Trail** | ⭐⭐⭐⭐ | HMAC-SHA256, non-repudiation, integrity verification | `scripts/audit.py`<br>`make verify-audit`<br>`.runtime/audit/jml-events.jsonl` | ✅ 22/22 valid signatures |
| **Secret Rotation** | ⭐⭐⭐ | Full orchestration, pre-deployment validation | `scripts/rotate_secret.sh`<br>`make rotate-secret-dry` | ✅ Dry-run OK |
| **DevSecOps** | ⭐⭐⭐ | CI/CD, 91% tests, secrets management | `.github/workflows/`<br>`Makefile` (30+ commands)<br>`pytest.ini` | ✅ 346 tests |
| **Python 3.12** | ⭐⭐⭐⭐ | Flask, pytest, type hints, async | All `.py` files<br>`requirements.txt` | ✅ Type-safe |
| **Docker** | ⭐⭐⭐ | Multi-service Compose, health checks, volumes | `docker-compose.yml`<br>`Dockerfile.flask` | ✅ 3 healthy services |
| **Nginx** | ⭐⭐⭐ | TLS 1.3, rate limiting, security headers | `proxy/nginx.conf`<br>`scripts/test_rate_limiting.sh` | ✅ Rate limit tests |
| **Compliance** | ⭐⭐⭐ | nLPD/GDPR/FINMA by design | `docs/THREAT_MODEL.md`<br>`docs/SECURITY_DESIGN.md` | ✅ Audited architecture |

**Legend**:  
⭐⭐⭐⭐ = Confirmed mastery (production-ready code)  
⭐⭐⭐ = Good knowledge (functional implementation)  
⭐⭐ = Basic understanding (documentation + tests)

---

## 🧪 Quick Validation (30 seconds)

### Option 1: Web Interface
```bash
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc
make quickstart  # 2 minutes
open https://localhost/verification  # Automatic tests
```

### Option 2: CLI
```bash
make test          # Unit tests (346 tests, 91% coverage)
make verify-audit  # HMAC signature verification
make doctor        # Azure + Docker health check
```

### Option 3: Code Review
Key files to examine (15 min):
- `app/api/scim.py` — SCIM RFC 7644 implementation
- `app/api/auth.py` — OIDC with PKCE
- `scripts/rotate_secret.sh` — Azure Key Vault rotation
- `Makefile` — Infrastructure as Code (30+ commands)

---

## 📈 Quality Metrics

| Indicator | Value | Target | Status |
|------------|--------|-------|--------|
| **Tests** | 346 | >200 | ✅ Exceeded |
| **Coverage** | 91% | >80% | ✅ Exceeded |
| **Azure Integration** | Key Vault + Entra ID Roadmap | Cloud-native | ✅ Operational |
| **Security Standards** | OWASP ASVS L2 | L1 minimum | ✅ Exceeded |
| **Documentation** | 10 docs/ files | 5 minimum | ✅ Complete |
| **Audit Trail** | 22/22 valid signatures | 100% | ✅ Perfect |

---

## Romandy Context

### Implemented Regulatory Compliance
- **nLPD (new Swiss Data Protection Act)**:
  - ✅ Timestamped audit trail with correlation-id
  - ✅ Personal data access traceability
  - ✅ Secure log retention (400 permissions)

- **GDPR**:
  - ✅ Consent tracked via audit trail
  - ✅ Right to be forgotten (soft-delete)
  - ✅ Portability (standard SCIM API)

- **FINMA (financial sector)**:
  - ✅ Non-repudiation via cryptographic signatures
  - ✅ Immutable audit log (tamper detection)
  - ✅ Evidence retention (immutable audit log)

### Valued Skills in Switzerland
1. **Azure Entra ID**: Microsoft cloud-native identity management
2. **SCIM 2.0 Provisioning**: Inter-enterprise IAM standard
3. **Compliance-by-design**: Architecture compliant from conception
4. **DevSecOps**: Automated tests, secret rotation, secure CI/CD
5. **Technical multilingualism**: FR/EN documentation, international standards

### Target Sectors
- **Finance** (Banks, Insurance): FINMA compliance, audit trail
- **Healthcare**: Strict nLPD/GDPR, traceability
- **Tech**: SaaS, Identity Providers, Cloud Security
- **Consulting**: Azure integration, Entra ID migrations

---

## 🎓 Training & Certifications (Recommended)

**Target Azure certifications**:
- [ ] **AZ-900**: Azure Fundamentals (foundation)
- [ ] **AZ-500**: Azure Security Engineer Associate (main target)
- [ ] **SC-300**: Microsoft Identity and Access Administrator (IAM focus)

**Complementary training**:
- OWASP Top 10 & ASVS
- SCIM 2.0 Protocol (RFC 7644)
- OAuth 2.0 & OIDC (RFC 6749, 6750, 7636)

---

## 📞 Frequently Asked Questions from Recruiters

### Q1: "Why Keycloak and not directly Entra ID?"
**A**: Pedagogical choice to demonstrate mastery of OIDC/MFA standards independently. The **Azure-native roadmap** is documented (Phase 1: Entra ID migration planned) with already compatible architecture.

### Q2: "Is the project production-ready?"
**A**: **Yes for security**, no for scalability:
- ✅ Azure Key Vault secrets management (production-grade)
- ✅ Non-repudiable cryptographic audit
- ✅ 91% tests, CI/CD, automated rotation
- ⚠️ SQLite → Azure SQL Database required for HA
- ⚠️ Local sessions → Azure Cache for Redis for distribution

### Q3: "What is the real Azure experience?"
**A**: **Learning project with functional implementation**:
- Operational Azure Key Vault integration (az cli, Python SDK)
- Understanding cloud-native architecture (Managed Identity, App Service, Monitor)
- Compliance-by-design approach (nLPD/GDPR/FINMA)
- **Seeking internship/apprenticeship** for large-scale production experience

### Q4: "Estimated ramp-up time?"
**A**: On existing Azure environment:
- **Week 1**: Familiarization with Entra ID, SCIM provisioning
- **Week 2-3**: API integration, conditional access policies
- **Month 2**: Autonomy on routine IAM (JML, MFA, RBAC)
- **Month 3-6**: Expertise on advanced topics (B2B/B2C, compliance audits)

### Q5: "Interview availability?"
**A**: Immediate. Notice period: none (active job search).

---

## 📂 Documentation Navigation

| Document | Audience | Content |
|----------|----------|---------|
| **[README.md](../README.md)** | All | General presentation, quickstart, roadmap |
| **[Hiring_Pack.md](Hiring_Pack.md)** | Recruiters | This document (Resume ↔ Repo mapping) |
| **[RBAC_DEMO_SCENARIOS.md](RBAC_DEMO_SCENARIOS.md)** | Tech Leads | Detailed JML workflows, user matrix, scenarios |
| **[SECURITY_DESIGN.md](SECURITY_DESIGN.md)** | CISO/SOC | Threat model, OWASP ASVS L2, protection |
| **[API_REFERENCE.md](API_REFERENCE.md)** | Engineers | SCIM endpoints, curl examples, error codes |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | DevOps | Azure App Service, CI/CD, monitoring |
| **[THREAT_MODEL.md](THREAT_MODEL.md)** | Security | Risk analysis, mitigations, audit |

---

## ✅ Technical Evaluation Checklist

**For HR recruiter** (5 minutes):
- [ ] Verify GitHub badges (tests, coverage, security)
- [ ] Consult Resume ↔ Repo mapping table
- [ ] Validate Azure Key Vault presence (production-ready)
- [ ] Verify nLPD/GDPR/FINMA compliance mentioned

**For Tech Lead** (30 minutes):
- [ ] Launch `make quickstart` → verify functional demo
- [ ] Test `/verification` page → validate automatic tests
- [ ] Examine `make rotate-secret-dry` → verify orchestration
- [ ] Code review `app/api/scim.py` → evaluate code quality
- [ ] Read `docs/SECURITY_DESIGN.md` → validate architecture

**For CISO** (1 hour):
- [ ] Audit trail: `make verify-audit` → 22/22 signatures OK
- [ ] Threat model: `docs/THREAT_MODEL.md` → identified risks
- [ ] Standards: OWASP ASVS L2, RFC 7644/7636, NIST 800-63B
- [ ] Compliance: nLPD (traceability), GDPR (portability), FINMA (non-repudiation)
- [ ] Roadmap: Entra ID migration, Managed Identity, Monitor

---

## 📧 Contact

**Candidate**: Alex (Romandy)  
**Email**: [See GitHub Profile](https://github.com/Alexs1004)  
**LinkedIn**: [To add if applicable]  
**Availability**: Immediate  
**Mobility**: Romandy

**Target roles**:
- Junior Cloud Security Engineer (Azure)
- IAM Engineer (Entra ID / SCIM)
- DevSecOps Cloud (Azure)
- Stage/Alternance Cloud Security

---

## 🙏 Why This Project?

This repository demonstrates my ability to:
1. **Design** a complete and auditable IAM system
2. **Implement** security standards (OWASP, RFC, NIST)
3. **Integrate** Azure services (Key Vault, Entra ID roadmap)
4. **Document** professionally (recruiters + engineers)
5. **Think compliance** from inception (nLPD, GDPR, FINMA)

**In summary**: I know how to build secure, auditable, and compliant cloud environments. I am now seeking to **apply these skills within a Romandy-based team**.
# Local SCIM Testing Guide

Purpose: verify the SCIM API locally (self-signed TLS) using curl.

## Prerequisites
- Stack running: `make quickstart` (or `make ensure-stack` if already built).
- `jq` and `curl` installed.
- Demo secrets loaded automatically by the stack (`automation-cli` client/secret).

## Retrieve the OpenAPI document
```bash
curl -sk https://localhost/openapi.json | jq '.info.title,.paths|length'
# Expect "IAM PoC SCIM 2.0 API" and path count
```

## Browse ReDoc
Open `https://localhost/scim/docs` in a browser (accept the self-signed certificate).

## Get a bearer token
```bash
# Service secret is loaded from .runtime/secrets/ in demo mode
SERVICE_SECRET=$(cat .runtime/secrets/keycloak-service-client-secret)

TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=$SERVICE_SECRET" \
  | jq -r '.access_token')
echo "${TOKEN:0:32}..."
```

**Note**: In demo mode, the service secret is auto-generated and stored in `.runtime/secrets/keycloak-service-client-secret`. In production, it's retrieved from Azure Key Vault.

## SCIM operations

### Create a user
```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "demo.scim",
    "name": {"givenName": "Demo", "familyName": "SCIM"},
    "emails": [{"value": "demo.scim@example.com", "primary": true}],
    "active": true
  }'
```

Capture the `id` from the response (e.g. store in `USER_ID`).

### Filter by userName
```bash
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22demo.scim%22" \
  -H "Authorization: Bearer $TOKEN" | jq '.Resources[] | {userName,active}'
```

### Disable the account (PATCH active=false)
```bash
curl -sk -X PATCH "https://localhost/scim/v2/Users/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{"op": "replace", "path": "active", "value": false}]
  }'
```

### Delete (soft-delete / disable)
```bash
curl -sk -X DELETE "https://localhost/scim/v2/Users/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" -i
```

## Audit verification
```bash
make verify-audit
tail -n 5 .runtime/audit/jml-events.jsonl
```
Expect signed events with `event_type` (`scim_create_user`, `scim_patch_user_active`, `scim_delete_user`).

## Troubleshooting
- `401 unauthorized`: token missing or expired → re-run token command.
- `403 forbidden`: token lacks `scim:write` or `scim:read` scope (check client configuration).
- `415 invalidSyntax`: ensure `Content-Type: application/scim+json`.
- `501 notImplemented`: PUT is disabled; use PATCH or DELETE instead.
- Review `docker compose logs flask-app` for stack errors.
# 🔐 RBAC Demo Scenarios — Joiner/Mover/Leaver Workflows

> **Objective**: Demonstrate RBAC mastery and IAM (JML) workflows for Cloud Security recruiters  
> **Audience**: HR Recruiters, Tech Leads, CISO, Hiring Managers

---

## 📊 Overview

This document details the **4 demo users** provisioned by `make demo` and the automated **JML scenarios** (Joiner/Mover/Leaver). It illustrates:
- **Privilege separation** (least privilege principle)
- **Cryptographic audit trail** (FINMA non-repudiation)
- **Real IAM workflows** used in enterprises

---

## 👥 User Matrix

### alice — Analyst → IAM Operator (Mover Scenario)

**Scenario**: Promotion from analyst to IAM operator (vertical movement)

| Attribute | Initial Value | Final Value |
|----------|-----------------|---------------|
| **Username** | `alice` | `alice` |
| **Role** | `analyst` | **`iam-operator`** ⬆️ |
| **Status** | ✅ Active | ✅ Active |
| **MFA** | ✅ TOTP required | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) | `Temp123!` (temporary) |
| **Admin UI Access** | ❌ 403 Forbidden | ✅ Full admin |
| **JML Operations** | ❌ None | ✅ Joiner/Mover/Leaver |

**JML Workflow**:
1. **Joiner**: Initial creation with `analyst` role
2. **Mover**: Promotion `analyst` → `iam-operator`
3. **Audit**: 2 HMAC-signed events in `/admin/audit`

**Manual Test**:
```bash
# 1. Login with alice (before promotion)
open https://localhost
# Username: alice | Password: Temp123!

# 2. Try to access admin dashboard (should fail)
open https://localhost/admin
# → Expected: 403 Forbidden page (analyst has no access)

# 3. After promotion (by joe), reconnect
# → alice can now access /admin with JML operations

# 4. Consult audit trail of her promotion
open https://localhost/admin/audit
# → Search for "joiner" (alice) + "mover" (alice) events
```

**Key Points**:
- ✅ Promotion without account re-creation (role migration)
- ✅ Existing sessions invalidated after mover
- ✅ Complete audit trail (creation + modification)
- ✅ **Strict access control**: analyst blocked before promotion (403), authorized after

---

### bob — Analyst → Disabled (Leaver Scenario)

**Scenario**: Employee departure (GDPR-compliant soft-delete)

| Attribute | Initial Value | Final Value |
|----------|-----------------|---------------|
| **Username** | `bob` | `bob` |
| **Role** | `analyst` | `analyst` (preserved) |
| **Status** | ✅ Active | ❌ **Disabled** |
| **MFA** | ✅ TOTP required | ✅ TOTP preserved |
| **Password** | `Temp123!` | `Temp123!` (preserved) |
| **Admin UI Access** | ❌ 403 Forbidden | ❌ Login impossible |
| **JML Operations** | ❌ None | ❌ None |

**JML Workflow**:
1. **Joiner**: Initial creation with `analyst` role
2. **Leaver**: Disablement (enabled=false)
3. **Audit**: 2 HMAC-signed events in `/admin/audit`

**Manual Test**:
```bash
# 1. Try to login with bob
open https://localhost
# Username: bob | Password: Temp123!
# → Expected: "Invalid username or password" (account disabled)

# 2. Verify status in admin UI (with alice/joe)
open https://localhost/admin
# → bob appears as "Disabled" (red badge)

# 3. Consult audit trail of his disablement
open https://localhost/admin/audit
# → Search for "leaver" event (bob)
```

**Key Points**:
- ✅ Soft-delete (data preserved, account inactive) ← **GDPR compliance**
- ✅ Keycloak sessions automatically revoked
- ✅ Reactivation possible via `/admin` (reversible)
- ✅ **Access control**: analyst already had no /admin access (403)

---

### carol — Manager (Stable Scenario)

**Scenario**: Stable user with read access (no JML operations)

| Attribute | Value |
|----------|--------|
| **Username** | `carol` |
| **Role** | `manager` |
| **Status** | ✅ Active |
| **MFA** | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) |
| **Admin UI Access** | ✅ Read-only |
| **JML Operations** | ❌ None |

**JML Workflow**:
1. **Joiner**: Creation with `manager` role
2. **Stable**: No modifications

**Manual Test**:
```bash
# 1. Login with carol
open https://localhost
# Username: carol | Password: Temp123!

# 2. Access admin dashboard (read-only)
open https://localhost/admin
# → No "Joiner", "Mover", "Leaver" buttons (read-only)

# 3. Access audit trail (read authorized)
open https://localhost/admin/audit
# → Can consult history, not modify it
```

**Key Points**:
- ✅ Read/write separation (least privilege principle)
- ✅ Audit trail access (compliance/monitoring)
- ✅ No privilege escalation possible via UI
- ✅ **Access control**: manager can read dashboard, analyst blocked (403)

---

### joe — IAM Operator + Realm Admin (Full Access)

**Scenario**: Complete IAM administrator (dual role)

| Attribute | Value |
|----------|--------|
| **Username** | `joe` |
| **Role** | `iam-operator` + `realm-admin` |
| **Status** | ✅ Active |
| **MFA** | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) |
| **Admin UI Access** | ✅ Full admin |
| **Keycloak Admin Access** | ✅ Full Keycloak console |
| **JML Operations** | ✅ Joiner/Mover/Leaver |

**JML Workflow**:
1. **Joiner**: Creation with `iam-operator` role
2. **Grant**: Assignment of `realm-admin` role (dual-role)
3. **Stable**: Permanent administrator account

**Manual Test**:
```bash
# 1. Login with joe
open https://localhost
# Username: joe | Password: Temp123!

# 2. Access admin dashboard (complete operations)
open https://localhost/admin
# → All JML buttons available

# 3. Access Keycloak Admin Console
open http://localhost:8080/admin/demo/console
# → joe can manage realm, clients, roles, users

# 4. Perform Joiner (create new user)
# → Fill form in /admin, assign "analyst" role
# → Verify in /admin/audit (signed "joiner" event)
```

**Key Points**:
- ✅ Dual role (IAM operator + Realm admin) = full control
- ✅ Keycloak console access (IdP infrastructure administration)
- ✅ Responsible for JML operations (operator traceability)

---

## 🔄 Detailed JML Workflows

### 1. Joiner (User Creation)

**Use case**: New employee joining the company

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Joiner" form
3. Fills:
   - Username (ex: `dave`)
   - Email, First name, Last name
   - Initial role (analyst/manager/iam-operator)
   - Options: ☑️ MFA required, ☑️ Update password on first login
4. Clicks "Create User"

**Backend (SCIM + Keycloak)**:
```python
# 1. SCIM API POST /Users
POST https://localhost/scim/v2/Users
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "dave",
  "name": {"givenName": "Dave", "familyName": "Smith"},
  "emails": [{"value": "dave@example.com", "primary": true}],
  "active": true
}

# 2. Keycloak API: Assign role + group
PUT /admin/realms/demo/users/{id}/role-mappings/realm
PUT /admin/realms/demo/users/{id}/groups/{iam-poc-managed-group-id}

# 3. Audit trail: Log event
{
  "event": "joiner",
  "username": "dave",
  "role": "analyst",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T10:30:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "joiner" event with username="dave"

# 2. Signature integrity
make verify-audit
# → Expected: Valid signature for "dave" event

# 3. New user login
open https://localhost
# Username: dave | Password: <temporary-provided> | MFA: Setup TOTP
```

---

### 2. Mover (Role Change)

**Use case**: Promotion, internal mobility, reorganization

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Mover" form
3. Selects:
   - User (ex: `alice`)
   - Current role (ex: `analyst`)
   - New role (ex: `iam-operator`)
4. Clicks "Change Role"

**Backend (Keycloak)**:
```python
# 1. Keycloak API: Remove old role
DELETE /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "analyst"}]

# 2. Keycloak API: Assign new role
POST /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "iam-operator"}]

# 3. Keycloak API: Revoke existing sessions
DELETE /admin/realms/demo/users/{alice-id}/sessions

# 4. Audit trail: Log event
{
  "event": "mover",
  "username": "alice",
  "from_role": "analyst",
  "to_role": "iam-operator",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T11:00:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "mover" event with from_role="analyst", to_role="iam-operator"

# 2. User reconnection (new session with new role)
open https://localhost
# Username: alice | Password: Temp123!
# → Verify that /admin now shows JML buttons

# 3. Signature integrity
make verify-audit
```

---

### 3. Leaver (User Disablement)

**Use case**: Employee departure, disciplinary suspension, long-term leave

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Leaver" form
3. Selects user (ex: `bob`)
4. Clicks "Disable User"

**Backend (SCIM + Keycloak)**:
```python
# 1. SCIM API PATCH /Users/{id}
PATCH https://localhost/scim/v2/Users/{bob-id}
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    }
  ]
}

# 2. Keycloak API: Set enabled=false
PUT /admin/realms/demo/users/{bob-id}
Body: {"enabled": false}

# 3. Keycloak API: Revoke all sessions
DELETE /admin/realms/demo/users/{bob-id}/sessions

# 4. Audit trail: Log event
{
  "event": "leaver",
  "username": "bob",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T12:00:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "leaver" event with username="bob"

# 2. Login attempt (should fail)
open https://localhost
# Username: bob | Password: Temp123!
# → Expected: "Invalid username or password"

# 3. Reactivation possible (soft-delete)
# → From /admin (with joe), "Reactivate" button on bob
# → After reactivation, bob can login again
```

---

## 🛡️ Security & Compliance

### Anti-Abuse Protection

| Scenario | Protection | Implementation |
|----------|-----------|----------------|
| **Self-modification** | User cannot modify their own account | `if username.lower() == current_username().lower(): abort(403)` |
| **Privilege escalation** | Manager cannot self-promote to realm-admin | Operator role verification in `@require_jml_operator` |
| **Admin deactivation** | Operator cannot disable their own account | Explicit check before leaver operation |
| **Realm-admin modification** | Only realm-admin can modify other realm-admins | `requires_operator_for_roles()` check |

### Cryptographic Audit Trail

**HMAC-SHA256 Signature**:
```python
import hmac
import hashlib

# 1. Canonical payload
canonical = f"{event}:{username}:{timestamp}:{correlation_id}"

# 2. Signing key (Azure Key Vault in prod)
signing_key = os.getenv("AUDIT_LOG_SIGNING_KEY")  # 64+ bytes

# 3. Signature
signature = hmac.new(
    signing_key.encode(),
    canonical.encode(),
    hashlib.sha256
).hexdigest()

# 4. Signed event
{
  "event": "joiner",
  "username": "dave",
  "signature": signature,
  ...
}
```

**Verification**:
```bash
make verify-audit
# Output:
# ✓ Event 1/22: signature valid (joiner, alice)
# ✓ Event 2/22: signature valid (joiner, bob)
# ...
# ✓ All 22 signatures valid
```

### Swiss Compliance

| Requirement | Implementation | Proof |
|----------|----------------|--------|
| **nLPD (Traceability)** | Timestamped audit trail for all operations | `/admin/audit` (ISO 8601 timestamps) |
| **GDPR (Right to be forgotten)** | Reversible soft-delete (enabled=false) | `PATCH /scim/v2/Users/{id}` with active=false |
| **FINMA (Non-repudiation)** | Non-falsifiable HMAC-SHA256 signatures | `make verify-audit` (22/22 valid) |

---

## 🧪 Automated Tests

### RBAC Unit Tests

```bash
# 1. Authorization tests
pytest tests/unit/test_core_rbac.py -v

# Coverage:
# ✓ test_user_has_role
# ✓ test_requires_operator_for_roles
# ✓ test_filter_display_roles
# ✓ test_collect_roles_from_access_token
```

### JML Integration Tests

```bash
# 1. Complete workflow tests
pytest tests/integration/test_admin_ui_helpers.py -v

# Coverage:
# ✓ test_ui_create_user (joiner)
# ✓ test_ui_change_role (mover)
# ✓ test_ui_disable_user (leaver)
# ✓ test_ui_set_user_active (reactivate)
```

### Audit Trail Tests

```bash
# 1. Cryptographic signature tests
pytest tests/unit/test_audit.py -v

# Coverage:
# ✓ test_log_jml_event_creates_file
# ✓ test_verify_audit_log_all_valid
# ✓ test_verify_audit_log_detects_tampering
```

---

## 🔗 References

- **[README.md](../README.md)** — Swiss positioning, quick start
- **[Hiring Pack](Hiring_Pack.md)** — CV ↔ Repo mapping for recruiters
- **[Security Design](SECURITY_DESIGN.md)** — OWASP ASVS L2, nLPD/GDPR/FINMA
- **[API Reference](API_REFERENCE.md)** — SCIM 2.0 endpoints, OAuth scopes
- **[Threat Model](THREAT_MODEL.md)** — STRIDE analysis, FINMA compliance

---

## 💡 For Recruiters: What This Demonstrates

### Technical Skills
- ✅ **Advanced RBAC** : 4 role levels, privilege separation
- ✅ **IAM Workflows** : Complete Joiner/Mover/Leaver automation
- ✅ **Cryptographic Audit** : HMAC-SHA256, non-repudiation
- ✅ **SCIM 2.0** : Standardized API (RFC 7644)
- ✅ **OIDC/MFA** : Modern authentication (PKCE, TOTP)

### Security & Compliance
- ✅ **Swiss Compliance** : nLPD, GDPR, FINMA by design
- ✅ **Least Privilege Principle** : Read-only vs. write access separation
- ✅ **Anti-Abuse Protection** : Self-modification blocked
- ✅ **Auditability** : Every action signed + timestamped
- ✅ **90% Test Coverage** : Verifiable quality

### Swiss Market Positioning
- **Finance** : FINMA compliance (non-repudiation, audit trail)
- **Healthcare** : Strict nLPD (traceability, soft-delete)
- **Tech/SaaS** : Modern IAM (SCIM, OIDC, automation)
- **Consulting** : Keycloak → Azure Entra ID migration path (Azure-native roadmap)

**Summary** : This project demonstrates **complete operational mastery of IAM standards** in an **Azure-first context** compliant with **Swiss requirements**. Ideal for **Junior Cloud Security Engineer (Azure)**, **IAM Engineer**, **DevSecOps Cloud** roles in Romandy.

# 📚 Documentation Hub — Mini IAM Lab

> **Smart navigation**: Documentation organized by profile (Recruiters · Security · DevOps)

---

## 🎯 For Recruiters & HR Screening

**Reading time: 5-10 minutes**

| Document | Objective | Audience |
|----------|----------|--------|
| **[Swiss Hiring Pack](Hiring_Pack.md)** | Resume ↔ Repo mapping, ATS keywords, quick validation | HR Recruiters, Hiring Managers |
| **[RBAC Demo Scenarios](RBAC_DEMO_SCENARIOS.md)** | Detailed Joiner/Mover/Leaver workflows, RBAC matrix, manual tests | HR Recruiters, Tech Leads |
| **[Main README](../README.md)** | Cloud Security Engineer positioning (Swiss), 2-min start | All (initial screening) |

**What recruiters should remember**:
- **Azure Entra ID SCIM 2.0 provisioning** (production-ready, RFC 7644 compliant)
- Operational Azure Key Vault (production-ready secrets management)
- Swiss compliance: nLPD, GDPR, FINMA (non-repudiable audit trail)
- 346 automated tests, 91% coverage (verifiable code quality)
- Security pipeline: Gitleaks, Trivy, Syft, Grype (CI/CD + local)
- Azure-native integration: Entra ID SCIM provisioning operational

---

## 🔐 For Security Engineers & CISO

**Reading time: 30-60 minutes**

| Document | Content | Standards |
|----------|---------|-----------|
| **[Security Design](SECURITY_DESIGN.md)** | Implemented controls, threat mitigation, secrets management | OWASP ASVS L2, nLPD, GDPR |
| **[Security Scanning](SECURITY_SCANNING.md)** | Gitleaks, Trivy, Syft, Grype (local + CI/CD), troubleshooting | NIST SP 800-190, EO 14028 |
| **[Threat Model](THREAT_MODEL.md)** | STRIDE analysis, MITRE ATT&CK, FINMA compliance | RFC 7644, NIST 800-63B |
| **[API Reference](API_REFERENCE.md)** | SCIM endpoints, OAuth authentication, rate limiting | RFC 7644, RFC 6749 |

**Key security points**:
- **AuthN/AuthZ**: OAuth 2.0 Bearer tokens, PKCE, MFA enforcement
- **Audit Trail**: HMAC-SHA256 signatures (non-repudiation), `make verify-audit`
- **Secrets**: Azure Key Vault (prod), automated rotation (`make rotate-secret`)
- **Transport**: TLS 1.3, HSTS, CSP, Secure/HttpOnly cookies
- **Security Scanning**: Gitleaks (secrets), Trivy (CVE), Syft (SBOM), Grype (vulnerabilities)
- **Compliance**: nLPD (traceability), GDPR (portability), FINMA (non-repudiation)

---

## 🛠️ For DevOps & Cloud Engineers

**Reading time: 45-90 minutes**

| Document | Content | Technologies |
|----------|---------|--------------|
| **[Deployment Guide](DEPLOYMENT_GUIDE.md)** | Azure App Service, Key Vault, Managed Identity, CI/CD | Azure, Docker, Nginx |
| **[Testing Guide](TESTING.md)** | Test strategy, coverage, CI/CD workflow, troubleshooting | pytest, coverage, xdist |
| **[Local SCIM Testing](LOCAL_SCIM_TESTING.md)** | Local tests, curl examples, troubleshooting | SCIM 2.0, OAuth 2.0 |

**Key commands**:
```bash
make quickstart              # 2-minute demo start
make doctor                  # Azure + Docker health check
make test-all                # Full suite (346 tests, 91% coverage)
make test-coverage           # Tests with HTML coverage report
make test-coverage-vscode    # Open report in VS Code
make verify-audit            # HMAC signature verification
make rotate-secret-dry       # Key Vault rotation simulation
make security-check          # Run all security scans
make scan-secrets            # Detect exposed secrets (Gitleaks)
make scan-vulns              # Scan HIGH/CRITICAL CVE (Trivy)
```

**Code coverage workflow**:
- `make test-coverage`: Runs all tests and generates `htmlcov/index.html`
- `make test-coverage-report`: Shows viewing options
- `make test-coverage-vscode`: Opens report in VS Code (recommended)
- `make test-coverage-open`: Attempts to open in system browser
- `make test-coverage-serve`: Starts HTTP server on `localhost:8888`

---

## 📋 Références Techniques (Core References)

| Document | Description |
|----------|-------------|
| [Security Scanning](SECURITY_SCANNING.md) | Gitleaks, Trivy, Syft, Grype — Guide complet local + CI/CD |
| [API Reference](API_REFERENCE.md) | Endpoints SCIM 2.0, OAuth, OpenAPI spec |
| [Security Design](SECURITY_DESIGN.md) | Contrôles sécurité, OWASP ASVS L2, threat mitigation |
| [Threat Model](THREAT_MODEL.md) | Analyse STRIDE, MITRE ATT&CK, conformité Swiss |
| [Deployment Guide](DEPLOYMENT_GUIDE.md) | Azure Key Vault, Managed Identity, App Service |
| [Testing Guide](TESTING.md) | Stratégie de test, couverture 91%, workflow CI/CD |
| [Local SCIM Testing](LOCAL_SCIM_TESTING.md) | Tests curl, troubleshooting, exemples |
| [RBAC Demo Scenarios](RBAC_DEMO_SCENARIOS.md) | Workflows JML complets, matrice utilisateurs, tests manuels |

---

## 🧪 Validation Interactive (UI Verification)

**Accès** : `https://localhost/verification` (après `make quickstart`)

| Test | Action UI |
|-------|-----------|
| OpenAPI responds 200 | `/verification` → **Check OpenAPI** |
| OAuth unauthenticated yields 401 | `/verification` → **Check OAuth 401** |
| Wrong media type returns 415 | `/verification` → **Check Media Type** |
| PATCH active toggle is idempotent (200/200) | `/verification` → **Check PATCH Idempotence** |
| PUT returns 501 with guidance message | `/verification` → **Check PUT 501** |
| Security headers enforced | `/verification` → **Check Security Headers** |

## Navigation
- [Documentation Hub (this page)](README.md)
- [Main README](../README.md)

## 📖 Glossary

| Term | Definition |
|------|------------|
| **SCIM Resource** | JSON representation of identity data (User, Group) conforming to RFC 7644 |
| **JWKS** | JSON Web Key Set - public keys used to verify JWT signatures |
| **Managed Identity** | Azure AD identity for Azure resources, eliminates credential management |
| **PKCE** | Proof Key for Code Exchange - OAuth security extension for public clients |
| **Bearer Token** | OAuth access token passed in Authorization header: `Bearer <token>` |
| **JML** | Joiner-Mover-Leaver - IAM workflow for user lifecycle management |
| **HMAC-SHA256** | Hash-based Message Authentication Code for audit log integrity |
| **OIDC** | OpenID Connect - identity layer on top of OAuth 2.0 |
| **CSP** | Content Security Policy - browser security header preventing XSS |
| **HSTS** | HTTP Strict Transport Security - enforces HTTPS connections |

## ✅ Quick Validation Checklist

```bash
# 1. Environment health check
make doctor

# 2. Unauthenticated SCIM access should return 401
curl -k https://localhost/scim/v2/Users
# Expected: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401",...}

# 3. Wrong content type should return 415
curl -k -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
# Expected: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"415",...}

# 4. Audit log integrity
make verify-audit
# Expected: ✅ All audit signatures valid

# 5. Rate limiting protection
for i in {1..12}; do curl -k https://localhost/verification; done
# Expected: First ~6 requests succeed, then 429 Too Many Requests
```
# Security Operations (SecOps)

## MFA Conditional Access Strategy

### Overview

The application implements a **Zero Trust Conditional Access** guard for privileged endpoints (`/admin/*`).
When enabled, it verifies that the user authenticated with Multi-Factor Authentication (MFA).

**Implementation**: [`app/flask_app.py`](../app/flask_app.py) — `require_mfa()` decorator

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `REQUIRE_MFA` | `false` | Enable MFA enforcement on `/admin/*` routes |

### How It Works

1. **Check `amr` claim**: The OIDC ID token contains an `amr` (Authentication Methods References) claim
2. **Validate MFA method**: Accepted methods: `mfa`, `otp`, `hwk`, `swk`, `pop`, `fido`
3. **Permissive fallback**: If `amr` claim is missing, access is allowed (IdP may not provide it)
4. **403 Forbidden**: If `amr` exists but contains no MFA method → access denied

### Token Claims Example

```json
{
  "sub": "user123",
  "amr": ["pwd", "mfa"],
  "iat": 1734567890,
  "exp": 1734571490
}
```

### Enabling MFA Enforcement

```bash
# .env
REQUIRE_MFA=true
```

### Azure Entra ID Conditional Access

To enforce MFA at the IdP level (recommended):

1. **Azure Portal** → Entra ID → Security → Conditional Access
2. Create new policy:
   - **Assignments**: Target users/groups (e.g., `demo-admins`)
   - **Cloud apps**: Select your App Registration
   - **Conditions**: Any device, any location
   - **Grant**: Require MFA
3. Enable policy → **On**

This ensures the `amr` claim contains `mfa` or `otp` when users access protected apps.

### Keycloak MFA Configuration

For Keycloak (local development):

1. **Realm Settings** → Authentication → Required Actions
2. Enable **Configure OTP** as default action
3. Users must configure TOTP on first login

### Security References

- [RFC 8176: Authentication Method Reference Values](https://datatracker.ietf.org/doc/html/rfc8176)
- [Azure AD amr claim](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [NIST 800-63B: Authentication Assurance](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Testing

```bash
# Run MFA guard tests
pytest -k mfa_guard -q

# Expected: all tests pass
```

---

## Additional Security Topics

- [Security Design](SECURITY_DESIGN.md) — OWASP ASVS L2 controls
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis
- [Security Scanning](SECURITY_SCANNING.md) — Gitleaks, Trivy, SBOM
# Security Design — Mini IAM Lab

> **Swiss Compliance Positioning**: nLPD, GDPR, FINMA compliant architecture  
> **Standards**: OWASP ASVS L2, RFC 7644 (SCIM 2.0), RFC 6749 (OAuth 2.0), NIST 800-63B

Authoritative view of the security controls implemented in this SCIM PoC. Derived from `app/api/*`, `app/core/*`, `app/flask_app.py`, `proxy/nginx.conf`, and tests under `tests/test_api_*`.

---

## Swiss Compliance Context

### nLPD (new Swiss Data Protection Act)
- **Traceability**: HMAC-SHA256 audit trail with ISO 8601 timestamps
- **Retention**: Logs with restrictive permissions (400), planned rotation
- **Transparency**: SCIM API for data portability

### GDPR (General Data Protection Regulation)
- **Right to erasure**: Soft-delete via `PATCH .../Users/{id}` (`active=false`)
- **Portability**: JSON export via `GET /scim/v2/Users` (RFC 7644 standard)
- **Consent**: Audit log traces all modifications (`jml-events.jsonl`)

### FINMA (Swiss Financial Market Supervisory Authority)
- **Non-repudiation**: HMAC-SHA256 signatures on each JML event
- **Integrity**: Tampering detection via `make verify-audit`
- **Auditability**: Correlation-ID, timestamps, actor tracking

---

## 🚨 Known TODO (Temporary Scope Bypass)

**Current**: `automation-cli` service account is allowed without explicit scopes (`is_service_account` check in `app/api/scim.py`).  
**Intent**: Will be removed once service client scopes are finalized in Keycloak configuration.  
**Mitigation**: Service account tokens are still validated for signature, issuer, and expiration.

## Guiding principles
- Secrets never live in the repo (`/run/secrets`, Azure Key Vault in production).
- Every SCIM call must authenticate (OAuth bearer token).
- Audit trail must be tamper-evident (HMAC-SHA256 per event).
- HTTP surface hardened with TLS 1.2+, HSTS, CSP, and secure cookies.
- Minimal scope exposure: `scim:read` vs `scim:write` enforced per verb.

## Implemented controls
| Category | Control | Evidence |
|----------|---------|----------|
| Transport | TLS 1.2/1.3, HSTS (1y), CSP deny-all | `proxy/nginx.conf` |
| AuthN | OAuth 2.0 bearer (`Authorization: Bearer …`) | `app/api/scim.py` before_request |
| AuthZ | Scope checks (`scim:read`, `scim:write`) | `app/api/scim.py` lines 70-110 |
| Service account bypass | `automation-cli` allowed even without scopes (temporary) | `app/api/scim.py` (`is_service_account`) |
| Input validation | Content-Type enforcement (`application/scim+json`), schema checks | `app/api/scim.py::validate_request`, `patch_user` |
| Filtering guard | Only `userName eq "value"` accepted | `app/core/provisioning_service.list_users_scim` |
| Secrets | `/run/secrets` + Azure Key Vault loader | `app/core/provisioning_service._load_secret_from_file`, `settings.service_client_secret_resolved` |
| Password security | Temp passwords NEVER returned in API/UI (production) | RFC 7644 § 7.7, `app/core/keycloak.send_password_reset_email` |
| Password reset | Keycloak native flow (secure token + email) | NIST SP 800-63B § 5.1.1.2, OWASP ASVS V2.1.12 |
| Audit | `scripts/audit.log_jml_event` HMAC signature + chmod 600 | `scripts/audit.py` |
| CSRF/UI hardening | CSRF tokens for admin UI, cookies `Secure`/`HttpOnly`/`SameSite=Lax` | `app/flask_app.py::_register_middleware` |
| Session security | Flask session secret key with rotation support (SECRET_KEY_FALLBACKS) | `app/flask_app.py:35-43` |

## Threat considerations
- **Bearer theft**: tokens are required on every request; expired/invalid tokens yield 401 with SCIM error payload.
- **Scope abuse**: write methods refuse tokens missing `scim:write`. Service account exception noted above; rotate secrets regularly.
- **Payload tampering**: PATCH handler only allows `replace active` with boolean value; malformed JSON returns 400.
- **Password exposure** ✅ **OWASP A07:2021 / RFC 7644 § 7.7**: Temporary passwords NEVER returned in SCIM responses or UI flash messages in production mode (`DEMO_MODE=false`). Demo mode displays passwords with prominent warning (`⚠️ DEMO MODE`). Production uses email-based password reset links. **Test**: `tests/unit/test_admin_password_security.py` validates no leakage.
- **Audit repudiation** ✅ **nLPD/FINMA compliance**: each JML event is signed with HMAC-SHA256; `make verify-audit` recomputes hashes to detect tampering (non-repudiation requirement for financial sector).
- **Secrets leakage**: production mode loads secrets from Azure Key Vault (soft-delete + purge protection recommended). Demo mode generates ephemeral secrets (printed to stdout).
- **Rate limiting**: not applied in code; rely on reverse proxy/WAF (TODO: add nginx `limit_req` or App Gateway policy).
- **Data portability** ✅ **RGPD compliance**: SCIM standard enables data export via `GET /Users` (RFC 7644).
- **Right to erasure** ✅ **RGPD compliance**: Soft-delete via `PATCH .../Users/{id}` with `active=false` (reversible, audit-logged).

## Error handling model
`ScimError` guarantees RFC 7644 compliant responses:
- Body always includes `schemas`, `status`, `detail`, optional `scimType`.
- Common detail strings:
  - Missing header → `"Authorization header missing. Provide 'Authorization: Bearer <token>'."`
  - Wrong scheme → `"Authorization header must use Bearer token scheme: 'Authorization: Bearer <token>'."`
  - Empty token → `"Bearer token is empty."`
  - Wrong media type → `"Content-Type must be application/scim+json"`
  - Unimplemented feature → `"Requested SCIM feature is not available in this PoC."`

## Open gaps / TODO
- Remove service-account scope bypass once Keycloak client scopes are configured.
- Add automated rate limiting / WAF rules for SCIM endpoints.
- **Swiss Compliance Roadmap** :
  - [ ] Archive audit logs to Azure Blob Storage with immutability policy (nLPD retention)
  - [ ] Implement GDPR data subject access request (DSAR) endpoint
  - [ ] Add audit log export to SIEM (Azure Sentinel) for FINMA compliance
  - [ ] Document data residency strategy (Swiss data center availability)

---

## 🔗 Related Documentation
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis, MITRE ATT&CK mapping
- [API Reference](API_REFERENCE.md) — SCIM 2.0 endpoints, OAuth scopes
- [Deployment Guide](DEPLOYMENT_GUIDE.md) — Azure Key Vault, Managed Identity
- [Swiss Hiring Pack](Hiring_Pack.md) — CV ↔ Repo skills mapping
- Extend audit shipping to immutable storage (Azure Blob immutability policy).
- Instrument Flask with OpenTelemetry/App Insights for centralised monitoring.

## 🎓 Why This Matters (Security Learning)

### Minimal Scope Principle (OWASP / NIST)
- **read vs write segregation**: Prevents privilege escalation - listing users doesn't grant modification rights
- **Service account isolation**: Dedicated client for automation, separate from user accounts

### Secret Rotation & Management
- **Azure Key Vault**: Centralized secret storage with access policies and audit trail
- **No secrets in repo**: Development secrets auto-generated, production secrets externally managed

### Defense in Depth
- **Multiple layers**: TLS (transport) + OAuth (application) + RBAC (business logic)
- **Fail secure**: Invalid tokens → 401, wrong content type → 415, unsupported operations → 501

## Verification checklist
- `make load-secrets` (Azure) → `/run/secrets/*` populated.
- `make verify-audit` → tamper check succeeds.
- `pytest tests/test_scim_oauth_validation.py` → confirms OAuth failures/successes.
- `pytest tests/unit/test_admin_password_security.py` → validates password security.
- `curl` without `Authorization` → `401 unauthorized` SCIM error.
- `curl -H "Content-Type: application/json"` on POST → `415 invalidSyntax`.

---

## 🔐 Password Management Architecture

### Design Decision: Keycloak Native Flow

**We use Keycloak's `execute-actions-email` endpoint instead of custom token generation.**

**Rationale**:
- ✅ **Security**: Keycloak is SOC2/ISO 27001 certified, audited by security experts
- ✅ **Standards**: Implements NIST SP 800-63B password reset guidelines
- ✅ **Crypto**: Uses cryptographically secure token generation (256 bits entropy)
- ✅ **Maintenance**: Zero custom crypto code to maintain
- ✅ **Audit**: Built-in event logging (who reset password, when, from where)
- ✅ **One-time use**: Tokens automatically invalidated after use
- ✅ **Expiration**: Default 5-minute token lifetime (configurable)

**Compliance**:
- **OWASP ASVS V2.1.12**: Password reset via secure tokenized link
- **RFC 7644 § 7.7**: "The password attribute MUST NOT be returned by default"
- **NIST SP 800-63B § 5.1.1.2**: Reset via out-of-band channel (email)

### Production Flow

```
1. Admin creates user via UI (/admin/joiner)
   ↓
2. provisioning_service.create_user_scim_like()
   ├── Creates user in Keycloak (temporary=True)
   ├── If DEMO_MODE=false:
   │   └── Calls keycloak.send_password_reset_email()
   │       ├── Keycloak generates secure token
   │       ├── Sends email with reset link
   │       └── Logs event in Keycloak audit trail
   └── Returns SCIM User (no _tempPassword field)
   ↓
3. User receives email:
   Subject: Welcome to IAM Platform - Set Your Password
   Link: https://keycloak.domain.com/.../reset-credentials?key=<TOKEN>
   ↓
4. User clicks → Keycloak reset password page
   ↓
5. User sets password → redirect to /auth/login
```

### Demo Mode (Local Testing)

```
1. Admin creates user via UI
   ↓
2. If DEMO_MODE=true:
   ├── Password included in SCIM response (_tempPassword field)
   ├── Flash message: "⚠️ DEMO MODE: Temporary password: XYZ"
   └── Red warning banner in UI
```

**Security Safeguards**:
- ⚠️ Default `.env.production` has `DEMO_MODE=false`
- ⚠️ Automated tests verify password NOT in response when `DEMO_MODE=false`
- ⚠️ Visual warning banner in UI when demo mode active

### SMTP Configuration

Password reset emails require SMTP configuration in Keycloak:

**Via Keycloak Admin Console**:
1. Realm Settings → Email
2. Configure:
   - From: `noreply@domain.com`
   - Host: `smtp.office365.com` (or Gmail, SendGrid, etc.)
   - Port: `587`
   - Enable StartTLS: ✅
   - Enable Authentication: ✅
   - Username: SMTP user
   - Password: SMTP password

**Via Script**:
```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=noreply@example.com
export SMTP_PASSWORD='app-specific-password'
python scripts/configure_smtp.py
```

**Test**:
```bash
# Set production mode
echo "DEMO_MODE=false" >> .env

# Create user via UI
# → User should receive email with reset link
```

### Error Handling

If email delivery fails:
- User is still created in Keycloak
- SCIM response includes `meta.emailDeliveryFailed=true`
- Admin can manually send reset email via Keycloak Admin UI:
  - Users → Select user → Actions → Send Reset Email

### Implementation

**Core function** (`app/core/keycloak/users.py`):
```python
def send_password_reset_email(kc_url, token, realm, user_id, redirect_uri):
    """Trigger Keycloak to send password reset email."""
    response = requests.put(
        f"{kc_url}/admin/realms/{realm}/users/{user_id}/execute-actions-email",
        headers={"Authorization": f"Bearer {token}"},
        json=["UPDATE_PASSWORD"],
        params={"redirect_uri": redirect_uri, "client_id": "flask-app"}
    )
    response.raise_for_status()
```

**Used by** (`app/core/provisioning_service.py`):
```python
def create_user_scim_like(payload, correlation_id=None):
    # ... create user in Keycloak ...
    
    if DEMO_MODE:
        scim_user["_tempPassword"] = temp_password
    else:
        send_password_reset_email(KEYCLOAK_BASE_URL, token, KEYCLOAK_REALM, user_id)
    
    return scim_user
```

**Test coverage**:
- `tests/unit/test_admin_password_security.py::test_joiner_no_password_in_flash_when_production_mode`
- `tests/unit/test_admin_password_security.py::test_joiner_password_visible_in_demo_mode`


# 🔐 Security Scanning Guide

This project includes comprehensive security scanning tools integrated in both **local development** (via Makefile) and **CI/CD** (GitHub Actions).

## 📋 Available Tools

| Tool | Purpose | Standards |
|------|---------|-----------|
| **Gitleaks** | Secret detection | Prevent API keys, tokens leaks |
| **Trivy** | CVE scanning | NIST SP 800-190 |
| **Syft** | SBOM generation | Executive Order 14028 |
| **Grype** | Vulnerability analysis | OWASP ASVS v4.0.3 |

---

## 🖥️ Local Scanning (Makefile)

### Quick Start

```bash
# Run all security scans
make security-check

# Run individual scans
make scan-secrets      # Detect secrets (Gitleaks)
make scan-vulns        # Check CVEs (Trivy)
make sbom              # Generate SBOM (Syft)
make scan-sbom         # Scan SBOM vulnerabilities (Grype)
```

### Detailed Commands

#### **Scan for Secrets** (Gitleaks)
```bash
make scan-secrets
```
- **Detects**: API keys, tokens, passwords, private keys
- **Configuration**: `.gitleaks.toml`
- **Allowlist**: Demo files (`.env.demo`), test fixtures, `venv/`
- **Exit code**: `0` if no leaks, `1` if found

**Example output:**
```
[scan-secrets] Scanning for secrets with Gitleaks...
8:28AM INF scanned ~4.36 MB in 192ms
8:28AM INF no leaks found
[scan-secrets] ✅ No secrets found
```

---

#### **Scan for Vulnerabilities** (Trivy)
```bash
make scan-vulns          # Requirements.txt only (fast)
make scan-vulns-all      # Entire project (slower)
```
- **Detects**: CVE in Python packages
- **Severity**: HIGH, CRITICAL (blocks build)
- **Database**: Updated daily from NVD + GitHub Advisory
- **Exit code**: `0` if clean, `1` if HIGH/CRITICAL found

**Example output:**
```
[scan-vulns]  Scanning for vulnerabilities with Trivy...
┌──────────────────┬──────┬─────────────────┐
│      Target      │ Type │ Vulnerabilities │
├──────────────────┼──────┼─────────────────┤
│ requirements.txt │ pip  │        0        │
└──────────────────┴──────┴─────────────────┘
[scan-vulns] ✅ No HIGH/CRITICAL vulnerabilities found
```

---

#### **Generate SBOM** (Syft)
```bash
make sbom
```
- **Formats**: SPDX-JSON + CycloneDX-JSON
- **Output**: `.runtime/sbom/`
- **Compliance**: Executive Order 14028 (SBOM requirement)
- **Size**: ~400KB (SPDX), ~245KB (CycloneDX)

**Example output:**
```
[sbom] Generating SBOM with Syft...
[sbom] ✅ SBOM generated:
    • .runtime/sbom/sbom-spdx.json (SPDX format)
    • .runtime/sbom/sbom-cyclonedx.json (CycloneDX format)
```

---

#### **Scan SBOM** (Grype)
```bash
make scan-sbom
```
- **Input**: SBOM generated by Syft
- **Detects**: Vulnerabilities in all dependencies
- **Fail on**: CRITICAL severity
- **Database**: NVD + OSV + GitHub Advisory

**Example output:**
```
[scan-sbom] Scanning SBOM with Grype...
NAME          INSTALLED  FIXED IN  TYPE    VULNERABILITY        SEVERITY
authlib       1.6.5      -         python  -                    -
cryptography  43.0.1     -         python  -                    -
[scan-sbom] ✅ No CRITICAL vulnerabilities in SBOM
```

---

## 🤖 CI/CD Integration (GitHub Actions)

### Workflow: `.github/workflows/security-scans.yml`

**Triggers:**
- Push to `main`, `develop`, `feature/*`, `entra/*`
- Pull requests to `main`, `develop`
- Weekly schedule (Monday 00:00 UTC)

**Jobs:**

1. **trivy-scan** (Trivy CVE scanning)
   - Scans filesystem, `requirements.txt`, `Dockerfile.flask`
   - Uploads SARIF to GitHub Security tab
   - Fails on HIGH/CRITICAL vulnerabilities

2. **gitleaks-scan** (Secret detection)
   - Scans full Git history
   - Uploads report as artifact on failure

3. **sbom-generation** (Syft SBOM + Grype scan)
   - Generates SBOM (SPDX + CycloneDX)
   - Scans with Grype
   - Uploads SBOM as artifacts

4. **dependency-review** (GitHub native, PR only)
   - Compares dependencies vs base branch
   - Blocks on `moderate` or higher
   - Rejects GPL-2.0/GPL-3.0 licenses

5. **security-summary** (Aggregated results)
   - Displays all scan statuses
   - Adds summary to PR

---

## 🚨 Handling Failures

### **Gitleaks finds secrets**

1. **Verify if false positive**:
   ```bash
   # Check detection
   docker run --rm -v $(pwd):/path ghcr.io/gitleaks/gitleaks:latest detect \
     --source /path --config /path/.gitleaks.toml --no-git --verbose
   ```

2. **Add to allowlist** (if legitimate demo/test data):
   ```toml
   # .gitleaks.toml
   [allowlist]
   paths = [
       '''tests/fixtures/demo-data\.json$''',  # Add your file
   ]
   ```

3. **Remove secret from Git history** (if real leak):
   ```bash
   git filter-repo --path-glob '*.env' --invert-paths
   # OR use BFG Repo-Cleaner
   ```

---

### **Trivy finds CVE**

1. **Update package**:
   ```bash
   # Example: Authlib 1.3.1 → 1.6.5
   sed -i 's/Authlib==1.3.1/Authlib==1.6.5/' requirements.txt
   pip install -r requirements.txt
   ```

2. **Verify fix**:
   ```bash
   make scan-vulns
   ```

3. **If no patch available**, add temporary ignore:
   ```yaml
   # .trivyignore (not recommended)
   CVE-2024-XXXXX  # Waiting for upstream fix (ticket #1234)
   ```

---

### **Grype reports HIGH vulns in venv/**

**Solution**: Grype scans the SBOM, which should exclude `venv/`. If still detected:

```bash
# Regenerate SBOM without venv
rm -rf .runtime/sbom
make sbom
make scan-sbom
```

---

## Viewing Results

### **Local**
```bash
make security-check  # Run all scans with colored output
```

### **CI/CD (GitHub)**
1. Go to **Actions** tab → Latest workflow run
2. Check individual job logs
3. View **Security** tab → **Code scanning** for Trivy/Grype alerts
4. Download SBOM artifacts from workflow run

---

## 🎯 Best Practices

### **Before Committing**
```bash
# Quick pre-commit check
make scan-secrets
make scan-vulns
```

### **Before PR Merge**
```bash
# Full security audit
make security-check
```

### **Weekly Maintenance**
```bash
# Update dependencies + scan
pip-compile requirements.in
pip install -r requirements.txt
make security-check
```

---

## 🔗 References

- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Syft Documentation](https://github.com/anchore/syft)
- [Grype Documentation](https://github.com/anchore/grype)
- [NIST SP 800-190 (Container Security)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Executive Order 14028 (SBOM)](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)

---

## 🆘 Troubleshooting

### **"Docker image not found"**
```bash
# Pull images manually
docker pull ghcr.io/gitleaks/gitleaks:latest
docker pull aquasec/trivy:latest
docker pull anchore/syft:latest
docker pull anchore/grype:latest
```

### **"Permission denied on .runtime/sbom/"**
```bash
# Fix permissions (created by root in Docker)
sudo chown -R $USER:$USER .runtime/sbom
```

### **"Grype is too slow"**
```bash
# Skip Grype for quick checks
make scan-secrets scan-vulns sbom
```# 🧪 Testing Guide — Mini IAM Lab

> **Complete testing guide**: strategy, commands, and code coverage workflow

---

## 📊 Current Metrics

- **Total tests**: 346 tests (300+ unit, 27 integration)
- **Coverage**: 91% on business code (`app/`)
- **Execution time**: ~3.5s (parallelized with pytest-xdist)
- **Test stack**: pytest + pytest-cov + pytest-xdist + pytest-mock

---

## 🎯 Test Strategy

### **Unit Tests** (300+ tests)
**Objective**: Validate business logic in isolation (Keycloak mocks)

**Command**:
```bash
make test
```

**Coverage**:
- `app/core/`: SCIM validation, RBAC, provisioning (100% on validators)
- `app/api/`: Flask endpoints, decorators, error handling (>90%)
- `app/config/`: Configuration validation, settings (96%)

**Execution**: Parallelized with `-n auto` (pytest-xdist)

---

### **Integration Tests** (27 E2E tests)
**Objective**: Validate complete flows with real Docker stack (Keycloak + Flask + Nginx)

**Command**:
```bash
make test-e2e
```

**Prerequisites**: Stack started (`make ensure-stack` automatically checks)

**Coverage**:
- OIDC/JWT validation (token parsing, claims, expiration)
- OAuth 2.0 SCIM authentication (Bearer tokens)
- Nginx security headers (HSTS, CSP, X-Frame-Options)
- Secrets security (Key Vault, Docker secrets)
- E2E SCIM flows (Joiner/Mover/Leaver)

**Automatic skip**: If stack is not accessible or OAuth credentials are invalid, tests gracefully disable (pytest.skip) instead of generating cascading errors.

---

### **Coverage Tests** (346 complete tests)
**Objective**: Generate detailed HTML report of code coverage

**Command**:
```bash
make test-coverage
```

**Output**: HTML report in `htmlcov/index.html` + terminal summary

**Recommended workflow**:
```bash
# 1. Run tests with coverage
make test-coverage

# 2. See viewing options
make test-coverage-report

# 3. Open in VS Code (recommended for CLI environments)
make test-coverage-vscode

# Alternatives depending on environment
make test-coverage-open    # System browser (Linux GUI, macOS)
make test-coverage-serve   # HTTP server localhost:8888
```

**Why multiple options?**
- **CLI environment** (WSL, SSH servers): `test-coverage-vscode` or `test-coverage-serve`
- **GUI environment** (Linux desktop, macOS): `test-coverage-open`
- **Remote review**: `test-coverage-serve` + SSH tunnel

---

## 🛡️ Critical Security Tests

**Command**:
```bash
make test/security
```

**Coverage**:
- JWT signature validation (JWKS, algorithms, expiration)
- RBAC enforcement (permissions, role hierarchy)
- Rate limiting (Nginx + Flask)
- Audit log signatures (HMAC-SHA256 verification)

**Pytest markers**: `-m critical` (non-negotiable tests)

---

## 🔄 CI/CD Workflow (GitHub Actions)

```yaml
- name: Run tests with coverage
  run: make test-coverage

- name: Upload coverage report
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

**Mandatory checks**:
- ✅ All unit tests pass (300+)
- ✅ Coverage >= 91% maintained
- ✅ No critical (security) test failures
- ✅ No regressions detected

---

## 🐛 Troubleshooting

### **Problem: Integration tests fail with 401 error**
**Cause**: Invalid OAuth credentials or stack not started

**Solution**:
```bash
# Verify stack is running
make ensure-stack

# Verify secrets
cat .runtime/secrets/keycloak_service_client_secret

# Regenerate secrets if necessary
make fresh-demo
```

**Note**: Since recent fix, OAuth fixtures use `pytest.skip()` if credentials are invalid, avoiding cascading errors.

---

### **Problem: Cannot open coverage report**
**Cause**: Linux CLI environment without browser

**Solution**:
```bash
# Option 1: Open in VS Code
make test-coverage-vscode

# Option 2: Serve via HTTP
make test-coverage-serve
# Then open http://localhost:8888 in local or tunneled browser
```

---

### **Problem: Slow tests or timeouts**
**Cause**: Non-optimal Docker stack, or sequential tests

**Solution**:
```bash
# Verify stack health
docker compose ps

# Restart if necessary
make restart

# Unit tests are parallelized by default (-n auto)
# Integration tests are sequential (rate limiting)
```

---

## 📚 References

- **pytest**: https://docs.pytest.org/
- **pytest-cov**: https://pytest-cov.readthedocs.io/
- **Coverage.py**: https://coverage.readthedocs.io/
- **pytest-xdist**: https://pytest-xdist.readthedocs.io/ (parallelization)

---

## 🎓 Applied Best Practices

1. **Isolated tests**: Mocks for unit tests, real stack for integration
2. **Smart skip**: `pytest.skip()` for missing external dependencies
3. **Parallelization**: `-n auto` for unit tests (3-4x gain)
4. **Fixture scope**: `module` for expensive setup (OAuth tokens), `function` for isolation
5. **Pytest markers**: `@pytest.mark.integration`, `@pytest.mark.critical`
6. **Targeted coverage**: Only `app/`, not tests or dependencies
7. **CI/CD friendly**: XML report for CodeCov, automatic skip without stack

---

**Back**: [Documentation Hub](README.md) | [Main README](../README.md)
# Threat Model — Mini IAM Lab

> **Swiss Compliance Focus** : Threat analysis aligned with nLPD, RGPD, FINMA requirements  
> **Frameworks** : STRIDE, MITRE ATT&CK, OWASP ASVS L2

---

## Swiss Regulatory Context

### nLPD (nouvelle Loi sur la Protection des Données)
**Requirements** :
- Traçabilité des accès et modifications
- Conservation sécurisée des logs (intégrité)
- Transparence sur le traitement des données

**Implementation** :
- ✅ Audit trail HMAC-SHA256 (`scripts/audit.py`)
- ✅ Permissions restrictives (chmod 400 sur logs)
- ✅ API SCIM pour export/transparence

### FINMA (Surveillance des marchés financiers)
**Requirements** :
- Non-répudiation des opérations critiques
- Détection d'altération des logs d'audit
- Traçabilité des accès privilégiés

**Implementation** :
- ✅ Signatures cryptographiques HMAC-SHA256
- ✅ Vérification intégrité : `make verify-audit`
- ✅ Corrélation-ID + actor tracking

---

## Scope
- SCIM 2.0 API (`/scim/v2`) served by Flask behind nginx.
- Keycloak (demo realm) providing OAuth tokens and admin REST API.
- Secrets stored under `/run/secrets` (demo) or Azure Key Vault (production).
- Audit events persisted in `.runtime/audit/jml-events.jsonl` with HMAC-SHA256 signatures.

## Architecture summary
```
Clients ──TLS──> nginx ──> Flask (Admin + SCIM) ──> Keycloak
                                 │
                                 └──> Azure Key Vault (prod secrets)
                                 └──> audit.jsonl (HMAC)
```

## STRIDE overview
| Threat | Scenario | Mitigation | Swiss Compliance |
|--------|----------|------------|------------------|
| **Spoofing** | Missing/invalid bearer token | `Authorization: Bearer` required for every non-discovery request; invalid tokens → 401 (`tests/test_scim_oauth_validation.py`). | FINMA: Authentication logged |
| **Tampering** | Malicious PATCH payload | Handler restricts to a single `replace active` operation with boolean value; other ops/paths → 501. | — |
| **Repudiation** | User denies disable action | Audit event logged via `scripts/audit.log_jml_event` with HMAC signature (`make verify-audit`). | ✅ **FINMA: Non-repudiation** |
| **Information disclosure** | Secrets leaked from filesystem | Production retrieves secrets from Key Vault (`settings.service_client_secret_resolved`); demo secrets are ephemeral. | nLPD: Secret protection |
| **Denial of service** | Filter abuse (`filter=userName sw *`) | `list_users_scim` only accepts `userName eq`; unrecognised operators return 501. | — |
| **Elevation of privilege** | Reuse of automation-cli token | Scope enforcement (read vs write). Note: service account bypass currently allows automation-cli without explicit scopes (documented TODO). | FINMA: Privileged access control |

## MITRE ATT&CK mapping
| Technique | ID | Relevance | Control |
|-----------|----|-----------|---------|
| Valid Accounts | T1078 | Bearer tokens reused | Rotate service account secret (`make rotate-secret`), monitor Keycloak events. |
| Exposed Admin Interface | T1190 | `/admin` UI | OIDC login + TOTP, CSRF enforcement, CSP (`proxy/nginx.conf`). |
| Credentials in Files | T1552.001 | Secrets in repo | Secrets resolved via Key Vault or generated at runtime; `.env` should not contain prod secrets. |
| API Abuse | T1190/T1499 | Flood SCIM endpoints | TODO: add nginx/App Gateway rate limiting; audit logs capture traffic for investigation. |

## RFC 7644 focus areas
- `PATCH` limited to toggling `active` to avoid privilege escalation via attribute changes.
- `PUT` disabled (`501`) to prevent unintended full replacement.
- `bulk` operations not supported (`ServiceProviderConfig.bulk.supported=false`).
- `filter` restricted to `userName eq` for predictability and injection resistance.

## Control verification
- OAuth enforcement: `pytest tests/test_scim_oauth_validation.py`.
- Content-Type enforcement: `tests/test_scim_api_negatives.py::test_content_type_validation`.
- Audit integrity: `make verify-audit`.
- TLS/CSP/HSTS: defined in `proxy/nginx.conf`.

## Open actions
- Enforce scope check for `automation-cli` (remove bypass).
- Implement rate limiting / WAF policy for SCIM endpoints.
- Ship audit logs to immutable storage (Azure Blob immutability).
- **Swiss Compliance Enhancements** :
  - [ ] Add GDPR data subject access request (DSAR) automation
  - [ ] Document data residency (Swiss Azure regions)
  - [ ] Integrate with Azure Sentinel (SIEM) for FINMA audit requirements
  - [ ] Implement log retention policy aligned with nLPD (minimum 12 months)

---

## 🔗 Related Documentation
- [Security Design](SECURITY_DESIGN.md) — OWASP ASVS L2 controls, nLPD/RGPD/FINMA implementation
- [API Reference](API_REFERENCE.md) — SCIM 2.0 endpoints, OAuth 2.0 scopes
- [Deployment Guide](DEPLOYMENT_GUIDE.md) — Azure Key Vault, Managed Identity, production hardening
- [Swiss Hiring Pack](Hiring_Pack.md) — Skills mapping for Swiss Cloud Security roles
- Add Azure Monitor detections for Key Vault secret access anomalies.
