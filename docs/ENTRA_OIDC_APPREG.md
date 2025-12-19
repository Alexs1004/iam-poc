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
