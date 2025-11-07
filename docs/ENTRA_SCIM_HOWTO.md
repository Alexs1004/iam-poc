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
*Placeholder: Application creation page capture*

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
![Provisioning configuration](images/entra_provisioning_config.png)  
*Placeholder: Tenant URL + Secret Token form*

**Screenshot:**  
![Test connection successful](images/entra_provisioning_test_connection.png)  
*Placeholder: Success message "You are connected..."*

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
*Placeholder: Mappings table userPrincipalName → userName, etc.*

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
*Placeholder: Result of 4 steps with success*

---

### 5. Enable Provisioning

1. In **Provisioning** → **Settings**
2. Change **Provisioning Status** from `Off` to `On`
3. **Save**
4. Entra ID launches initial sync cycle (may take 20-40 min)

**Screenshot:**  
![Provisioning enabled](images/entra_provisioning_enabled.png)  
*Placeholder: Toggle "Provisioning Status: On"*

---

### 6. Test Deactivation

1. In Entra ID, **disable a user**:
   - Go to **Users** → Select user → **Block sign-in**
2. Wait for next sync cycle (or force with **Restart provisioning**)
3. Verify that `PATCH /scim/v2/Users/{id}` is called with `{ "active": false }`
4. Check **audit logs** in application (endpoint `/admin/audit`)

**Screenshot:**  
![Visible deactivation](images/entra_provisioning_deactivate.png)  
*Placeholder: HMAC audit logs showing user.deactivated*

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

---

## 📸 Screenshots (TODO)

The following images should be added in `docs/images/`:

- [ ] `entra_provisioning_create_app.png` - Enterprise Application creation
- [ ] `entra_provisioning_config.png` - Tenant URL + Secret Token configuration
- [ ] `entra_provisioning_test_connection.png` - Successful "Test Connection" result
- [ ] `entra_provisioning_mappings.png` - Attribute mappings table
- [ ] `entra_provisioning_on_demand.png` - "Provision on demand" result with 4 steps
- [ ] `entra_provisioning_enabled.png` - Provisioning Status: On
- [ ] `entra_provisioning_deactivate.png` - Audit logs showing deactivation

**How to capture:**
1. Follow this guide step by step in a test Entra ID tenant.
2. Take PNG screenshots (max resolution 1920x1080).
3. Hide sensitive data (domains, IPs, tokens).
4. Save in `/home/alex/iam-poc/docs/images/`.

---

**Last updated:** 2025-11-05  
**Author:** IAM PoC Team
