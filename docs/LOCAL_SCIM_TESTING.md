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
