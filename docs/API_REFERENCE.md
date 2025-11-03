# API Reference — SCIM 2.0

Authoritative description of the `/scim/v2` surface exposed by `app/api/scim.py`. All requests are served over HTTPS and return JSON bodies using the SCIM error schema (`schemas`, `status`, `detail`, optional `scimType`).

## Interactive Documentation
- **OpenAPI Specification**: [scim_openapi.yaml](../openapi/scim_openapi.yaml)
- **ReDoc Interface**: https://localhost/scim/docs
- **Swagger UI**: Available via ReDoc at runtime

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
