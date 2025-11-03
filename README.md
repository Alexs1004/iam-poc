# Mini IAM Lab — SCIM 2.0 · Azure Key Vault · JML

![Made with Azure Key Vault](https://img.shields.io/badge/Azure-Key%20Vault-0078D4?logo=microsoft-azure&logoColor=white)
![Demo in ~2 min](https://img.shields.io/badge/Demo-~2%20minutes-success?logo=github)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-~240%20passed-brightgreen?logo=pytest)
![Coverage](https://img.shields.io/badge/Coverage-~90%25-brightgreen?logo=codecov)
![Security](https://img.shields.io/badge/Security-OWASP%20ASVS%20L2-blue?logo=owasp)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## Architecture

```
┌─────────────┐    ┌───────────┐    ┌─────────────┐    ┌──────────────┐
│   Browser   │───▶│   nginx   │───▶│    Flask    │───▶│  Keycloak    │
│   (HTTPS)   │    │ (TLS/Rate │    │  (SCIM API) │    │  (OIDC/JWT)  │
└─────────────┘    │  Limit)   │    └─────────────┘    └──────────────┘
                   └───────────┘            │                   │
                                           ▼                   ▼
                                  ┌─────────────┐    ┌──────────────┐
                                  │ Azure Key   │    │  Audit Logs  │
                                  │ Vault       │    │ (HMAC-SHA256)│
                                  │ (Secrets)   │    │ (.runtime/)  │
                                  └─────────────┘    └──────────────┘
```

## Why / What / Proof
- **Why**: demonstrate Azure security fundamentals (secrets off-code, rotation, audit integrity).
- **What**: SCIM 2.0 (RFC 7644) + Azure Key Vault + HMAC-signed audit trail (JML automation on Keycloak 24).
- **Proof**: >240 pytest checks (~90% coverage) and a 2-minute quickstart path.

## Try
```bash
make quickstart
open https://localhost
```
You will see: Keycloak login, JML workflow, SCIM calls, signed audit log.

## Common Make Commands

```bash
make quickstart      # Zero-config start: .env + stack + JML demo
make fresh-demo      # Full reset: volumes + secrets + certs + demo
make test            # Unit tests (mocked Keycloak)
make test-e2e        # Integration tests (requires running stack)
make rotate-secret   # Production secret rotation (requires Key Vault)
make logs SERVICE=   # View logs (e.g., SERVICE=flask-app)
make doctor          # Health check: Azure CLI, Key Vault, Docker
```

For complete command reference: `make help-all`

📋 **Full Documentation**: [docs/README.md](docs/README.md)

Verify from UI (1 click): https://localhost/verification — runs:
- OpenAPI docs respond with 200
- OAuth-protected endpoint returns 401 when unauthenticated
- Wrong media type triggers 415 invalidSyntax
- PATCH `/Users/{id}` active toggle stays idempotent (200 then 200)
- PUT `/Users/{id}` returns 501 with detailed message
- Security headers (HSTS, CSP, etc.) are present

## Verifiable proofs
- OpenAPI (ReDoc): https://localhost/scim/docs
- [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)
- `make verify-audit` + [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## How to validate this PoC
- Go to https://localhost/verification and run “SCIM verification”.
- The page asserts:
  - SCIM RFC 7644 behavior (POST/GET/PATCH/DELETE, filter guard, PUT=501, media-type enforcement).
  - OAuth enforcement (401 missing/invalid token, 403 insufficient scope).
  - Audit integrity via signature verification.
  - Error handling correctness (SCIM error payloads, status codes).

## SCIM support matrix
| Method | Endpoint | Status |
|--------|---------|--------|
| GET    | /scim/v2/Users          | OK |
| POST   | /scim/v2/Users          | OK |
| GET    | /scim/v2/Users/{id}     | OK |
| PATCH  | /scim/v2/Users/{id}     | OK — `replace path=active` only (idempotent) |
| DELETE | /scim/v2/Users/{id}     | OK — soft-delete (disable) |
| PUT    | /scim/v2/Users/{id}     | **501** — use PATCH or DELETE |

PUT returns 501 with detail: `Full replace is not supported. Use PATCH (active) or DELETE.`

## Security Protection
- **Rate Limiting**: Nginx-based DoS protection
  - `/verification`: 10 req/min + burst=5 (testing endpoint)
  - `/scim/v2/*`: 60 req/min + burst=10 (API endpoints)
  - `/admin/*`: 30 req/min + burst=8 (admin interface)
- Test: `./test_rate_limiting.sh` (demonstrates 429 responses)
- Documentation: [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md)

## Tests
- `make test` (pytest -n auto)
- `SKIP_E2E=true make test-all`

## Current limitations
- Filter: `userName eq` only.
- PATCH limited to `active`.
- Requires `Content-Type: application/scim+json`.

## Role target
Target roles: Junior IAM Engineer / Cloud Security Engineer (Azure).

## Documentation hub
- [docs/README.md](docs/README.md)
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- [docs/SECURITY_DESIGN.md](docs/SECURITY_DESIGN.md)
- [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md)
- [docs/TEST_STRATEGY.md](docs/TEST_STRATEGY.md)
- [docs/LOCAL_SCIM_TESTING.md](docs/LOCAL_SCIM_TESTING.md)
- [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
