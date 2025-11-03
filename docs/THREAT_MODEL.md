# Threat Model — Mini IAM Lab

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
| Threat | Scenario | Mitigation |
|--------|----------|------------|
| Spoofing | Missing/invalid bearer token | `Authorization: Bearer` required for every non-discovery request; invalid tokens → 401 (`tests/test_scim_oauth_validation.py`). |
| Tampering | Malicious PATCH payload | Handler restricts to a single `replace active` operation with boolean value; other ops/paths → 501. |
| Repudiation | User denies disable action | Audit event logged via `scripts/audit.log_jml_event` with HMAC signature (`make verify-audit`). |
| Information disclosure | Secrets leaked from filesystem | Production retrieves secrets from Key Vault (`settings.service_client_secret_resolved`); demo secrets are ephemeral. |
| Denial of service | Filter abuse (`filter=userName sw *`) | `list_users_scim` only accepts `userName eq`; unrecognised operators return 501. |
| Elevation of privilege | Reuse of automation-cli token | Scope enforcement (read vs write). Note: service account bypass currently allows automation-cli without explicit scopes (documented TODO). |

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
- Add Azure Monitor detections for Key Vault secret access anomalies.
