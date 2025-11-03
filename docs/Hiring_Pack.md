# Hiring Pack — Mini IAM Lab

| Control | Verification |
|--------|-------------|
| Azure Key Vault secrets | `make load-secrets`, mounted under `/run/secrets` |
| Auth / API Security | OAuth Bearer, SCIM RFC 7644, strict 415 |
| HTTP Hardening | HSTS, CSP, Secure/HttpOnly cookies (`proxy/nginx.conf`, `app/flask_app.py::_register_middleware`) |
| Tamper-proof audit | `make verify-audit` + docs/THREAT_MODEL.md |
| Testing | ~90% coverage + pytest (docs/TEST_STRATEGY.md) |

## 30-second demo
1. `make quickstart`
2. PATCH `/scim/v2/Users/{id}` with `active=false` (Bearer `automation-cli` token).
3. Run `make verify-audit` and observe the signed event in `audit/jml-events.jsonl`.
