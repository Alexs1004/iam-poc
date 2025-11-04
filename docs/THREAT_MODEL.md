# Threat Model — Mini IAM Lab

> **Swiss Compliance Focus** : Threat analysis aligned with nLPD, RGPD, FINMA requirements  
> **Frameworks** : STRIDE, MITRE ATT&CK, OWASP ASVS L2

---

## 🇨🇭 Swiss Regulatory Context

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
