# Documentation Hub

Single access point for the Mini IAM Lab documentation. The root README stays recruiter-facing; use the index below for engineering details.

## Core references
- [API Reference](API_REFERENCE.md)
- [Security Design](SECURITY_DESIGN.md)
- [Test Strategy](TEST_STRATEGY.md)
- [Local SCIM Testing](LOCAL_SCIM_TESTING.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Threat Model](THREAT_MODEL.md)

## UI verification shortcuts
| Proof | UI action |
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
