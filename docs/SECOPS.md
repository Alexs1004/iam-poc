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
