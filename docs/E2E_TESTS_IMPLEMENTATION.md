# E2E Tests Implementation Guide

## Overview

This guide documents the comprehensive End-to-End test suite for the IAM PoC project, aligned with `E2E_TEST_PLAN.md`. The tests validate the complete stack from browser to Keycloak, including OIDC authentication, RBAC, SCIM API, session revocation, and security headers.

## Test Structure

### Files
- **`tests/test_e2e_comprehensive.py`** - Main E2E test suite (16 tests, 9 automated)
- **`tests/test_integration_e2e.py`** - Original SCIM integration tests (5 tests)
- **`tests/conftest.py`** - Shared fixtures and helpers

### Test Categories

| Category | Tests | Status | Markers |
|----------|-------|--------|---------|
| **Section 3: OIDC + PKCE + MFA** | 2 tests | 1 automated, 1 manual | `@pytest.mark.oidc` |
| **Section 4: RBAC UI** | 3 tests | Manual (requires browser) | `@pytest.mark.rbac` |
| **Section 5: SCIM 2.0 CRUD** | 5 tests | All automated ✅ | `@pytest.mark.scim` |
| **Section 6: Leaver (CRITICAL)** | 1 test | Manual (complex setup) | `@pytest.mark.leaver` |
| **Section 8: Nginx/TLS** | 3 tests | 2 automated, 1 manual | `@pytest.mark.nginx` |
| **Section 9: Secrets** | 2 tests | 1 automated, 1 manual | `@pytest.mark.secrets` |
| **Total** | **16 tests** | **9 automated, 7 manual** | - |

## Prerequisites

### 1. Running Stack
```bash
# Start complete stack (Keycloak + Flask + Nginx)
make quickstart

# Verify stack is healthy
curl -k https://localhost/health
# Expected: {"status": "healthy", ...}
```

### 2. Demo Users
The stack must have these users configured (done by `make quickstart`):
- **alice** (analyst) - View-only access
- **carol** (manager) - View-only access
- **joe** (iam-operator, realm-admin) - Full JML access
- **admin** (realm-admin) - Full admin access

### 3. Environment Variables
Ensure `.env` contains:
```bash
KEYCLOAK_URL=https://localhost/keycloak
APP_BASE_URL=https://localhost
KEYCLOAK_SERVICE_CLIENT_SECRET=demo-service-secret  # Or from Azure KV
```

### 4. Self-Signed Certificates
Accept self-signed certificates in your browser:
```bash
# Firefox: Advanced → Accept Risk
# Chrome: Proceed to localhost (unsafe)
# curl: Use -k or --insecure flag
```

## Running Tests

### Quick Start
```bash
# Run all automated E2E tests
make pytest-e2e-comprehensive

# Run only critical tests
make pytest-e2e-critical

# Run specific category
pytest tests/test_e2e_comprehensive.py -v -m scim
```

### Available Make Commands

| Command | Description | Requirements |
|---------|-------------|--------------|
| `make pytest-e2e` | Original SCIM integration tests | Stack running |
| `make pytest-e2e-comprehensive` | Full E2E test suite | Stack running |
| `make pytest-e2e-critical` | Critical tests only | Stack running |
| `make pytest-e2e-scim` | SCIM API tests only | Stack running |
| `make pytest-e2e-full` | All E2E suites combined | Stack running |

### Manual Test Execution
```bash
# Activate virtualenv
source venv/bin/activate

# Run with verbose output
pytest tests/test_e2e_comprehensive.py -v

# Run specific test
pytest tests/test_e2e_comprehensive.py::test_scim_01_create_user -xvs

# Run by marker
pytest tests/test_e2e_comprehensive.py -v -m "scim and critical"

# Show coverage summary
pytest tests/test_e2e_comprehensive.py::test_e2e_coverage_summary -xvs
```

## Test Details

### Section 3: OIDC + PKCE + MFA

#### test_oidc_01_pkce_flow_successful (MANUAL)
**Status:** Skipped (requires browser automation)

**Manual test procedure:**
1. Open browser to `https://localhost/`
2. Click "Login" → redirected to Keycloak
3. Login as `alice` / `alice123`
4. If first time: Configure TOTP MFA (scan QR code, enter 6-digit code)
5. After successful auth, redirected back to `/admin`
6. Verify:
   - No `invalid_grant` errors
   - Session cookie set with `Secure`, `HttpOnly`, `SameSite=Lax`
   - URL contains no tokens (tokens stored in session)

#### test_oidc_02_jwt_validation_enforced (AUTOMATED)
**Status:** ✅ Passing

**What it tests:**
- Invalid JWT tokens rejected (401/403, not 500)
- Algorithm "none" rejected
- No stack traces in error responses

**Expected output:**
```
✅ OIDC-02: JWT validation enforced correctly
```

---

### Section 4: RBAC UI (Personas)

#### test_rbac_01_analyst_view_only (MANUAL)
**Status:** Skipped (requires authenticated session)

**Manual test procedure:**
1. Login as `alice` / `alice123`
2. Navigate to `https://localhost/admin/`
3. Verify:
   - ✅ Can view user list and audit logs
   - ❌ JML form buttons ABSENT (no Joiner/Mover/Leaver)
4. Attempt `POST /admin/joiner` (via browser DevTools or curl)
5. Verify: `403 Forbidden`

#### test_rbac_02_manager_view_only (MANUAL)
Same as RBAC-01 but with `carol` / `carol123`.

#### test_rbac_03_operator_full_access (MANUAL)
**Manual test procedure:**
1. Login as `joe` / `joe123`
2. Navigate to `https://localhost/admin/`
3. Verify:
   - ✅ JML forms visible (Joiner/Mover/Leaver tabs)
   - ✅ Can create new user via Joiner form
   - ✅ Can change user roles via Mover form
   - ✅ Can disable user via Leaver form

---

### Section 5: SCIM 2.0 CRUD

All SCIM tests are **AUTOMATED ✅** and run against the live stack.

#### test_scim_01_create_user (CRITICAL)
**What it tests:**
- `POST /scim/v2/Users` returns `201 Created`
- Response includes `id`, `schemas`, `meta.resourceType`
- Schema compliant: `urn:ietf:params:scim:schemas:core:2.0:User`
- `_tempPassword` NOT leaked in response

**Expected output:**
```
✅ SCIM-01: Created user e2e_test_1729800000
```

#### test_scim_02_read_and_filter (AUTOMATED)
Tests `GET /Users/{id}` and `GET /Users?filter=...`.

#### test_scim_03_update_idempotent (AUTOMATED)
Tests `PUT /Users/{id}` with same data multiple times (no duplications).

#### test_scim_04_soft_delete (CRITICAL)
**What it tests:**
- `DELETE /Users/{id}` returns `204 No Content`
- User still exists but `active=false` (no irreversible deletion)

**Expected output:**
```
✅ SCIM-04: Soft delete successful (user disabled, not removed)
```

#### test_scim_05_errors_rfc_compliant (AUTOMATED)
**What it tests:**
- Invalid schema → `400` with RFC 7644 error structure
- Non-existent user → `404` with `schemas`, `status`, `detail`

---

### Section 6: Leaver - Session Revocation (CRITICAL)

#### test_leaver_01_immediate_session_revocation (MANUAL)
**Status:** Skipped (complex setup required)

**This is THE MOST CRITICAL security test in the suite.**

**Manual test procedure:**

1. **Create test user via SCIM:**
   ```bash
   curl -k -X POST https://localhost/scim/v2/Users \
     -H "Authorization: Bearer $(./get_token.sh)" \
     -H "Content-Type: application/scim+json" \
     -d '{
       "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
       "userName": "test_leaver",
       "emails": [{"value": "test_leaver@example.com", "primary": true}],
       "name": {"givenName": "Test", "familyName": "Leaver"},
       "active": true
     }'
   ```
   Note the `id` from response.

2. **Login as test user in browser:**
   - Open new incognito window
   - Navigate to `https://localhost/`
   - Login as `test_leaver` / (check response for temp password)
   - Verify access to `/admin/`
   - **Important:** Save the session cookie from DevTools

3. **Disable user via SCIM (simulate leaver):**
   ```bash
   curl -k -X PUT https://localhost/scim/v2/Users/{id} \
     -H "Authorization: Bearer $(./get_token.sh)" \
     -H "Content-Type: application/scim+json" \
     -d '{
       "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
       "id": "{id}",
       "userName": "test_leaver",
       "active": false
     }'
   ```

4. **Immediately test session revocation:**
   - Go back to incognito browser (with old session cookie)
   - Refresh `/admin/` page
   - **Expected:** `401 Unauthorized` or redirect to `/login` (NOT `200 OK`)

5. **Verify in Keycloak Admin Console:**
   - Login to `https://localhost/keycloak/admin/`
   - Navigate to: Users → `test_leaver` → Sessions
   - **Expected:** 0 sessions (all revoked)

6. **Verify audit log:**
   ```bash
   cat .runtime/audit/jml-events.jsonl | grep test_leaver | jq .
   ```
   **Expected:** Events for user creation + deactivation + session revocation

**Pass criteria:**
- ✅ Old session cookie immediately invalid (401/403)
- ✅ Keycloak shows 0 active sessions
- ✅ Audit log contains revocation event with HMAC signature

---

### Section 8: Nginx / TLS / Security Headers

#### test_ngx_01_http_to_https_redirect (AUTOMATED)
**What it tests:**
- `http://localhost` → `301/302` → `https://localhost`

**Note:** May skip if HTTP port not exposed (Docker network config).

#### test_ngx_02_security_headers_present (CRITICAL)
**What it tests:**
All responses include security headers:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self' ...`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

**Expected output:**
```
✅ homepage security headers OK
✅ health endpoint security headers OK
✅ admin dashboard security headers OK
✅ NGX-02: All security headers present
```

#### test_ngx_03_tls_version_minimum (MANUAL)
**Status:** Skipped (requires OpenSSL CLI)

**Manual test procedure:**
```bash
# TLS 1.0 should FAIL
openssl s_client -connect localhost:443 -tls1 < /dev/null
# Expected: handshake failure

# TLS 1.2 should SUCCEED
openssl s_client -connect localhost:443 -tls1_2 < /dev/null
# Expected: successful connection

# TLS 1.3 should SUCCEED
openssl s_client -connect localhost:443 -tls1_3 < /dev/null
# Expected: successful connection
```

---

### Section 9: Secrets Confidentiality

#### test_secrets_01_no_leak_in_http_responses (CRITICAL)
**What it tests:**
No secrets leaked in HTTP response bodies or headers:
- `/` homepage
- `/health` endpoint
- `/scim/v2/ServiceProviderConfig`

**Patterns checked:**
- `demo-service-secret`
- `FLASK_SECRET_KEY`
- `KEYCLOAK_SERVICE_CLIENT_SECRET`
- `password: "..."`
- JWT Bearer tokens in body

**Expected output:**
```
✅ / - no secrets leaked
✅ /health - no secrets leaked
✅ /scim/v2/ServiceProviderConfig - no secrets leaked
✅ SECRETS-01: No secrets leaked in HTTP responses
```

#### test_secrets_02_no_leak_in_logs (MANUAL)
**Status:** Skipped (requires log file access)

**Manual test procedure:**
```bash
# Check container logs
docker compose logs flask-app 2>&1 | grep -iE "(secret|password|token)" | grep -v "***"
# Expected: No plaintext secrets, only HMAC digests or *** redactions

# Check audit logs
cat .runtime/audit/jml-events.jsonl | jq -r '.details' | grep -iE "(secret|password)"
# Expected: No matches (passwords not logged)

# Verify HMAC signatures present
cat .runtime/audit/jml-events.jsonl | jq -r '.signature' | head -n 5
# Expected: HMAC-SHA256 hashes (64 hex chars)
```

**Pass criteria:**
- ✅ No plaintext secrets in `docker compose logs`
- ✅ No plaintext passwords in audit logs
- ✅ All audit events have valid HMAC signatures

---

## Coverage Summary

### Automated Tests (9)
| Test | Section | Status |
|------|---------|--------|
| `test_oidc_02_jwt_validation_enforced` | OIDC | ✅ Passing |
| `test_scim_01_create_user` | SCIM | ✅ Passing |
| `test_scim_02_read_and_filter` | SCIM | ✅ Passing |
| `test_scim_03_update_idempotent` | SCIM | ✅ Passing |
| `test_scim_04_soft_delete` | SCIM | ✅ Passing |
| `test_scim_05_errors_rfc_compliant` | SCIM | ✅ Passing |
| `test_ngx_01_http_to_https_redirect` | Nginx | ✅ Passing* |
| `test_ngx_02_security_headers_present` | Nginx | ✅ Passing |
| `test_secrets_01_no_leak_in_http_responses` | Secrets | ✅ Passing |

*May skip if HTTP port not exposed

### Manual Tests (7)
| Test | Section | Reason |
|------|---------|--------|
| `test_oidc_01_pkce_flow_successful` | OIDC | Requires browser automation |
| `test_rbac_01_analyst_view_only` | RBAC | Requires authenticated session |
| `test_rbac_02_manager_view_only` | RBAC | Requires authenticated session |
| `test_rbac_03_operator_full_access` | RBAC | Requires authenticated session |
| `test_leaver_01_immediate_session_revocation` | Leaver | Complex multi-step setup |
| `test_ngx_03_tls_version_minimum` | Nginx | Requires OpenSSL CLI |
| `test_secrets_02_no_leak_in_logs` | Secrets | Requires log file access |

## Execution Report

### Expected Results (Stack Running)

```bash
$ make pytest-e2e-comprehensive

[pytest-e2e-comprehensive] Running comprehensive E2E test suite...
tests/test_e2e_comprehensive.py::test_oidc_02_jwt_validation_enforced PASSED
tests/test_e2e_comprehensive.py::test_scim_01_create_user PASSED
tests/test_e2e_comprehensive.py::test_scim_02_read_and_filter PASSED
tests/test_e2e_comprehensive.py::test_scim_03_update_idempotent PASSED
tests/test_e2e_comprehensive.py::test_scim_04_soft_delete PASSED
tests/test_e2e_comprehensive.py::test_scim_05_errors_rfc_compliant PASSED
tests/test_e2e_comprehensive.py::test_ngx_01_http_to_https_redirect PASSED
tests/test_e2e_comprehensive.py::test_ngx_02_security_headers_present PASSED
tests/test_e2e_comprehensive.py::test_secrets_01_no_leak_in_http_responses PASSED

========== 9 passed, 7 skipped in 12.34s ==========
```

### Failures and Debugging

#### Flask not accessible
**Error:** `SKIPPED (Flask app not accessible: ...)`

**Solution:**
```bash
# Ensure stack is running
make ps

# Check Flask health
curl -k https://localhost/health

# Restart if needed
make fresh-demo
```

#### Invalid OAuth token
**Error:** `Failed to get service token: 401 Unauthorized`

**Solution:**
```bash
# Verify service account secret
source .env
echo $KEYCLOAK_SERVICE_CLIENT_SECRET

# Regenerate if needed
make rotate-secret
```

#### Security headers missing
**Error:** `test_ngx_02_security_headers_present FAILED: Some endpoints missing security headers`

**Solution:**
Check `proxy/nginx.conf` security headers configuration:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; ..." always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

Restart nginx:
```bash
docker compose restart nginx
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: E2E Tests
on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start Stack
        run: make quickstart
      
      - name: Wait for Health
        run: |
          timeout 60 bash -c 'until curl -k https://localhost/health; do sleep 2; done'
      
      - name: Run E2E Tests
        run: make pytest-e2e-comprehensive
      
      - name: Run Manual Test Checklist
        run: |
          echo "Manual tests to perform:"
          echo "1. OIDC PKCE flow (browser)"
          echo "2. RBAC personas (alice, carol, joe)"
          echo "3. Leaver session revocation"
          echo "4. TLS version enforcement"
          echo "5. Log confidentiality"
```

## Maintenance

### Adding New E2E Tests
1. Add test function to `tests/test_e2e_comprehensive.py`
2. Use appropriate markers: `@pytest.mark.oidc`, `@pytest.mark.scim`, etc.
3. Mark as critical if security-sensitive: `@pytest.mark.critical`
4. If requires stack, use `running_stack` fixture
5. If requires OAuth, use `service_oauth_token` and `scim_headers` fixtures
6. Update this documentation with test details

### Updating Test Plan
When E2E_TEST_PLAN.md changes:
1. Review new requirements
2. Implement new tests or update existing ones
3. Update `test_e2e_coverage_summary()` output
4. Update this documentation
5. Update `.copilot-instructions.md` if architecture changes

## Related Documentation
- `docs/E2E_TEST_PLAN.md` - Original test plan (16 test cases)
- `docs/P0_TESTS_IMPLEMENTATION_REPORT.md` - P0 unit tests
- `README.md` - Project setup and quickstart
- `.github/copilot-instructions.md` - Architecture overview

## Questions & Support
- Check test output for specific failure details
- Review `docker compose logs` for application errors
- Verify `.env` configuration matches requirements
- Ensure Keycloak demo users exist (run `make demo-jml`)

---

**Last Updated:** 2025-10-24  
**Test Suite Version:** 1.0  
**Automated Tests:** 9/16 (56%)  
**Critical Tests:** 6 (3 automated, 3 manual)
