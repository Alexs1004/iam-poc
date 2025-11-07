# 🔐 RBAC Demo Scenarios — Joiner/Mover/Leaver Workflows

> **Objective**: Demonstrate RBAC mastery and IAM (JML) workflows for Cloud Security recruiters  
> **Audience**: HR Recruiters, Tech Leads, CISO, Hiring Managers

---

## 📊 Overview

This document details the **4 demo users** provisioned by `make demo` and the automated **JML scenarios** (Joiner/Mover/Leaver). It illustrates:
- **Privilege separation** (least privilege principle)
- **Cryptographic audit trail** (FINMA non-repudiation)
- **Real IAM workflows** used in enterprises

---

## 👥 User Matrix

### alice — Analyst → IAM Operator (Mover Scenario)

**Scenario**: Promotion from analyst to IAM operator (vertical movement)

| Attribute | Initial Value | Final Value |
|----------|-----------------|---------------|
| **Username** | `alice` | `alice` |
| **Role** | `analyst` | **`iam-operator`** ⬆️ |
| **Status** | ✅ Active | ✅ Active |
| **MFA** | ✅ TOTP required | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) | `Temp123!` (temporary) |
| **Admin UI Access** | ❌ 403 Forbidden | ✅ Full admin |
| **JML Operations** | ❌ None | ✅ Joiner/Mover/Leaver |

**JML Workflow**:
1. **Joiner**: Initial creation with `analyst` role
2. **Mover**: Promotion `analyst` → `iam-operator`
3. **Audit**: 2 HMAC-signed events in `/admin/audit`

**Manual Test**:
```bash
# 1. Login with alice (before promotion)
open https://localhost
# Username: alice | Password: Temp123!

# 2. Try to access admin dashboard (should fail)
open https://localhost/admin
# → Expected: 403 Forbidden page (analyst has no access)

# 3. After promotion (by joe), reconnect
# → alice can now access /admin with JML operations

# 4. Consult audit trail of her promotion
open https://localhost/admin/audit
# → Search for "joiner" (alice) + "mover" (alice) events
```

**Key Points**:
- ✅ Promotion without account re-creation (role migration)
- ✅ Existing sessions invalidated after mover
- ✅ Complete audit trail (creation + modification)
- ✅ **Strict access control**: analyst blocked before promotion (403), authorized after

---

### bob — Analyst → Disabled (Leaver Scenario)

**Scenario**: Employee departure (GDPR-compliant soft-delete)

| Attribute | Initial Value | Final Value |
|----------|-----------------|---------------|
| **Username** | `bob` | `bob` |
| **Role** | `analyst` | `analyst` (preserved) |
| **Status** | ✅ Active | ❌ **Disabled** |
| **MFA** | ✅ TOTP required | ✅ TOTP preserved |
| **Password** | `Temp123!` | `Temp123!` (preserved) |
| **Admin UI Access** | ❌ 403 Forbidden | ❌ Login impossible |
| **JML Operations** | ❌ None | ❌ None |

**JML Workflow**:
1. **Joiner**: Initial creation with `analyst` role
2. **Leaver**: Disablement (enabled=false)
3. **Audit**: 2 HMAC-signed events in `/admin/audit`

**Manual Test**:
```bash
# 1. Try to login with bob
open https://localhost
# Username: bob | Password: Temp123!
# → Expected: "Invalid username or password" (account disabled)

# 2. Verify status in admin UI (with alice/joe)
open https://localhost/admin
# → bob appears as "Disabled" (red badge)

# 3. Consult audit trail of his disablement
open https://localhost/admin/audit
# → Search for "leaver" event (bob)
```

**Key Points**:
- ✅ Soft-delete (data preserved, account inactive) ← **GDPR compliance**
- ✅ Keycloak sessions automatically revoked
- ✅ Reactivation possible via `/admin` (reversible)
- ✅ **Access control**: analyst already had no /admin access (403)

---

### carol — Manager (Stable Scenario)

**Scenario**: Stable user with read access (no JML operations)

| Attribute | Value |
|----------|--------|
| **Username** | `carol` |
| **Role** | `manager` |
| **Status** | ✅ Active |
| **MFA** | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) |
| **Admin UI Access** | ✅ Read-only |
| **JML Operations** | ❌ None |

**JML Workflow**:
1. **Joiner**: Creation with `manager` role
2. **Stable**: No modifications

**Manual Test**:
```bash
# 1. Login with carol
open https://localhost
# Username: carol | Password: Temp123!

# 2. Access admin dashboard (read-only)
open https://localhost/admin
# → No "Joiner", "Mover", "Leaver" buttons (read-only)

# 3. Access audit trail (read authorized)
open https://localhost/admin/audit
# → Can consult history, not modify it
```

**Key Points**:
- ✅ Read/write separation (least privilege principle)
- ✅ Audit trail access (compliance/monitoring)
- ✅ No privilege escalation possible via UI
- ✅ **Access control**: manager can read dashboard, analyst blocked (403)

---

### joe — IAM Operator + Realm Admin (Full Access)

**Scenario**: Complete IAM administrator (dual role)

| Attribute | Value |
|----------|--------|
| **Username** | `joe` |
| **Role** | `iam-operator` + `realm-admin` |
| **Status** | ✅ Active |
| **MFA** | ✅ TOTP required |
| **Password** | `Temp123!` (temporary) |
| **Admin UI Access** | ✅ Full admin |
| **Keycloak Admin Access** | ✅ Full Keycloak console |
| **JML Operations** | ✅ Joiner/Mover/Leaver |

**JML Workflow**:
1. **Joiner**: Creation with `iam-operator` role
2. **Grant**: Assignment of `realm-admin` role (dual-role)
3. **Stable**: Permanent administrator account

**Manual Test**:
```bash
# 1. Login with joe
open https://localhost
# Username: joe | Password: Temp123!

# 2. Access admin dashboard (complete operations)
open https://localhost/admin
# → All JML buttons available

# 3. Access Keycloak Admin Console
open http://localhost:8080/admin/demo/console
# → joe can manage realm, clients, roles, users

# 4. Perform Joiner (create new user)
# → Fill form in /admin, assign "analyst" role
# → Verify in /admin/audit (signed "joiner" event)
```

**Key Points**:
- ✅ Dual role (IAM operator + Realm admin) = full control
- ✅ Keycloak console access (IdP infrastructure administration)
- ✅ Responsible for JML operations (operator traceability)

---

## 🔄 Detailed JML Workflows

### 1. Joiner (User Creation)

**Use case**: New employee joining the company

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Joiner" form
3. Fills:
   - Username (ex: `dave`)
   - Email, First name, Last name
   - Initial role (analyst/manager/iam-operator)
   - Options: ☑️ MFA required, ☑️ Update password on first login
4. Clicks "Create User"

**Backend (SCIM + Keycloak)**:
```python
# 1. SCIM API POST /Users
POST https://localhost/scim/v2/Users
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "dave",
  "name": {"givenName": "Dave", "familyName": "Smith"},
  "emails": [{"value": "dave@example.com", "primary": true}],
  "active": true
}

# 2. Keycloak API: Assign role + group
PUT /admin/realms/demo/users/{id}/role-mappings/realm
PUT /admin/realms/demo/users/{id}/groups/{iam-poc-managed-group-id}

# 3. Audit trail: Log event
{
  "event": "joiner",
  "username": "dave",
  "role": "analyst",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T10:30:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "joiner" event with username="dave"

# 2. Signature integrity
make verify-audit
# → Expected: Valid signature for "dave" event

# 3. New user login
open https://localhost
# Username: dave | Password: <temporary-provided> | MFA: Setup TOTP
```

---

### 2. Mover (Role Change)

**Use case**: Promotion, internal mobility, reorganization

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Mover" form
3. Selects:
   - User (ex: `alice`)
   - Current role (ex: `analyst`)
   - New role (ex: `iam-operator`)
4. Clicks "Change Role"

**Backend (Keycloak)**:
```python
# 1. Keycloak API: Remove old role
DELETE /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "analyst"}]

# 2. Keycloak API: Assign new role
POST /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "iam-operator"}]

# 3. Keycloak API: Revoke existing sessions
DELETE /admin/realms/demo/users/{alice-id}/sessions

# 4. Audit trail: Log event
{
  "event": "mover",
  "username": "alice",
  "from_role": "analyst",
  "to_role": "iam-operator",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T11:00:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "mover" event with from_role="analyst", to_role="iam-operator"

# 2. User reconnection (new session with new role)
open https://localhost
# Username: alice | Password: Temp123!
# → Verify that /admin now shows JML buttons

# 3. Signature integrity
make verify-audit
```

---

### 3. Leaver (User Disablement)

**Use case**: Employee departure, disciplinary suspension, long-term leave

**Steps**:
1. Operator logs in (`joe` or `alice` after promotion)
2. Accesses `/admin` → "Leaver" form
3. Selects user (ex: `bob`)
4. Clicks "Disable User"

**Backend (SCIM + Keycloak)**:
```python
# 1. SCIM API PATCH /Users/{id}
PATCH https://localhost/scim/v2/Users/{bob-id}
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    }
  ]
}

# 2. Keycloak API: Set enabled=false
PUT /admin/realms/demo/users/{bob-id}
Body: {"enabled": false}

# 3. Keycloak API: Revoke all sessions
DELETE /admin/realms/demo/users/{bob-id}/sessions

# 4. Audit trail: Log event
{
  "event": "leaver",
  "username": "bob",
  "correlation_id": "uuid",
  "timestamp": "2025-11-07T12:00:00Z",
  "signature": "hmac-sha256(...)"
}
```

**Verification**:
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Search for "leaver" event with username="bob"

# 2. Login attempt (should fail)
open https://localhost
# Username: bob | Password: Temp123!
# → Expected: "Invalid username or password"

# 3. Reactivation possible (soft-delete)
# → From /admin (with joe), "Reactivate" button on bob
# → After reactivation, bob can login again
```

---

## 🛡️ Security & Compliance

### Anti-Abuse Protection

| Scenario | Protection | Implementation |
|----------|-----------|----------------|
| **Self-modification** | User cannot modify their own account | `if username.lower() == current_username().lower(): abort(403)` |
| **Privilege escalation** | Manager cannot self-promote to realm-admin | Operator role verification in `@require_jml_operator` |
| **Admin deactivation** | Operator cannot disable their own account | Explicit check before leaver operation |
| **Realm-admin modification** | Only realm-admin can modify other realm-admins | `requires_operator_for_roles()` check |

### Cryptographic Audit Trail

**HMAC-SHA256 Signature**:
```python
import hmac
import hashlib

# 1. Canonical payload
canonical = f"{event}:{username}:{timestamp}:{correlation_id}"

# 2. Signing key (Azure Key Vault in prod)
signing_key = os.getenv("AUDIT_LOG_SIGNING_KEY")  # 64+ bytes

# 3. Signature
signature = hmac.new(
    signing_key.encode(),
    canonical.encode(),
    hashlib.sha256
).hexdigest()

# 4. Signed event
{
  "event": "joiner",
  "username": "dave",
  "signature": signature,
  ...
}
```

**Verification**:
```bash
make verify-audit
# Output:
# ✓ Event 1/22: signature valid (joiner, alice)
# ✓ Event 2/22: signature valid (joiner, bob)
# ...
# ✓ All 22 signatures valid
```

### Swiss Compliance

| Requirement | Implementation | Proof |
|----------|----------------|--------|
| **nLPD (Traceability)** | Timestamped audit trail for all operations | `/admin/audit` (ISO 8601 timestamps) |
| **GDPR (Right to be forgotten)** | Reversible soft-delete (enabled=false) | `PATCH /scim/v2/Users/{id}` with active=false |
| **FINMA (Non-repudiation)** | Non-falsifiable HMAC-SHA256 signatures | `make verify-audit` (22/22 valid) |

---

## 🧪 Automated Tests

### RBAC Unit Tests

```bash
# 1. Authorization tests
pytest tests/unit/test_core_rbac.py -v

# Coverage:
# ✓ test_user_has_role
# ✓ test_requires_operator_for_roles
# ✓ test_filter_display_roles
# ✓ test_collect_roles_from_access_token
```

### JML Integration Tests

```bash
# 1. Complete workflow tests
pytest tests/integration/test_admin_ui_helpers.py -v

# Coverage:
# ✓ test_ui_create_user (joiner)
# ✓ test_ui_change_role (mover)
# ✓ test_ui_disable_user (leaver)
# ✓ test_ui_set_user_active (reactivate)
```

### Audit Trail Tests

```bash
# 1. Cryptographic signature tests
pytest tests/unit/test_audit.py -v

# Coverage:
# ✓ test_log_jml_event_creates_file
# ✓ test_verify_audit_log_all_valid
# ✓ test_verify_audit_log_detects_tampering
```

---

## 🔗 References

- **[README.md](../README.md)** — Swiss positioning, quick start
- **[Hiring Pack](Hiring_Pack.md)** — CV ↔ Repo mapping for recruiters
- **[Security Design](SECURITY_DESIGN.md)** — OWASP ASVS L2, nLPD/GDPR/FINMA
- **[API Reference](API_REFERENCE.md)** — SCIM 2.0 endpoints, OAuth scopes
- **[Threat Model](THREAT_MODEL.md)** — STRIDE analysis, FINMA compliance

---

## 💡 For Recruiters: What This Demonstrates

### Technical Skills
- ✅ **Advanced RBAC** : 4 role levels, privilege separation
- ✅ **IAM Workflows** : Complete Joiner/Mover/Leaver automation
- ✅ **Cryptographic Audit** : HMAC-SHA256, non-repudiation
- ✅ **SCIM 2.0** : Standardized API (RFC 7644)
- ✅ **OIDC/MFA** : Modern authentication (PKCE, TOTP)

### Security & Compliance
- ✅ **Swiss Compliance** : nLPD, GDPR, FINMA by design
- ✅ **Least Privilege Principle** : Read-only vs. write access separation
- ✅ **Anti-Abuse Protection** : Self-modification blocked
- ✅ **Auditability** : Every action signed + timestamped
- ✅ **90% Test Coverage** : Verifiable quality

### Swiss Market Positioning
- 🇨🇭 **Finance** : FINMA compliance (non-repudiation, audit trail)
- 🇨🇭 **Healthcare** : Strict nLPD (traceability, soft-delete)
- 🇨🇭 **Tech/SaaS** : Modern IAM (SCIM, OIDC, automation)
- 🇨🇭 **Consulting** : Keycloak → Azure Entra ID migration path (Azure-native roadmap)

**Summary** : This project demonstrates **complete operational mastery of IAM standards** in an **Azure-first context** compliant with **Swiss requirements**. Ideal for **Junior Cloud Security Engineer (Azure)**, **IAM Engineer**, **DevSecOps Cloud** roles in Romandy.

