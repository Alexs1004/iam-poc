# 🏗️ Architecture Phase 2.1 — Provisioning IAM avec Audit Trail

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CLIENT (Browser/curl)                              │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │ HTTPS (TLS 1.3)
                             ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Reverse Proxy (nginx)                                 │
│  • TLS termination                                                           │
│  • HSTS enforcement                                                          │
│  • Security headers (CSP, X-Frame-Options, etc.)                            │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │ X-Forwarded-* headers
                             ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Flask Application                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Admin Routes (/admin)                           │   │
│  │                                                                       │   │
│  │  POST /admin/joiner  ──┐                                            │   │
│  │  POST /admin/mover   ──┼──> Validation Layer                        │   │
│  │  POST /admin/leaver  ──┘     • _normalize_username()                │   │
│  │                               • _validate_email()                     │   │
│  │                               • _validate_name()                      │   │
│  │                               • CSRF token check                      │   │
│  │                                                                       │   │
│  │                               ↓                                       │   │
│  │                                                                       │   │
│  │                          Authorization                                │   │
│  │                          @require_role(iam-operator)                 │   │
│  │                                                                       │   │
│  │                               ↓                                       │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │              JML Operations (scripts/jml.py)                  │  │   │
│  │  │                                                               │  │   │
│  │  │  create_user()    ─┐                                         │  │   │
│  │  │  change_role()    ─┼─> Keycloak Admin API                   │  │   │
│  │  │  disable_user()   ─┘    • Bearer token (service account)    │  │   │
│  │  │                          • Idempotent operations             │  │   │
│  │  │                                                               │  │   │
│  │  │  disable_user() flow:                                        │  │   │
│  │  │    1. GET /users/{id}/sessions                               │  │   │
│  │  │    2. POST /users/{id}/logout    ← ✨ NEW: Session revoke   │  │   │
│  │  │    3. PUT /users/{id} enabled=false                          │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  │                               │                                     │   │
│  │                               ↓ Success/Failure                     │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │           Audit Logger (scripts/audit.py)                    │  │   │
│  │  │                                                               │  │   │
│  │  │  log_jml_event(                                              │  │   │
│  │  │    event_type="joiner|mover|leaver",                        │  │   │
│  │  │    username="alice",                                         │  │   │
│  │  │    operator="joe@example.com",                              │  │   │
│  │  │    success=True|False,                                       │  │   │
│  │  │    details={...}                                             │  │   │
│  │  │  )                                                            │  │   │
│  │  │                                                               │  │   │
│  │  │  1. Build canonical JSON                                     │  │   │
│  │  │  2. Sign with HMAC-SHA256(key, json)                        │  │   │
│  │  │  3. Append to .runtime/audit/jml-events.jsonl               │  │   │
│  │  │  4. Set permissions 600 (owner read/write only)             │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  │                                                                     │   │
│  │  GET /admin/audit ─────────────> Display audit trail              │   │
│  │                                   • Chronological order             │   │
│  │                                   • Signature verification          │   │
│  │                                   • Filter by type/status           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Keycloak (IAM Provider)                             │
│                                                                              │
│  Realm: demo                                                                 │
│  ┌────────────────────────────────────────────────────────────────┐        │
│  │ Users:                                                          │        │
│  │   alice  (enabled=true,  roles=[iam-operator], totp=✅)       │        │
│  │   bob    (enabled=false, roles=[analyst])        ← leaver      │        │
│  │   joe    (enabled=true,  roles=[realm-admin])                 │        │
│  │                                                                 │        │
│  │ Clients:                                                        │        │
│  │   flask-app       (public, OIDC)                               │        │
│  │   automation-cli  (confidential, service account)              │        │
│  │                                                                 │        │
│  │ Sessions:                                                       │        │
│  │   alice: session_xyz (last_access=2min ago)                   │        │
│  │   joe:   session_abc (last_access=5sec ago)                   │        │
│  │   bob:   [REVOKED via /logout] ← ✨ NEW                       │        │
│  └────────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                             ↑
                             │ Token requests (Client Credentials)
                             │
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Service Account (automation-cli)                       │
│                                                                              │
│  Permissions:                                                                │
│    • manage-users  (create, update, disable)                                │
│    • manage-realm  (roles, required actions)                                │
│    • manage-clients (security-admin-console config)                         │
│                                                                              │
│  Secret rotation:                                                            │
│    make bootstrap-service-account                                            │
│      → Generate new secret                                                   │
│      → Update Key Vault                                                      │
│      → Audit log rotation (HMAC signed)                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                             ↑
                             │ Secrets retrieval (DefaultAzureCredential)
                             │
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Azure Key Vault (Secrets Store)                        │
│                                                                              │
│  Secrets:                                                                    │
│    ├─ flask-secret-key                    (Flask session encryption)        │
│    ├─ keycloak-service-client-secret      (automation-cli credential)       │
│    ├─ keycloak-admin-password             (bootstrap only)                  │
│    ├─ alice-temp-password                 (initial joiner)                  │
│    ├─ bob-temp-password                   (initial joiner)                  │
│    └─ audit-log-signing-key               ✨ NEW (HMAC-SHA256)             │
│                                                                              │
│  Access:                                                                     │
│    • Managed Identity (flask-app container)                                 │
│    • Role: Key Vault Secrets User                                           │
│    • Audit: All access logged to Azure Monitor                              │
└─────────────────────────────────────────────────────────────────────────────┘


════════════════════════════════════════════════════════════════════════════════
                              Data Flows
════════════════════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────────────────────┐
│                       1. JOINER (Provision User)                              │
└──────────────────────────────────────────────────────────────────────────────┘

User (joe@example.com)
  │
  │ POST /admin/joiner
  │   username=alice
  │   email=alice@example.com
  │   role=analyst
  ↓
Flask: Validation
  │ ├─ _normalize_username("alice") → "alice" ✅
  │ ├─ _validate_email("alice@example.com") → ✅
  │ └─ _validate_name("Alice") → ✅
  ↓
Flask: Authorization
  │ @require_role(iam-operator) → joe has role ✅
  ↓
JML: create_user()
  │ ├─ GET /users?username=alice → not exists
  │ ├─ POST /users {...} → user_id=uuid
  │ ├─ PUT /users/{uuid}/reset-password
  │ └─ POST /users/{uuid}/role-mappings
  ↓
Audit: log_jml_event()
  │ {
  │   "event_type": "joiner",
  │   "username": "alice",
  │   "operator": "joe@example.com",
  │   "success": true,
  │   "details": {"role": "analyst", "email": "alice@example.com"},
  │   "signature": "a3f5b2c8..."
  │ }
  └─> .runtime/audit/jml-events.jsonl (append, mode 600)

Response: "User 'alice' provisioned ✅"


┌──────────────────────────────────────────────────────────────────────────────┐
│                       2. LEAVER (Disable User)                                │
└──────────────────────────────────────────────────────────────────────────────┘

User (joe@example.com)
  │
  │ POST /admin/leaver
  │   username=bob
  ↓
Flask: Authorization
  │ @require_role(iam-operator) → joe has role ✅
  │ Check: bob has iam-operator role? → No ✅ (can proceed)
  ↓
JML: disable_user()
  │ ├─ GET /users?username=bob → user_id=uuid
  │ ├─ GET /users/{uuid}/sessions → [session1, session2] ✨ NEW
  │ ├─ POST /users/{uuid}/logout → 204 No Content        ✨ NEW
  │ │    → All refresh_tokens revoked
  │ │    → All access_tokens blacklisted
  │ └─ PUT /users/{uuid} enabled=false
  ↓
Audit: log_jml_event()
  │ {
  │   "event_type": "leaver",
  │   "username": "bob",
  │   "operator": "joe@example.com",
  │   "success": true,
  │   "details": {"sessions_revoked": true}
  │ }
  └─> .runtime/audit/jml-events.jsonl

Response: "User 'bob' disabled successfully ✅"

Bob tries to access /admin with old token:
  ↓
  401 Unauthorized (session revoked immediately)


┌──────────────────────────────────────────────────────────────────────────────┐
│                       3. AUDIT VERIFICATION                                   │
└──────────────────────────────────────────────────────────────────────────────┘

Admin
  │
  │ make verify-audit
  ↓
scripts/audit.py
  │ ├─ Read .runtime/audit/jml-events.jsonl
  │ ├─ For each line:
  │ │   ├─ Parse JSON
  │ │   ├─ Extract signature
  │ │   ├─ Recompute HMAC-SHA256(key, canonical_json)
  │ │   └─ Compare signatures (constant-time)
  │ └─ Return (total_events, valid_signatures)
  ↓
Output:
  ✅ "Audit log: 15/15 events with valid signatures"

If tampered:
  ⚠️ "Audit log: 14/15 events with valid signatures"


════════════════════════════════════════════════════════════════════════════════
                         Security Properties
════════════════════════════════════════════════════════════════════════════════

✅ Confidentiality:
   • TLS 1.3 end-to-end
   • Secrets in Key Vault (not in code/logs)
   • Session cookies HttpOnly + Secure

✅ Integrity:
   • CSRF tokens for state-changing operations
   • Audit log HMAC-SHA256 signatures
   • Input validation prevents injection

✅ Availability:
   • Idempotent operations (safe retries)
   • Health checks (/health)
   • Graceful error handling

✅ Accountability:
   • All JML operations logged with operator
   • Cryptographic signatures prevent tampering
   • Non-repudiation via audit trail

✅ Authorization:
   • RBAC enforced (iam-operator, realm-admin)
   • Service account with minimal permissions
   • Self-modification prevented (can't change own role)

✅ Session Management:
   • Leaver revokes sessions immediately     ✨ NEW
   • Token refresh with expiry validation
   • Logout clears all cookies + server session
```
