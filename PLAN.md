# IAM PoC — Development Plan (5 Days)  
**Project:** Keycloak + OIDC SSO + MFA + RBAC + JML Automation  
**Goal:** Demonstrate skills aligned with an IAM Junior Developer internship (Linux, Docker, scripting, web, testing, security-by-design).

---

## 0) Success Criteria
- ✅ Keycloak realm `demo`, client `flask-app`, roles `admin`/`analyst` configured via script.
- ✅ Flask app authenticates with **OIDC Authorization Code + PKCE**, enforces **MFA (TOTP)** on first login, shows claims, and restricts `/admin` to role `admin`.
- ✅ **JML automation** (`init`, `joiner`, `mover`, `leaver`) works end-to-end using the Keycloak Admin API.
- ✅ README + DEMO SCRIPT allow a 2–3 minute live demo without guessing.
- ✅ Security considered at every step (see **Security Checklist**).

---

## 1) Architecture (High-Level)
- **Keycloak** (IdP) in Docker: realm `demo`, client `flask-app`, roles `admin`/`analyst`.
- **Flask** demo app: OIDC login, `/me` (claims), `/admin` (role-protected), session-based.
- **Automation**: Python script `scripts/jml.py` for Joiner–Mover–Leaver via Keycloak Admin REST.

```
[User] → Browser → Flask App (OIDC client) → Keycloak (OpenID Connect)
                 ← tokens/claims ←         ← discovery/introspection →
```

---

## 2) Security Non-Functional Requirements (NFR)
- **Identity**: OIDC Authorization Code + **PKCE** (no implicit flow).
- **MFA**: Enforce TOTP as a **required action** at first login.
- **RBAC**: Realm roles used in ID token/userinfo; app enforces authorization server-side.
- **Secrets**: No secrets in repo. Use `.env` (local dev) and environment variables.
- **HTTPS**: Document that production must use HTTPS; dev uses `http://localhost`.
- **Sessions**: Server-side session; set `HttpOnly`, `Secure` (when HTTPS), `SameSite=Lax`.
- **Logging**: No tokens or passwords in logs; errors sanitized.
- **Least privilege**: Prefer **service account** (client credentials) for automation over admin user.
- **CORS/Redirect URIs**: Restrict to explicit origins/URIs; disable wildcards.
- **Password Policy**: Set minimal demo policy; document stronger prod policy.
- **Rotation/Disable**: `leaver` disables accounts; document token revocation options.

---

## 3) Work Breakdown (5 Days)

### Day 1 — Environment & SSO
- [ ] Initialize Git repo; add `.gitignore`, `README.md`.
- [ ] Create `.env.template` for Flask app variables.
- [ ] Start Keycloak with Docker Compose; verify admin console at `:8080`.
- [ ] Implement OIDC client in Flask (`Authlib`), Code + PKCE, `/login` → `/callback` → `/me`.
**Acceptance:** Login works with a manual user; `/me` shows userinfo claims.

### Day 2 — MFA & RBAC
- [ ] Configure **required actions** in Keycloak to enforce **TOTP** at first login.
- [ ] Map realm roles to tokens (userinfo or ID token).
- [ ] Add `/admin` route with **role check**; return 403 if missing role.
**Acceptance:** First login asks to set up TOTP; `/admin` requires `admin` role.

### Day 3 — JML Automation (Joiner–Mover–Leaver)
- [ ] `init`: create realm `demo`, client `flask-app` (public, PKCE), roles `admin`/`analyst`.
- [ ] `joiner`: create user (temp password, `CONFIGURE_TOTP`, `UPDATE_PASSWORD`, assign role).
- [ ] `mover`: change role (remove old role, add new one).
- [ ] `leaver`: disable user.
**Acceptance:** Commands succeed idempotently; visible effects in app.

### Day 4 — Hardening, Tests, Docs
- [ ] Replace admin password grant with **service account** (client credentials):
      - Create confidential client `automation-cli`, enable **Service Accounts**.
      - Grant service account minimal realm roles to manage users.
      - Update `jml.py` to get token via client credentials.
- [ ] Add basic **unit tests** for role-check decorator and security headers.
- [ ] Write **DEMO SCRIPT** and finalize README (screenshots optional).
**Acceptance:** Automation works without using admin user creds; tests pass locally.

### Day 5 — Polish & Rehearsal
- [ ] Run through the demo end-to-end twice; time it (≤3 minutes).
- [ ] Review security checklist; fix any gaps.
- [ ] Create a short **“Next steps”** section (what you would do in month 1–2).
- [ ] Tag release `v0.1`. Prepare a zipped bundle to share if needed.
**Acceptance:** Confident demo + clean repo + clear documentation.

---

## 4) Task-by-Task with Copilot Prompts (pair programming guardrails)

### A. Flask OIDC (Day 1)
**Goal:** Implement OIDC Code + PKCE with Authlib, safe session handling.
**Prompt to AI:**  
“Implement a Flask route `/login` and `/callback` using Authlib with OIDC Code + PKCE against a Keycloak issuer `${KEYCLOAK_ISSUER}`. Do **not** store tokens in localStorage; keep tokens in the server session. Ensure no secrets or tokens are logged. Add a `/me` route calling the userinfo endpoint. Use environment variables for issuer, client id, redirect URI.”

**Security acceptance:**
- Tokens only in session; no printing tokens.
- Session cookies: `HttpOnly`, `SameSite=Lax`. (Enable `Secure` when HTTPS.)

### B. Role-Based Access (Day 2)
**Goal:** Enforce `admin` role on `/admin`.
**Prompt:**  
“Create a Flask decorator `require_role('admin')` that checks roles from userinfo or ID token and returns a 403 page if the role is missing. Write a simple unit test for the decorator using a fake session.”

**Security acceptance:**  
- Server-side check; not relying on client-side UI.

### C. Keycloak Init (Day 3)
**Goal:** Script `init` to configure realm, client, roles idempotently.
**Prompt:**  
“Write Python functions to call Keycloak Admin REST: (1) create realm if not exists, (2) create a public OIDC client `flask-app` with redirect `http://localhost:5000/callback`, `standardFlowEnabled=true`, PKCE, (3) create roles `admin`, `analyst`. Ensure idempotency and robust error handling.”

**Security acceptance:**  
- No admin password in logs.
- Restrictive redirect URIs; no wildcards.

### D. Joiner/Mover/Leaver (Day 3)
**Goal:** User lifecycle APIs.
**Prompt:**  
“Implement `joiner(username, email, first, last, role)` that (a) creates user, (b) sets temp password, (c) sets required actions `CONFIGURE_TOTP` and `UPDATE_PASSWORD`, (d) assigns role. Implement `mover` to swap roles and `leaver` to disable user. Handle 404 gracefully.”

**Security acceptance:**  
- Temporary passwords only for demo; document policy.
- Log only high-level outcomes, not credentials.

### E. Service Account (Day 4)
**Goal:** Replace admin user with least-privilege service account.
**Prompt:**  
“In Keycloak, create a **confidential** client `automation-cli` with Service Accounts enabled. Grant the service account only the roles required to manage users in realm `demo`. Update `jml.py` to obtain an access token via **client credentials** and use that for Admin REST calls.”

**Security acceptance:**  
- No human admin password needed.
- Minimal roles for the service account.

### F. Tests & Headers (Day 4)
**Goal:** Basic unit tests + security headers.
**Prompt:**  
“Add `pytest` and write tests for the role decorator. Configure Flask to set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` on authenticated routes.”

---

## 5) Security Checklist (Go/No-Go)
- [ ] **OIDC**: Code + PKCE; confidential clients for server-to-server.
- [ ] **MFA**: `CONFIGURE_TOTP` required on first login.
- [ ] **Redirect URIs**: exact match only; web origins restricted.
- [ ] **Sessions**: `HttpOnly`, `SameSite=Lax`; no tokens in logs.
- [ ] **Secrets**: `.env` used locally; `.env` in `.gitignore`.
- [ ] **Least privilege**: use **service account** (client credentials) for automation.
- [ ] **Password Policy**: documented; demo uses temp password + change on first login.
- [ ] **CORS**: limited to localhost dev; no `*`.
- [ ] **Keycloak Admin**: not exposed publicly in real life; document network controls.
- [ ] **Docs**: clear warning that this is a **dev PoC**; production needs HTTPS, vault, rotation.

---

## 6) Git & Workflow
- Branching: `main` (stable), `feature/*` for tasks.  
- Commits: message format `feat`, `fix`, `docs`, `chore`.  
- PR Review (self-review): checklist from Security + Tests.  
- Tag `v0.1` before interview.

---

## 7) Deliverables
- Repository with `README.md`, `PLAN.md`, `DEMO_SCRIPT.md`.
- Zip archive for offline demo.
- Optional screenshots (Keycloak login, TOTP setup, `/me`, 403 on `/admin` without role).

---

## 8) Next Steps (if hired)
- Switch Flask app to **confidential** client + HTTPS (reverse proxy).
- Centralize config; add **SCIM** connector exploration.
- CI pipeline (lint, tests) and containerization for the Flask app.
- Add access review/recertification mock flow (CSV-based).
