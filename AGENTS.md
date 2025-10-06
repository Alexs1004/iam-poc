# AGENTS.md — Collaboration Guide for AI Coding Agent (Codex)

> Project: **Mini IAM Lab** — Keycloak + OIDC (Auth Code + PKCE) + MFA (TOTP) + RBAC + JML automation  
> Purpose: Build a professional PoC demonstrating IAM skills with strong security practices.

---

## 1) Mission & Scope

**Mission for the Agent**
- Deliver and harden a minimal yet complete IAM PoC:
  - Keycloak (Docker) as IdP (`realm: demo`)
  - Flask demo app using **OIDC Authorization Code + PKCE**
  - **MFA (TOTP)** required at first login
  - **RBAC** with roles `admin` and `analyst`, `/admin` protected
  - JML automation script: `init`, `joiner`, `mover`, `leaver` via Keycloak Admin REST
- Provide clean documentation (**README**, **PLAN**, **DEMO_SCRIPT**) and light tests.

**Out of scope (Anti-goals)**
- Production deployment (no public exposure, no cloud hosting).
- Storing real secrets or disabling security warnings.
- Complex UI/UX; keep app minimal & server-rendered.

---

## 2) Repository Layout (expected)

```
iam-poc/
├─ docker-compose.yml
├─ README.md
├─ PLAN.md
├─ DEMO_SCRIPT.md
├─ AGENTS.md              <-- this file
├─ app/
│  ├─ flask_app.py
│  └─ requirements.txt
├─ scripts/
│  ├─ jml.py
│  └─ requirements.txt
└─ .env.template          (to be created; not committed with secrets)
```

**Create if missing:** `.gitignore`, `.env.template`.

---

## 3) Environment & Secrets Policy

- **Never** commit real secrets.
- Use environment variables (see `.env.template`):
  - `KEYCLOAK_ISSUER` = `http://localhost:8080/realms/demo`
  - `OIDC_CLIENT_ID` = `flask-app`
  - `OIDC_REDIRECT_URI` = `http://localhost:5000/callback`
  - `FLASK_SECRET` = development placeholder
- For automation (Day 4+), prefer **service account** (client credentials) over admin user/password.
- In docs, clearly state **dev only**; production needs HTTPS + reverse proxy + vault + stricter policies.

---

## 4) Security Guardrails (Agent MUST follow)

1. **OIDC flow**: Use **Authorization Code + PKCE** only. No implicit/hybrid.
2. **Session handling**: Keep tokens **server-side** (Flask session). Do **not** write tokens to logs, console, or client-side storage.
3. **MFA**: Enforce `CONFIGURE_TOTP` at first login (required action).
4. **Authorization**: Enforce `/admin` on the **server** using roles from token/userinfo.
5. **Redirect URIs & CORS**: Exact matches; no wildcards. Origins limited to `http://localhost:5000`.
6. **Least privilege**: Use a **confidential** client with **service account** for admin API calls (client credentials). Give minimal roles needed.
7. **Headers**: Add `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` on authenticated routes.
8. **Docs**: Warn that this is a developer PoC; list production hardening steps (HTTPS, vault, rotation, CI/CD checks).

---

## 5) Coding Standards

- Python ≥ 3.10. Stick to stdlib + listed deps (`Authlib`, `Flask`, `requests`).
- Style: clear functions, docstrings where non-obvious, minimal global state.
- Errors: raise with helpful messages; sanitize sensitive data.
- Logging: INFO-level high-level events, **never** secrets or tokens.
- Tests (lightweight): unit test for role-check decorator; basic header checks.

Commit messages: `feat: …`, `fix: …`, `docs: …`, `chore: …`, `test: …`.

---

## 6) Milestones & Definition of Done (DoD)

**M1 — SSO (Day 1)**
- Flask routes `/login`, `/callback`, `/me` working with OIDC Code + PKCE.
- DoD: manual user can login; `/me` shows claims; no token logs.

**M2 — MFA & RBAC (Day 2)**
- Required TOTP on first login; `/admin` protected by `admin` role.
- DoD: login triggers MFA enrollment; 403 without role; 200 with `admin`.

**M3 — JML Automation (Day 3)**
- `jml.py` implements `init`, `joiner`, `mover`, `leaver` idempotently.
- DoD: commands reflect in Keycloak; effects visible in app.

**M4 — Hardening & Tests (Day 4)**
- Switch to **service account** (client credentials) for admin API.
- Add security headers; minimal tests pass.
- DoD: no reliance on admin username/password; tests green.

**M5 — Polish & Docs (Day 5)**
- README/PLAN/DEMO_SCRIPT finalized; demo rehearsed ≤ 3 min.
- DoD: repo/zip ready to share.

---

## 7) Task List (Actionable)

### 7.1 Setup
- [ ] Create `.env.template` with keys listed in §3.
- [ ] Add `.gitignore` (ignore `.env`, venv, `__pycache__`, `.pytest_cache`).

### 7.2 OIDC Client (Flask)
- [ ] Implement `/login`, `/callback`, `/logout`, `/me`.
- [ ] Store token in server session; map roles from `userinfo`/ID token.
- [ ] Add simple templates (server-rendered).

### 7.3 RBAC + MFA
- [ ] Decorator `require_role('admin')` returning 403 if missing.
- [ ] Keycloak: enable required actions (`CONFIGURE_TOTP`, `UPDATE_PASSWORD`).

### 7.4 JML Script
- [ ] `init`: realm, public client (`flask-app`), roles.
- [ ] `joiner`: user + temp password + required actions + role.
- [ ] `mover`: role switch (remove/add).
- [ ] `leaver`: disable user.

### 7.5 Hardening
- [ ] Create confidential client `automation-cli` with **service accounts**.
- [ ] Token via **client credentials**; minimize realm roles for service account.
- [ ] Security headers on protected routes.

### 7.6 Tests & Docs
- [ ] `pytest` for `require_role` and headers.
- [ ] Update README (usage), PLAN (work plan), DEMO_SCRIPT (script).
- [ ] Add 3–4 screenshots as fallback.

---

## 8) Prompts & Interaction Rules (for the Agent)

When asking the agent for code, **always** provide:
- The file path(s), current content (if editing), and the exact change you want.
- Security constraints from §4 that must be respected.
- Acceptance criteria and a test/check you’ll run.

**Prompt templates**

**A) Implement OIDC in Flask**
```
Context:
- File: app/flask_app.py
- Use Authlib, OIDC Authorization Code + PKCE against ${KEYCLOAK_ISSUER}
- Tokens must be stored in server session; no logging of tokens
Task:
- Implement routes /login, /callback, /logout, /me
- Read env: KEYCLOAK_ISSUER, OIDC_CLIENT_ID, OIDC_REDIRECT_URI, FLASK_SECRET
Acceptance:
- After login, /me shows userinfo; no tokens in logs.
```

**B) Role decorator**
```
Context: Flask app has userinfo with roles in realm_access
Task: Create @require_role('admin') decorator that returns 403 if role missing
Acceptance: Access /admin returns 403 without role; 200 with 'admin'
Security: Server-side check only; do not rely on client UI
```

**C) JML script**
```
Context: scripts/jml.py using Keycloak Admin REST
Task: Implement init, joiner, mover, leaver idempotently
Acceptance: Running commands shows expected effects in Keycloak and app
Security: Do not log secrets; handle 404/409 gracefully
```

**D) Service account switch**
```
Context: Replace admin password grant with client credentials
Task: Create confidential client 'automation-cli' (service accounts) and update jml.py to fetch tokens with client_id/secret
Acceptance: JML commands work without admin user; minimal roles for service account
```

**E) Headers & tests**
```
Task: Add headers (nosniff, DENY, no-store) on authenticated routes; write pytest for role decorator
Acceptance: Tests pass locally; headers visible in responses
```

---

## 9) Review Checklist (Agent self-review)

- [ ] No secrets or tokens in code or logs.
- [ ] OIDC flow is **Code + PKCE**; redirect URI matches exactly.
- [ ] Sessions are server-side; cookies `HttpOnly`, `SameSite=Lax`.
- [ ] `/admin` is enforced server-side via roles.
- [ ] MFA required on first login (required actions configured).
- [ ] Service account in use for automation; least privilege documented.
- [ ] README/PLAN/DEMO updated; commands copy-pastable.
- [ ] Tests provided and passing (if applicable).

---

## 10) Common Pitfalls

- `invalid_redirect_uri`: must **exactly** match the configured URI.
- Missing roles in token: add proper role mappers or read from `userinfo`.
- TOTP not triggered: ensure `CONFIGURE_TOTP` is checked as required action.
- 403 on `/admin` even as admin: confirm role name, token refresh, or re-login after role change.
- Exposed tokens: remove debug prints; sanitize logs.

---

## 11) Handover Notes

- This is a **developer PoC**. For production:
  - Use **HTTPS**, **confidential client**, reverse proxy.
  - Store secrets in a **vault**, rotate tokens/keys.
  - CI: lint, tests, SAST/DAST as applicable.
  - Consider SCIM for provisioning to SaaS apps.
