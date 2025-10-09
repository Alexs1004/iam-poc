# Mini IAM Lab — Keycloak + Flask + JML Automation

Developer PoC demonstrating **OIDC Authorization Code + PKCE**, **MFA (TOTP)**, **RBAC**, and **Joiner/Mover/Leaver automation** on a local Keycloak instance.

## Stack at a glance
- **Keycloak** 24 (Docker) → realm `demo`, public client `flask-app`, service client `automation-cli`.
- **Flask** demo at `http://localhost:5000` (Authlib + Flask-Session, server-side tokens, role-gated `/admin`).
- **Automation** script `scripts/jml.py` + `make` helpers (init/joiner/mover/leaver/delete-realm).
- **UI** rendered via Jinja templates with a simple responsive theme (no JS logic, all checks server-side).

## Prerequisites
- Docker (Desktop/Engine)
- Python 3.10+
- `make`
- Authenticator application (TOTP) for MFA demo

Everything is intended for localhost only. Production notes live in the **Security Guardrails** section.

## Quick start (5 commands)
```bash
python3 -m venv .venv && source .venv/bin/activate          # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
make bootstrap-service-account # one-time; generates secret for automation-cli
make demo                                                   # idempotent init + sample users + mover/leaver
python app/flask_app.py                                     # start Flask UI (or run via your WSGI setup)
```
Notes:
- `make demo` will bootstrap automatically if `KEYCLOAK_SERVICE_CLIENT_SECRET` is missing (secret stays in memory unless you export it into `.env`).
- Keycloak is bound to `127.0.0.1:8080`; adjust `KEYCLOAK_URL` if you map the container differently.

## What `make demo` does
1. Bootstraps/rotates the `automation-cli` confidential client in realm `demo` (service account with `manage-realm`, `manage-users`, `manage-clients`).
2. Runs `init`, `joiner (alice)`, `joiner (bob)`, `mover (alice→admin)`, `leaver (bob)`.
3. Prints a clean sequence you can replay during a 2–3 minute demo.

Available targets (see `Makefile`):
- `make init`, `make joiner-alice`, `make joiner-bob`, `make mover-alice`, `make leaver-bob`, `make delete-realm`
- `make pytest` (runs the Flask/JML unit tests)

## Flask demo UI highlights
- Uses Jinja templates (`app/templates/`) and a single stylesheet (`app/static/css/styles.css`).
- The top navigation exposes **Home / Profile / Admin / Logout** plus a *Login as different user* shortcut (forces `prompt=login`).
- `/me` renders roles as color-coded chips and shows the userinfo JSON (server-side formatting, no tokens in the DOM).
- `/admin` is decorated with `@require_role("admin")`; unauthorized users receive a styled 403 page.
- Security headers (`Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, `Expires: 0`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`) are applied to authenticated/403 responses to prevent back-button disclosure.

## Automation script (`scripts/jml.py`)
- `init`: realm/client/roles setup (idempotent).
- `joiner`: creates/updates a user, sets a temporary password, sets required actions **unless** TOTP is already configured (new helper `_user_has_totp`).
- `mover`: removes/adds realm roles.
- `leaver`: disables the account.
- `delete-realm`: deletes realm (skips master, useful for clean resets).
- Authenticates to Keycloak using client-credentials from `automation-cli`; master admin credentials are only needed for the bootstrap command.

## MFA behaviour
- On first run `joiner` sets `CONFIGURE_TOTP` and `UPDATE_PASSWORD`.
- If the user already has an OTP credential, `joiner` keeps it and only re-applies `UPDATE_PASSWORD`, so repeated demos do **not** force re-enrolment unless you wipe the realm.

## Security guardrails (dev PoC)
1. **Flow**: Authorization Code + PKCE only; no implicit/hybrid.
2. **Sessions**: server-side, HttpOnly, SameSite=Lax (and `Secure` optional via env).
3. **Tokens/Secrets**: never written to logs/DOM/localStorage; `.env` is gitignored.
4. **Headers**: `Cache-Control`, `Pragma`, `Expires`, `X-Content-Type-Options`, `X-Frame-Options` enforced on sensitive routes.
5. **Least privilege**: automation uses `automation-cli` (manage-users / manage-clients / manage-realm) scoped to realm `demo`.
6. **MFA**: `CONFIGURE_TOTP` required on first login; `joiner` re-applies only if the user lacks an OTP credential.
7. **RBAC**: `/admin` is enforced server-side; UI just reflects effective roles.
8. **Dev only**: plain HTTP + dev secrets; README reminds that production needs HTTPS, dedicated secrets storage, monitoring, etc.

## Demo walkthrough (suggested)
1. `make demo` → show CLI output (realm, users, role promotion, leaver).
2. `python app/flask_app.py` → open `http://localhost:5000`.
3. Login as `alice` with temp password, enrol OTP, reach `/me` (observe claims/roles).
4. Visit `/admin` (should succeed with admin chip). Logout.
5. Attempt login as `bob` (disabled) or as a non-admin to show 403 page.
6. Use `make joiner-bob` + `make mover-alice` live if you want to demonstrate automation on the fly.

## Tests
```bash
pytest            # runs both Flask UI and JML unit tests
```
Coverage includes RBAC headers, role filtering, bootstrap guardrails, and the new service-account helper.

## Cleanup
```bash
docker compose down -v
rm -rf .venv  # optional
```

## Next steps (if you take it further)
- Serve Flask behind HTTPS (gunicorn + nginx) and enforce `SESSION_COOKIE_SECURE`.
- Externalize secrets (vault, SOPS, AWS Parameter Store, …) and rotate `automation-cli` automatically.
- Add SCIM/SCIM-like provisioning or webhook integrations.
- Expand test coverage with integration tests (e.g., `pytest` + `responses` mocking Keycloak endpoints).
