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

## Quick start (6 commands)
```bash
./scripts/run_https.sh                                 # generate cert + start Keycloak, Flask app, reverse proxy
make bootstrap-service-account # one-time; generates secret for automation-cli
make demo                                                   # idempotent init + sample users + mover/leaver
```
Notes:
- `make bootstrap-service-account` now refreshes the secret in `.env` automatically; re-source your environment after running it.
- `make demo` relies on the secret stored in `.env`; run the bootstrap target once (or whenever you intentionally rotate the client secret).
- Once the compose stack is up, access the demo at https://localhost (Chrome/Firefox will prompt to trust the self-signed cert on first visit).
- Keycloak is bound to `127.0.0.1:8080`; adjust `KEYCLOAK_URL` if you map the container differently.
- To stop the stack, run `docker compose down` (add `-v` if you want to clear Keycloak's data volume).
- Docker Compose reads variables from `.env` automatically, so updating that file keeps the containers in sync with the CLI tooling.
- A local Python virtualenv is optional; keep it only if you want to run pytest or scripts hors Docker.
- Session cookies ship with `Secure`/`HttpOnly`/`SameSite=Lax`; override `TRUSTED_PROXY_IPS` if your reverse proxy sits outside the default RFC1918 range.
- `DEMO_MODE=true` permet une mise en route sans `.env` en injectant des secrets/identifiants de démonstration (`demo-service-secret`, `admin`, `Passw0rd!`, etc.) et affiche un avertissement au démarrage. En production (`DEMO_MODE=false` ou absent), ces variables deviennent obligatoires et l'app refusera de démarrer si elles manquent.

## Mini-checklist « démo saine »
- `DEMO_MODE=true` requis pour activer tous les fallbacks.
- Secrets de démo manifestes (`admin/admin`, `demo-service-secret`, `Passw0rd!`) + warning au démarrage.
- Services exposés uniquement en local (`127.0.0.1` pour Keycloak, Nginx 80/443 sur localhost).
- ProxyFix + cookies Secure/HttpOnly/SameSite + en-têtes de sécurité actifs.
- Pour passer en production : copier `.env.demo`, renseigner vos propres secrets, régler `DEMO_MODE=false`, basculer les URLs en `https://`, élargir `TRUSTED_PROXY_IPS`.

## What `make demo` does
1. Bootstraps/rotates the `automation-cli` confidential client in realm `demo` (service account with `manage-realm`, `manage-users`, `manage-clients`).
2. Runs `init`, `joiner (alice)`, `joiner (bob)`, `mover (alice→admin)`, `leaver (bob)` via `scripts/demo_jml.sh`.

## HTTPS & reverse proxy
- `scripts/run_https.sh` creates a self-signed certificate (default validity 30 days) and launches the compose stack; rerun with `CERT_DAYS=7 ./scripts/run_https.sh --rotate` to regenerate on demand.
- `docker-compose.yml` now includes:
  - `flask-app`: a dedicated Gunicorn worker listening on port 8000.
  - `reverse-proxy`: Nginx terminating TLS, redirecting HTTP→HTTPS, and forwarding `Host`/`X-Forwarded-*` headers to the Flask app.
- `proxy/nginx.conf` adds HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Content-Security-Policy, and X-XSS-Protection headers (services bound to localhost only).
- Flask trusts the forwarded headers through `ProxyFix`, so `url_for` and redirects generate HTTPS links while session cookies stay secure.
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
2. **Sessions**: server-side, HttpOnly, SameSite=Lax, always `Secure`; CSRF tokens required for POST/PUT/PATCH/DELETE; rotate `FLASK_SECRET_KEY` with `FLASK_SECRET_KEY_FALLBACKS`.
3. **Trusted proxy**: requests must arrive via the configured proxy IP ranges (`TRUSTED_PROXY_IPS`) with strict `X-Forwarded-*` values.
4. **Tokens/Secrets**: never written to logs/DOM/localStorage; `.env` is gitignored.
5. **Headers**: `Cache-Control`, `Pragma`, `Expires`, `X-Content-Type-Options`, `X-Frame-Options` enforced on sensitive routes.
6. **Least privilege**: automation uses `automation-cli` (manage-users / manage-clients / manage-realm) scoped to realm `demo`.
7. **MFA**: `CONFIGURE_TOTP` required on first login; `joiner` re-applies only if the user lacks an OTP credential.
8. **RBAC**: `/admin` is enforced server-side; UI just reflects effective roles.
9. **Dev only**: plain HTTP + dev secrets; README reminds that production needs HTTPS, dedicated secrets storage, monitoring, etc.

## Demo walkthrough (suggested)
1. `make demo` → show CLI output (realm, users, role promotion, leaver).
2. `python app/flask_app.py` (optionnel, hors Docker) → open `http://localhost:5000`.
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
