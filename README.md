# Mini IAM Lab — Keycloak + Flask + JML Automation

> Hands-on identity lab showing how I design, secure, and automate OIDC user journeys end to end.

## Elevator pitch
- Identity & access sandbox that combines Authorization Code + PKCE, TOTP MFA, and RBAC to mirror enterprise IAM requirements.
- Python automation (`scripts/jml.py`, `Makefile`) provisions Keycloak, enforces joiner/mover/leaver workflows, and rotates secrets safely.
- Developer-friendly Docker Compose stack with HTTPS by default, optional Azure Key Vault integration, and pytest coverage for the security controls.

## Project Highlights
- Production-style auth: Authorization Code + PKCE, required TOTP enrollment, server-side sessions, CSRF protection, and hardened security headers in `app/flask_app.py`.
- One-command demo: `make quickstart` builds TLS certs, starts Keycloak, Flask, and Nginx, and runs the scripted demo via `scripts/run_https.sh` and `scripts/demo_jml.sh`.
- Operational discipline: health checks on every container, Make targets that fail fast on missing secrets, and tests that lock down RBAC, cookies, CSRF, and proxy handling (`tests/test_flask_app.py`).

## Architecture in 60 seconds
- **Keycloak 24** (`docker-compose.yml`) acts as the IdP with realm `demo`, public client `flask-app`, and service client `automation-cli`.
- **Flask app** (`Dockerfile.flask`, `app/flask_app.py`) uses Authlib + Flask-Session, renders Jinja templates, and lives behind an Nginx reverse proxy.
- **Automation CLI** (`scripts/jml.py`) drives the Keycloak admin REST API for realm bootstrap, joiner/mover/leaver flows, and secret rotation.
- **Tooling**: `scripts/run_https.sh` issues self-signed certs, syncs Azure credentials, rebuilds containers, and keeps the stack reproducible on any machine.

## Demo storyline (Joiner → Mover → Leaver)
1. `make quickstart` or `./scripts/run_https.sh` brings up the stack with HTTPS and runs `make demo`.
2. `scripts/jml.py init` seeds the realm, roles, redirect URIs, and MFA requirements.
3. `joiner` commands create analyst users with temporary passwords plus required TOTP enrollment.
4. `mover` promotes Alice to `admin`, while `leaver` disables Bob to showcase access revocation and login impact in the Flask UI.

## Getting started

**Prerequisites**: Docker Desktop/Engine, Python 3.10+, `make`, and (optionally) Azure CLI if you enable Key Vault.

### Quick start (recommended)
```bash
cp .env.demo .env                # defaults enable DEMO_MODE
make quickstart                  # certificates + stack + automation storyline
open https://localhost           # trust the self-signed cert on first visit
```

### Run it step by step
```bash
./scripts/run_https.sh           # generate certs, build Flask image, start Docker Compose
make bootstrap-service-account   # one-time secret rotation via Keycloak master realm
make demo                        # idempotent init + joiner/mover/leaver walk-through
```
When `DEMO_MODE=true`, the app injects temporary secrets and warns at startup. Set `DEMO_MODE=false`, supply your own secrets in `.env`, and the same automation becomes production-ready.

**Stopping & cleaning**
```bash
docker compose down              # stop services (add -v to clear Keycloak data)
make clean-secrets               # remove cached secrets and Azure credentials
```

## Automation CLI & Make targets
- `scripts/jml.py` exposes subcommands (`init`, `joiner`, `mover`, `leaver`, `delete-realm`, `bootstrap-service-account`) with consistent logging and timeouts.
- The `Makefile` wraps CLI usage and protects against missing secrets by loading `.env`, optionally fetching values from Azure Key Vault, and providing targets like `fresh-demo`, `rotate-secret`, and `doctor`.
- `scripts/demo_jml.sh` orchestrates the end-to-end storyline, so recruiters can see repeatable IAM automation in practice.

## Security guardrails baked in
- Authorization Code + PKCE, enforced roles on every route, MFA required actions, and server-side session storage.
- Strict cookie flags (`Secure`, `HttpOnly`, `SameSite=Lax`), CSRF tokens on state-changing endpoints, and trusted proxy allow-lists.
- Nginx reverse proxy with HSTS, TLS 1.2+, and explicit security headers; TLS certs rotate automatically with each run.

## Cloud-ready secrets with Azure
- Setting `AZURE_USE_KEYVAULT=true` instructs the app and Make targets to pull secrets, certificates, and keys from Azure Key Vault.
- `scripts/run_https.sh` syncs your `az login` context into the container, supports device-code auth, and verifies access tokens before booting the stack.
- Secrets written by `make bootstrap-service-account` land in Key Vault and are reloaded into Flask via environment variables or Key Vault APIs.

## Quality & testing
- `pytest` suite (`tests/test_flask_app.py`) validates RBAC rules, security headers, CSRF enforcement, and proxy safeguards.
- Container health checks ensure Keycloak, Flask, and Nginx are ready before automation runs.
- `make doctor` provides a pre-flight to confirm Azure access and Docker compatibility.

## Repository tour
- `app/` Flask app, templates, and static assets for the demo UI.
- `scripts/` automation helpers (`run_https.sh`, `jml.py`, `demo_jml.sh`, `update_env.py`, `keycloak_entrypoint.sh`).
- `proxy/nginx.conf` reverse proxy configuration with strict security headers.
- `docker-compose.yml` and `Dockerfile.flask` define the local environment.
- `tests/` pytest coverage focused on authentication and authorization behavior.

## Where I’d take it next
- Add integration tests that exercise live Keycloak endpoints via dockerized pytest.
- Publish the automation CLI as a lightweight package and plug in SCIM/webhook integrations.
- Wire the stack into GitHub Actions for automated builds, linting, and container image security scanning.
