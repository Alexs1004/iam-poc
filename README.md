# Mini IAM Lab — Azure-First Identity Demo

> TODO: CI badge · TODO: Documentation link

## Table of Contents
1. [🚀 Elevator Pitch](#-elevator-pitch)
2. [💡 Project Highlights](#-project-highlights)
3. [🧱 Architecture (dev)](#-architecture-dev)
4. [⚙️ Quickstart (2 minutes)](#️-quickstart-2-minutes)
5. [🛠️ Make Commands — Quick Reference](#️-make-commands--quick-reference)
6. [🔐 Configuration & Secrets](#-configuration--secrets)
7. [🧰 Security Guardrails](#-security-guardrails)
8. [🧪 Tests](#-tests)
9. [🚧 Troubleshooting](#-troubleshooting)
10. [☁️ Production Notes](#️-production-notes)
11. [🗺️ Roadmap](#️-roadmap)
12. [📄 License & Credits](#-license--credits)
13. [🔗 Badges & Useful Links](#-badges--useful-links)

## 🚀 Elevator Pitch
Modern IAM lab that showcases how I design, secure, and automate identity workloads with Keycloak, Flask, and Azure services.  
Implements OIDC Authorization Code + PKCE, TOTP MFA, RBAC, and Joiner/Mover/Leaver automation across a Docker Compose stack.  
Azure Key Vault (DefaultAzureCredential) keeps secrets out of source control while an HTTPS reverse proxy protects every request.  
Automation scripts rebuild containers on source hash changes, rotate secrets, and validate readiness before exposing endpoints.  
Ideal for enterprise teams evaluating my approach to IAM architecture, DevSecOps, and Azure-first operations.

## 💡 Project Highlights
- Azure-first secret management via Key Vault and `DefaultAzureCredential` with device-code fallback.
- Reproducible automation: `scripts/jml.py` provisions realms, roles, and JML workflows with clear logging.
- Hardened Flask app: server-side sessions, CSRF tokens, strict proxy validation, and RBAC-protected admin routes.
- HTTPS by default: `scripts/run_https.sh` mints certs, rebuilds Gunicorn images, and wires health checks end to end.
- Operational Makefile: guard clauses highlight missing secrets, enabling safe rotations and demos (`make doctor`, `make rotate-secret`).
- Testable sandbox: pytest coverage for auth controls, ensuring “trust but verify” on cookies, headers, and RBAC.

## 🧱 Architecture (dev)
```
              +---------------------+
              |   Azure Key Vault   |
              |   (<VAULT_NAME>)    |
              +----------+----------+
                         ^
                         | secrets (DefaultAzureCredential)
+-----------+   HTTPS    |                      +----------------+
|  Browser  | <--------> |  Reverse Proxy (NGINX)| self-signed TLS|
+-----------+            v                      +-------+--------+
                        443                             |
                                                     proxy_pass
                                                      |
                                              +-------v--------+
                                              | Flask App      |
                                              | (Gunicorn)     |
                                              +-------+--------+
                                                      |
                                                      | OIDC / REST
                                                      v
                                              +-------+--------+
                                              | Keycloak 24    |
                                              | realm: demo    |
                                              +----------------+
```
Docker Compose orchestrates three services (Keycloak, Flask/Gunicorn, Nginx). Azure Key Vault remains external, providing secrets to automation and runtime via environment injection.

## ⚙️ Quickstart (2 minutes)
```bash
cp .env.demo .env                                    # enable DEMO_MODE defaults
make quickstart                                      # HTTPS certs + stack + scripted JML demo
open https://localhost                              # trust the self-signed certificate once
```
Shutdown:
```bash
make down
```

## 🛠️ Make Commands — Quick Reference
- `make quickstart` — Full bootstrap (certs, containers, automation storyline).
- `make demo` — Replay the Joiner/Mover/Leaver script against a running stack.
- `make fresh-demo` — Reset volumes, regenerate secrets, and rerun `make quickstart`.
- `make down` — Stop containers (manually add `docker compose down -v` to purge data).
- `make pytest` — Execute unit tests inside a managed Python virtual environment.
- `make rotate-secret` — Rotate Keycloak service client secret and restart Flask.
- `make doctor` — Validate `az login`, Key Vault permissions, and docker compose availability.
- `make open` — Launch https://localhost in the default browser.
- `make help` — Display all available targets with inline descriptions.

## 🔐 Configuration & Secrets
- Copy `.env.demo` to `.env`; DEMO defaults enable warnings and generate safe placeholder secrets.
- Set `DEMO_MODE=false` to force production-grade secret checks; the app will refuse to start otherwise.
- Enable `AZURE_USE_KEYVAULT=true` to load secrets from Key Vault using `DefaultAzureCredential` (supports device-code sign-in).
- Map secret names in `.env` (e.g., `AZURE_SECRET_KEYCLOAK_SERVICE_CLIENT_SECRET=<SECRET_NAME>`) instead of storing raw values.
- `scripts/run_https.sh` syncs `~/.azure` → `.runtime/azure` for container auth; clear caches with `make clean-secrets`.
- Generated Keycloak secrets land in `.runtime/secrets` and mount read-only into containers; keep the directory git-ignored.

## 🧰 Security Guardrails
- Enforce HTTPS through Nginx with self-signed certificates regenerated on every quickstart.
- Require Authorization Code + PKCE, role checks, and mandatory TOTP enrollment in the Keycloak realm.
- Rotate secrets via Key Vault-backed automation (`make rotate-secret`); never store credentials in plaintext.
- Harden session cookies (`Secure`, `HttpOnly`, `SameSite=Lax`) and validate CSRF tokens on every state-changing route.
- Restrict proxy forwarding with trusted IP allow lists and reject non-HTTPS `X-Forwarded-Proto` headers.
- Capture structured audit logs from `scripts/jml.py`, redacting tokens and surfacing failed admin calls.
- Deny missing environment variables in non-demo mode, preventing accidental startup without required secrets.

## 🧪 Tests
- `tests/test_flask_app.py` validates RBAC enforcement, admin-only routes, hardened headers, CSRF protection, secure cookies, and proxy trust logic.
- `tests/test_jml.py` exercises the automation CLI, ensuring service-account tokens, bootstrap safeguards, and secret rotations behave as expected.
- The suite runs under `DEMO_MODE=true`, keeping tests self-contained while mimicking Keycloak token payloads.

## 🚧 Troubleshooting
- **Flask unhealthy** → missing `az login` → run `make doctor` then rerun `scripts/run_https.sh`.
- **404 on automation calls** → stack not running → execute `make quickstart` to bootstrap services.
- **Key Vault denied** → insufficient RBAC → assign **Key Vault Secrets User** on `<VAULT_NAME>`.
- **Browser TLS warning** → stale cert trust → accept the new self-signed cert or clear old certificate caches.
- **Service secret empty** → skipped bootstrap → run `make bootstrap-service-account` or `make rotate-secret`.
- **Compose rebuild loop** → bind mount stale → remove `.runtime/azure` via `make clean-secrets` and retry.
- **pytest import error** → missing deps → run `make pytest` to create venv and install requirements.
- **Keycloak 401** → admin credentials absent → confirm `KEYCLOAK_ADMIN` plus Key Vault secret mappings in `.env`.

## ☁️ Production Notes
- Remove development bind mounts (`.:/srv/app`, `./.runtime/azure:/root/.azure`) and bake source into container images.
- Replace Azure CLI credential sync with Managed Identity or workload identity federation in production environments.
- Disable `DEMO_MODE`, supply real secrets via Key Vault, and ensure automation guards against missing values.
- Swap self-signed certs for managed certificates (Azure Application Gateway, Front Door, or cert manager).
- Tighten Nginx security policies (CSP, HSTS max-age, referrer policies) to align with enterprise standards.
- Keep logs centralised (Azure Monitor, App Insights) and enforce retention/alerting policies.
- Integrate container scanning and IaC validation into CI/CD (e.g., GitHub Actions + Trivy/Terraform Validate).

## 🗺️ Roadmap
- Phase 2 — Add Microsoft Entra ID (Azure AD) support with configuration switches and consent automation.
- Phase 3 — Deliver SCIM/webhook provisioning to extend JML workflows beyond Keycloak.
- Phase 4 — Introduce integration tests against live containers using pytest + docker.
- Phase 5 — Package `scripts/jml.py` as a versioned CLI with documentation and release automation.
- Phase 6 — Layer in observability (structured logging, metrics, distributed tracing) across services.
- Phase 7 — Automate certificate management (ACME/Let’s Encrypt) and key rotation pipelines.
- Phase 8 — Add policy-as-code guardrails (OPA/Azure Policy) for configuration drift detection.

## 📄 License & Credits
> TODO: Add license details and acknowledgements.

## 🔗 Badges & Useful Links
- TODO: CI status badge
- TODO: Architecture / documentation portal
- TODO: Demo walkthrough recording
