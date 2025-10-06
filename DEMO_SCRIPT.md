# IAM PoC — Demo Script (2–3 minutes)

## 0) Intro (15s)
“J’ai construit un mini-lab IAM : Keycloak (Docker) + app Flask en OIDC, **MFA TOTP**, rôles **admin/analyst**, et un script **JML** (joiner/mover/leaver). Tout est documenté et automatisé.”

## 1) Show services (10s)
```bash
docker compose ps
```
> Keycloak is running on http://localhost:8080

## 2) Initialize Realm & Client (20s)
```bash
python scripts/jml.py init --kc-url http://localhost:8080 --admin-user admin --admin-pass admin --realm demo --client-id flask-app --redirect-uri http://localhost:5000/callback
```
- Creates realm `demo`, client `flask-app`, roles `admin`/`analyst`.

## 3) Create User (Joiner) (20s)
```bash
python scripts/jml.py joiner --realm demo --username alice --email alice@example.com --first Alice --last Example --role analyst --temp-password Passw0rd!
```
- Temp password + **required actions**: TOTP + password update.

## 4) Login & MFA (40s)
- Open `http://localhost:5000`, click **Login**.
- Sign in as `alice`, Keycloak asks to **configure TOTP** (scan QR / enter code).
- After login, view `/me` → see **claims** and **roles**.

## 5) RBAC: Analyst → Admin (20s)
```bash
python scripts/jml.py mover --realm demo --username alice --from-role analyst --to-role admin
```
- Refresh app → `/admin` now accessible.

## 6) Leaver (20s)
```bash
python scripts/jml.py leaver --realm demo --username alice
```
- Try to login again → access denied/disabled.

## 7) Wrap-up (15s)
- Security choices: **PKCE**, **MFA**, **server-side session**, **least privilege** (service account planned).
- If I join, next steps: confidential client + HTTPS, tests & CI, explore **SCIM**.

## Fallback (if live demo fails)
- Show screenshots: login, TOTP, `/me`, `/admin` 403 → 200 after role change.
- Explain flows and decisions (1 minute max).
