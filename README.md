# Mini IAM Lab (5-Day PoC) — Keycloak + OIDC + MFA + JML Automation

This project is a compact **Identity & Access Management (IAM)** lab to showcase your fit for an **IAM Junior Developer** internship.

## What you get
- **Keycloak** (Docker) as IdP (realm `demo`)
- **Flask** app with **OIDC (Authorization Code + PKCE)** login
- **MFA (TOTP)** enforced for new users
- **RBAC** via Keycloak realm roles (`admin`, `analyst`)
- **JML automation** script (`joiner/mover/leaver`) using Keycloak **Admin REST API**

## Architecture (high level)
```
[User] <--browser--> [Flask App @ http://localhost:5000]
   |                                 |
   | OIDC Auth Code Flow             | OIDC Discovery / Token Introspection
   v                                 v
                         [Keycloak @ http://localhost:8080]
                              Realm: demo
                              Client: flask-app (public)
                              Roles: admin, analyst
```

---

## Prerequisites
- **Docker Desktop** (or Docker Engine) installed
- **Python 3.10+** and `pip`

---

## 1) Start Keycloak
```bash
docker compose up -d
# Wait ~10–20s for Keycloak to become ready
```

Keycloak admin (dev mode):
- URL: http://localhost:8080
- Username: `admin`
- Password: `admin`

> NOTE: Dev settings only. Do **not** use in production.

---

## 2) Initialize the realm, client, and roles
```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r scripts/requirements.txt
python scripts/jml.py init --kc-url http://localhost:8080 --admin-user admin --admin-pass admin --realm demo --client-id flask-app --redirect-uri http://localhost:5000/callback
```

This will:
- Create realm `demo` (idempotent)
- Create a **public** client `flask-app` (Auth Code + PKCE) with redirect `http://localhost:5000/callback`
- Create realm roles: `admin`, `analyst`

---

## 3) Create a user (Joiner) with MFA required
```bash
python scripts/jml.py joiner --realm demo --username alice --email alice@example.com --first Alice --last Example --role analyst --temp-password Passw0rd!
```

This will:
- Create user `alice`
- Set temp password (user must change on first login)
- Require **TOTP enrollment** at next login
- Assign role `analyst`

You can later **move** the user:
```bash
python scripts/jml.py mover --realm demo --username alice --from-role analyst --to-role admin
```

Or **disable** (leaver):
```bash
python scripts/jml.py leaver --realm demo --username alice
```

---

## 4) Run the Flask OIDC demo app
Install app deps and run:
```bash
pip install -r app/requirements.txt
export KEYCLOAK_ISSUER=http://localhost:8080/realms/demo
export OIDC_CLIENT_ID=flask-app
export OIDC_CLIENT_SECRET=      # (empty for public client)
export OIDC_REDIRECT_URI=http://localhost:5000/callback
python app/flask_app.py
# Open http://localhost:5000
```

What you can demo:
- **Login** with `alice` → will force **TOTP** configuration (scan QR code)
- App shows **ID Token** claims and the user's **roles**
- Try **role-based route**: `/admin` only works for `admin`

---

## 5) Demo Script (2–3 minutes)
1. Show `docker compose ps` (Keycloak up).  
2. Run `joiner` to create `alice`.  
3. Login at the app, enroll **TOTP** and access `/me`.  
4. `mover` from `analyst` → `admin`, refresh page → `/admin` now works.  
5. `leaver` disables the account → next login fails.

---

## 6) Test Scenarios
- Happy path login (with MFA)  
- Wrong password / expired session  
- Role change (analyst → admin) affects access  
- Leaver disables account (401/403 at app)

---

## 7) Notes
- For brevity, this PoC uses **public** client and **dev** Keycloak settings.  
- In production you would use **confidential** client, HTTPS, secrets in a **vault**, etc.

---

## 8) Cleanup
```bash
docker compose down -v
deactivate
```

Good luck with your interview! ✨
