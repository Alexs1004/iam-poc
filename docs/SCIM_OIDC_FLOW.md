# SCIM & OIDC Flow (Swiss Azure PoC)

Ce document illustre le parcours d’authentification OIDC, le provisioning SCIM ainsi que le mapping d’attributs dans le cadre du PoC IAM orienté recrutement.

## 1. Séquence OIDC (PKCE)

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Browser
    participant Flask as Flask (IAM PoC)
    participant Keycloak
    participant KV as Azure Key Vault

    User->>Browser: Accès /admin
    Browser->>Flask: HTTPS GET /admin (state nonce)
    Flask-->>Browser: Redirect vers Keycloak (code_challenge, client_id=flask-app)
    Browser->>Keycloak: GET /realms/demo/protocol/openid-connect/auth
    Keycloak-->>Browser: UI Login (TOTP + password)
    Browser->>Keycloak: POST credentials + OTP
    Keycloak-->>Browser: Redirect (code)
    Browser->>Flask: GET /callback?code=...
    Flask->>Keycloak: POST token (code_verifier)
    Keycloak-->>Flask: id_token + access_token
    Flask->>KV: DefaultAzureCredential (pour secrets OIDC si nécessaire)
    KV-->>Flask: Secrets (client_secret, JWKS cache)
    Flask-->>Browser: Session sécurisée (cookie HttpOnly, SameSite=Lax)
```

## 2. Séquence SCIM (Service Account)

```mermaid
sequenceDiagram
    autonumber
    participant HR as SCIM Client
    participant Flask as Flask SCIM API
    participant Provision as provisioning_service.py
    participant JML as scripts/jml.py
    participant Keycloak
    participant Audit as audit.py (JSONL)

    HR->>Flask: POST /scim/v2/Users (Bearer automation-cli)
    Flask->>Provision: validate payload, map attributs
    Provision->>JML: create_user(username, realm)
    JML->>Keycloak: Admin REST API (service account)
    Keycloak-->>JML: 201 Created
    JML-->>Provision: succès (id, meta)
    Provision->>Audit: log_jml_event(joiner,…)
    Audit->>Audit: HMAC signature, chmod 600
    Provision-->>Flask: User DTO
    Flask-->>HR: 201 + payload SCIM
```

## 3. Mapping d’Attributs

| SCIM                        | Keycloak                               | Commentaire                                        |
|----------------------------|-----------------------------------------|----------------------------------------------------|
| `userName`                 | Username                                | Normalisé lowercase, sans accents.                 |
| `name.givenName`           | `firstName`                             | UTF-8 autorisé, max 64 caractères.                 |
| `name.familyName`          | `lastName`                              | Idem, obligatoire pour création.                   |
| `emails[primary].value`    | `email`                                 | Validation stricte (regex + domaine).              |
| `active`                   | User enabled/disabled                   | `false` ⇒ disable + revoke sessions.               |
| `externalId`               | Keycloak attribute `externalId` (custom)| Optionnel, utilisé pour mapping ATS.               |
| `meta.location`            | Calculé par Flask                       | Ex: `https://host/scim/v2/Users/{id}`              |
| `schemas`                  | RFC 7644 core                           | Aucun schéma custom pour PoC.                      |

## 4. Points d’attention

- **OAuth obligatoire** : chaque appel SCIM doit fournir un bearer token (service account `automation-cli`).  
- **Filtrage restreint** : seul `filter=userName eq "value"` est autorisé pour limiter les risques d’injection SCIM.  
- **Audit trail** : toute opération génère une entrée signée HMAC (non répudiation).  
- **Migration Entra ID** : mapping identique (userPrincipalName ⇄ `userName`) ; prévoir extension attributs custom.  
- **Limites** : opérations PATCH limitées à `replace` (nom, email, active).

Références : RFC 7644, RFC 7643, FINMA Circ. 08/21 (sécurité des API), nLPD art. 8-12 (principes).

