# Local SCIM Testing Guide

Objectif : vérifier rapidement l’API SCIM sur l’environnement de développement (PoC, TLS self-signed).

## 1. Prérequis

- Stack lancée : `make quickstart` (ou `make ensure-stack` si déjà démarrée).
- jq, curl installés.
- Fichier `.env` chargé (`set -a; source .env; set +a`).

## 2. Vérifier l’OpenAPI

```bash
curl -sk https://localhost/openapi.json | jq '.info.title,.paths|length'
# → "IAM PoC SCIM 2.0 API", nombre de routes
```

## 3. Consulter la documentation ReDoc

Ouvrir le navigateur sur `https://localhost/scim/docs` (certificat auto-signé).  
> ⚠️ En production, restreindre l’accès (VPN, Basic Auth, IP allow-list).

## 4. Obtenir un Bearer Token

```bash
TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${KEYCLOAK_SERVICE_CLIENT_ID:-automation-cli}" \
  -d "client_secret=${KEYCLOAK_SERVICE_CLIENT_SECRET:-demo-service-secret}" \
  | jq -r '.access_token')

echo "${TOKEN:0:32}..."
```

## 5. Appels SCIM Exemples

### Créer un utilisateur

```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "demo.scim",
    "name": {"givenName": "Demo", "familyName": "SCIM"},
    "emails": [{"value": "demo.scim@example.com", "primary": true}],
    "active": true
  }' | jq
```

### Lister / filtrer

```bash
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22demo.scim%22" \
  -H "Authorization: Bearer $TOKEN" | jq '.Resources[] | {userName,active}'
```

### Désactiver (PATCH)

```bash
curl -sk -X PATCH "https://localhost/scim/v2/Users/{userId}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "path": "active",
      "value": false
    }]
  }'
```

## 6. Nettoyage

- Supprimer l’utilisateur : `DELETE /scim/v2/Users/{id}`.
- Vérifier l’audit : `cat .runtime/audit/jml-events.jsonl | tail -n 5`.

## 7. Notes

- Si la requête retourne 401 ⇒ vérifier `TOKEN`.
- Si 403 ⇒ rôle Keycloak insuffisant.
- Si 500 ⇒ consulter `docker compose logs flask-app`.
- Limites actuelles : filtrage `eq`, patch restreint (voir OpenAPI).
