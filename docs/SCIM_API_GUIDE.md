# 🔌 Mini API SCIM 2.0 — Guide d'utilisation

## 📌 Vue d'ensemble

Une implémentation minimale de SCIM 2.0 (RFC 7644) exposant les endpoints essentiels pour le provisioning d'utilisateurs via une API REST standard.

**Base URL** : `https://localhost/scim/v2`

**Authentification** : OAuth 2.0 Bearer Token (service account)

---

## 🚀 Endpoints disponibles

| Endpoint | Méthode | Description | RFC |
|----------|---------|-------------|-----|
| `/ServiceProviderConfig` | GET | Configuration du fournisseur | §5 |
| `/ResourceTypes` | GET | Types de ressources supportés | §6 |
| `/Schemas` | GET | Schémas SCIM disponibles | §7 |
| `/Users` | POST | Créer un utilisateur | §3.3 |
| `/Users` | GET | Lister les utilisateurs | §3.4.2 |
| `/Users/{id}` | GET | Récupérer un utilisateur | §3.4.1 |
| `/Users/{id}` | PUT | Remplacer un utilisateur | §3.5.1 |
| `/Users/{id}` | DELETE | Supprimer un utilisateur | §3.6 |

---

## 📖 Exemples d'utilisation

### 1. Configuration du service

```bash
curl https://localhost/scim/v2/ServiceProviderConfig
```

**Réponse** :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
  "filter": {
    "supported": true,
    "maxResults": 100
  },
  "authenticationSchemes": [
    {
      "type": "oauthbearertoken",
      "name": "OAuth Bearer Token"
    }
  ]
}
```

---

### 2. Créer un utilisateur (Joiner)

```bash
curl -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice",
    "emails": [
      {
        "value": "alice@example.com",
        "type": "work",
        "primary": true
      }
    ],
    "name": {
      "givenName": "Alice",
      "familyName": "Demo"
    },
    "active": true
  }'
```

**Réponse** (201 Created) :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "userName": "alice",
  "emails": [
    {
      "value": "alice@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "name": {
    "givenName": "Alice",
    "familyName": "Demo",
    "formatted": "Alice Demo"
  },
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2025-10-17T14:32:10Z",
    "lastModified": "2025-10-17T14:32:10Z",
    "location": "https://localhost/scim/v2/Users/2819c223-7f76-453a-919d-413861904646"
  },
  "_tempPassword": "Xj8#kL2p@9Qm"
}
```

**Note** : `_tempPassword` est un ajout non-standard pour récupérer le mot de passe temporaire.

---

### 3. Récupérer un utilisateur

```bash
curl https://localhost/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer ${TOKEN}"
```

**Réponse** (200 OK) :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "userName": "alice",
  "emails": [...],
  "name": {...},
  "active": true,
  "meta": {...}
}
```

---

### 4. Lister les utilisateurs

```bash
# Tous les utilisateurs
curl "https://localhost/scim/v2/Users" \
  -H "Authorization: Bearer ${TOKEN}"

# Avec pagination
curl "https://localhost/scim/v2/Users?startIndex=1&count=10" \
  -H "Authorization: Bearer ${TOKEN}"

# Avec filtering (simple)
curl "https://localhost/scim/v2/Users?filter=userName%20eq%20%22alice%22" \
  -H "Authorization: Bearer ${TOKEN}"
```

**Réponse** (200 OK) :
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 3,
  "startIndex": 1,
  "itemsPerPage": 3,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "2819c223...",
      "userName": "alice",
      ...
    },
    ...
  ]
}
```

---

### 5. Désactiver un utilisateur (Leaver)

```bash
curl -X PUT https://localhost/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice",
    "active": false
  }'
```

**Réponse** (200 OK) :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "userName": "alice",
  "active": false,
  ...
}
```

**Important** : Les sessions actives sont révoquées automatiquement.

---

### 6. Supprimer un utilisateur

```bash
curl -X DELETE https://localhost/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer ${TOKEN}"
```

**Réponse** (204 No Content)

**Note** : Implémente un *soft delete* (désactivation) plutôt qu'une suppression physique.

---

## 🔐 Authentification

### Obtenir un token service account

```bash
TOKEN=$(curl -X POST https://localhost/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=${KEYCLOAK_SERVICE_CLIENT_SECRET}" \
  | jq -r '.access_token')
```

Puis utiliser dans les requêtes :

```bash
curl https://localhost/scim/v2/Users \
  -H "Authorization: Bearer ${TOKEN}"
```

---

## ⚠️ Limitations actuelles

| Fonctionnalité SCIM | Implémenté | Note |
|---------------------|------------|------|
| **POST /Users** | ✅ | Création complète |
| **GET /Users** | ✅ | Listing avec pagination |
| **GET /Users/{id}** | ✅ | Récupération individuelle |
| **PUT /Users/{id}** | ⚠️ Partiel | Supporte uniquement `active` |
| **PATCH /Users/{id}** | ❌ | Non implémenté |
| **DELETE /Users/{id}** | ✅ | Soft delete (disable) |
| **Filtering** | ⚠️ Basique | Uniquement `userName eq "value"` |
| **Sorting** | ❌ | Non implémenté |
| **Bulk operations** | ❌ | Non implémenté |
| **Groups** | ❌ | Non implémenté |

---

## 🔍 Gestion des erreurs

### Erreur 400 (Bad Request)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "detail": "Missing required attribute: userName"
}
```

### Erreur 404 (Not Found)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "User 2819c223-7f76-453a-919d-413861904646 not found"
}
```

### Erreur 409 (Conflict - unicité)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with userName 'alice' already exists"
}
```

### Erreur 500 (Internal Server Error)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "500",
  "detail": "Authentication failed: ..."
}
```

---

## 🧪 Tests avec curl

### Scénario complet

```bash
# 1. Obtenir token
TOKEN=$(curl -sk -X POST https://localhost/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=${KEYCLOAK_SERVICE_CLIENT_SECRET}" \
  | jq -r '.access_token')

# 2. Créer utilisateur
curl -sk -X POST https://localhost/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser",
    "emails": [{"value": "test@example.com", "primary": true}],
    "name": {"givenName": "Test", "familyName": "User"},
    "active": true
  }' | jq '.'

# 3. Lister utilisateurs
curl -sk https://localhost/scim/v2/Users \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq '.Resources[] | {id, userName, active}'

# 4. Filtrer par nom
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22testuser%22" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq '.Resources[0]'

# 5. Désactiver utilisateur
USER_ID=$(curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22testuser%22" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq -r '.Resources[0].id')

curl -sk -X PUT "https://localhost/scim/v2/Users/${USER_ID}" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser",
    "active": false
  }' | jq '.active'

# 6. Supprimer utilisateur
curl -sk -X DELETE "https://localhost/scim/v2/Users/${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -w "\nHTTP Status: %{http_code}\n"
```

---

## 📝 Audit Trail

Toutes les opérations SCIM sont enregistrées dans l'audit trail :

```bash
jq 'select(.details.via == "scim")' .runtime/audit/jml-events.jsonl
```

**Exemple d'événement** :
```json
{
  "timestamp": "2025-10-17T16:45:30Z",
  "event_type": "joiner",
  "realm": "demo",
  "username": "alice",
  "operator": "scim-api",
  "success": true,
  "details": {
    "email": "alice@example.com",
    "role": "analyst",
    "via": "scim"
  },
  "signature": "a3f5b2c8..."
}
```

---

## 🔧 Configuration

Variables d'environnement pour personnaliser l'API SCIM :

```bash
# Rôle par défaut assigné aux nouveaux utilisateurs
SCIM_DEFAULT_ROLE=analyst

# Realm Keycloak cible
KEYCLOAK_REALM=demo

# Service account pour opérations
KEYCLOAK_SERVICE_CLIENT_ID=automation-cli
KEYCLOAK_SERVICE_CLIENT_SECRET=<secret>
```

---

## 🚀 Intégration avec systèmes externes

### Okta → SCIM

1. Dans Okta Admin : Applications → Create App Integration
2. Choisir : "API Services" (SCIM)
3. Configurer :
   - **SCIM Base URL** : `https://votre-domaine.com/scim/v2`
   - **Auth** : OAuth 2.0 Bearer Token
   - **Token** : `${SERVICE_ACCOUNT_TOKEN}`

### Azure AD → SCIM

1. Azure Portal → Enterprise Applications → New
2. "Non-gallery application"
3. Provisioning → Automatic
4. Configurer :
   - **Tenant URL** : `https://votre-domaine.com/scim/v2`
   - **Secret Token** : `${SERVICE_ACCOUNT_TOKEN}`

---

## 📚 Références

- **RFC 7644** (SCIM Protocol) : https://datatracker.ietf.org/doc/html/rfc7644
- **RFC 7643** (SCIM Core Schema) : https://datatracker.ietf.org/doc/html/rfc7643
- **RFC 7642** (SCIM Requirements) : https://datatracker.ietf.org/doc/html/rfc7642

---

## ✅ Conformité

Cette implémentation est **conforme SCIM 2.0** pour :
- ✅ Endpoints REST standards (`/Users`)
- ✅ Schéma User complet avec `meta`
- ✅ Format d'erreur SCIM
- ✅ Filtering basique
- ✅ Pagination
- ✅ Content-Type `application/scim+json`

**Limitations** : PATCH, bulk operations, groups non implémentés (hors scope minimal).
