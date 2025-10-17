# Guide de Test — API SCIM 2.0

Ce guide vous accompagne pour tester l'API SCIM 2.0 de votre projet IAM PoC.

---

## Prérequis

1. **Stack Docker active** :
   ```bash
   make quickstart
   ```

2. **Variables d'environnement** (dans `.env` ou `.env.demo`) :
   ```bash
   KEYCLOAK_SERVICE_CLIENT_SECRET=your-secret
   KEYCLOAK_URL=http://localhost:8080
   KEYCLOAK_REALM=demo
   ```

3. **Outils requis** :
   - `curl`
   - `jq` (pour parsing JSON)
   - `bash` / `zsh`

---

## Test Rapide (1 minute)

### Script Automatisé

```bash
./scripts/test_scim_api.sh
```

**Sortie attendue** :
```
═══════════════════════════════════════════════════
       SCIM 2.0 API Test Suite
═══════════════════════════════════════════════════

[test] Obtaining service account token...
✓ Token obtained (1247 chars)

[test] Test 1: GET /ServiceProviderConfig
✓ ServiceProviderConfig OK

[test] Test 3: POST /Users (create)
✓ User created: scimtest1729178240 (ID: 12345678...)

...

✓ All tests passed
```

---

## Tests Manuels

### 1. Obtenir un Token OAuth

```bash
export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_REALM="demo"
export CLIENT_ID="automation-cli"
export CLIENT_SECRET="your-secret-here"

TOKEN=$(curl -sk -X POST \
  "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  | jq -r '.access_token')

echo "Token obtained: ${TOKEN:0:50}..."
```

### 2. ServiceProviderConfig

```bash
curl -sk "https://localhost/scim/v2/ServiceProviderConfig" | jq '.'
```

**Réponse attendue** :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "filter": {
    "supported": true,
    "maxResults": 200
  },
  "patch": {
    "supported": false
  },
  "bulk": {
    "supported": false,
    "maxOperations": 0,
    "maxPayloadSize": 0
  }
}
```

### 3. Créer un Utilisateur (POST)

```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser123",
    "emails": [{"value": "testuser123@example.com", "primary": true}],
    "name": {"givenName": "Test", "familyName": "User"},
    "active": true
  }' | jq '.'
```

**Réponse attendue** (HTTP 201) :
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "userName": "testuser123",
  "name": {
    "givenName": "Test",
    "familyName": "User"
  },
  "emails": [
    {
      "value": "testuser123@example.com",
      "primary": true
    }
  ],
  "active": true,
  "_tempPassword": "Xy7#kL9pQm2$vN3r",
  "meta": {
    "resourceType": "User",
    "created": "2025-10-17T14:30:00Z",
    "lastModified": "2025-10-17T14:30:00Z",
    "location": "https://localhost/scim/v2/Users/a1b2c3d4..."
  }
}
```

### 4. Lister les Utilisateurs (GET)

```bash
curl -sk "https://localhost/scim/v2/Users?count=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**Réponse attendue** :
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 4,
  "startIndex": 1,
  "itemsPerPage": 4,
  "Resources": [
    {
      "id": "...",
      "userName": "alice",
      "active": true,
      ...
    },
    ...
  ]
}
```

### 5. Filtrer par Username

```bash
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22alice%22" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**Réponse attendue** :
```json
{
  "totalResults": 1,
  "Resources": [
    {
      "userName": "alice",
      ...
    }
  ]
}
```

### 6. Récupérer un Utilisateur Spécifique

```bash
USER_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

curl -sk "https://localhost/scim/v2/Users/${USER_ID}" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

### 7. Désactiver un Utilisateur (PUT)

```bash
curl -sk -X PUT "https://localhost/scim/v2/Users/${USER_ID}" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser123",
    "active": false
  }' | jq '.'
```

**Réponse attendue** :
```json
{
  "id": "a1b2c3d4...",
  "userName": "testuser123",
  "active": false,
  ...
}
```

### 8. Supprimer un Utilisateur (DELETE)

```bash
curl -sk -X DELETE "https://localhost/scim/v2/Users/${USER_ID}" \
  -H "Authorization: Bearer $TOKEN" \
  -w "HTTP Status: %{http_code}\n"
```

**Réponse attendue** : HTTP 204 (No Content)

---

## Tests d'Erreurs

### 1. Conflit de Username (409)

```bash
# Créer alice (déjà existante)
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice",
    "emails": [{"value": "alice@example.com"}],
    "active": true
  }' | jq '.'
```

**Réponse attendue** (HTTP 409) :
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with userName 'alice' already exists"
}
```

### 2. Validation Échec (400)

```bash
# Username manquant
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "emails": [{"value": "test@example.com"}]
  }' | jq '.'
```

**Réponse attendue** (HTTP 400) :
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "userName is required"
}
```

### 3. Utilisateur Non Trouvé (404)

```bash
curl -sk "https://localhost/scim/v2/Users/nonexistent-id-12345" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**Réponse attendue** (HTTP 404) :
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "User not found"
}
```

---

## Vérification de l'Audit Trail

Après avoir créé/modifié des utilisateurs via SCIM :

```bash
# Vérifier que les events sont loggés
cat logs/audit.jsonl | tail -5

# Vérifier les signatures
python -m scripts.audit verify
```

**Sortie attendue** :
```
✅ All 15 events verified successfully
No tampering detected
```

---

## Tests de Performance (Optionnel)

### Latence Moyenne

```bash
for i in {1..10}; do
  time curl -sk "https://localhost/scim/v2/Users?count=10" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null 2>&1
done
```

**Attendu** : < 200ms par requête

### Throughput

```bash
# Créer 50 utilisateurs en parallèle
seq 1 50 | xargs -P 10 -I {} curl -sk -X POST \
  "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"],
    \"userName\": \"loadtest{}\",
    \"emails\": [{\"value\": \"loadtest{}@example.com\"}],
    \"active\": true
  }"
```

---

## Troubleshooting

### Erreur : Token Invalide (401)

**Cause** : Token expiré ou secret incorrect

**Solution** :
```bash
# Re-générer le token
TOKEN=$(curl -sk -X POST \
  "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=${CLIENT_SECRET}" \
  | jq -r '.access_token')
```

### Erreur : Connection Refused

**Cause** : Stack Docker non démarrée

**Solution** :
```bash
make quickstart
```

### Erreur : CSRF Validation Failed

**Cause** : Requête sans `Content-Type: application/scim+json`

**Solution** :
```bash
# Ajouter le header
-H "Content-Type: application/scim+json"
```

### Erreur : 500 Internal Server Error

**Cause** : Keycloak inaccessible ou secret manquant

**Solution** :
```bash
# Vérifier logs Flask
docker logs iam-poc-flask-app-1

# Vérifier Keycloak
curl -sk http://localhost:8080/health
```

---

## Checklist de Validation

Avant de marquer Phase 2.1 comme complète :

- [ ] `./scripts/test_scim_api.sh` passe tous les tests
- [ ] Création manuelle d'utilisateur via curl fonctionne
- [ ] Filtrage par username retourne bon résultat
- [ ] Désactivation utilisateur révoque sessions immédiatement
- [ ] Audit logs contiennent events SCIM avec signatures
- [ ] `python -m scripts.audit verify` ne trouve aucune altération
- [ ] Documentation SCIM lue et comprise (`docs/SCIM_API_GUIDE.md`)

---

## Prochaines Étapes

Après validation :

1. **Intégrer avec IdP externe** (Okta/Azure AD)
2. **Monitorer métriques** (temps réponse, erreurs)
3. **Ajouter rate limiting** (protection DoS)
4. **Implémenter webhooks** (notifications push)

---

**Dernière mise à jour** : 2025-10-17  
**Auteur** : GitHub Copilot
