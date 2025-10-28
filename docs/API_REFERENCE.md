# API Reference — SCIM 2.0

## Scope
- Standard SCIM 2.0 endpoints exposés via Flask.
- Compatible clients : Azure AD (Entra ID), Okta, systèmes internes.
- **Auth** : OAuth 2.0 Bearer Token (client credentials). Validation serveur en cours d’implémentation — voir [Security Design](SECURITY_DESIGN.md#road-to-azure-native).

## Base URL
- Reverse proxy (démo) : `https://localhost/scim/v2`
- Direct Flask (dev) : `http://localhost:8000/scim/v2`

## Endpoints
| Méthode | URI | Description |
|---------|-----|-------------|
| `GET` | `/Users` | Lister les utilisateurs (supporte `filter`, `count`, `startIndex`). |
| `POST` | `/Users` | Créer un utilisateur. |
| `GET` | `/Users/{id}` | Récupérer un utilisateur par ID. |
| `PUT` | `/Users/{id}` | Remplacer l’utilisateur (used pour mover/leaver). |
| `PATCH` | `/Users/{id}` | Support planifié (RFC 7644 section 3.5). |
| `DELETE` | `/Users/{id}` | Soft delete (désactive l’utilisateur). |
| `GET` | `/ServiceProviderConfig` | Capacités déclarées (auth, filtering). |
| `GET` | `/Schemas` | Schémas supportés (User, EnterpriseUser). |
| `GET` | `/ResourceTypes` | Types de ressources disponibles. |

## Headers requis
- `Content-Type: application/scim+json`
- `Accept: application/scim+json`
- `Authorization: Bearer <token>`
- `X-Request-ID` conseillé pour corréler les logs (si client supporte).

## Exemples `curl`
```bash
# Obtenir un token (demo realm)
TOKEN=$(curl -sk -X POST \
  "https://localhost/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=automation-cli" \
  -d "client_secret=demo-service-secret" \
  | jq -r '.access_token')

# Créer un utilisateur
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "caroline",
    "name": {"givenName": "Caroline", "familyName": "Meyer"},
    "emails": [{"value": "caroline@example.com", "primary": true}],
    "active": true,
    "roles": [{"value": "analyst"}]
  }'

# Lister avec filtre
curl -sk "https://localhost/scim/v2/Users?filter=userName%20eq%20%22alice%22" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/scim+json"
```

## Format de réponse
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "5fde8f20-cbab-4fbb-b1b5-0a7b8210e8b2",
  "userName": "caroline",
  "name": {
    "givenName": "Caroline",
    "familyName": "Meyer"
  },
  "emails": [
    {
      "value": "caroline@example.com",
      "primary": true
    }
  ],
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2025-01-20T10:30:12Z",
    "lastModified": "2025-01-20T10:30:12Z",
    "location": "https://localhost/scim/v2/Users/5fde8f20-cbab-4fbb-b1b5-0a7b8210e8b2"
  }
}
```

## Codes d'erreur courants
| HTTP | SCIM Error | Motif | Notes |
|------|------------|-------|-------|
| `400` | `invalidValue` | Payload invalide, `schemas` absents | Vérifier le format JSON SCIM. |
| `401` | `invalidToken` | **À implémenter** : token manquant/expiré | Priorité P0 dans la [Roadmap](ROADMAP.md). |
| `403` | `forbidden` | Rôle insuffisant | Requiert `realm-management` (demo). |
| `404` | `notFound` | ID inconnu | Vérifier l’UUID retourné lors de la création. |
| `409` | `uniqueness` | `userName` déjà existant | Se base sur `userName`. |
| `500` | `internalError` | Erreur Keycloak ou transformation | Voir logs Flask + audit HMAC. |

## Mapping Keycloak
- `userName` → `username`
- `name.givenName` → `firstName`
- `name.familyName` → `lastName`
- `emails[0].value` → attribut mail + `emailVerified`
- `roles` → groupes Keycloak (`iam-analyst`, `iam-operator`, etc.)
- `active=false` → `enabled=false` dans Keycloak

## Bonnes pratiques intégrateur
- Utiliser des scopes dédiés (`scim.provisioning`) dans l’IdP.
- Conserver le `id` SCIM retourné pour les opérations PUT/DELETE.
- Logger `X-Request-ID` côté client pour faciliter la corrélation.
- Tester les scénarios négatifs (`401`, `403`, `409`) avant mise en production.

## Ressources complémentaires
- Principes sécurité : [Security Design](SECURITY_DESIGN.md)
- Procédure setup : [Setup Guide](SETUP_GUIDE.md)
- Tests associés : [Test Strategy](TEST_STRATEGY.md)
