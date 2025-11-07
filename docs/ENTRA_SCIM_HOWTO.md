# Microsoft Entra ID SCIM Provisioning - Guide d'intégration

## 📋 Vue d'ensemble

Ce guide décrit l'intégration de **Microsoft Entra ID (workforce identities)** avec cette application via **SCIM 2.0** pour le provisioning automatisé des utilisateurs.

**Flux d'authentification :** Bearer token statique (mode démonstration/développement) ou OAuth2 (production).

---

## 🎯 Objectifs

- ✅ Créer une **Enterprise Application non-galerie** dans Entra ID
- ✅ Configurer le **provisioning automatique SCIM**
- ✅ Tester la connexion avec **Test connection** (GET `/scim/v2/ServiceProviderConfig`)
- ✅ Définir les **mappings d'attributs** (userPrincipalName, objectId, mail, accountEnabled)
- ✅ Valider la création/désactivation avec **Provision on demand**
- ✅ Consulter les logs d'audit HMAC côté application

---

## 🔧 Configuration Entra ID

### 1. Créer l'Enterprise Application

1. Connectez-vous au [portail Azure](https://portal.azure.com)
2. Naviguez vers **Microsoft Entra ID** → **Enterprise Applications**
3. Cliquez sur **+ New application**
4. Sélectionnez **+ Create your own application**
5. Nommez l'application (ex : `IAM PoC SCIM`) et choisissez **Integrate any other application you don't find in the gallery (Non-gallery)**
6. Cliquez sur **Create**

**Capture d'écran :**  
![Création Enterprise App](images/entra_provisioning_create_app.png)  
*Placeholder : Capture de la page de création d'application*

---

### 2. Configurer le Provisioning

1. Dans l'application créée, allez dans **Provisioning** (menu latéral)
2. Cliquez sur **Get started**
3. Sélectionnez **Provisioning Mode : Automatic**
4. Remplissez les champs **Admin Credentials** :

   | Champ | Valeur |
   |-------|--------|
   | **Tenant URL** | `https://<votre-domaine>/scim/v2` |
   | **Secret Token** | Voir section [Authentification](#authentification) ci-dessous |

5. Cliquez sur **Test Connection** → Doit retourner **200 OK**
   - Entra ID appelle `GET /scim/v2/ServiceProviderConfig`
   - Vérifie que l'endpoint répond avec le schéma SCIM

6. Si succès → **Save**

**Capture d'écran :**  
![Configuration provisioning](images/entra_provisioning_config.png)  
*Placeholder : Formulaire Tenant URL + Secret Token*

**Capture d'écran :**  
![Test connection réussi](images/entra_provisioning_test_connection.png)  
*Placeholder : Message de succès "You are connected..."*

---

### 3. Définir les Attribute Mappings

1. Dans **Provisioning** → **Mappings** → **Provision Azure Active Directory Users**
2. Configurez les mappings suivants :

   | Attribut Entra ID | Attribut SCIM | Obligatoire | Notes |
   |-------------------|---------------|-------------|-------|
   | `userPrincipalName` | `userName` | ✅ | Identifiant unique (ex : `alice@contoso.com`) |
   | `objectId` | `externalId` | ✅ | GUID Entra ID pour corrélation |
   | `mail` | `emails[type eq "work"].value` | ✅ | Email professionnel |
   | `displayName` | `displayName` | ✅ | Nom complet de l'utilisateur |
   | `Switch([IsSoftDeleted], , "False", "True", "True", "False")` | `active` | ⚠️ | Désactivation soft (voir note) |

   **Note sur `active` :**  
   - Le mapping `accountEnabled → active` peut nécessiter un ajustement selon votre configuration Entra ID.
   - Utilisez l'expression `Switch([IsSoftDeleted], , "False", "True", "True", "False")` pour mapper la désactivation.
   - Alternative : mapper directement `accountEnabled` si exposé dans votre tenant.

3. **Désactivez** les mappings non supportés (groupes, rôles complexes) si présents.
4. **Save** les changements.

**Capture d'écran :**  
![Attribute mappings](images/entra_provisioning_mappings.png)  
*Placeholder : Table des mappings userPrincipalName → userName, etc.*

---

### 4. Tester avec "Provision on demand"

Avant d'activer le provisioning complet, testez avec un utilisateur spécifique :

1. Dans **Provisioning** → **Provision on demand**
2. Sélectionnez un utilisateur de test (ex : `alice@contoso.com`)
3. Cliquez sur **Provision**
4. Vérifiez les étapes :
   - ✅ **Import** : Entra ID lit l'utilisateur
   - ✅ **Match** : Vérifie si l'utilisateur existe (via `userName`)
   - ✅ **Action** : Décide de créer (POST) ou mettre à jour (PATCH)
   - ✅ **Create** : Appelle `POST /scim/v2/Users`

5. **Résultat attendu :** `201 Created` avec l'utilisateur SCIM retourné

**Capture d'écran :**  
![Provision on demand](images/entra_provisioning_on_demand.png)  
*Placeholder : Résultat des 4 étapes avec succès*

---

### 5. Activer le Provisioning

1. Dans **Provisioning** → **Settings**
2. Changez **Provisioning Status** de `Off` à `On`
3. **Save**
4. Entra ID lance un cycle de synchronisation initial (peut prendre 20-40 min)

**Capture d'écran :**  
![Provisioning activé](images/entra_provisioning_enabled.png)  
*Placeholder : Toggle "Provisioning Status: On"*

---

### 6. Tester la désactivation

1. Dans Entra ID, **désactivez un utilisateur** :
   - Allez dans **Users** → Sélectionnez l'utilisateur → **Block sign-in**
2. Attendez le prochain cycle de sync (ou forcez avec **Restart provisioning**)
3. Vérifiez que `PATCH /scim/v2/Users/{id}` est appelé avec `{ "active": false }`
4. Consultez les **logs d'audit** dans l'application (endpoint `/admin/audit`)

**Capture d'écran :**  
![Désactivation visible](images/entra_provisioning_deactivate.png)  
*Placeholder : Logs d'audit HMAC montrant user.deactivated*

---

## 🔐 Authentification

### Mode Token Statique (Démonstration/Développement)

**Activation :**
- `DEMO_MODE=true` **OU** `SCIM_STATIC_TOKEN_SOURCE=keyvault`
- Endpoint : `/scim/v2/*` uniquement

**Configuration du secret :**

| Priorité | Source | Variable |
|----------|--------|----------|
| 1 | Azure Key Vault | Secret `scim-static-token` (si `AZURE_USE_KEYVAULT=true`) |
| 2 | Environnement | `SCIM_STATIC_TOKEN` |

**Exemple `.env` (développement) :**
```bash
DEMO_MODE=true
AZURE_USE_KEYVAULT=false
SCIM_STATIC_TOKEN=demo-scim-token-change-me
SCIM_STATIC_TOKEN_SOURCE=  # Vide = utiliser SCIM_STATIC_TOKEN
```

**Exemple Azure Key Vault (production) :**
```bash
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=my-keyvault
SCIM_STATIC_TOKEN_SOURCE=keyvault
# Le secret 'scim-static-token' sera chargé depuis Key Vault
```

**⚠️ Sécurité :**
- **NE JAMAIS** utiliser de token statique en production sans Key Vault.
- Le token statique est rejeté sur les endpoints non-SCIM (`/admin`, `/scim/docs`).
- Comparaison en **constant-time** (`hmac.compare_digest`) pour éviter les timing attacks.

**Header dans Entra ID :**
```
Authorization: Bearer demo-scim-token-change-me
```

### Mode OAuth2 (Production recommandé)

Pour une sécurité renforcée, utilisez OAuth2 client credentials :

1. Configurez un client dédié dans Keycloak avec scopes `scim:read` et `scim:write`
2. Entra ID obtient un token via `POST /realms/demo/protocol/openid-connect/token`
3. Le token est validé à chaque requête (signature RSA-SHA256, expiration, issuer)

**Voir :** [SECURITY_DESIGN.md](SECURITY_DESIGN.md) pour les détails OAuth2

---

## 📡 Endpoints SCIM

| Méthode | Endpoint | Description | Auth requise |
|---------|----------|-------------|--------------|
| `GET` | `/scim/v2/ServiceProviderConfig` | Découverte des capacités SCIM | ❌ Public |
| `GET` | `/scim/v2/ResourceTypes` | Types de ressources supportés | ❌ Public |
| `GET` | `/scim/v2/Schemas` | Schémas SCIM disponibles | ❌ Public |
| `GET` | `/scim/v2/Users` | Liste des utilisateurs (avec filtrage) | ✅ Bearer |
| `GET` | `/scim/v2/Users/{id}` | Détail d'un utilisateur | ✅ Bearer |
| `POST` | `/scim/v2/Users` | Créer un utilisateur | ✅ Bearer |
| `PATCH` | `/scim/v2/Users/{id}` | Mise à jour partielle | ✅ Bearer |
| `DELETE` | `/scim/v2/Users/{id}` | Supprimer un utilisateur | ✅ Bearer |

---

## 🚫 Limites actuelles

| Opération | Statut | Notes |
|-----------|--------|-------|
| `PUT /scim/v2/Users/{id}` | ❌ **501 Not Implemented** | Utiliser `PATCH` à la place |
| Provisioning de groupes | ❌ Non supporté | Mappings uniquement utilisateurs |
| Filtres complexes | ⚠️ Partiel | Supporté : `userName eq "alice@contoso.com"`<br>Non supporté : filtres AND/OR imbriqués |
| Bulk operations | ❌ Non supporté | `ServiceProviderConfig.bulk.supported = false` |
| Change password | ❌ Non supporté | Les mots de passe doivent être définis dans Keycloak |

**Content-Type requis :** `application/scim+json` (Entra ID l'envoie automatiquement)

---

## 📊 Vérification et Audit

### Logs d'audit HMAC

Chaque opération SCIM génère une entrée d'audit signée avec HMAC-SHA256 :

**Endpoint :** `GET /admin/audit` (authentification requise)

**Exemple d'événement :**
```json
{
  "timestamp": "2025-11-05T14:23:10Z",
  "event_type": "user.created",
  "actor": "automation-cli",
  "target_user": "alice@contoso.com",
  "auth_method": "static",
  "client_ip": "20.190.160.5",
  "correlation_id": "abc123",
  "signature": "hmac-sha256:a3f4e8..."
}
```

**Champs importants :**
- `auth_method` : `static` (token statique) ou `oauth` (OAuth2)
- `client_ip` : IP source de la requête Entra ID
- `correlation_id` : ID de traçabilité (header `X-Correlation-Id`)

### Header de réponse

Chaque réponse SCIM inclut `X-Auth-Method` pour transparence :

```http
HTTP/1.1 200 OK
X-Auth-Method: static
X-Correlation-Id: abc123
Content-Type: application/scim+json
```

---

## 🔍 Troubleshooting

### "Test Connection" échoue

**Symptômes :** Entra ID retourne "Failed to connect" lors du test.

**Solutions :**
1. Vérifiez que l'URL est accessible depuis Internet (ou configurez un VPN/Private Link).
2. Testez manuellement avec `curl` :
   ```bash
   curl -H "Authorization: Bearer <token>" \
        https://votre-domaine/scim/v2/ServiceProviderConfig
   ```
3. Vérifiez les logs de l'application pour les erreurs d'authentification.

### Utilisateurs non créés

**Symptômes :** Le cycle de provisioning se termine sans créer d'utilisateurs.

**Solutions :**
1. Vérifiez les **Scoping filters** dans Entra ID (Provisioning → Settings → Scope).
2. Assurez-vous que les utilisateurs sont **assignés à l'application** (Users and groups).
3. Consultez les **Provisioning logs** (Entra ID → Enterprise App → Provisioning logs).

### Erreur 401 Unauthorized

**Symptômes :** Toutes les requêtes SCIM retournent `401`.

**Solutions :**
1. Vérifiez que le **Secret Token** dans Entra ID correspond à `SCIM_STATIC_TOKEN` (ou au secret Key Vault).
2. Assurez-vous que le mode statique est activé (`DEMO_MODE=true` ou `SCIM_STATIC_TOKEN_SOURCE=keyvault`).
3. Vérifiez les logs pour voir le hash du token reçu (SHA256 tronqué, pas le token complet).

### Erreur 403 Forbidden (portée)

**Symptômes :** L'authentification réussit mais Entra ID reçoit `403`.

**Solutions :**
1. Le token statique est accepté uniquement sur `/scim/v2/*`.
2. Si vous utilisez OAuth2, vérifiez que le client Keycloak a les scopes `scim:read` et `scim:write`.

### Désactivation non détectée

**Symptômes :** Un utilisateur bloqué dans Entra ID reste actif dans l'application.

**Solutions :**
1. Vérifiez le mapping `accountEnabled → active` (voir section Attribute Mappings).
2. Forcez un cycle de sync avec **Restart provisioning**.
3. Consultez les logs Entra ID pour voir si `PATCH` est envoyé.

---

## 🎓 Bonne pratique de sécurité

### En développement

- ✅ Utilisez `DEMO_MODE=true` avec `SCIM_STATIC_TOKEN` dans `.env`
- ✅ Testez sur localhost avec HTTPS (certificats auto-signés OK)
- ✅ Limitez la portée du token statique à `/scim/v2/*` (déjà implémenté)

### En production

- ✅ **Obligatoire :** Stockez `scim-static-token` dans Azure Key Vault
- ✅ Définissez `SCIM_STATIC_TOKEN_SOURCE=keyvault` et `AZURE_USE_KEYVAULT=true`
- ✅ Utilisez un token long et aléatoire (minimum 32 caractères) : `openssl rand -base64 32`
- ✅ Configurez des **IP whitelisting** si possible (plages IP Entra ID)
- ✅ Activez les **Provisioning logs** dans Entra ID (90 jours de rétention)
- ✅ Surveillez les événements `auth_method=static` dans les logs d'audit

**Rotation du secret :**
1. Générez un nouveau token : `openssl rand -base64 32`
2. Ajoutez-le dans Key Vault avec le nom `scim-static-token`
3. Mettez à jour le **Secret Token** dans Entra ID (sans arrêter le provisioning)
4. Redémarrez les services : `make load-secrets && make restart`

---

## 📚 Références

- [RFC 7644 - SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- [RFC 7643 - SCIM Core Schema](https://datatracker.ietf.org/doc/html/rfc7643)
- [Microsoft Entra ID SCIM Documentation](https://learn.microsoft.com/en-us/azure/active-directory/app-provisioning/use-scim-to-provision-users-and-groups)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)

---

## 📸 Captures d'écran (TODO)

Les images suivantes doivent être ajoutées dans `docs/images/` :

- [ ] `entra_provisioning_create_app.png` - Création de l'Enterprise Application
- [ ] `entra_provisioning_config.png` - Configuration Tenant URL + Secret Token
- [ ] `entra_provisioning_test_connection.png` - Résultat "Test Connection" réussi
- [ ] `entra_provisioning_mappings.png` - Table des attribute mappings
- [ ] `entra_provisioning_on_demand.png` - Résultat "Provision on demand" avec 4 étapes
- [ ] `entra_provisioning_enabled.png` - Provisioning Status: On
- [ ] `entra_provisioning_deactivate.png` - Logs d'audit montrant désactivation

**Comment capturer :**
1. Suivez ce guide étape par étape dans un tenant Entra ID de test.
2. Prenez des captures au format PNG (résolution 1920x1080 max).
3. Masquez les données sensibles (domaines, IPs, tokens).
4. Sauvegardez dans `/home/alex/iam-poc/docs/images/`.

---

**Dernière mise à jour :** 2025-11-05  
**Auteur :** IAM PoC Team
