# 🔐 RBAC Demo Scenarios — Joiner/Mover/Leaver Workflows

> **Objectif** : Démontrer la maîtrise RBAC et des workflows IAM (JML) pour recruteurs Cloud Security  
> **Audience** : Recruteurs RH, Tech Leads, CISO, Hiring Managers

---

## 📊 Vue d'ensemble

Ce document détaille les **4 utilisateurs de démo** provisionnés par `make demo` et les **scénarios JML** (Joiner/Mover/Leaver) automatisés. Il illustre :
- La **séparation des privilèges** (principe du moindre privilège)
- L'**audit trail cryptographique** (non-répudiation FINMA)
- Les **workflows IAM réels** utilisés en entreprise

---

## 👥 Matrice des Utilisateurs

### alice — Analyst → IAM Operator (Mover Scenario)

**Scénario** : Promotion d'analyste vers opérateur IAM (mouvement vertical)

| Attribut | Valeur Initiale | Valeur Finale |
|----------|-----------------|---------------|
| **Username** | `alice` | `alice` |
| **Rôle** | `analyst` | **`iam-operator`** ⬆️ |
| **Statut** | ✅ Actif | ✅ Actif |
| **MFA** | ✅ TOTP requis | ✅ TOTP requis |
| **Mot de passe** | `Temp123!` (temporaire) | `Temp123!` (temporaire) |
| **Accès Admin UI** | ❌ 403 Forbidden | ✅ Admin complet |
| **Opérations JML** | ❌ Aucune | ✅ Joiner/Mover/Leaver |

**Workflow JML** :
1. **Joiner** : Création initiale avec rôle `analyst`
2. **Mover** : Promotion `analyst` → `iam-operator`
3. **Audit** : 2 événements signés HMAC dans `/admin/audit`

**Test Manuel** :
```bash
# 1. Se connecter avec alice (avant promotion)
open https://localhost
# Username: alice | Password: Temp123!

# 2. Tenter d'accéder au dashboard admin (doit échouer)
open https://localhost/admin
# → Attendu: Page 403 Forbidden (analyst n'a pas accès)

# 3. Après promotion (par joe), se reconnecter
# → alice peut maintenant accéder à /admin avec opérations JML

# 4. Consulter l'audit trail de sa promotion
open https://localhost/admin/audit
# → Chercher événements "joiner" (alice) + "mover" (alice)
```

**Points Clés** :
- ✅ Promotion sans re-création de compte (migration de rôle)
- ✅ Sessions existantes invalidées après mover
- ✅ Audit trail complet (création + modification)
- ✅ **Contrôle d'accès strict** : analyst bloqué avant promotion (403), autorisé après

---

### bob — Analyst → Disabled (Leaver Scenario)

**Scénario** : Départ d'un collaborateur (soft-delete conforme RGPD)

| Attribut | Valeur Initiale | Valeur Finale |
|----------|-----------------|---------------|
| **Username** | `bob` | `bob` |
| **Rôle** | `analyst` | `analyst` (conservé) |
| **Statut** | ✅ Actif | ❌ **Désactivé** |
| **MFA** | ✅ TOTP requis | ✅ TOTP conservé |
| **Mot de passe** | `Temp123!` | `Temp123!` (conservé) |
| **Accès Admin UI** | ❌ 403 Forbidden | ❌ Connexion impossible |
| **Opérations JML** | ❌ Aucune | ❌ Aucune |

**Workflow JML** :
1. **Joiner** : Création initiale avec rôle `analyst`
2. **Leaver** : Désactivation (enabled=false)
3. **Audit** : 2 événements signés HMAC dans `/admin/audit`

**Test Manuel** :
```bash
# 1. Tenter de se connecter avec bob
open https://localhost
# Username: bob | Password: Temp123!
# → Attendu: "Invalid username or password" (compte désactivé)

# 2. Vérifier statut dans l'admin UI (avec alice/joe)
open https://localhost/admin
# → bob apparaît comme "Disabled" (badge rouge)

# 3. Consulter l'audit trail de sa désactivation
open https://localhost/admin/audit
# → Chercher événement "leaver" (bob)
```

**Points Clés** :
- ✅ Soft-delete (données conservées, compte inactif) ← **RGPD compliance**
- ✅ Sessions Keycloak révoquées automatiquement
- ✅ Réactivation possible via `/admin` (réversible)
- ✅ **Contrôle d'accès** : analyst n'avait déjà pas accès /admin (403)

---

### carol — Manager (Stable Scenario)

**Scénario** : Utilisateur stable avec accès lecture (pas d'opérations JML)

| Attribut | Valeur |
|----------|--------|
| **Username** | `carol` |
| **Rôle** | `manager` |
| **Statut** | ✅ Actif |
| **MFA** | ✅ TOTP requis |
| **Mot de passe** | `Temp123!` (temporaire) |
| **Accès Admin UI** | ✅ Lecture seule |
| **Opérations JML** | ❌ Aucune |

**Workflow JML** :
1. **Joiner** : Création avec rôle `manager`
2. **Stable** : Aucune modification

**Test Manuel** :
```bash
# 1. Se connecter avec carol
open https://localhost
# Username: carol | Password: Temp123!

# 2. Accéder au dashboard admin (lecture seule)
open https://localhost/admin
# → Pas de boutons "Joiner", "Mover", "Leaver" (read-only)

# 3. Accéder à l'audit trail (lecture autorisée)
open https://localhost/admin/audit
# → Peut consulter l'historique, pas le modifier
```

**Points Clés** :
- ✅ Séparation lecture/écriture (principe du moindre privilège)
- ✅ Accès audit trail (conformité/surveillance)
- ✅ Pas d'escalade de privilèges possible via UI
- ✅ **Contrôle d'accès** : manager peut lire dashboard, analyst bloqué (403)

---

### joe — IAM Operator + Realm Admin (Full Access)

**Scénario** : Administrateur IAM complet (double rôle)

| Attribut | Valeur |
|----------|--------|
| **Username** | `joe` |
| **Rôle** | `iam-operator` + `realm-admin` |
| **Statut** | ✅ Actif |
| **MFA** | ✅ TOTP requis |
| **Mot de passe** | `Temp123!` (temporaire) |
| **Accès Admin UI** | ✅ Admin complet |
| **Accès Keycloak Admin** | ✅ Console Keycloak complète |
| **Opérations JML** | ✅ Joiner/Mover/Leaver |

**Workflow JML** :
1. **Joiner** : Création avec rôle `iam-operator`
2. **Grant** : Attribution rôle `realm-admin` (double-hatting)
3. **Stable** : Compte administrateur permanent

**Test Manuel** :
```bash
# 1. Se connecter avec joe
open https://localhost
# Username: joe | Password: Temp123!

# 2. Accéder au dashboard admin (opérations complètes)
open https://localhost/admin
# → Tous les boutons JML disponibles

# 3. Accéder à Keycloak Admin Console
open http://localhost:8080/admin/demo/console
# → joe peut gérer realm, clients, roles, users

# 4. Effectuer un Joiner (créer un nouveau user)
# → Remplir formulaire dans /admin, assigner rôle "analyst"
# → Vérifier dans /admin/audit (événement "joiner" signé)
```

**Points Clés** :
- ✅ Double rôle (IAM operator + Realm admin) = contrôle total
- ✅ Accès console Keycloak (administration infra IdP)
- ✅ Responsable des opérations JML (traçabilité operator)

---

## 🔄 Workflows JML Détaillés

### 1. Joiner (Création Utilisateur)

**Cas d'usage** : Nouvel employé rejoignant l'entreprise

**Étapes** :
1. Opérateur se connecte (`joe` ou `alice` après promotion)
2. Accède à `/admin` → Formulaire "Joiner"
3. Remplit :
   - Username (ex: `dave`)
   - First Name / Last Name
   - Email (ex: `dave@example.com`)
   - Rôle initial (ex: `analyst`)
   - Mot de passe temporaire (généré automatiquement si vide)
   - Options : ☑️ MFA required, ☑️ Update password on first login
4. Clique "Create User"

**Backend (SCIM + Keycloak)** :
```python
# 1. API SCIM POST /Users
POST https://localhost/scim/v2/Users
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "dave",
  "emails": [{"value": "dave@example.com", "primary": true}],
  "name": {"givenName": "Dave", "familyName": "Smith"},
  "active": true
}

# 2. Keycloak API: Assign role + group
PUT /admin/realms/demo/users/{id}/role-mappings/realm
PUT /admin/realms/demo/users/{id}/groups/{iam-poc-managed-group-id}

# 3. Audit trail: Log event
{
  "event": "joiner",
  "username": "dave",
  "operator": "joe",
  "timestamp": "2025-11-04T10:30:00Z",
  "correlation_id": "uuid",
  "signature": "hmac-sha256(...)"
}
```

**Vérification** :
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Chercher événement "joiner" avec username="dave"

# 2. Intégrité signature
make verify-audit
# → Attendu: Signature valide pour événement "dave"

# 3. Connexion nouveau user
open https://localhost
# Username: dave | Password: <temporaire-fourni> | MFA: Setup TOTP
```

---

### 2. Mover (Changement de Rôle)

**Cas d'usage** : Promotion, mobilité interne, réorganisation

**Étapes** :
1. Opérateur se connecte (`joe` ou `alice` après promotion)
2. Accède à `/admin` → Formulaire "Mover"
3. Sélectionne :
   - Utilisateur (ex: `alice`)
   - Rôle actuel (ex: `analyst`)
   - Nouveau rôle (ex: `iam-operator`)
4. Clique "Change Role"

**Backend (Keycloak)** :
```python
# 1. Keycloak API: Remove old role
DELETE /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "analyst"}]

# 2. Keycloak API: Assign new role
POST /admin/realms/demo/users/{alice-id}/role-mappings/realm
Body: [{"name": "iam-operator"}]

# 3. Keycloak API: Revoke existing sessions
DELETE /admin/realms/demo/users/{alice-id}/sessions

# 4. Audit trail: Log event
{
  "event": "mover",
  "username": "alice",
  "operator": "joe",
  "details": {"from_role": "analyst", "to_role": "iam-operator"},
  "timestamp": "2025-11-04T10:35:00Z",
  "correlation_id": "uuid",
  "signature": "hmac-sha256(...)"
}
```

**Vérification** :
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Chercher événement "mover" avec from_role="analyst", to_role="iam-operator"

# 2. Reconnexion utilisateur (nouvelle session avec nouveau rôle)
open https://localhost
# Username: alice | Password: Temp123!
# → Vérifier que /admin montre maintenant les boutons JML

# 3. Intégrité signature
make verify-audit
```

---

### 3. Leaver (Désactivation Utilisateur)

**Cas d'usage** : Départ employé, suspension disciplinaire, congé longue durée

**Étapes** :
1. Opérateur se connecte (`joe` ou `alice` après promotion)
2. Accède à `/admin` → Formulaire "Leaver"
3. Sélectionne utilisateur (ex: `bob`)
4. Clique "Disable User"

**Backend (SCIM + Keycloak)** :
```python
# 1. API SCIM PATCH /Users/{id}
PATCH https://localhost/scim/v2/Users/{bob-id}
Authorization: Bearer <token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    }
  ]
}

# 2. Keycloak API: Set enabled=false
PUT /admin/realms/demo/users/{bob-id}
Body: {"enabled": false}

# 3. Keycloak API: Revoke all sessions
DELETE /admin/realms/demo/users/{bob-id}/sessions

# 4. Audit trail: Log event
{
  "event": "leaver",
  "username": "bob",
  "operator": "joe",
  "timestamp": "2025-11-04T10:40:00Z",
  "correlation_id": "uuid",
  "signature": "hmac-sha256(...)"
}
```

**Vérification** :
```bash
# 1. Audit trail
open https://localhost/admin/audit
# → Chercher événement "leaver" avec username="bob"

# 2. Tentative connexion (doit échouer)
open https://localhost
# Username: bob | Password: Temp123!
# → Attendu: "Invalid username or password"

# 3. Réactivation possible (soft-delete)
# → Depuis /admin (avec joe), bouton "Reactivate" sur bob
# → Après réactivation, bob peut se reconnecter
```

---

## 🛡️ Sécurité & Conformité

### Protection Anti-Abus

| Scénario | Protection | Implémentation |
|----------|-----------|----------------|
| **Auto-modification** | Utilisateur ne peut pas modifier son propre compte | `if username.lower() == current_username().lower(): abort(403)` |
| **Escalade de privilèges** | Manager ne peut pas s'auto-promouvoir realm-admin | Vérification rôle opérateur dans `@require_jml_operator` |
| **Désactivation admin** | Opérateur ne peut pas désactiver son propre compte | Check explicite avant leaver operation |
| **Modification realm-admin** | Seul realm-admin peut modifier autres realm-admin | `requires_operator_for_roles()` check |

### Audit Trail Cryptographique

**Signature HMAC-SHA256** :
```python
import hmac
import hashlib

# 1. Payload canonique
canonical = f"{event}:{username}:{timestamp}:{correlation_id}"

# 2. Clé de signature (Azure Key Vault en prod)
signing_key = os.getenv("AUDIT_LOG_SIGNING_KEY")  # 64+ bytes

# 3. Signature
signature = hmac.new(
    signing_key.encode(),
    canonical.encode(),
    hashlib.sha256
).hexdigest()

# 4. Événement signé
{
  "event": "joiner",
  "username": "dave",
  "signature": signature,
  ...
}
```

**Vérification** :
```bash
make verify-audit
# Output:
# ✓ Event 1/22: signature valid (joiner, alice)
# ✓ Event 2/22: signature valid (joiner, bob)
# ...
# ✓ All 22 signatures valid
```

### Conformité Swiss

| Exigence | Implémentation | Preuve |
|----------|----------------|--------|
| **nLPD (Traçabilité)** | Audit trail horodaté pour toutes opérations | `/admin/audit` (timestamps ISO 8601) |
| **RGPD (Droit à l'oubli)** | Soft-delete réversible (enabled=false) | `PATCH /scim/v2/Users/{id}` avec active=false |
| **FINMA (Non-répudiation)** | Signatures HMAC-SHA256 non falsifiables | `make verify-audit` (22/22 valid) |

---

## 🧪 Tests Automatisés

### Tests Unitaires RBAC

```bash
# 1. Tests d'autorisation
pytest tests/unit/test_core_rbac.py -v

# Coverage:
# ✓ test_user_has_role
# ✓ test_requires_operator_for_roles
# ✓ test_filter_display_roles
# ✓ test_collect_roles_from_access_token
```

### Tests d'Intégration JML

```bash
# 1. Tests workflows complets
pytest tests/integration/test_admin_ui_helpers.py -v

# Coverage:
# ✓ test_ui_create_user (joiner)
# ✓ test_ui_change_role (mover)
# ✓ test_ui_disable_user (leaver)
# ✓ test_ui_set_user_active (reactivate)
```

### Tests Audit Trail

```bash
# 1. Tests signatures cryptographiques
pytest tests/unit/test_audit.py -v

# Coverage:
# ✓ test_log_jml_event_creates_file
# ✓ test_verify_audit_log_all_valid
# ✓ test_verify_audit_log_detects_tampering
```

---

## 🔗 Références

- **[README.md](../README.md)** — Positionnement Swiss, démarrage rapide
- **[Hiring Pack](Hiring_Pack.md)** — Correspondance CV ↔ Repo pour recruteurs
- **[Security Design](SECURITY_DESIGN.md)** — OWASP ASVS L2, nLPD/RGPD/FINMA
- **[API Reference](API_REFERENCE.md)** — Endpoints SCIM 2.0, OAuth scopes
- **[Threat Model](THREAT_MODEL.md)** — STRIDE analysis, FINMA compliance

---

## 💡 Pour Recruteurs : Ce Que Cela Démontre

### Compétences Techniques
- ✅ **RBAC avancé** : 4 niveaux de rôles, séparation privilèges
- ✅ **Workflows IAM** : Joiner/Mover/Leaver automation complète
- ✅ **Audit cryptographique** : HMAC-SHA256, non-répudiation
- ✅ **SCIM 2.0** : API standardisée (RFC 7644)
- ✅ **OIDC/MFA** : Authentification moderne (PKCE, TOTP)

### Sécurité & Conformité
- ✅ **Swiss compliance** : nLPD, RGPD, FINMA by design
- ✅ **Principe du moindre privilège** : Read-only vs. write access
- ✅ **Protection anti-abus** : Auto-modification bloquée
- ✅ **Traçabilité** : Chaque action signée + horodatée
- ✅ **Tests 90% coverage** : Qualité vérifiable

### Positionnement Marché Suisse
- 🇨🇭 **Finance** : FINMA compliance (non-répudiation, audit trail)
- 🇨🇭 **Healthcare** : nLPD strict (traçabilité, soft-delete)
- 🇨🇭 **Tech/SaaS** : IAM moderne (SCIM, OIDC, automation)
- 🇨🇭 **Conseil** : Migration Keycloak → Azure Entra ID (roadmap Azure-native)

**En résumé** : Ce projet démontre une **maîtrise opérationnelle complète des standards IAM** dans un contexte **Azure-first** et **conforme aux exigences suisses**. Idéal pour postes **Junior Cloud Security Engineer (Azure)**, **IAM Engineer**, **DevSecOps Cloud** en Suisse Romande (Genève, Lausanne, Berne).
