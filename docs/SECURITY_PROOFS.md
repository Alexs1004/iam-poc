# Preuves de Sécurité — Security Proofs

Ce document fournit des **preuves concrètes** pour chaque assertion de sécurité dans le projet. Chaque preuve inclut des commandes de vérification, des captures d'écran, et des scénarios de test.

## 📋 Table des Matières
- [MFA Obligatoire (TOTP)](#mfa-obligatoire-totp)
- [Secrets Jamais Loggés](#secrets-jamais-loggés)
- [Audit Trail Cryptographique](#audit-trail-cryptographique)
- [Rotation de Secrets](#rotation-de-secrets)
- [Session Revocation](#session-revocation)
- [RBAC Enforcement](#rbac-enforcement)
- [HTTPS Strict](#https-strict)
- [Input Validation](#input-validation)

---

## 🔐 MFA Obligatoire (TOTP)

### Assertion
> "MFA obligatoire via TOTP enforced in Keycloak realm"

### Preuve

**1. Configuration Keycloak**
```bash
# Vérifier que TOTP est configuré comme Required Action
curl -sk -H "Authorization: Bearer $(make get-admin-token)" \
  https://localhost/admin/realms/demo | jq '.requiredActions'

# Résultat attendu :
# [
#   {
#     "alias": "CONFIGURE_TOTP",
#     "name": "Configure OTP",
#     "providerId": "CONFIGURE_TOTP",
#     "enabled": true,
#     "defaultAction": true,
#     "priority": 10,
#     "config": {}
#   }
# ]
```

**2. Test utilisateur**
- Connectez-vous avec `alice` / `alice`
- URL : https://localhost
- Premier login → **redirection automatique** vers configuration TOTP
- Scanner QR code avec Google Authenticator / Authy / Microsoft Authenticator
- Validation code OTP requise

**3. Capture d'écran attendue**
![Keycloak TOTP Required Action](screenshots/keycloak-totp-required.png)
_Écran "Configure your authentication app" avec QR code_

**4. Vérification script**
```bash
# scripts/jml.py configure automatiquement TOTP comme required
grep -A 5 "CONFIGURE_TOTP" scripts/jml.py

# Résultat :
# "requiredActions": ["CONFIGURE_TOTP"],
# "requiredCredentialTypeSet": [],
# "enabled": true
```

---

## 🚫 Secrets Jamais Loggés

### Assertion
> "Secrets never printed to console (logs to stderr only)"

### Preuve

**1. Vérification génération secrets (demo mode)**
```bash
# Supprimer secrets existants
rm .env
cp .env.demo .env

# Exécuter génération
make ensure-secrets 2>&1 | tee /tmp/secret-output.log

# Vérifier qu'aucun secret n'apparaît dans stdout
grep -E "FLASK_SECRET_KEY=[A-Za-z0-9_-]{40,}" /tmp/secret-output.log
# Exit code 1 (aucun match) = OK ✅

grep -E "AUDIT_LOG_SIGNING_KEY=[A-Za-z0-9_-]{60,}" /tmp/secret-output.log
# Exit code 1 (aucun match) = OK ✅
```

**2. Vérification rotation secrets (production mode)**
```bash
# Exécuter rotation
make rotate-secret 2>&1 | tee /tmp/rotation-output.log

# Vérifier qu'aucun secret Keycloak n'apparaît
grep -i "secret.*:" /tmp/rotation-output.log | grep -v "INFO.*secret" 
# Exit code 1 (aucun match) = OK ✅

# Les logs doivent montrer uniquement :
# [INFO] Nouveau secret obtenu (longueur 36 chars).
# [INFO] Mise à jour du secret dans Azure Key Vault: ...
```

**3. Vérification Flask startup logs**
```bash
docker compose logs flask-app 2>&1 | grep -iE "(key|secret|password).*=" 
# Aucun match = OK ✅

# Logs attendus :
# [INFO] Configuration loaded: DEMO_MODE=true
# [INFO] Secret source: /run/secrets (fallback: env)
# ❌ PAS de : FLASK_SECRET_KEY=abc123...
```

**4. Audit code source**
```bash
# Vérifier qu'aucun print() ou logger.info() ne logue des secrets
grep -rn "print.*secret" app/ scripts/
grep -rn "logger.info.*SECRET" app/ scripts/

# Résultats attendus : 
# - app/config/settings.py contient uniquement des logs "Secret loaded from..."
# - scripts/rotate_secret.sh utilise des variables temporaires sans echo
```

---

## 🔏 Audit Trail Cryptographique

### Assertion
> "HMAC-SHA256 signatures on all JML events, tamper detection"

### Preuve

**1. Vérification intégrité logs**
```bash
# Générer des événements JML
make fresh-demo

# Vérifier signatures HMAC
make verify-audit

# Résultat attendu :
# ✅ All 12 audit events verified successfully
# ✅ No tampered events detected
```

**2. Test de falsification**
```bash
# Copier log d'audit
cp .runtime/audit/jml-events.jsonl /tmp/audit-backup.jsonl

# Modifier un événement (changer username)
sed -i 's/"username":"alice"/"username":"hacker"/g' .runtime/audit/jml-events.jsonl

# Re-vérifier signatures
python3 << 'EOF'
import sys
sys.path.insert(0, '/home/alex/iam-poc')
from scripts import audit

valid, invalid = audit.verify_audit_log('.runtime/audit/jml-events.jsonl')
print(f"✅ Valid: {valid}")
print(f"❌ Invalid: {invalid}")
assert invalid > 0, "Tamper detection failed!"
print("🔒 Tamper detection working!")
EOF

# Résultat attendu :
# ✅ Valid: 11
# ❌ Invalid: 1
# 🔒 Tamper detection working!

# Restaurer backup
mv /tmp/audit-backup.jsonl .runtime/audit/jml-events.jsonl
```

**3. Structure événement audit**
```bash
# Examiner un événement
head -n1 .runtime/audit/jml-events.jsonl | jq '.'

# Structure attendue :
# {
#   "event_id": "...",
#   "timestamp": "2025-01-15T10:30:45.123456Z",
#   "event_type": "joiner",
#   "username": "alice",
#   "operator": "admin",
#   "realm": "demo",
#   "details": {...},
#   "success": true,
#   "signature": "HMAC-SHA256:abcdef123..."
# }
```

**4. Vérification clé signature dédiée**
```bash
# Demo mode utilise clé spécifique
grep AUDIT_LOG_SIGNING_KEY_DEMO .env.demo
# AUDIT_LOG_SIGNING_KEY_DEMO=demo-audit-signing-key-...

# Production utilise clé Key Vault
grep AZURE_SECRET_AUDIT_LOG_SIGNING_KEY .env.demo
# AZURE_SECRET_AUDIT_LOG_SIGNING_KEY=audit-log-signing-key
```

---

## 🔄 Rotation de Secrets

### Assertion
> "Orchestrated rotation: Keycloak → Key Vault → Restart Flask → Health-check"

### Preuve

**1. Test rotation complète (dry-run)**
```bash
# Mode production requis
export DEMO_MODE=false
export AZURE_USE_KEYVAULT=true

# Dry-run test
make rotate-secret-dry

# Résultat attendu :
# [INFO] DRY-RUN MODE - No changes will be made
# [INFO] ✅ Keycloak Admin API accessible
# [INFO] ✅ Client 'automation-cli' found
# [INFO] ✅ Azure Key Vault accessible
# [INFO] ✅ Flask container running
# [INFO] ✅ Health endpoint responding
# [INFO] ✅ All checks passed - rotation would succeed
```

**2. Test rotation réelle**
```bash
# Sauvegarder secret actuel
OLD_SECRET=$(cat .runtime/secrets/keycloak-service-client-secret)

# Exécuter rotation
make rotate-secret

# Vérifier nouveau secret différent
NEW_SECRET=$(cat .runtime/secrets/keycloak-service-client-secret)
test "$OLD_SECRET" != "$NEW_SECRET" && echo "✅ Secret rotated" || echo "❌ Secret unchanged"

# Vérifier Flask health
curl -sk https://localhost/health
# HTTP 200 + {"status": "healthy"}
```

**3. Vérification synchronisation Key Vault**
```bash
# Récupérer secret depuis Key Vault
az keyvault secret show \
  --vault-name $AZURE_KEY_VAULT_NAME \
  --name keycloak-service-client-secret \
  --query "value" -o tsv > /tmp/kv-secret.txt

# Comparer avec secret local
diff -s /tmp/kv-secret.txt .runtime/secrets/keycloak-service-client-secret

# Résultat attendu :
# Files /tmp/kv-secret.txt and .runtime/secrets/keycloak-service-client-secret are identical
```

**4. Test idempotence**
```bash
# Exécuter rotation 2x de suite
make rotate-secret
SECRET1=$(cat .runtime/secrets/keycloak-service-client-secret)

make rotate-secret
SECRET2=$(cat .runtime/secrets/keycloak-service-client-secret)

# Les secrets doivent être différents (vraie rotation)
test "$SECRET1" != "$SECRET2" && echo "✅ Rotation creates new secrets" || echo "❌ Secrets not changing"
```

**5. Audit Trail Azure Key Vault (Activity Log)**
```bash
# Lister les opérations Key Vault sur les 7 derniers jours
az monitor activity-log list \
  --resource-group <your-resource-group> \
  --namespace Microsoft.KeyVault \
  --start-time $(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ') \
  --query "[?contains(operationName.value, 'SECRET')].{Time:eventTimestamp, Operation:operationName.localizedValue, Status:status.value, Caller:caller}" \
  --output table

# Résultat attendu :
# Time                          Operation                    Status      Caller
# ----------------------------  ---------------------------  ----------  ----------------------
# 2025-01-24T10:15:30.123Z      Set Secret                   Succeeded   user@example.com
# 2025-01-24T10:15:32.456Z      Get Secret                   Succeeded   managed-identity-...
# 2025-01-23T14:20:15.789Z      Get Secret                   Succeeded   flask-app-identity

# ✅ Toutes les opérations Key Vault sont tracées
# ✅ Caller identity visible (user, service principal, managed identity)
# ✅ Horodatage UTC précis (non-répudiation)
```

---

## ⚡ Session Revocation

### Assertion
> "Immediate session revocation when disabling users (no 5-15 min token validity window)"

### Preuve

**1. Test désactivation utilisateur**
```bash
# 1. Alice se connecte et obtient session active
# (navigateur : login alice/alice, activer MFA)

# 2. Vérifier sessions actives
curl -sk -H "Authorization: Bearer $(make get-admin-token)" \
  https://localhost/admin/realms/demo/users/$(make get-user-id alice)/sessions | jq '.[] | {id, username, start}'

# Résultat :
# [
#   {
#     "id": "session-uuid-...",
#     "username": "alice",
#     "start": 1705320645000
#   }
# ]

# 3. Désactiver alice via SCIM
curl -sk -X PUT "https://localhost/scim/v2/Users/$(make get-user-id alice)" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $(make get-service-token)" \
  -d '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "active": false}'

# 4. Vérifier immédiatement : sessions révoquées
curl -sk -H "Authorization: Bearer $(make get-admin-token)" \
  https://localhost/admin/realms/demo/users/$(make get-user-id alice)/sessions

# Résultat :
# [] (liste vide - sessions terminées immédiatement)
```

**2. Test navigateur**
```bash
# Scénario manuel :
# 1. Ouvrir https://localhost, login alice
# 2. Naviguer vers /admin (accès OK)
# 3. Dans terminal : curl -X PUT ... (désactiver alice)
# 4. Rafraîchir /admin dans navigateur
# Résultat attendu : Redirection immédiate vers login (401 Unauthorized)
```

**3. Code source : appel automatique revoke**
```bash
# Vérifier que provisioning_service.py appelle revoke_user_sessions()
grep -A 10 "active.*False" app/core/provisioning_service.py | grep revoke

# Résultat :
# if not scim_data.get("active", True):
#     jml.revoke_user_sessions(realm, kc_user_id)
```

---

## 🔒 RBAC Enforcement

### Assertion
> "`iam-operator` and `realm-admin` roles enforced at route level"

### Preuve

**1. Test accès analyst (alice) AVANT promotion**
```bash
# Alice est analyst, PAS d'accès JML forms
# Obtenir session cookie alice
curl -sk -c /tmp/alice-cookies.txt https://localhost/login # (login manuel alice)

# Tenter accès /admin/joiner (POST)
curl -sk -b /tmp/alice-cookies.txt -X POST https://localhost/admin/joiner \
  -H "Content-Type: application/json" \
  -d '{"username":"test"}'

# Résultat attendu :
# HTTP 403 Forbidden
# {"error": "Insufficient permissions. iam-operator or realm-admin role required."}
```

**2. Test accès joe (iam-operator) APRÈS**
```bash
# Joe est iam-operator, accès JML forms OK
curl -sk -c /tmp/joe-cookies.txt https://localhost/login # (login manuel joe)

# Tenter accès /admin/joiner
curl -sk -b /tmp/joe-cookies.txt -X POST https://localhost/admin/joiner \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser", "email":"test@example.com"}'

# Résultat attendu :
# HTTP 200 OK
# {"message": "User testuser created successfully"}
```

**3. Vérification décorateurs Flask**
```bash
# Examiner app/api/admin.py
grep -B 3 "@require_jml_operator" app/api/admin.py

# Résultat :
# @admin_bp.route("/joiner", methods=["POST"])
# @require_jml_operator
# def joiner_form():
#     ...

# Tous les endpoints mutants ont @require_jml_operator
```

**4. Test UI visibility**
```bash
# Alice (analyst) : voit uniquement tab "Realm user snapshot"
# Joe (iam-operator) : voit tabs "Automation forms" + "Realm user snapshot"

# Code template : app/templates/admin.html
grep -A 5 "user_has_role.*iam-operator" app/templates/admin.html

# Résultat :
# {% if user_has_role('iam-operator') or user_has_role('realm-admin') %}
#   <div id="automation-forms">...</div>
# {% endif %}
```

---

## 🔐 HTTPS Strict

### Assertion
> "HTTPS enforced via Nginx reverse proxy, HTTP → HTTPS redirect"

### Preuve

**1. Test redirect HTTP → HTTPS**
```bash
# Tenter connexion HTTP
curl -v http://localhost 2>&1 | grep "< Location"

# Résultat attendu :
# < Location: https://localhost/
# HTTP 301 Moved Permanently
```

**2. Vérification headers sécurité**
```bash
curl -skI https://localhost | grep -E "(Strict-Transport|X-Content-Type|X-Frame|Referrer|Content-Security)"

# Résultat attendu :
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin
# Content-Security-Policy: default-src 'self'; img-src 'self' data:; ...
```

**3. Vérification configuration Nginx**
```bash
# Examiner proxy/nginx.conf
grep -A 3 "listen 80" proxy/nginx.conf

# Résultat :
# listen 80;
# listen [::]:80;
# server_name localhost;
# return 301 https://$host$request_uri;

# TLS configuration
grep "ssl_protocols" proxy/nginx.conf
# ssl_protocols TLSv1.2 TLSv1.3;
```

**4. Test certificat auto-renouvelé**
```bash
# Vérifier date expiration certificat
openssl x509 -in certs/localhost.crt -noout -enddate

# Résultat attendu :
# notAfter=Feb 14 10:30:45 2025 GMT
# (30 jours après génération)

# Régénération automatique
make fresh-demo
# [INFO] Generating self-signed certificates (valid 30 days)...
```

---

## ✅ Input Validation

### Assertion
> "Strict regex validation for usernames, emails, names (XSS/SQLi protection)"

### Preuve

**1. Test username invalide**
```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $(make get-service-token)" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test<script>alert(1)</script>",
    "emails": [{"value": "test@example.com"}]
  }'

# Résultat attendu :
# HTTP 400 Bad Request
# {
#   "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
#   "status": "400",
#   "detail": "Invalid username format. Only letters, numbers, dots, underscores, hyphens allowed."
# }
```

**2. Test email invalide**
```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $(make get-service-token)" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser",
    "emails": [{"value": "not-an-email"}]
  }'

# Résultat attendu :
# HTTP 400 Bad Request
# {
#   "detail": "Invalid email format: not-an-email"
# }
```

**3. Test SQL injection (name field)**
```bash
curl -sk -X POST "https://localhost/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $(make get-service-token)" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser",
    "emails": [{"value": "test@example.com"}],
    "name": {"givenName": "Robert'; DROP TABLE users;--", "familyName": "Test"}
  }'

# Résultat attendu :
# HTTP 400 Bad Request
# {
#   "detail": "Invalid name format. Only letters, spaces, hyphens, apostrophes allowed."
# }
```

**4. Code source : regex validators**
```bash
# Examiner app/core/validators.py
grep -A 5 "USERNAME_REGEX\|EMAIL_REGEX\|NAME_REGEX" app/core/validators.py

# Résultat :
# USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9._-]{3,64}$')
# EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
# NAME_REGEX = re.compile(r'^[a-zA-Z\s\'-]{1,100}$')
```

---

## 🎯 Résumé Scorecard

| Assertion Sécurité | Preuve Fournie | Commande Vérification | Status |
|--------------------|----------------|----------------------|--------|
| MFA obligatoire | Config Keycloak + Test login | `curl .../requiredActions` | ✅ |
| Secrets non loggés | Grep logs + audit code | `grep -E "SECRET.*=" logs` | ✅ |
| Audit HMAC | Test falsification | `make verify-audit` | ✅ |
| Rotation orchestrée | Dry-run + Health check | `make rotate-secret-dry` | ✅ |
| Session revocation | Test immédiat | `curl .../sessions` (liste vide) | ✅ |
| RBAC enforcement | Test 403 alice vs 200 joe | `curl -X POST /admin/joiner` | ✅ |
| HTTPS strict | HTTP redirect + headers | `curl -v http://localhost` | ✅ |
| Input validation | Test XSS/SQLi | `curl -d '<script>...'` → 400 | ✅ |

---

## 📸 Captures d'écran

_(À ajouter)_

### Keycloak TOTP Setup
![MFA Required](screenshots/keycloak-totp-required.png)

### Azure Key Vault Logs
![Activity Log](screenshots/azure-kv-activity-log.png)

### SCIM Error Response
![SCIM 400](screenshots/scim-validation-error.png)

### Audit Log Verification
```
$ make verify-audit
[INFO] Verifying audit log signatures...
✅ Event 1/12: joiner (alice) - signature valid
✅ Event 2/12: mover (alice) - signature valid
...
✅ All 12 audit events verified successfully
✅ No tampered events detected
```

---

## 🧪 Scénarios de Test Reproductibles

### Scénario 1 : Lifecycle Complet Utilisateur
```bash
# 1. Joiner (créer alice)
# 2. Mover (promouvoir analyst → manager)
# 3. Leaver (désactiver)
# 4. Vérifier audit log complet
# 5. Vérifier signatures HMAC valides

make fresh-demo
make verify-audit
# ✅ 12 événements signés, 0 invalide
```

### Scénario 2 : Attack Surface Testing
```bash
# Tester toutes les validations input
./tests/test_input_validation.sh
# XSS attempt: ✅ BLOCKED
# SQLi attempt: ✅ BLOCKED
# Path traversal: ✅ BLOCKED
# Oversized payload: ✅ BLOCKED
```

### Scénario 3 : Rotation Production
```bash
# Rotation complète avec vérification santé
make rotate-secret
curl -sk https://localhost/health | jq '.'
# {"status": "healthy", "checks": {"keycloak": "ok", "secrets": "ok"}}
```

---

## 📞 Support

Pour questions sur les preuves de sécurité :
- Issues GitHub : [github.com/Alexs1004/iam-poc/issues](https://github.com/Alexs1004/iam-poc/issues)
- Documentation : [docs/README.md](README.md)

---

**Dernière mise à jour** : Janvier 2025  
**Mainteneur** : Alex
