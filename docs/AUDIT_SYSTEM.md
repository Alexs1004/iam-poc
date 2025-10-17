# 🔍 Audit Trail System — JML Operations

## Vue d'ensemble

Le système d'audit enregistre **toutes les opérations de cycle de vie des identités** (Joiner/Mover/Leaver) dans un journal signé cryptographiquement pour garantir l'intégrité et la non-répudiation.

## Fonctionnalités

### 1. **Événements tracés**

Chaque opération JML génère un événement structuré contenant :

- **Timestamp** (UTC, ISO 8601)
- **Type d'événement** : `joiner`, `mover`, `leaver`, `role_grant`, `role_revoke`
- **Username** : compte cible
- **Operator** : qui a exécuté l'opération (utilisateur authentifié ou `system`)
- **Realm** : domaine Keycloak concerné
- **Success** : statut de l'opération (`true`/`false`)
- **Details** : contexte additionnel (rôles, erreurs, etc.)
- **Signature HMAC-SHA256** : intégrité cryptographique

### 2. **Format de stockage**

Les événements sont stockés au format **JSONL** (JSON Lines) :
- Un événement = une ligne JSON
- Fichier : `.runtime/audit/jml-events.jsonl`
- Permissions : `600` (lecture/écriture propriétaire uniquement)
- Répertoire : `700` (accès propriétaire uniquement)

### 3. **Signature cryptographique**

Chaque événement est signé avec HMAC-SHA256 :

```python
signature = HMAC-SHA256(AUDIT_LOG_SIGNING_KEY, canonical_json(event))
```

La clé de signature est :
- **Développement** : variable `AUDIT_LOG_SIGNING_KEY` (local)
- **Production** : récupérée depuis **Azure Key Vault** (`audit-log-signing-key`)

### 4. **Vérification d'intégrité**

Commande de vérification :

```bash
make verify-audit
```

Ou directement :

```bash
python3 scripts/audit.py
```

Sortie :
```
Audit log: 15/15 events with valid signatures
```

En cas de compromission :
```
Audit log: 14/15 events with valid signatures
```

## Architecture

```
app/flask_app.py
    └─> scripts/audit.py
            ├─> log_jml_event()
            │       └─> .runtime/audit/jml-events.jsonl
            │
            └─> verify_audit_log()
```

## Interface utilisateur

### Route d'audit

**URL** : `/admin/audit`

**Permissions** : `realm-admin` ou `iam-operator`

**Fonctionnalités** :
- Vue chronologique inverse (événements récents en haut)
- Filtres par type, succès/échec
- Détails expandables (JSON structuré)
- Indicateur d'intégrité des signatures

## Événements typiques

### Joiner (provision d'utilisateur)

```json
{
  "timestamp": "2025-10-17T14:32:10Z",
  "event_type": "joiner",
  "realm": "demo",
  "username": "alice",
  "operator": "admin@example.com",
  "success": true,
  "details": {
    "role": "analyst",
    "email": "alice@example.com",
    "require_totp": true,
    "require_password_update": true
  },
  "signature": "a3f5b..."
}
```

### Mover (changement de rôle)

```json
{
  "timestamp": "2025-10-17T15:45:22Z",
  "event_type": "mover",
  "realm": "demo",
  "username": "alice",
  "operator": "system",
  "success": true,
  "details": {
    "from_role": "analyst",
    "to_role": "iam-operator"
  },
  "signature": "b7e9c..."
}
```

### Leaver (désactivation + révocation sessions)

```json
{
  "timestamp": "2025-10-17T16:20:05Z",
  "event_type": "leaver",
  "realm": "demo",
  "username": "bob",
  "operator": "joe@example.com",
  "success": true,
  "details": {
    "sessions_revoked": true
  },
  "signature": "d8f2a..."
}
```

### Échec d'opération

```json
{
  "timestamp": "2025-10-17T17:10:30Z",
  "event_type": "joiner",
  "realm": "demo",
  "username": "malformed@user",
  "operator": "admin@example.com",
  "success": false,
  "details": {
    "error": "Validation error: Username must be at least 3 characters",
    "role": "analyst"
  },
  "signature": "e1c4b..."
}
```

## Sécurité & Conformité

### Guardrails appliqués

✅ **Intégrité cryptographique** : signatures HMAC-SHA256  
✅ **Non-répudiation** : opérateur tracé pour chaque action  
✅ **Horodatage UTC** : traçabilité temporelle précise  
✅ **Permissions restreintes** : fichiers `600`, répertoire `700`  
✅ **Pas de données sensibles** : mots de passe exclus du log  
✅ **Format structuré** : JSONL pour parsing automatisé  

### Standards respectés

- **ISO 27001** : journalisation des accès et modifications
- **SOC 2 Type II** : audit trail immuable et signé
- **FINMA Circ. 2023/1** : traçabilité des opérations privilégiées
- **NIST 800-53 AU-2** : audit d'événements sécurité

## Tests automatisés

Fichier : `tests/test_audit.py`

Couverture :
- ✅ Création de fichier audit
- ✅ Format JSON valide
- ✅ Événements multiples
- ✅ Vérification signatures valides
- ✅ Détection de compromission (tampering)
- ✅ Gestion absence de clé de signature
- ✅ Opérations en échec
- ✅ Permissions fichiers

Exécution :
```bash
make pytest
```

## Rotation de la clé de signature

1. **Générer nouvelle clé** :
   ```bash
   openssl rand -base64 32
   ```

2. **Stocker dans Key Vault** :
   ```bash
   az keyvault secret set \
     --vault-name demo-key-vault-alex \
     --name audit-log-signing-key \
     --value "nouvelle-clé-base64"
   ```

3. **Redémarrer l'application** :
   ```bash
   docker compose restart flask-app
   ```

4. **Archiver ancien log** :
   ```bash
   mv .runtime/audit/jml-events.jsonl .runtime/audit/jml-events-$(date +%Y%m%d).jsonl
   ```

## Requêtes d'analyse

### Compter événements par type

```bash
jq -s 'group_by(.event_type) | map({type: .[0].event_type, count: length})' .runtime/audit/jml-events.jsonl
```

### Lister échecs récents

```bash
jq 'select(.success == false) | {timestamp, username, error: .details.error}' .runtime/audit/jml-events.jsonl
```

### Opérations par opérateur

```bash
jq -s 'group_by(.operator) | map({operator: .[0].operator, ops: length})' .runtime/audit/jml-events.jsonl
```

### Événements des dernières 24h

```bash
jq --arg cutoff "$(date -u -d '24 hours ago' +%Y-%m-%d)" 'select(.timestamp > $cutoff)' .runtime/audit/jml-events.jsonl
```

## Intégration future (Phase 5.2)

Le système d'audit est conçu pour s'intégrer avec :

- **Azure Monitor / Log Analytics** : ingestion via agent ou webhook
- **Microsoft Sentinel** : règles KQL pour détection d'anomalies
- **SIEM externe** : export JSONL vers Splunk, ELK, etc.
- **Alerting** : webhook déclenché sur événements sensibles

Exemple de règle Sentinel :

```kql
AuditEvents_CL
| where event_type_s == "leaver" and operator_s != "system"
| where success_b == true
| summarize Count=count() by operator_s, bin(TimeGenerated, 1h)
| where Count > 5  // Plus de 5 désactivations en 1h
```

## Maintenance

### Archivage automatique

Ajouter dans cron (mensuel) :

```cron
0 0 1 * * /usr/bin/gzip -c /app/.runtime/audit/jml-events.jsonl > /backups/audit-$(date +\%Y-\%m).jsonl.gz && > /app/.runtime/audit/jml-events.jsonl
```

### Vérification quotidienne

```cron
0 6 * * * cd /app && /usr/bin/python3 scripts/audit.py || echo "Audit integrity check FAILED" | mail -s "Audit Alert" security@example.com
```

## Références

- [RFC 5424 - Syslog Protocol](https://tools.ietf.org/html/rfc5424)
- [NIST 800-92 - Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [Azure Monitor Best Practices](https://learn.microsoft.com/azure/azure-monitor/best-practices)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
