# 📝 Audit Logging avec HMAC-SHA256 : Guide Approfondi

> **Objectif** : Comprendre comment les logs d'audit sont sécurisés avec signatures cryptographiques (non-répudiation, détection tampering)

**Pré-requis** : Notions de base en cryptographie (hash, HMAC).

---

## 🎯 C'est Quoi l'Audit Logging Sécurisé ?

**Problème** : Les logs classiques (fichiers texte) peuvent être modifiés par un attaquant :
```bash
# Attaquant supprime ligne compromettante
sed -i '/user-deleted-by-attacker/d' app.log
# Log modifié, aucune trace !
```

**Solution HMAC** : Chaque événement est signé cryptographiquement :
```json
{
  "timestamp": "2024-10-25T14:30:01Z",
  "event_type": "joiner",
  "username": "alice",
  "operator": "admin",
  "success": true,
  "hmac": "d4f3c2b1a0e9f8d7c6b5a4e3d2c1b0a9..."  // Signature HMAC-SHA256
}
```

**Si attaquant modifie** : HMAC devient invalide → Détection tampering.

---

## 🏗️ Architecture Audit dans IAM PoC

```
┌────────────────────────────────────────────────────────┐
│  ÉVÉNEMENT JML                                         │
│  create_user(), change_role(), disable_user()         │
└────────────────────────────────────────────────────────┘
                     ↓ appelle
┌────────────────────────────────────────────────────────┐
│  app/core/provisioning_service.py                      │
│  Après succès opération Keycloak                       │
└────────────────────────────────────────────────────────┘
                     ↓ log_jml_event()
┌────────────────────────────────────────────────────────┐
│  scripts/audit.py                                      │
│  1. Sérialise événement en JSON                        │
│  2. Calcule HMAC-SHA256 avec secret key               │
│  3. Append à .runtime/audit/jml-events.jsonl          │
└────────────────────────────────────────────────────────┘
                     ↓ stockage
┌────────────────────────────────────────────────────────┐
│  .runtime/audit/jml-events.jsonl (append-only)        │
│  Une ligne JSON par événement + HMAC                   │
└────────────────────────────────────────────────────────┘
```

---

## 🔐 HMAC : Qu'est-ce Que C'est ?

### Définition

**HMAC = Hash-based Message Authentication Code**

**Formule** :
```
HMAC-SHA256(message, secret_key) = 
    SHA256((secret_key ⊕ opad) || SHA256((secret_key ⊕ ipad) || message))
```

**Version simplifiée** :
```python
import hmac
import hashlib

def calculate_hmac(message: str, secret_key: bytes) -> str:
    """Calcule HMAC-SHA256 d'un message."""
    signature = hmac.new(
        secret_key,
        message.encode('utf-8'),
        hashlib.sha256
    )
    return signature.hexdigest()  # Retourne hex string (64 chars)
```

---

### HMAC vs Simple Hash

| Aspect | Simple Hash (SHA256) | HMAC-SHA256 |
|--------|---------------------|-------------|
| **Input** | Message seulement | Message + Secret Key |
| **Sécurité** | ❌ Pas d'authentification | ✅ Authentifié (nécessite clé) |
| **Modification** | Attaquant peut recalculer hash | Attaquant ne peut PAS recalculer sans clé |
| **Use case** | Intégrité fichier (checksum) | Authentification message (signature) |

**Exemple attaque sans HMAC** :
```json
// Log original
{"event": "joiner", "username": "alice"}

// Attaquant modifie
{"event": "joiner", "username": "bob"}
// Recalcule SHA256 → Validation passe ❌
```

**Avec HMAC** :
```json
// Log original
{"event": "joiner", "username": "alice", "hmac": "d4f3c2..."}

// Attaquant modifie username
{"event": "joiner", "username": "bob", "hmac": "d4f3c2..."}
// HMAC invalide (calculé avec "alice") → Détection tampering ✅
```

---

## 📄 Structure d'un Événement Audit

### Format JSONL (JSON Lines)

**Fichier** : `.runtime/audit/jml-events.jsonl`

Chaque ligne = 1 événement JSON complet :
```jsonl
{"timestamp": "2024-10-25T14:30:00Z", "event_type": "joiner", "username": "alice", "hmac": "abc123..."}
{"timestamp": "2024-10-25T14:31:00Z", "event_type": "mover", "username": "alice", "hmac": "def456..."}
{"timestamp": "2024-10-25T14:32:00Z", "event_type": "leaver", "username": "bob", "hmac": "ghi789..."}
```

**Avantages JSONL** :
- ✅ **Append-only** : Ajout en fin de fichier (pas de réécriture)
- ✅ **Stream-friendly** : Lecture ligne par ligne (pas de chargement mémoire complet)
- ✅ **Humain-lisible** : `cat jml-events.jsonl` fonctionne

---

### Schéma Événement

**Fichier** : `scripts/audit.py`

```python
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any

@dataclass
class AuditEvent:
    """Représentation événement JML."""
    
    # Champs obligatoires
    timestamp: str              # ISO 8601 UTC (ex: "2024-10-25T14:30:00.123Z")
    event_type: str             # joiner|mover|leaver|scim_create_user|scim_update_user|etc.
    username: str               # User impacté
    operator: str               # Qui a effectué l'action
    realm: str                  # Keycloak realm (demo)
    success: bool               # True si succès, False si échec
    
    # Champs optionnels
    details: Optional[Dict[str, Any]] = None  # Métadonnées supplémentaires
    error: Optional[str] = None               # Message erreur si success=False
    
    # Signature HMAC (calculée automatiquement)
    hmac: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convertit en dict pour sérialisation JSON."""
        return {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'username': self.username,
            'operator': self.operator,
            'realm': self.realm,
            'success': self.success,
            'details': self.details,
            'error': self.error,
            'hmac': self.hmac
        }
```

---

### Exemple Événements Réels

#### Joiner (Nouvel Employé)
```json
{
  "timestamp": "2024-10-25T14:30:01.234Z",
  "event_type": "joiner",
  "username": "alice",
  "operator": "admin@example.com",
  "realm": "demo",
  "success": true,
  "details": {
    "user_id": "8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d",
    "email": "alice@example.com",
    "initial_role": "analyst",
    "temp_password": "***"  // Masqué pour sécurité
  },
  "hmac": "d4f3c2b1a0e9f8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4b3"
}
```

#### Mover (Changement Rôle)
```json
{
  "timestamp": "2024-10-25T15:00:00.567Z",
  "event_type": "mover",
  "username": "alice",
  "operator": "hr-manager@example.com",
  "realm": "demo",
  "success": true,
  "details": {
    "user_id": "8a7f2d1e-4b3c-9f2e-1d4c-8e7f2a1b3c4d",
    "from_role": "analyst",
    "to_role": "manager",
    "reason": "Promotion Q4 2024"
  },
  "hmac": "e5g4d3c2b1a0f9e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4"
}
```

#### Leaver (Départ Employé)
```json
{
  "timestamp": "2024-10-25T16:30:00.890Z",
  "event_type": "leaver",
  "username": "bob",
  "operator": "admin@example.com",
  "realm": "demo",
  "success": true,
  "details": {
    "user_id": "9b8g3e2f-5c4d-0g3f-2e5d-9f8g3b2c4d5e",
    "disabled": true,
    "sessions_revoked": 3,
    "reason": "End of contract"
  },
  "hmac": "f6h5e4d3c2b1a0g0f9e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8f7e6"
}
```

#### SCIM API Create User
```json
{
  "timestamp": "2024-10-25T17:00:00.123Z",
  "event_type": "scim_create_user",
  "username": "charlie",
  "operator": "azure-ad-sync",  // Service account
  "realm": "demo",
  "success": true,
  "details": {
    "user_id": "0c9h4f3g-6d5e-1h4g-3f6e-0g9h4c3d5e6f",
    "source": "azure_ad",
    "scim_schema": "urn:ietf:params:scim:schemas:core:2.0:User",
    "client_id": "automation-cli"
  },
  "hmac": "g7i6f5e4d3c2b1a0h1g0f9e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0b9a8"
}
```

#### Échec (Error Handling)
```json
{
  "timestamp": "2024-10-25T18:00:00.456Z",
  "event_type": "joiner",
  "username": "duplicate-user",
  "operator": "admin@example.com",
  "realm": "demo",
  "success": false,
  "error": "User already exists (409 Conflict)",
  "details": {
    "attempted_email": "user@example.com",
    "keycloak_error": "User with username 'duplicate-user' already exists"
  },
  "hmac": "h8j7g6f5e4d3c2b1a0i2h1g0f9e8d7c6b5a4e3d2c1b0a9f8e7d6c5b4a3e2d1c0"
}
```

---

## 🔧 Implémentation : Code Complet

### Fichier : `scripts/audit.py`

```python
"""Audit logging utilities for IAM operations (JML events)."""
import os
import json
import hmac
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Configuration
AUDIT_DIR = Path('.runtime/audit')
AUDIT_FILE = AUDIT_DIR / 'jml-events.jsonl'
DEFAULT_REALM = 'demo'

def _get_signing_key() -> bytes:
    """
    Récupère clé de signature HMAC depuis environnement.
    
    Ordre de priorité:
    1. Docker secret: /run/secrets/audit-log-signing-key
    2. Environment variable: AUDIT_LOG_SIGNING_KEY
    3. Demo mode fallback (INSECURE - dev only)
    
    Returns:
        bytes: Secret key pour HMAC-SHA256
    """
    # 1. Docker secret
    secret_file = Path('/run/secrets/audit-log-signing-key')
    if secret_file.exists():
        return secret_file.read_bytes().strip()
    
    # 2. Environment variable
    env_key = os.getenv('AUDIT_LOG_SIGNING_KEY')
    if env_key:
        return env_key.encode('utf-8')
    
    # 3. Demo mode fallback
    if os.getenv('DEMO_MODE') == 'true':
        print('[audit] WARNING: Using demo signing key (NOT FOR PRODUCTION)')
        return b'demo-audit-signing-key-change-in-production'
    
    raise ValueError('AUDIT_LOG_SIGNING_KEY not found (not in /run/secrets, env, or demo mode)')

def _ensure_audit_dir() -> None:
    """Crée répertoire audit si n'existe pas."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

def _sign_event(event: dict) -> str:
    """
    Calcule signature HMAC-SHA256 d'un événement.
    
    Process:
    1. Sérialise événement en JSON canonique (sorted keys)
    2. Calcule HMAC-SHA256 avec secret key
    3. Retourne hex digest
    
    Args:
        event: Dict événement (sans champ 'hmac')
    
    Returns:
        str: Signature HMAC (64 caractères hex)
    """
    # Sérialisation canonique (clés triées pour reproductibilité)
    event_copy = {k: v for k, v in event.items() if k != 'hmac'}  # Exclut hmac si présent
    canonical_json = json.dumps(event_copy, sort_keys=True, separators=(',', ':'))
    
    # Calcul HMAC
    signing_key = _get_signing_key()
    signature = hmac.new(
        signing_key,
        canonical_json.encode('utf-8'),
        hashlib.sha256
    )
    
    return signature.hexdigest()

def log_jml_event(
    event_type: str,
    username: str,
    operator: str,
    success: bool,
    realm: str = DEFAULT_REALM,
    details: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
) -> None:
    """
    Enregistre événement JML avec signature HMAC.
    
    Args:
        event_type: Type événement (joiner|mover|leaver|scim_*)
        username: User impacté par l'opération
        operator: User/service qui a effectué l'action
        success: True si succès, False si échec
        realm: Keycloak realm (default: demo)
        details: Métadonnées supplémentaires (dict)
        error: Message erreur si success=False
    
    Raises:
        Exception: Si écriture fichier échoue
    
    Example:
        >>> log_jml_event(
        ...     event_type='joiner',
        ...     username='alice',
        ...     operator='admin',
        ...     success=True,
        ...     details={'email': 'alice@example.com', 'role': 'analyst'}
        ... )
    """
    _ensure_audit_dir()
    
    # 1. Construit événement
    event = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'username': username,
        'operator': operator,
        'realm': realm,
        'success': success,
        'details': details or {},
        'error': error
    }
    
    # 2. Calcule HMAC
    event['hmac'] = _sign_event(event)
    
    # 3. Append à fichier (mode append, une ligne par événement)
    try:
        with AUDIT_FILE.open('a', encoding='utf-8') as f:
            json.dump(event, f, separators=(',', ':'))
            f.write('\n')  # JSONL format
    except Exception as e:
        # Log to stderr (ne doit JAMAIS crasher l'application)
        print(f'[audit] ERROR: Failed to write audit log: {e}', file=sys.stderr)
        raise

def safe_log_jml_event(*args, **kwargs) -> None:
    """
    Wrapper safe de log_jml_event (ne lève jamais d'exception).
    
    Utiliser dans code critique où échec audit ne doit pas bloquer opération.
    """
    try:
        log_jml_event(*args, **kwargs)
    except Exception as e:
        print(f'[audit] ERROR: Audit logging failed: {e}', file=sys.stderr)
        # Continue execution (audit failure non-fatal)

def verify_audit_log() -> tuple[int, int]:
    """
    Vérifie intégrité de tous les événements audit.
    
    Returns:
        tuple: (événements_valides, événements_invalides)
    
    Example:
        >>> valid, invalid = verify_audit_log()
        >>> print(f"Valid: {valid}, Invalid: {invalid}")
    """
    if not AUDIT_FILE.exists():
        print('[audit] No audit log found')
        return 0, 0
    
    valid_count = 0
    invalid_count = 0
    
    with AUDIT_FILE.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, start=1):
            try:
                event = json.loads(line.strip())
                stored_hmac = event.pop('hmac', None)
                
                if not stored_hmac:
                    print(f'[audit] Line {line_num}: Missing HMAC')
                    invalid_count += 1
                    continue
                
                # Recalcule HMAC
                calculated_hmac = _sign_event(event)
                
                if calculated_hmac == stored_hmac:
                    valid_count += 1
                else:
                    print(f'[audit] Line {line_num}: HMAC mismatch (tampering detected!)')
                    print(f'  Expected: {calculated_hmac}')
                    print(f'  Got:      {stored_hmac}')
                    invalid_count += 1
                    
            except json.JSONDecodeError as e:
                print(f'[audit] Line {line_num}: Invalid JSON: {e}')
                invalid_count += 1
    
    print(f'[audit] Verification complete: {valid_count} valid, {invalid_count} invalid')
    return valid_count, invalid_count

# CLI interface
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        valid, invalid = verify_audit_log()
        sys.exit(0 if invalid == 0 else 1)
    else:
        print('Usage: python audit.py verify')
        sys.exit(1)
```

---

## 🧪 Tests & Validation

### Test 1 : Écriture Événement

```python
# tests/test_audit.py
import pytest
from scripts import audit

def test_log_jml_event_success(tmp_path, monkeypatch):
    """Test log événement avec succès."""
    # Override audit directory
    monkeypatch.setattr(audit, 'AUDIT_DIR', tmp_path)
    monkeypatch.setattr(audit, 'AUDIT_FILE', tmp_path / 'test-audit.jsonl')
    monkeypatch.setenv('DEMO_MODE', 'true')
    
    # Log événement
    audit.log_jml_event(
        event_type='joiner',
        username='alice',
        operator='admin',
        success=True,
        details={'email': 'alice@example.com'}
    )
    
    # Vérifie fichier créé
    audit_file = tmp_path / 'test-audit.jsonl'
    assert audit_file.exists()
    
    # Vérifie contenu
    lines = audit_file.read_text().strip().split('\n')
    assert len(lines) == 1
    
    event = json.loads(lines[0])
    assert event['event_type'] == 'joiner'
    assert event['username'] == 'alice'
    assert event['success'] is True
    assert 'hmac' in event
    assert len(event['hmac']) == 64  # SHA256 hex = 64 chars
```

---

### Test 2 : Vérification HMAC

```python
def test_verify_audit_log_valid(tmp_path, monkeypatch):
    """Test vérification événements valides."""
    monkeypatch.setattr(audit, 'AUDIT_DIR', tmp_path)
    monkeypatch.setattr(audit, 'AUDIT_FILE', tmp_path / 'test-audit.jsonl')
    monkeypatch.setenv('DEMO_MODE', 'true')
    
    # Log 3 événements
    for i in range(3):
        audit.log_jml_event(
            event_type='joiner',
            username=f'user{i}',
            operator='admin',
            success=True
        )
    
    # Vérifie intégrité
    valid, invalid = audit.verify_audit_log()
    assert valid == 3
    assert invalid == 0
```

---

### Test 3 : Détection Tampering

```python
def test_detect_tampering(tmp_path, monkeypatch):
    """Test détection modification événement."""
    monkeypatch.setattr(audit, 'AUDIT_DIR', tmp_path)
    audit_file = tmp_path / 'test-audit.jsonl'
    monkeypatch.setattr(audit, 'AUDIT_FILE', audit_file)
    monkeypatch.setenv('DEMO_MODE', 'true')
    
    # Log événement
    audit.log_jml_event(
        event_type='joiner',
        username='alice',
        operator='admin',
        success=True
    )
    
    # ATTAQUE: Modifie username (garde HMAC original)
    with audit_file.open('r') as f:
        event = json.loads(f.read())
    
    event['username'] = 'bob'  # Modification malveillante
    
    with audit_file.open('w') as f:
        json.dump(event, f)
        f.write('\n')
    
    # Vérifie détection
    valid, invalid = audit.verify_audit_log()
    assert valid == 0
    assert invalid == 1  # Tampering détecté !
```

---

## 🔐 Sécurité : Points Critiques

### 1. **Protection Secret Key**

**Hiérarchie secrets** :
```
BEST       → Vault externe (Azure Key Vault, HashiCorp Vault)
GOOD       → Docker secret (/run/secrets/*, tmpfs)
ACCEPTABLE → Environment variable (AUDIT_LOG_SIGNING_KEY)
BAD        → Fichier .env commité en Git
TERRIBLE   → Hardcodé dans code
```

**Implémentation IAM PoC** :
```python
# 1. Prodution: Azure Key Vault → Docker secret
/run/secrets/audit-log-signing-key

# 2. Dev: Environment variable
export AUDIT_LOG_SIGNING_KEY=$(openssl rand -hex 32)

# 3. Demo: Fallback auto-généré
DEMO_MODE=true  # Auto-génère clé (warning affiché)
```

---

### 2. **Rotation Clé de Signature**

**Problème** : Si clé compromise, attaquant peut forger événements.

**Solution** : Rotation périodique avec versioning.

**Schéma avancé** (non implémenté, POC production) :
```json
{
  "timestamp": "2024-10-25T14:30:00Z",
  "event_type": "joiner",
  "username": "alice",
  "key_version": "2024-10",  // Version clé utilisée
  "hmac": "d4f3c2..."
}
```

**Process rotation** :
```bash
# 1. Génère nouvelle clé
NEW_KEY=$(openssl rand -hex 32)

# 2. Stocke en Key Vault avec version
az keyvault secret set --vault-name iam-poc-kv \
  --name audit-signing-key \
  --value "$NEW_KEY" \
  --tags version=2024-11

# 3. Redémarre application (charge nouvelle clé)
docker compose restart flask-app

# 4. Anciens logs vérifiables avec ancienne clé (archive)
```

---

### 3. **Append-Only Storage**

**Protection filesystem** :
```bash
# Permissions audit directory (root:root, lecture seule pour app)
chown root:root .runtime/audit
chmod 755 .runtime/audit  # rwxr-xr-x

# Fichier audit (Flask peut écrire, pas supprimer)
chown flask-app:flask-app .runtime/audit/jml-events.jsonl
chmod 644 .runtime/audit/jml-events.jsonl  # rw-r--r--
```

**Protection avancée (Linux)** :
```bash
# Immutable flag (même root ne peut modifier)
chattr +a .runtime/audit/jml-events.jsonl  # Append-only
chattr +i .runtime/audit/old-logs/         # Immutable (archives)
```

---

### 4. **PII (Données Personnelles)**

**Données sensibles dans logs** :
- ✅ Username (nécessaire pour audit)
- ✅ Email (nécessaire pour investigation)
- ❌ Mot de passe (JAMAIS logger, même temporaire)
- ⚠️ IP address (optionnel, selon RGPD)

**Bonnes pratiques** :
```python
# ✅ BON : Masque password
details = {
    'user_id': user_id,
    'temp_password': '***'  # Masqué
}

# ❌ MAUVAIS : Log password en clair
details = {
    'user_id': user_id,
    'temp_password': 'SecretP@ss123'  # NEVER DO THIS
}
```

**Compliance RGPD** :
- Logs = "données de journalisation" (Article 30 RGPD)
- Rétention limitée : 90 jours recommandé (configurable)
- Droit à l'effacement : Pseudonymisation (`user_<hash>` au lieu de `alice`)

---

## 📊 Analyse & Reporting

### Commande Makefile

```bash
# Vérification intégrité
make audit-verify
# → python scripts/audit.py verify

# Affichage logs récents
make audit-tail
# → tail -f .runtime/audit/jml-events.jsonl

# Statistiques
make audit-stats
# → jq -r '.event_type' .runtime/audit/jml-events.jsonl | sort | uniq -c
```

---

### Requêtes jq (JSON Query)

**Compter événements par type** :
```bash
jq -r '.event_type' .runtime/audit/jml-events.jsonl | sort | uniq -c
# Output:
#  12 joiner
#   8 mover
#   5 leaver
#  23 scim_create_user
```

**Filtrer échecs** :
```bash
jq 'select(.success == false)' .runtime/audit/jml-events.jsonl
```

**Événements Alice** :
```bash
jq 'select(.username == "alice")' .runtime/audit/jml-events.jsonl
```

**Opérations par admin spécifique** :
```bash
jq 'select(.operator == "admin@example.com")' .runtime/audit/jml-events.jsonl
```

---

### Dashboard (Optionnel - Elasticsearch + Kibana)

**Architecture production** :
```
Flask → Filebeat → Elasticsearch → Kibana Dashboard
```

**Avantages** :
- Recherche full-text
- Visualisations temps réel
- Alerting (ex: 10 échecs en 5 min → Alert Slack)

---

## 🎓 Concepts pour Entretien Sécurité

### 1. **Non-Répudiation**

**Définition** : Impossible pour l'opérateur de nier avoir effectué une action.

**Implémentation** :
- ✅ Signature HMAC (attaquant ne peut pas modifier log sans clé)
- ✅ Timestamp UTC (horodatage non-altérable)
- ✅ Operator = User JWT sub claim (authentifié OAuth)

**Cas d'usage** :
- Conformité audit (SOC 2, ISO 27001)
- Investigation incident sécurité
- Litiges RH (qui a désactivé Alice ?)

---

### 2. **OWASP A09:2021 - Security Logging Failures**

**Erreurs fréquentes** :
- ❌ **Pas de logs** : Impossible d'investiguer incidents
- ❌ **Logs non protégés** : Attaquant modifie/supprime traces
- ❌ **Pas d'alerting** : Attaques non détectées en temps réel
- ❌ **PII non masqués** : Violation RGPD

**Bonnes pratiques implémentées** :
- ✅ **HMAC signatures** : Détection tampering
- ✅ **Append-only** : Logs non-modifiables
- ✅ **Structured logging** : JSON parsable (SIEM-ready)
- ✅ **PII minimization** : Passwords masqués

---

### 3. **SIEM Integration**

**SIEM = Security Information and Event Management**

**Cas d'usage** :
```
Audit logs → SIEM (Splunk, ELK, Sentinel) → Détection patterns anormaux
```

**Exemples règles** :
- Alert si 5 échecs login en 10 min (brute-force)
- Alert si création 10+ users en 1 min (automation compromise)
- Alert si Leaver event hors heures bureau (accès non-autorisé)

---

## 🎯 Récapitulatif : Audit Logging Sécurisé

| Aspect | Implémentation IAM PoC |
|--------|------------------------|
| **Format** | JSONL (JSON Lines) - Une ligne par événement |
| **Signature** | HMAC-SHA256 avec secret key |
| **Storage** | Append-only file (.runtime/audit/jml-events.jsonl) |
| **Secret** | Docker secret (/run/secrets) > env var > demo fallback |
| **Vérification** | `make audit-verify` (valide tous HMAC) |
| **PII** | Passwords masqués, usernames/emails loggés |
| **Compliance** | Non-répudiation (SOC 2, ISO 27001, RGPD) |

---

## 📚 Ressources Complémentaires

### Standards
- **RFC 6234** : HMAC-SHA256 specification
- **NIST SP 800-107** : Recommendation for hash algorithms
- **ISO 27001:2022** : Annex A.8.15 (Logging)

### OWASP
- **A09:2021** : Security Logging and Monitoring Failures
- **Logging Cheat Sheet** : https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

### Tests
- **Fichier** : `tests/test_audit.py`
- **Commande** : `pytest tests/test_audit.py -v`

---

**Dernière mise à jour** : Octobre 2025  
**Auteur** : Alex (IAM PoC Portfolio)
