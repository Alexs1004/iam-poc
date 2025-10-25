# 🐳 Docker Secrets Pattern : Guide Approfondi

> **Objectif** : Comprendre comment gérer les secrets de manière sécurisée avec Docker Secrets + Azure Key Vault

**Pré-requis** : Notions Docker, docker-compose.

---

## 🎯 Pourquoi Docker Secrets ?

### Problème : Secrets en Clair

**Anti-pattern classique** :
```yaml
# docker-compose.yml ❌ DANGEREUX
services:
  flask-app:
    environment:
      - FLASK_SECRET_KEY=my-super-secret-key-123  # En clair !
      - DATABASE_PASSWORD=admin123                # Commité en Git !
```

**Conséquences** :
- ❌ **Git history** : Secret visible dans tous les commits
- ❌ **Logs Docker** : `docker inspect` expose secrets
- ❌ **Process env** : `/proc/<pid>/environ` lisible par root
- ❌ **Dumps mémoire** : Core dumps contiennent secrets

---

### Solution : Docker Secrets

**Principe** :
```
Secrets stockés en tmpfs (/run/secrets/)
├─ Montage RAM (pas disque)
├─ Accessible seulement par container autorisé
└─ Effacé au redémarrage
```

**Avantages** :
- ✅ **Pas sur disque** : Secrets jamais écrits en persistant storage
- ✅ **Isolation** : Chaque container ne voit que ses secrets
- ✅ **Audit trail** : Docker logs qui accède à quoi
- ✅ **Rotation facile** : Update secret → Restart container

---

## 🏗️ Architecture Secrets dans IAM PoC

```
┌──────────────────────────────────────────────────────────┐
│  DÉVELOPPEMENT (Demo Mode)                               │
│  .env → Auto-génération secrets → Docker secrets        │
└──────────────────────────────────────────────────────────┘
                     ↓ transition
┌──────────────────────────────────────────────────────────┐
│  PRODUCTION                                              │
│  Azure Key Vault → load_secrets_from_keyvault.sh →     │
│  .runtime/secrets/ → Docker secrets → Containers        │
└──────────────────────────────────────────────────────────┘
```

---

## 📁 Structure Secrets Projet

```
iam-poc/
├── .env.demo                    # Template secrets (non commité)
├── .env                         # Secrets actifs (gitignored)
├── .runtime/secrets/            # Secrets chargés (gitignored)
│   ├── flask-secret-key
│   ├── keycloak-service-client-secret
│   ├── keycloak-admin-password
│   └── audit-log-signing-key
└── docker-compose.yml           # Référence secrets
```

---

## 🔧 Implémentation : 3 Modes

### Mode 1 : Développement Local (Demo)

**Fichier** : `.env.demo` (template committé)

```bash
# .env.demo - Template pour développement
DEMO_MODE=true
AZURE_USE_KEYVAULT=false

# Secrets auto-générés par make ensure-secrets
FLASK_SECRET_KEY=
KEYCLOAK_SERVICE_CLIENT_SECRET=
KEYCLOAK_ADMIN_PASSWORD=
AUDIT_LOG_SIGNING_KEY=
```

**Workflow développeur** :
```bash
# 1. Clone repo
git clone https://github.com/Alexs1004/iam-poc.git
cd iam-poc

# 2. Copie template
cp .env.demo .env

# 3. Génère secrets automatiquement
make ensure-secrets
# → Auto-génère secrets aléatoires dans .env

# 4. Démarre stack
make quickstart
# → Charge secrets dans Docker secrets
```

**Code génération** : `Makefile`

```makefile
ensure-secrets:
	@echo "🔑 Ensuring secrets are set..."
	@if [ ! -f .env ]; then \
		cp .env.demo .env; \
		echo "✓ Created .env from template"; \
	fi
	@python3 scripts/update_env.py .env FLASK_SECRET_KEY "$$(openssl rand -hex 32)" || true
	@python3 scripts/update_env.py .env KEYCLOAK_SERVICE_CLIENT_SECRET "$$(openssl rand -hex 16)" || true
	@python3 scripts/update_env.py .env KEYCLOAK_ADMIN_PASSWORD "$$(openssl rand -base64 16)" || true
	@python3 scripts/update_env.py .env AUDIT_LOG_SIGNING_KEY "$$(openssl rand -hex 32)" || true
	@echo "✓ All secrets generated"
```

---

### Mode 2 : Production avec Docker Secrets Locaux

**Fichier** : `docker-compose.yml`

```yaml
version: '3.8'

services:
  flask-app:
    image: iam-poc-flask
    secrets:
      - flask-secret-key
      - keycloak-service-client-secret
      - audit-log-signing-key
    environment:
      # Pas de secrets en env vars ! Seulement config non-sensible
      - DEMO_MODE=false
      - KEYCLOAK_URL=http://keycloak:8080
    volumes:
      - type: bind
        source: ./.runtime/secrets
        target: /run/secrets
        read_only: true  # Important: lecture seule

secrets:
  flask-secret-key:
    file: .runtime/secrets/flask-secret-key
  keycloak-service-client-secret:
    file: .runtime/secrets/keycloak-service-client-secret
  audit-log-signing-key:
    file: .runtime/secrets/audit-log-signing-key
```

**Structure tmpfs dans container** :
```
/run/secrets/                             # tmpfs mount (RAM)
├── flask-secret-key                      # Mode 0400 (read-only owner)
├── keycloak-service-client-secret        # Mode 0400
└── audit-log-signing-key                 # Mode 0400
```

**Code chargement** : `app/config/settings.py`

```python
from pathlib import Path
import os

class Config:
    """Centralized configuration with Docker Secrets support."""
    
    @staticmethod
    def get_secret(name: str, default: str = None) -> str:
        """
        Load secret with fallback hierarchy:
        1. Docker secret (/run/secrets/*)
        2. Environment variable
        3. Demo mode fallback
        
        Args:
            name: Secret name (ex: 'flask-secret-key')
            default: Fallback value if not found
        
        Returns:
            str: Secret value
        
        Raises:
            ValueError: If secret not found in production mode
        """
        # 1. Docker secret (production pattern)
        secret_file = Path(f'/run/secrets/{name}')
        if secret_file.exists():
            print(f'[settings] ✓ Loaded {name} from Docker secret')
            return secret_file.read_text().strip()
        
        # 2. Environment variable (dev/CI)
        env_value = os.getenv(name.upper().replace('-', '_'))
        if env_value:
            print(f'[settings] ✓ Loaded {name} from environment (fallback)')
            return env_value
        
        # 3. Demo mode fallback (INSECURE - dev only)
        if os.getenv('DEMO_MODE') == 'true':
            demo_defaults = {
                'flask-secret-key': 'demo-flask-secret-change-in-production',
                'keycloak-service-client-secret': 'demo-service-secret',
                'keycloak-admin-password': 'admin',
                'audit-log-signing-key': 'demo-audit-signing-key'
            }
            if name in demo_defaults:
                print(f'[settings] ⚠ WARNING: Using demo value for {name}')
                return demo_defaults[name]
        
        # 4. Not found
        raise ValueError(
            f'Secret {name} not found. '
            f'Check: /run/secrets/{name}, ${name.upper()}, or set DEMO_MODE=true'
        )
    
    # Configuration attributes
    FLASK_SECRET_KEY = get_secret('flask-secret-key')
    KEYCLOAK_CLIENT_SECRET = get_secret('keycloak-service-client-secret')
    AUDIT_LOG_SIGNING_KEY = get_secret('audit-log-signing-key')
```

---

### Mode 3 : Production avec Azure Key Vault

**Architecture** :
```
┌──────────────────────────────────────────────────────────┐
│  AZURE KEY VAULT (Cloud HSM)                             │
│  - flask-secret-key                                      │
│  - keycloak-service-client-secret                        │
│  - audit-log-signing-key                                 │
└──────────────────────────────────────────────────────────┘
                     ↓ az CLI (DefaultAzureCredential)
┌──────────────────────────────────────────────────────────┐
│  SCRIPT: scripts/load_secrets_from_keyvault.sh           │
│  Download secrets → .runtime/secrets/                    │
└──────────────────────────────────────────────────────────┘
                     ↓ Docker volume mount
┌──────────────────────────────────────────────────────────┐
│  CONTAINER: /run/secrets/ (tmpfs)                        │
│  Flask app lit secrets via Config.get_secret()           │
└──────────────────────────────────────────────────────────┘
```

**Script chargement** : `scripts/load_secrets_from_keyvault.sh`

```bash
#!/usr/bin/env bash
# Load secrets from Azure Key Vault to local filesystem

set -euo pipefail

VAULT_NAME="${AZURE_KEYVAULT_NAME:-iam-poc-kv}"
SECRETS_DIR=".runtime/secrets"

echo "🔑 Loading secrets from Azure Key Vault: $VAULT_NAME"

# Ensure directory exists
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"  # Owner only

# Load each secret
secrets=(
    "flask-secret-key"
    "keycloak-service-client-secret"
    "keycloak-admin-password"
    "audit-log-signing-key"
)

for secret_name in "${secrets[@]}"; do
    echo "  ↓ Downloading $secret_name..."
    
    # Download secret from Key Vault
    az keyvault secret show \
        --vault-name "$VAULT_NAME" \
        --name "$secret_name" \
        --query value \
        --output tsv > "$SECRETS_DIR/$secret_name"
    
    # Set permissions (read-only owner)
    chmod 400 "$SECRETS_DIR/$secret_name"
    
    echo "  ✓ Saved to $SECRETS_DIR/$secret_name"
done

echo "✓ All secrets loaded successfully"
```

**Workflow production** :
```bash
# 1. Authenticate Azure CLI
az login

# 2. Load secrets from Key Vault
make load-secrets
# → scripts/load_secrets_from_keyvault.sh

# 3. Start stack (uses secrets from .runtime/secrets/)
docker compose up -d

# 4. Verify secrets loaded
docker compose exec flask-app ls -la /run/secrets/
```

---

## 🔐 Sécurité : Points Critiques

### 1. **Permissions Filesystem**

**Best practices** :
```bash
# Secrets directory (owner only)
chmod 700 .runtime/secrets/
chown root:root .runtime/secrets/  # Production

# Individual secrets (read-only owner)
chmod 400 .runtime/secrets/flask-secret-key
chown root:root .runtime/secrets/flask-secret-key
```

**Vérification** :
```bash
ls -la .runtime/secrets/
# drwx------ 2 root root 4096 Oct 25 14:30 .
# -r-------- 1 root root   64 Oct 25 14:30 flask-secret-key
# -r-------- 1 root root   32 Oct 25 14:30 keycloak-service-client-secret
```

---

### 2. **Gitignore Critical**

**Fichier** : `.gitignore`

```gitignore
# Secrets (NEVER commit)
.env
.runtime/secrets/
/run/secrets/

# Logs may contain secrets
*.log
.runtime/audit/

# Docker volumes may contain secrets
.runtime/
```

**Vérification** :
```bash
# Check si secrets committables
git status --ignored

# Check historique Git
git log --all --full-history -- .env
# → Should be empty (never committed)
```

---

### 3. **Docker Inspect Protection**

**Problème** : `docker inspect` peut exposer env vars.

**Solution** : Utiliser secrets au lieu d'env vars.

**Comparaison** :

```bash
# ❌ MAUVAIS : Secret en env var
docker compose exec flask-app env | grep SECRET
# FLASK_SECRET_KEY=my-super-secret-123  # Visible !

# ✅ BON : Secret en Docker secret
docker compose exec flask-app env | grep SECRET
# (vide - secret pas dans env vars)

docker compose exec flask-app cat /run/secrets/flask-secret-key
# my-super-secret-123  # Accessible seulement via filesystem
```

---

### 4. **Rotation Secrets**

**Script rotation** : `scripts/rotate_secret.sh`

```bash
#!/usr/bin/env bash
# Rotate Keycloak service account secret

set -euo pipefail

SECRET_NAME="keycloak-service-client-secret"
VAULT_NAME="${AZURE_KEYVAULT_NAME:-iam-poc-kv}"

echo "🔄 Rotating $SECRET_NAME..."

# 1. Generate new secret
NEW_SECRET=$(openssl rand -hex 32)
echo "  ✓ Generated new secret (64 chars)"

# 2. Update Keycloak client credential
echo "  ↓ Updating Keycloak client 'automation-cli'..."
# (Code omitted - see scripts/rotate_secret.sh for full implementation)

# 3. Store in Key Vault
echo "  ↓ Storing in Azure Key Vault..."
az keyvault secret set \
    --vault-name "$VAULT_NAME" \
    --name "$SECRET_NAME" \
    --value "$NEW_SECRET" \
    --tags "rotated=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > /dev/null

echo "  ✓ Stored in Key Vault"

# 4. Update local secrets file
echo "$NEW_SECRET" > ".runtime/secrets/$SECRET_NAME"
chmod 400 ".runtime/secrets/$SECRET_NAME"
echo "  ✓ Updated local secret file"

# 5. Restart Flask app (reload secret)
echo "  ↓ Restarting Flask application..."
docker compose restart flask-app
sleep 3

# 6. Health check
echo "  ↓ Health check..."
curl -sf http://localhost:8000/health > /dev/null
echo "  ✓ Application healthy with new secret"

echo "✓ Secret rotation complete"
```

**Workflow rotation** :
```bash
# Dry-run (validation only)
make rotate-secret-dry

# Execute rotation
make rotate-secret
# 1. Génère nouveau secret
# 2. Update Keycloak client credential
# 3. Store in Key Vault
# 4. Update local file
# 5. Restart Flask app
# 6. Health check
```

---

## 🧪 Tests & Validation

### Test 1 : Chargement Secrets

```python
# tests/test_settings_load.py
import pytest
from pathlib import Path
from app.config.settings import Config

def test_load_secret_from_file(tmp_path, monkeypatch):
    """Test chargement secret depuis Docker secret."""
    # Create mock secret file
    secret_file = tmp_path / 'test-secret'
    secret_file.write_text('my-secret-value\n')
    
    # Mock /run/secrets path
    monkeypatch.setattr(Path, 'exists', lambda self: str(self) == str(secret_file))
    monkeypatch.setattr(Path, 'read_text', lambda self: secret_file.read_text())
    
    # Test
    secret = Config.get_secret('test-secret')
    assert secret == 'my-secret-value'
```

---

### Test 2 : Fallback Env Var

```python
def test_fallback_env_var(monkeypatch):
    """Test fallback vers env var si Docker secret absent."""
    # Mock: Docker secret n'existe pas
    monkeypatch.setattr(Path, 'exists', lambda self: False)
    
    # Set env var
    monkeypatch.setenv('TEST_SECRET', 'env-value')
    
    # Test
    secret = Config.get_secret('test-secret')
    assert secret == 'env-value'
```

---

### Test 3 : Demo Mode Fallback

```python
def test_demo_mode_fallback(monkeypatch):
    """Test demo mode génère secrets automatiquement."""
    # Mock: Pas de Docker secret ni env var
    monkeypatch.setattr(Path, 'exists', lambda self: False)
    monkeypatch.delenv('TEST_SECRET', raising=False)
    
    # Enable demo mode
    monkeypatch.setenv('DEMO_MODE', 'true')
    
    # Test
    secret = Config.get_secret('flask-secret-key')
    assert secret.startswith('demo-')  # Demo prefix
```

---

## 📊 Monitoring & Audit

### Secret Access Logs

**Docker logs** (audit trail) :
```bash
# Voir quels containers accèdent secrets
docker events --filter event=mount --filter type=secret

# Logs Flask (secret load events)
docker compose logs flask-app | grep '\[settings\]'
# [settings] ✓ Loaded flask-secret-key from Docker secret
# [settings] ✓ Loaded keycloak-service-client-secret from Docker secret
```

---

### Health Check Secret Validity

**Endpoint** : `/health`

```python
# app/api/health.py
from flask import Blueprint, jsonify
from app.config.settings import Config

bp = Blueprint('health', __name__)

@bp.route('/health')
def health_check():
    """
    Health check endpoint avec validation secrets.
    
    Returns:
        200: All systems operational
        503: Service unhealthy (secrets missing/invalid)
    """
    checks = {
        'status': 'healthy',
        'secrets': {}
    }
    
    # Validate secrets loaded
    try:
        Config.get_secret('flask-secret-key')
        checks['secrets']['flask-secret-key'] = 'loaded'
    except Exception as e:
        checks['secrets']['flask-secret-key'] = f'missing: {e}'
        checks['status'] = 'unhealthy'
    
    try:
        Config.get_secret('keycloak-service-client-secret')
        checks['secrets']['keycloak-service-client-secret'] = 'loaded'
    except Exception as e:
        checks['secrets']['keycloak-service-client-secret'] = f'missing: {e}'
        checks['status'] = 'unhealthy'
    
    status_code = 200 if checks['status'] == 'healthy' else 503
    return jsonify(checks), status_code
```

**Test** :
```bash
curl -s http://localhost:8000/health | jq
# {
#   "status": "healthy",
#   "secrets": {
#     "flask-secret-key": "loaded",
#     "keycloak-service-client-secret": "loaded"
#   }
# }
```

---

## 🎓 Concepts pour Entretien Sécurité

### 1. **Secrets Management Hierarchy**

| Niveau | Solution | Sécurité | Complexité | Coût |
|--------|----------|----------|------------|------|
| **1. Hardcodé** | Code source | ❌ Très faible | Très faible | Gratuit |
| **2. .env local** | Fichier gitignored | ⚠️ Faible | Faible | Gratuit |
| **3. Env vars** | Environment variables | ⚠️ Moyenne | Faible | Gratuit |
| **4. Docker Secrets** | tmpfs mount | ✅ Bonne | Moyenne | Gratuit |
| **5. Key Vault** | Azure KV, Vault | ✅ Excellente | Élevée | ~5$/mois |
| **6. HSM** | Hardware Security Module | ✅ Maximum | Très élevée | ~100$/mois |

**Recommandation IAM PoC** :
- **Dev** : Docker Secrets (mode demo)
- **Staging** : Azure Key Vault
- **Production** : Azure Key Vault + Managed Identity

---

### 2. **12-Factor App Principles**

**Factor III: Config** : Store config in environment.

**Interprétation moderne** :
- ✅ Config non-sensible : Environment variables (URLs, feature flags)
- ✅ Secrets sensibles : Secret management service (Key Vault)
- ❌ Secrets dans env vars : Anti-pattern (visible `docker inspect`, logs)

**IAM PoC implémentation** :
```yaml
# docker-compose.yml
environment:
  - KEYCLOAK_URL=http://keycloak:8080  # ✅ Config non-sensible
  - DEMO_MODE=false                     # ✅ Feature flag
  # ❌ Pas de secrets ici !

secrets:
  - flask-secret-key                    # ✅ Secret sensible
  - keycloak-service-client-secret      # ✅ Secret sensible
```

---

### 3. **OWASP A02:2021 - Cryptographic Failures**

**Erreurs fréquentes** :
- ❌ Secrets committés en Git (même supprimés après, restent dans history)
- ❌ Secrets en logs (`logger.debug(f"Using password: {password}")`)
- ❌ Secrets en erreurs (`ValueError: Invalid key: my-secret-123`)
- ❌ Permissions fichiers laxistes (`chmod 777 secrets/`)

**Bonnes pratiques implémentées** :
- ✅ Secrets dans `.gitignore` (jamais committés)
- ✅ Logs masquent secrets (`***` au lieu valeur réelle)
- ✅ Erreurs génériques ("Secret not found" sans leak valeur)
- ✅ Permissions 400 (read-only owner)

---

### 4. **Azure Key Vault Best Practices**

**Configuration recommandée** :

```bash
# 1. Create Key Vault
az keyvault create \
    --name iam-poc-kv \
    --resource-group iam-poc-rg \
    --location westeurope \
    --enable-soft-delete true \
    --retention-days 90 \
    --enable-purge-protection true

# 2. Enable diagnostic logging
az monitor diagnostic-settings create \
    --resource-id /subscriptions/.../iam-poc-kv \
    --name kv-audit-logs \
    --workspace /subscriptions/.../log-analytics-workspace \
    --logs '[{"category":"AuditEvent","enabled":true}]'

# 3. Set access policy (Managed Identity)
az keyvault set-policy \
    --name iam-poc-kv \
    --object-id <flask-app-managed-identity-id> \
    --secret-permissions get list
```

**Avantages** :
- ✅ **Soft-delete** : Secrets récupérables 90 jours (protection suppression accidentelle)
- ✅ **Purge protection** : Impossible de supprimer définitivement (compliance)
- ✅ **Audit logs** : Qui a accédé à quel secret quand
- ✅ **Managed Identity** : Pas de credentials hardcodés pour accéder Key Vault

---

## 🎯 Récapitulatif : Docker Secrets Pattern

| Aspect | Dev (Demo) | Production (Key Vault) |
|--------|------------|------------------------|
| **Source** | Auto-généré (openssl) | Azure Key Vault |
| **Storage** | `.env` (gitignored) | `/run/secrets` (tmpfs) |
| **Chargement** | `make ensure-secrets` | `scripts/load_secrets_from_keyvault.sh` |
| **Rotation** | Manuelle (dev only) | `make rotate-secret` (orchestré) |
| **Audit** | Aucun | Key Vault access logs |
| **Backup** | Aucun | Key Vault automatic backup |

---

## 📚 Ressources Complémentaires

### Docker
- **Docker Secrets** : https://docs.docker.com/engine/swarm/secrets/
- **Compose Secrets** : https://docs.docker.com/compose/compose-file/05-services/#secrets

### Azure
- **Key Vault Best Practices** : https://learn.microsoft.com/azure/key-vault/general/best-practices
- **Managed Identity** : https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/

### OWASP
- **A02:2021** : Cryptographic Failures
- **Secrets Management Cheat Sheet** : https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

**Dernière mise à jour** : Octobre 2025  
**Auteur** : Alex (IAM PoC Portfolio)
