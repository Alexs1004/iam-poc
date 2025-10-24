# Amélioration : Gestion Automatique des Secrets en Mode Production

## 📋 Résumé

Cette amélioration permet à `make ensure-secrets` de **vider automatiquement** les secrets locaux (`FLASK_SECRET_KEY` et `AUDIT_LOG_SIGNING_KEY`) dans `.env` lorsque `DEMO_MODE=false` et `AZURE_USE_KEYVAULT=true`.

## 🎯 Problème Résolu

**Avant :** Lorsqu'on lançait `make demo` ou `make fresh-demo` avec une configuration production (`DEMO_MODE=false`, `AZURE_USE_KEYVAULT=true`), les secrets étaient générés dans `.env` même si on voulait les charger depuis Azure Key Vault.

**Après :** Les secrets sont automatiquement vidés en mode production avec Key Vault, forçant leur chargement depuis Azure.

## 🔧 Changements Techniques

### 1. Makefile (target `ensure-secrets`)

**Comportement par mode :**

| `DEMO_MODE` | `AZURE_USE_KEYVAULT` | Comportement |
|-------------|---------------------|--------------|
| `true` | `false` | ✅ Génère des secrets si vides (mode démo) |
| `true` | `true` | ⚠️ Configuration invalide (détectée par `validate-env`) |
| `false` | `true` | 🔒 **VIDE** les secrets (chargement depuis Key Vault) |
| `false` | `false` | ⚠️ Avertissement (gestion manuelle requise) |

**Code ajouté :**
```bash
if [[ "$${DEMO_MODE,,}" == "false" ]]; then
    if [[ "$${AZURE_USE_KEYVAULT,,}" == "true" ]]; then
        echo "[ensure-secrets] Azure Key Vault enabled: clearing local secrets in .env" >&2
        sed -i "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=|" .env
        sed -i "s|^AUDIT_LOG_SIGNING_KEY=.*|AUDIT_LOG_SIGNING_KEY=|" .env
        echo "[ensure-secrets] ✓ FLASK_SECRET_KEY cleared (will load from Key Vault)" >&2
        echo "[ensure-secrets] ✓ AUDIT_LOG_SIGNING_KEY cleared (will load from Key Vault)" >&2
    fi
fi
```

### 2. Nouveau Template : `.env.production`

Fichier de référence pour configuration production avec commentaires explicites :
```bash
DEMO_MODE=false
AZURE_USE_KEYVAULT=true
AZURE_KEY_VAULT_NAME=your-keyvault-name

# ⚠️ Leave these EMPTY when AZURE_USE_KEYVAULT=true
FLASK_SECRET_KEY=
AUDIT_LOG_SIGNING_KEY=
```

### 3. Nouvelle Commande : `make init-production`

Initialise `.env` avec le template production :
```bash
make init-production
# Output:
# [init-production] ✓ .env initialized for production mode
# [init-production] Next steps:
#   1. Edit .env and set AZURE_KEY_VAULT_NAME=<your-vault>
#   2. Update URLs (KEYCLOAK_ISSUER, OIDC_REDIRECT_URI, etc.)
#   3. Run 'make validate-env' to check configuration
#   4. Run 'make ensure-secrets' to clear local secrets
#   5. Run 'make load-secrets' to load from Azure Key Vault
```

### 4. Documentation Mise à Jour

**README.md :** Nouvelle section "Production Mode Behavior" avec matrice de comportements.

### 5. Tests Automatisés

**Nouveau fichier :** `tests/test_ensure_secrets.py`

4 tests couvrant tous les cas :
1. ✅ Génération en mode démo (secrets vides → secrets générés)
2. ✅ Vidage en mode production avec Key Vault (secrets existants → vidés)
3. ✅ Avertissement en mode production sans Key Vault (secrets préservés)
4. ✅ Idempotence (exécutions multiples sûres)

**Résultat :**
```
============================================================
✅ All tests passed!
============================================================
```

## 🚀 Workflow d'Utilisation

### Mode Démo (Développement Local)
```bash
make quickstart
# → Auto-génère les secrets dans .env
# → Démarre la stack complète
```

### Mode Production (Azure Key Vault)
```bash
# Option 1 : Partir de zéro
make init-production
# Éditer .env (AZURE_KEY_VAULT_NAME, URLs, etc.)
make ensure-secrets    # Vide les secrets locaux
make load-secrets      # Charge depuis Azure Key Vault
make quickstart        # Démarre avec secrets Azure

# Option 2 : Depuis .env existant
# 1. Modifier .env :
#    DEMO_MODE=false
#    AZURE_USE_KEYVAULT=true
make ensure-secrets    # Vide automatiquement les secrets
make load-secrets      # Charge depuis Azure Key Vault
make quickstart
```

## 🎓 Avantages

1. **Source de vérité unique :** En production, tous les secrets viennent d'Azure Key Vault
2. **Pas de secrets obsolètes :** `.env` ne contient jamais de valeurs périmées
3. **Workflow idempotent :** `make fresh-demo` fonctionne correctement en mode production
4. **Sécurité renforcée :** Impossible d'utiliser accidentellement des secrets locaux en production
5. **Erreur impossible :** Configuration DEMO_MODE=true + AZURE_USE_KEYVAULT=true détectée par `validate-env`

## 📊 Impact sur les Fichiers

| Fichier | Type | Lignes Modifiées |
|---------|------|------------------|
| `Makefile` | Modifié | ~15 lignes dans `ensure-secrets` + 15 lignes `init-production` |
| `.env.production` | Nouveau | 80 lignes (template) |
| `tests/test_ensure_secrets.py` | Nouveau | 220 lignes (tests) |
| `README.md` | Modifié | ~30 lignes (section comportement) |
| `docs/SECRET_MANAGEMENT.md` | Nouveau | Ce document |

## 🧪 Validation

Tous les tests passent :
```bash
python3 tests/test_ensure_secrets.py
# ✅ Test 1 passed: Secrets generated in demo mode
# ✅ Test 2 passed: Secrets cleared in production mode with Key Vault
# ✅ Test 3 passed: Warning shown, secrets unchanged
# ✅ Test 4 passed: Idempotent behavior confirmed
```

## 🔗 Références

- **Makefile :** `ensure-secrets` target (lignes 59-98)
- **Template :** `.env.production` (nouveau fichier)
- **Tests :** `tests/test_ensure_secrets.py` (nouveau fichier)
- **Documentation :** `README.md` section "🔐 Configuration & Secrets"
- **Architecture :** Suit le pattern Docker Secrets (`/run/secrets`)

## ✅ Statut

**Implémenté et validé** — Prêt pour utilisation en production.

**Date :** 2025-01-23  
**Auteur :** Alexs1004  
**Branch :** feature/audit-jml_api-scim
