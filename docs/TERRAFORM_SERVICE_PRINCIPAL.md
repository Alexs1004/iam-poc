# 🔐 Terraform Service Principal avec Azure Key Vault

## Pourquoi stocker ARM_CLIENT_SECRET dans Key Vault ?

### Risques du secret en clair

`ARM_CLIENT_SECRET` est **très sensible** :
- Permet l'accès complet à votre souscription Azure (selon le rôle du Service Principal)
- Peut créer/modifier/supprimer toutes les ressources
- Si exposé = compromission totale de l'infrastructure

**Bonnes pratiques** :
- ✅ Stocker dans Azure Key Vault (encryption AES-256)
- ✅ Charger au runtime via `/run/secrets` (Docker)
- ✅ Jamais en clair dans `.env` ou dans Git
- ✅ Rotation régulière (recommandé : 90 jours)

---

## 🛠️ Configuration

### 1. Créer un Service Principal

```bash
# Créer le Service Principal pour Terraform
SP_OUTPUT=$(az ad sp create-for-rbac \
  --name iam-poc-terraform \
  --role Contributor \
  --scopes /subscriptions/$(az account show --query id -o tsv) \
  --output json)

# Extraire les valeurs
ARM_CLIENT_ID=$(echo $SP_OUTPUT | jq -r '.appId')
ARM_CLIENT_SECRET=$(echo $SP_OUTPUT | jq -r '.password')
ARM_TENANT_ID=$(echo $SP_OUTPUT | jq -r '.tenant')
ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)

echo "📋 Service Principal créé:"
echo "  ARM_CLIENT_ID: $ARM_CLIENT_ID"
echo "  ARM_TENANT_ID: $ARM_TENANT_ID"
echo "  ARM_SUBSCRIPTION_ID: $ARM_SUBSCRIPTION_ID"
echo "  ARM_CLIENT_SECRET: <secret>"
```

### 2. Ajouter les valeurs non-sensibles dans `.env`

```bash
cat >> .env <<EOF

# Terraform Service Principal
ARM_TENANT_ID=$ARM_TENANT_ID
ARM_SUBSCRIPTION_ID=$ARM_SUBSCRIPTION_ID
ARM_CLIENT_ID=$ARM_CLIENT_ID
EOF
```

### 3. Uploader le secret dans Key Vault

```bash
# Via le script fourni
./scripts/upload-terraform-secret.sh "$ARM_CLIENT_SECRET"

# Ou manuellement
az keyvault secret set \
  --vault-name demo-key-vault-alex \
  --name arm-client-secret \
  --value "$ARM_CLIENT_SECRET"
```

### 4. Charger les secrets

```bash
# Charger tous les secrets depuis Key Vault
./scripts/load_secrets_from_keyvault.sh

# Vérifier
ls -la .runtime/secrets/arm_client_secret
# -r-------- 1 alex alex 44 Nov 13 10:00 arm_client_secret
```

### 5. Utiliser Terraform

```bash
cd infra
make init    # ARM_CLIENT_SECRET chargé automatiquement depuis /run/secrets
make plan
make apply
```

---

## 🔒 Comment ça fonctionne ?

### Architecture

```
┌────────────────────────────────────────────┐
│ Azure Key Vault                             │
│  └─ Secret: arm-client-secret               │
│     Value: <service-principal-password>     │
└────────────┬───────────────────────────────┘
             │
             │ ./scripts/load_secrets_from_keyvault.sh
             ↓
┌────────────────────────────────────────────┐
│ .runtime/secrets/arm_client_secret          │
│  (chmod 400, read-only)                     │
└────────────┬───────────────────────────────┘
             │
             │ Docker volume mount (ro)
             ↓
┌────────────────────────────────────────────┐
│ Container: terraform                        │
│  /run/secrets/arm_client_secret (ro)        │
│                                             │
│  terraform-wrapper:                         │
│    export ARM_CLIENT_SECRET=$(cat ...)      │
│    exec terraform "$@"                      │
└─────────────────────────────────────────────┘
```

### Dockerfile.terraform (wrapper)

Le wrapper charge automatiquement le secret :

```dockerfile
COPY --chmod=755 <<'EOF' /usr/local/bin/terraform-wrapper
#!/bin/bash
if [ -f /run/secrets/arm_client_secret ]; then
    export ARM_CLIENT_SECRET=$(cat /run/secrets/arm_client_secret)
fi
exec terraform "$@"
EOF

ENTRYPOINT ["terraform-wrapper"]
```

**Avantages** :
- ✅ Transparent : `make init` fonctionne sans changement
- ✅ Sécurisé : secret jamais en variable d'environnement Docker Compose
- ✅ Auditable : accès au secret via Key Vault logs
- ✅ Rotation facile : re-upload + reload

---

## 🔄 Rotation du secret

### Pourquoi rotationner ?

**Bonnes pratiques de sécurité** :
- NIST SP 800-53 IA-5(1) : rotation régulière des credentials
- Limite l'exposition en cas de fuite
- Détecte les accès non autorisés (ancien secret = alerte)

### Procédure de rotation (90 jours recommandé)

```bash
# 1. Créer un nouveau secret pour le Service Principal
NEW_SECRET=$(az ad sp credential reset \
  --id $ARM_CLIENT_ID \
  --query password -o tsv)

# 2. Uploader dans Key Vault
./scripts/upload-terraform-secret.sh "$NEW_SECRET"

# 3. Recharger les secrets
./scripts/load_secrets_from_keyvault.sh

# 4. Tester Terraform
cd infra && make validate

# 5. Si OK, l'ancien secret est automatiquement révoqué
```

**Automation (optionnel)** :
- Azure Key Vault rotation policy (auto-rotation)
- GitHub Actions workflow mensuel/trimestriel
- Azure Monitor alert si secret > 80 jours

---

## 🧪 Vérification

### Test 1 : Secret chargé correctement

```bash
docker compose run --rm terraform version
# Terraform v1.9.x

docker compose run --rm terraform -chdir=/workspace/infra init
# Initializing the backend...
# Successfully configured the backend "azurerm"!
```

### Test 2 : Authentication Azure

```bash
docker compose run --rm --entrypoint sh terraform -c 'echo "ARM_CLIENT_SECRET length: $(cat /run/secrets/arm_client_secret | wc -c)"'
# ARM_CLIENT_SECRET length: 44
```

### Test 3 : Permissions Key Vault

```bash
az keyvault secret show \
  --vault-name demo-key-vault-alex \
  --name arm-client-secret \
  --query "attributes.{Created:created,Updated:updated}" -o table

# Created                       Updated
# ----------------------------  ----------------------------
# 2025-11-13T09:00:00+00:00    2025-11-13T09:00:00+00:00
```

---

## 🎓 Points à mentionner en entretien

### Question : "Comment gérez-vous les secrets Terraform ?"

**Votre réponse :**

> "Je stocke le `ARM_CLIENT_SECRET` du Service Principal dans Azure Key Vault avec encryption AES-256. Au runtime, je charge le secret via un script qui le place dans `.runtime/secrets/` avec permissions 400. Le conteneur Docker Terraform monte ce répertoire en read-only sur `/run/secrets/`, et un wrapper bash injecte automatiquement la variable `ARM_CLIENT_SECRET` avant d'exécuter Terraform. Ça évite d'avoir le secret en clair dans `.env` ou dans les logs Docker Compose. Je fais aussi une rotation trimestrielle du secret via `az ad sp credential reset`."

**Ce qui impressionne** :
- ✅ Vous connaissez le pattern `/run/secrets/` (Docker Swarm, Kubernetes)
- ✅ Vous pensez rotation et audit trail
- ✅ Vous citez une bonne pratique reconnue (NIST)
- ✅ Vous avez automatisé la sécurité (wrapper transparent)

---

## 🚨 Erreurs à éviter

### ❌ Secret en clair dans docker-compose.yml

```yaml
# MAUVAIS
environment:
  ARM_CLIENT_SECRET: ${ARM_CLIENT_SECRET}  # Exposé dans logs
```

**Pourquoi c'est grave** :
- Visible dans `docker compose config`
- Loggé dans `docker inspect`
- Potentiellement dans les crash dumps

### ❌ Secret commité dans .env

```bash
# MAUVAIS
git add .env
# .env contient ARM_CLIENT_SECRET=xyz123...
```

**Solution** : `.gitignore` + Key Vault + `/run/secrets/`

### ❌ Pas de rotation

Service Principal avec le même secret pendant 2 ans = **bombe à retardement**.

**Solution** : Rotation trimestrielle + Azure Monitor alert

---

## 📚 Références

- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [NIST SP 800-53 IA-5(1) - Password-Based Authentication](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Docker Secrets](https://docs.docker.com/engine/swarm/secrets/)
- [Terraform azurerm Backend Authentication](https://www.terraform.io/language/settings/backends/azurerm#authentication)

---

**TL;DR** : `ARM_CLIENT_SECRET` dans Key Vault + pattern `/run/secrets/` = sécurité production-grade. 🔐
