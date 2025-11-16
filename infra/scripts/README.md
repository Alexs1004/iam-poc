# 🔧 Infrastructure Scripts

Scripts pour la gestion de l'infrastructure Terraform Azure.

---

## 📁 Organisation

```
infra/scripts/
├── setup-backend.sh            # Créer le backend Azure Storage
├── register-providers.sh        # Enregistrer les providers Azure
├── setup-local-mode.sh         # Configurer Terraform en mode local
├── upload-terraform-secret.sh  # Uploader ARM_CLIENT_SECRET dans Key Vault
└── README.md                   # Ce fichier
```

---

## 🚀 Scripts disponibles

### 1. `setup-backend.sh`

**Usage** :
```bash
./infra/scripts/setup-backend.sh
```

**Description** :
- Crée un Resource Group dédié au state Terraform (`tfstate-rg`)
- Crée un Storage Account avec nom unique (`tfstateiam<random>`)
- Configure le container `tfstate`
- Active le versioning, soft delete (30 jours), et chiffrement AES-256
- Vérifie automatiquement l'enregistrement du provider `Microsoft.Storage`
- Génère `backend.hcl` avec les valeurs réelles

**Prérequis** :
- Azure CLI installé et authentifié (`az login`)
- Souscription Azure active (état "Enabled")
- Provider `Microsoft.Storage` enregistré (auto-check inclus)

**Output** :
```
✅ Backend Azure créé avec succès
📝 Configuration sauvegardée dans infra/backend.hcl

Prochaines étapes:
  cd infra && make init
```

---

### 2. `register-providers.sh`

**Usage** :
```bash
./infra/scripts/register-providers.sh
```

**Description** :
- Enregistre tous les providers Azure nécessaires pour le projet
- Vérifie l'état de chaque provider
- Affiche les providers déjà enregistrés

**Providers enregistrés** :
- `Microsoft.Storage` (Backend Terraform)
- `Microsoft.Web` (App Service)
- `Microsoft.KeyVault` (Key Vault)
- `Microsoft.OperationalInsights` (Log Analytics)
- `Microsoft.Insights` (Application Insights)
- `Microsoft.Network` (VNet, NSG)

**Prérequis** :
- Azure CLI authentifié
- Souscription Azure active

---

### 3. `setup-local-mode.sh`

**Usage** :
```bash
./infra/scripts/setup-local-mode.sh
```

**Description** :
- Configure Terraform pour fonctionner en mode local (sans Azure)
- Sauvegarde `backend.tf` original vers `backend.tf.azure`
- Crée un backend local (`terraform.tfstate`)
- Permet de valider la syntaxe sans déployer sur Azure

**Use case** :
- Apprentissage sans coût Azure
- Validation de configuration hors ligne
- Tests de structure Terraform

**⚠️ Limitations** :
- Pas de déploiement réel sur Azure
- Pas de backend distant sécurisé
- State local non partageable

**Retour au mode Azure** :
```bash
mv infra/backend.tf.azure infra/backend.tf
cd infra && terraform init -migrate-state
```

---

### 4. `upload-terraform-secret.sh`

**Usage** :
```bash
./infra/scripts/upload-terraform-secret.sh
```

**Description** :
- Upload `ARM_CLIENT_SECRET` depuis `.runtime/secrets/arm_client_secret` vers Azure Key Vault
- Sécurise le secret avec des tags (rotation, expiration)
- Vérifie que le Key Vault existe

**Prérequis** :
- Key Vault déployé (Phase C4)
- `.runtime/secrets/arm_client_secret` présent
- Variable `AZURE_SECRET_ARM_CLIENT_SECRET` définie dans `.env`

**⚠️ Important** :
- Script à exécuter **après** le déploiement du Key Vault (Phase C4)
- Pattern recommandé : migrer le secret de `/run/secrets/` vers Key Vault

---

## 🔒 Sécurité

### Secrets management

**Actuellement (Phase C1)** :
```
.runtime/secrets/arm_client_secret  (chmod 400)
  ↓
  /run/secrets/arm_client_secret (Docker mount)
  ↓
  terraform-wrapper injecte ARM_CLIENT_SECRET
```

**Future migration (Phase C4)** :
```
Azure Key Vault
  ↓
  scripts/load_secrets_from_keyvault.sh
  ↓
  .runtime/secrets/arm_client_secret (chmod 400)
  ↓
  Docker mount
```

### Fichiers sensibles gitignorés

- `infra/backend.hcl` (contient le nom du Storage Account)
- `infra/terraform.tfstate` (state local si mode local activé)
- `.runtime/secrets/` (tous les secrets)

---

## 📊 Ordre d'exécution recommandé

### Setup initial

```bash
# 1. Enregistrer les providers Azure
./infra/scripts/register-providers.sh

# 2. Créer le backend Azure Storage
./infra/scripts/setup-backend.sh

# 3. Initialiser Terraform
cd infra && make init

# 4. Valider la configuration
make validate
```

### Mode local (sans Azure)

```bash
# 1. Configurer le mode local
./infra/scripts/setup-local-mode.sh

# 2. Initialiser Terraform (local)
cd infra && terraform init

# 3. Valider
terraform validate
```

---

## 🎓 Apprentissage Léger

### Pourquoi séparer les scripts ?

**Organisation claire** :
- `scripts/` (racine) : Scripts applicatifs (SMTP, JML, audit, rotation)
- `infra/scripts/` : Scripts infrastructure (Terraform, Azure setup)

**Principe** : **Séparation des responsabilités** (Separation of Concerns - SoC)
- Code applicatif ≠ code infrastructure
- Plus facile à naviguer en entretien
- Pattern reconnu dans l'industrie (AWS CDK, Pulumi, etc.)

### Erreurs fréquentes évitées

❌ **Tout dans `/scripts`** → Confusion entre setup infra et scripts app  
❌ **Scripts inline dans Makefile** → Difficile à tester et réutiliser  
❌ **Pas de README dans scripts/** → Recruteur perdu  

✅ **Structure claire avec READMEs** → Professionnalisme démontré

---

## 🔧 Maintenance

### Ajouter un nouveau script

1. Créer le script dans `infra/scripts/`
2. Rendre exécutable : `chmod +x infra/scripts/<script>.sh`
3. Documenter dans ce README
4. Tester avant de commit

### Bonnes pratiques

- **Shebang** : `#!/bin/bash` en première ligne
- **Error handling** : `set -e` (stop on error)
- **Messages clairs** : Emojis + couleurs pour UX
- **Idempotence** : Relancer le script ne doit pas casser l'état
- **Vérifications** : Checker les prérequis avant exécution

---

## 📚 Références

- [Terraform Backend Configuration](https://developer.hashicorp.com/terraform/language/settings/backends/configuration)
- [Azure Storage Backend](https://developer.hashicorp.com/terraform/language/settings/backends/azurerm)
- [Azure Resource Providers](https://learn.microsoft.com/azure/azure-resource-manager/management/resource-providers-and-types)
- [Terraform State Security Best Practices](../docs/TERRAFORM_BACKEND_SECURITY.md)

---

**Besoin d'aide ?** Voir la documentation complète dans `/docs`.
