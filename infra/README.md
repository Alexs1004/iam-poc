# Infrastructure Terraform - IAM POC

## 📋 Prérequis

### Installation de Terraform

**Option 1 : Docker (recommandé, pas d'installation locale)**
```bash
# Build du conteneur Terraform
docker compose build terraform

# Vérifier l'installation
docker compose run --rm terraform version
```

**Option 2 : Installation locale sur Ubuntu/Debian**
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
terraform version
```

### Authentification Azure

```bash
az login
az account show
```

## 🚀 Utilisation

### 0. Configuration du backend distant (RECOMMANDÉ pour production)

**Pourquoi ?** Le state Terraform contient des données sensibles (IPs, credentials, metadata). Un backend distant offre :
- ✅ Encryption au repos (AES-256)
- ✅ State locking (évite les modifications concurrentes)
- ✅ Versioning (rollback possible)
- ✅ Audit trail (traçabilité LPD/FINMA)

**Setup rapide :**

```bash
# 1. Créer l'infrastructure de backend (une seule fois)
./scripts/setup-backend.sh

# 2. Le script affichera les commandes pour créer backend.hcl
# Suivez les instructions affichées

# 3. Initialiser Terraform avec le backend
terraform -chdir=infra init -backend-config=backend.hcl
```

**Alternative (développement local uniquement) :**

Si vous voulez tester sans backend distant, commentez le bloc `backend "azurerm"` dans `backend.tf`.

### 1. Initialisation

**Avec Docker (recommandé) :**
```bash
cd infra
make init
```

**Ou en local :**
```bash
terraform -chdir=infra init -backend-config=backend.hcl
```

### 2. Validation de la configuration

**Docker :**
```bash
cd infra && make validate
```

**Local :**
```bash
terraform -chdir=infra validate
```

### 3. Formatage du code

**Docker :**
```bash
cd infra && make fmt
```

**Local :**
```bash
terraform -chdir=infra fmt -recursive
```

### 4. Plan (simulation)

**Docker :**
```bash
cd infra && make plan
```

**Local :**
```bash
terraform -chdir=infra plan -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

### 5. Application (déploiement réel)

⚠️ **Attention**: Cela va créer des ressources Azure facturables.

**Docker :**
```bash
cd infra && make apply
```

**Local :**
```bash
terraform -chdir=infra apply -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

### 6. Destruction

**Docker :**
```bash
cd infra && make destroy
```

**Local :**
```bash
terraform -chdir=infra destroy -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

## 📝 Variables disponibles

| Variable | Description | Défaut | Requis |
|----------|-------------|--------|--------|
| `prefix` | Préfixe pour nommer les ressources | `iam-poc` | Non |
| `location` | Région Azure | `switzerlandnorth` | Non |
| `rg_name` | Nom du Resource Group | Auto-généré | Non |
| `tenant_id` | Azure AD Tenant ID | - | **Oui** |
| `subnet_id` | ID du subnet pour Private Endpoints | `""` | Non |
| `environment` | Environnement (dev/staging/prod) | `dev` | Non |
| `tags` | Tags communs | `{Project, ManagedBy}` | Non |

### Exemple avec variables personnalisées

```bash
terraform -chdir=infra plan \
  -var="prefix=mon-iam" \
  -var="location=switzerlandnorth" \
  -var="environment=prod" \
  -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

### Utilisation d'un fichier .tfvars

Créez `infra/terraform.tfvars`:

```hcl
prefix      = "iam-poc"
location    = "switzerlandnorth"
environment = "dev"
tenant_id   = "votre-tenant-id-ici"

tags = {
  Project   = "IAM-POC"
  Owner     = "VotreNom"
  ManagedBy = "Terraform"
}
```

Puis exécutez:

```bash
terraform -chdir=infra plan
terraform -chdir=infra apply
```

## 🔐 Sécurité

### Backend Terraform State

**⚠️ IMPORTANT** : Le state Terraform contient :
- IPs publiques de vos ressources
- Identifiants de déploiement (site credentials)
- Metadata de configuration (potentiellement sensible)

**Bonnes pratiques :**
1. **Production** : Toujours utiliser un backend distant (Azure Storage)
2. **Ne jamais commiter** `terraform.tfstate` ou `backend.hcl` dans Git
3. **Activer le versioning** sur le Storage Account (rollback)
4. **Activer soft delete** (conformité LPD/FINMA - rétention 30j)
5. **Utiliser Azure CLI auth** plutôt que des access keys en clair

### Fichiers à ne jamais commiter

- ⚠️ **Ne jamais commiter** `terraform.tfvars` ou `*.tfstate` dans Git
- Le fichier `.gitignore` à la racine du projet doit contenir:
  ```
  **/.terraform/
  **/.terraform.lock.hcl
  **/terraform.tfstate
  **/terraform.tfstate.backup
  **/*.tfvars
  **/*.tfvars.json
  ```

## 📂 Structure actuelle

```
infra/
├── providers.tf         # Configuration du provider azurerm ~>3
├── variables.tf         # Variables d'entrée
├── outputs.tf           # Outputs (placeholders pour phases suivantes)
├── main.tf              # Configuration principale (placeholder)
├── backend.tf           # Backend Azure Storage (state distant)
├── backend.hcl.example  # Exemple de configuration backend
├── Makefile             # Commandes Terraform simplifiées (Docker)
├── .gitignore           # Protection secrets/state
├── README.md            # Ce fichier
└── scripts/             # Scripts d'infrastructure
    ├── setup-backend.sh           # Création backend Azure Storage
    ├── register-providers.sh      # Enregistrement providers Azure
    ├── setup-local-mode.sh        # Configuration mode local
    ├── upload-terraform-secret.sh # Upload secrets vers Key Vault
    └── README.md                  # Documentation scripts
```

## 🗺️ Phases suivantes

- **C2**: Resource Group + Log Analytics Workspace
- **C3**: VNet + Subnet pour Private Endpoints
- **C4**: Key Vault privé avec Private Endpoint
- **C5**: App Service + Managed Identity
- **C6**: Diagnostic Settings vers Log Analytics

---

**Note**: Cette infrastructure suit les bonnes pratiques de sécurité Azure et les exigences de conformité suisses (LPD/FINMA).
