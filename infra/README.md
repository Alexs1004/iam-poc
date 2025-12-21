# Infrastructure Terraform - IAM POC

**Azure-native infrastructure** déployée avec Terraform pour l'IAM Security PoC.

---

## 🚀 Quick Start

```bash
# 1. Setup Azure backend (première fois uniquement)
./scripts/infra/setup-backend.sh

# 2. Initialize Terraform
make infra/init

# 3. Preview changes
make infra/plan

# 4. Deploy to Azure
make infra/apply
```

---

## 📋 Prérequis

### Docker (requis)
```bash
docker --version       # Docker Desktop ou Docker Engine
docker compose version # Docker Compose v2
```

### Azure CLI (requis)
```bash
az login
az account show  # Vérifier la souscription active
```

> **Note**: Terraform s'exécute via Docker pour garantir la reproductibilité.
> Vos credentials Azure (`~/.azure`) sont montées automatiquement.

### Terraform local (optionnel - fallback)
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
```

---

## 🔧 Commandes Terraform

### Via Makefile (recommandé)
```bash
make infra/init       # Initialize Terraform
make infra/validate   # Validate configuration
make infra/plan       # Show execution plan
make infra/apply      # Apply changes
make infra/destroy    # Destroy infrastructure
make infra/fmt        # Format Terraform files
make infra/clean      # Remove cache
```

### Via Docker directement
```bash
docker compose run --rm terraform init -backend-config=infra/backend.hcl
docker compose run --rm terraform plan
docker compose run --rm terraform apply
```

---

## 📂 Infrastructure Actuelle (Phase C2)

### Ressources Déployées
- ✅ **Resource Group**: `rg-iam-demo` (Switzerland North)
- ✅ **Log Analytics Workspace**: `iam-poc-law-dev`
  - Retention: 30 jours (compliance FINMA)
  - SKU: PerGB2018
  - Tags: `Compliance=LPD-FINMA`, `Purpose=Observability`

### Backend Azure Storage
- **Storage Account**: Auto-généré (`tfstateiam<random>`)
- **Container**: `tfstate`
- **Security**:
  - ✅ Encryption at rest (AES-256)
  - ✅ Versioning (rollback capability)
  - ✅ Soft delete (30 jours)
  - ✅ HTTPS only (TLS 1.2+)
  - ✅ Public access disabled

---

## 🔐 Configuration Backend (Première fois)

### 1. Créer le backend Azure Storage

```bash
./scripts/infra/setup-backend.sh
```

**Ce script va**:
- Créer un Resource Group dédié (`tfstate-rg`)
- Créer un Storage Account sécurisé (nom unique)
- Activer versioning, soft delete, encryption
- Générer `infra/backend.hcl` automatiquement

### 2. Initialiser Terraform

```bash
make infra/init
```

**Alternative (mode local - dev uniquement)**:
```bash
./scripts/infra/setup-local-mode.sh
```

---

## 📝 Variables Terraform

| Variable | Description | Défaut | Requis |
|----------|-------------|--------|--------|
| `prefix` | Préfixe pour nommer les ressources | `iam-poc` | Non |
| `location` | Région Azure | `switzerlandnorth` | Non |
| `rg_name` | Nom du Resource Group | `rg-iam-demo` | Non |
| `subnet_id` | ID du subnet pour Private Endpoints | `""` | Non |
| `environment` | Environnement (dev/staging/prod) | `dev` | Non |
| `tags` | Tags communs | `{Project, ManagedBy}` | Non |

**Note**: `tenant_id` est auto-détecté via `data.azurerm_client_config`

### Exemple avec variables personnalisées

Créez `infra/terraform.tfvars`:
```hcl
prefix      = "mon-iam"
location    = "switzerlandnorth"
environment = "prod"

tags = {
  Project   = "IAM-POC"
  Owner     = "VotreNom"
  ManagedBy = "Terraform"
}
```

---

## 🗺️ Roadmap Infrastructure

### ✅ Phase C1: Skeleton (Completed)
- Providers configuration (azurerm ~>3)
- Azure Storage backend
- Variables + outputs structure
- Docker containerization

### ✅ Phase C2: Foundation (Completed)
- Resource Group (imported existing `rg-iam-demo`)
- Log Analytics Workspace (30d retention)
- Service Principal authentication
- Auto-detection `tenant_id`

### 🔄 Phase C3: Network (In Progress)
- VNet (10.0.0.0/16)
- Subnet for Private Endpoints
- Network Security Group (NSG)

### 📋 Phase C4: Key Vault
- Azure Key Vault with Private Endpoint
- Network isolation (no public access)
- RBAC policies

### 📋 Phase C5: App Service
- Azure App Service Plan (Linux)
- Web App with Managed Identity
- VNet integration

### 📋 Phase C6: Monitoring
- Diagnostic settings to Log Analytics
- Alerts + dashboards
- Cost monitoring

---

## 📂 Structure du Projet

```
infra/
├── providers.tf         # Configuration azurerm provider
├── variables.tf         # Variables d'entrée
├── outputs.tf           # Outputs Terraform
├── main.tf              # Auto-detection tenant_id
├── log_analytics.tf     # Resource Group + Log Analytics
├── backend.tf           # Backend Azure Storage
├── backend.hcl          # Configuration backend (généré par script)
├── .gitignore           # Protection secrets/state
└── README.md            # Ce fichier
```

---

## 🔒 Sécurité & Bonnes Pratiques

### Backend Terraform State
⚠️ **Le state Terraform contient des données sensibles**:
- IPs publiques
- Identifiants de déploiement
- Metadata de configuration

**Bonnes pratiques**:
1. ✅ Toujours utiliser un backend distant (Azure Storage)
2. ✅ Activer versioning (rollback possible)
3. ✅ Activer soft delete (30 jours - compliance FINMA)
4. ✅ Utiliser Azure CLI auth (éviter access keys en clair)
5. ❌ **Ne jamais commiter** `terraform.tfstate`, `backend.hcl`, `*.tfvars`

### Fichiers à ne jamais commiter
```gitignore
**/.terraform/
**/.terraform.lock.hcl
**/terraform.tfstate
**/terraform.tfstate.backup
**/*.tfvars
**/*.tfvars.json
**/backend.hcl
```

---

## 🛠️ Scripts d'Infrastructure

Disponibles dans `scripts/infra/`:

| Script | Description |
|--------|-------------|
| `setup-backend.sh` | Créer backend Azure Storage (première fois) |
| `register-providers.sh` | Enregistrer providers Azure (si nécessaire) |
| `setup-local-mode.sh` | Mode local sans backend distant (dev) |
| `upload-terraform-secret.sh` | Upload ARM_CLIENT_SECRET dans Key Vault |

---

## 📘 Documentation Complémentaire

- **[Deployment Guide](../docs/DEPLOYMENT_GUIDE.md)**: Déploiement Azure App Service
- **[Security Design](../docs/SECURITY_DESIGN.md)**: Architecture de sécurité

---

**[↩ Back to Project Root](../README.md)**

---

**Note**: Cette infrastructure suit les bonnes pratiques Azure et les exigences de conformité suisses (LPD/FINMA).
