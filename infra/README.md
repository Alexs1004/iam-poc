# Infrastructure Terraform - IAM POC

## 📋 Prérequis

### Installation de Terraform

**Sur Ubuntu/Debian:**
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
```

**Vérifier l'installation:**
```bash
terraform version
```

### Authentification Azure

```bash
az login
az account show
```

## 🚀 Utilisation

### 1. Initialisation

```bash
terraform -chdir=infra init
```

### 2. Validation de la configuration

```bash
terraform -chdir=infra validate
```

### 3. Formatage du code

```bash
terraform -chdir=infra fmt -recursive
```

### 4. Plan (simulation)

```bash
terraform -chdir=infra plan \
  -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

### 5. Application (déploiement réel)

⚠️ **Attention**: Cela va créer des ressources Azure facturables.

```bash
terraform -chdir=infra apply \
  -var="tenant_id=$(az account show --query tenantId -o tsv)"
```

### 6. Destruction

```bash
terraform -chdir=infra destroy \
  -var="tenant_id=$(az account show --query tenantId -o tsv)"
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
├── providers.tf   # Configuration du provider azurerm ~>3
├── variables.tf   # Variables d'entrée
├── outputs.tf     # Outputs (placeholders pour phases suivantes)
├── main.tf        # Configuration principale (placeholder)
└── README.md      # Ce fichier
```

## 🗺️ Phases suivantes

- **C2**: Resource Group + Log Analytics Workspace
- **C3**: VNet + Subnet pour Private Endpoints
- **C4**: Key Vault privé avec Private Endpoint
- **C5**: App Service + Managed Identity
- **C6**: Diagnostic Settings vers Log Analytics

---

**Note**: Cette infrastructure suit les bonnes pratiques de sécurité Azure et les exigences de conformité suisses (LPD/FINMA).
