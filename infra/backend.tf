# Backend configuration for Terraform state
# 
# Benefits:
# - State encryption at rest (Azure Storage SSE)
# - State locking (prevents concurrent modifications)
# - Versioning (rollback capability)
# - Shared across team/CI/CD
# - Audit trail (who modified what, when)
#
# Required: Azure Storage Account + Container
# Setup instructions: See infra/README.md section "Backend Setup"

terraform {
  backend "azurerm" {
    # These values should be set via:
    # 1. Backend config file: terraform init -backend-config=backend.hcl
    # 2. Environment variables: ARM_ACCESS_KEY or use Azure CLI auth
    # 3. Partial configuration (recommended for security)

    # resource_group_name  = "tfstate-rg"           # Set via -backend-config
    # storage_account_name = "tfstate<uniqueid>"    # Set via -backend-config
    # container_name       = "tfstate"              # Set via -backend-config
    # key                  = "iam-poc.terraform.tfstate"

    # Security features (enabled by default in Azure Storage)
    # - Encryption at rest: AES-256
    # - TLS in transit: enforced
    # - Blob versioning: enable in storage account
    # - Soft delete: enable for compliance (FINMA/LPD)
  }
}

# Alternative: Uncomment for local development (NOT for production)
# terraform {
#   backend "local" {
#     path = "terraform.tfstate"
#   }
# }
