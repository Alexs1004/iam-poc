# Main Terraform configuration - Infrastructure skeleton

locals {
  # Auto-generate resource group name if not provided
  rg_name = var.rg_name != "" ? var.rg_name : "${var.prefix}-rg-${var.environment}"

  # Merge default tags with environment tag
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      Location    = var.location
    }
  )
}

# Placeholder: actual resources will be added in subsequent phases
# Phase C2: Resource Group + Log Analytics Workspace
# Phase C3: VNet + Subnet for Private Endpoints
# Phase C4: Key Vault with Private Endpoint
# Phase C5: App Service Plan + Web App with Managed Identity
# Phase C6: Diagnostic Settings
