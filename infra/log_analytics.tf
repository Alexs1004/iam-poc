# Resource Group + Log Analytics Workspace
# Phase C2: Foundation pour observabilité et conformité LPD/FINMA

# Resource Group principal
resource "azurerm_resource_group" "main" {
  name     = local.rg_name
  location = var.location
  tags     = local.common_tags
}

# Log Analytics Workspace (rétention 30 jours)
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-law-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Rétention 30 jours (conformité LPD: minimisation des données)
  retention_in_days = 30

  # SKU PerGB2018 (pay-as-you-go, économique pour POC)
  sku = "PerGB2018"

  tags = merge(
    local.common_tags,
    {
      Purpose    = "Observability"
      Compliance = "LPD-FINMA"
    }
  )
}
