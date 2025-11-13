# Outputs - will be populated in subsequent phases

output "resource_group_name" {
  description = "Name of the resource group"
  value       = local.rg_name
}

output "resource_group_location" {
  description = "Location of the resource group"
  value       = var.location
}

# Placeholder for Log Analytics Workspace (Phase C2)
# output "log_analytics_workspace_id" {
#   description = "ID of the Log Analytics Workspace"
#   value       = azurerm_log_analytics_workspace.main.id
# }

# Placeholder for VNet/Subnet (Phase C3)
# output "vnet_id" {
#   description = "ID of the Virtual Network"
#   value       = azurerm_virtual_network.main.id
# }

# output "private_endpoint_subnet_id" {
#   description = "ID of the subnet for Private Endpoints"
#   value       = azurerm_subnet.private_endpoints.id
# }

# Placeholder for Key Vault (Phase C4)
# output "key_vault_id" {
#   description = "ID of the Key Vault"
#   value       = azurerm_key_vault.main.id
# }

# output "key_vault_uri" {
#   description = "URI of the Key Vault"
#   value       = azurerm_key_vault.main.vault_uri
# }

# Placeholder for App Service (Phase C5)
# output "app_service_principal_id" {
#   description = "Principal ID of the App Service Managed Identity"
#   value       = azurerm_linux_web_app.main.identity[0].principal_id
# }

# output "app_service_default_hostname" {
#   description = "Default hostname of the App Service"
#   value       = azurerm_linux_web_app.main.default_hostname
# }
