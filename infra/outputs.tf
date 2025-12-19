# Outputs - will be populated in subsequent phases

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_location" {
  description = "Location of the resource group"
  value       = azurerm_resource_group.main.location
}

# Log Analytics Workspace (Phase C2)
output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.main.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.main.name
}

# VNet/Subnet (Phase C3)
output "vnet_id" {
  description = "ID of the Virtual Network"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Name of the Virtual Network"
  value       = azurerm_virtual_network.main.name
}

output "private_endpoint_subnet_id" {
  description = "ID of the subnet for Private Endpoints"
  value       = azurerm_subnet.private_endpoints.id
}

output "app_service_subnet_id" {
  description = "ID of the subnet for App Service VNet Integration"
  value       = azurerm_subnet.app_service.id
}

# Key Vault (Phase C4)
output "key_vault_id" {
  description = "ID of the Key Vault"
  value       = azurerm_key_vault.main.id
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.main.name
}

# App Service (Phase C5)
output "app_service_id" {
  description = "ID of the App Service"
  value       = azurerm_linux_web_app.main.id
}

output "app_service_principal_id" {
  description = "Principal ID of the App Service Managed Identity"
  value       = azurerm_linux_web_app.main.identity[0].principal_id
}

output "app_service_default_hostname" {
  description = "Default hostname of the App Service"
  value       = azurerm_linux_web_app.main.default_hostname
}

output "app_service_url" {
  description = "HTTPS URL of the App Service"
  value       = "https://${azurerm_linux_web_app.main.default_hostname}"
}
