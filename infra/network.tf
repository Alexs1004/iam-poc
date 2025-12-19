# Virtual Network + Subnet for Private Endpoints
# Phase C3: Isolation réseau pour Key Vault et autres services

# VNet principal
resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # RFC1918 address space (10.0.0.0/16 = 65,536 addresses)
  address_space = ["10.0.0.0/16"]

  tags = merge(
    local.common_tags,
    {
      Purpose = "Network-Isolation"
    }
  )
}

# Subnet dédié aux Private Endpoints
resource "azurerm_subnet" "private_endpoints" {
  name                 = "${var.prefix}-snet-pe-${var.environment}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name

  # /24 = 256 addresses (largement suffisant pour les PE)
  address_prefixes = ["10.0.1.0/24"]

  # Désactiver les network policies pour permettre les Private Endpoints
  # Requis pour que les PE fonctionnent correctement
  private_endpoint_network_policies = "Disabled"
}

# Subnet pour App Service (VNet Integration)
resource "azurerm_subnet" "app_service" {
  name                 = "${var.prefix}-snet-app-${var.environment}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name

  address_prefixes = ["10.0.2.0/24"]

  # Délégation requise pour App Service VNet Integration
  delegation {
    name = "appservice-delegation"

    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}
