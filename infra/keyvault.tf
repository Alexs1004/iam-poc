# Azure Key Vault with Private Endpoint
# Phase C4: Gestion sécurisée des secrets (isolation réseau complète)

# Key Vault principal
resource "azurerm_key_vault" "main" {
  name                = "${var.prefix}-kv-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = local.tenant_id

  # SKU standard (suffisant pour POC, premium pour HSM)
  sku_name = "standard"

  # ═══════════════════════════════════════════════════════════════════════════
  # SÉCURITÉ: Isolation réseau complète
  # ═══════════════════════════════════════════════════════════════════════════
  # Désactiver l'accès public - accès uniquement via Private Endpoint
  # Bonne pratique Azure: Zero Trust Network Access
  public_network_access_enabled = false

  # Soft delete activé (protection contre suppression accidentelle)
  # Retention 90 jours (maximum recommandé pour conformité)
  soft_delete_retention_days = 90

  # Purge protection: empêche la suppression définitive pendant la période de retention
  # CRITIQUE pour conformité FINMA/LPD: non-répudiation des secrets
  purge_protection_enabled = true

  # RBAC pour l'accès aux secrets (recommandé vs Access Policies)
  enable_rbac_authorization = true

  # Configuration réseau
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices" # Permet aux services Azure de confiance d'accéder
  }

  tags = merge(
    local.common_tags,
    {
      Purpose    = "Secrets-Management"
      Compliance = "LPD-FINMA"
      Security   = "Private-Endpoint"
    }
  )
}

# ═══════════════════════════════════════════════════════════════════════════
# Private Endpoint pour Key Vault
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_private_endpoint" "keyvault" {
  name                = "${var.prefix}-pe-kv-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.prefix}-psc-kv-${var.environment}"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  tags = local.common_tags
}

# ═══════════════════════════════════════════════════════════════════════════
# Private DNS Zone pour résolution interne
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.main.name

  tags = local.common_tags
}

# Lien DNS Zone <-> VNet
resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "${var.prefix}-dnslink-kv-${var.environment}"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.main.id

  tags = local.common_tags
}

# Enregistrement DNS A pour le Private Endpoint
resource "azurerm_private_dns_a_record" "keyvault" {
  name                = azurerm_key_vault.main.name
  zone_name           = azurerm_private_dns_zone.keyvault.name
  resource_group_name = azurerm_resource_group.main.name
  ttl                 = 300
  records             = [azurerm_private_endpoint.keyvault.private_service_connection[0].private_ip_address]
}
