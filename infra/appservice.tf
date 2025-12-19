# App Service Plan + Linux Web App with Managed Identity
# Phase C5: Hébergement de l'application avec identité managée

# ═══════════════════════════════════════════════════════════════════════════
# App Service Plan (Linux, B1 pour POC)
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_service_plan" "main" {
  name                = "${var.prefix}-asp-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Linux container support
  os_type = "Linux"

  # B1: Basic tier (suffisant pour POC, upgrade vers P1v2 en prod)
  # B1 = 1 core, 1.75 GB RAM, ~$13/month
  sku_name = "B1"

  tags = local.common_tags
}

# ═══════════════════════════════════════════════════════════════════════════
# Linux Web App avec Managed Identity
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_linux_web_app" "main" {
  name                = "${var.prefix}-app-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  service_plan_id     = azurerm_service_plan.main.id

  # HTTPS uniquement (redirection automatique)
  https_only = true

  # ═══════════════════════════════════════════════════════════════════════════
  # Managed Identity (System-Assigned)
  # Permet à l'app d'accéder à Key Vault sans credentials
  # ═══════════════════════════════════════════════════════════════════════════
  identity {
    type = "SystemAssigned"
  }

  site_config {
    # TLS 1.2 minimum (conformité sécurité)
    minimum_tls_version = "1.2"

    # HTTP/2 pour performance
    http2_enabled = true

    # Always On: garde l'app chargée (évite cold start)
    always_on = true

    # Health check endpoint
    health_check_path = "/health"

    # Container settings (Python 3.12)
    application_stack {
      python_version = "3.12"
    }
  }

  # ═══════════════════════════════════════════════════════════════════════════
  # App Settings (configuration de l'application)
  # ═══════════════════════════════════════════════════════════════════════════
  app_settings = {
    # Port d'écoute pour Gunicorn
    WEBSITES_PORT = "8000"

    # URL du Key Vault pour récupérer les secrets
    KEY_VAULT_URL = azurerm_key_vault.main.vault_uri

    # Activer l'utilisation de Key Vault via Managed Identity
    AZURE_USE_KEYVAULT = "true"

    # Mode production (pas de demo mode)
    DEMO_MODE = "false"

    # SCM (Kudu) séparé pour sécurité
    SCM_DO_BUILD_DURING_DEPLOYMENT = "true"

    # Timezone Suisse
    TZ = "Europe/Zurich"
  }

  tags = merge(
    local.common_tags,
    {
      Purpose = "IAM-Application"
    }
  )
}

# ═══════════════════════════════════════════════════════════════════════════
# RBAC: Donner à l'App Service l'accès aux secrets Key Vault
# ═══════════════════════════════════════════════════════════════════════════
# Role "Key Vault Secrets User" - lecture seule des secrets
resource "azurerm_role_assignment" "app_keyvault_secrets" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.main.identity[0].principal_id
}

# ═══════════════════════════════════════════════════════════════════════════
# VNet Integration (optionnel mais recommandé pour accès PE)
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_app_service_virtual_network_swift_connection" "main" {
  app_service_id = azurerm_linux_web_app.main.id
  subnet_id      = azurerm_subnet.app_service.id
}
