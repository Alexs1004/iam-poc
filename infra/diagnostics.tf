# Diagnostic Settings - Logs vers Log Analytics
# Phase C6: Observabilité et conformité audit

# ═══════════════════════════════════════════════════════════════════════════
# Diagnostic Settings pour App Service
# Envoie les logs HTTP et Console vers Log Analytics
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_monitor_diagnostic_setting" "app_service" {
  name                       = "${var.prefix}-diag-app-${var.environment}"
  target_resource_id         = azurerm_linux_web_app.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  # HTTP Logs (requêtes entrantes, codes de réponse)
  enabled_log {
    category = "AppServiceHTTPLogs"
  }

  # Console Logs (stdout/stderr de l'application)
  enabled_log {
    category = "AppServiceConsoleLogs"
  }

  # App Logs (logs applicatifs)
  enabled_log {
    category = "AppServiceAppLogs"
  }

  # Audit Logs (changements de configuration)
  enabled_log {
    category = "AppServiceAuditLogs"
  }

  # Métriques (CPU, mémoire, requêtes)
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════
# Diagnostic Settings pour Key Vault
# Audit trail des accès aux secrets (conformité FINMA)
# ═══════════════════════════════════════════════════════════════════════════
resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "${var.prefix}-diag-kv-${var.environment}"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  # Audit Events (qui a accédé à quoi, quand)
  enabled_log {
    category = "AuditEvent"
  }

  # Métriques Key Vault
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
