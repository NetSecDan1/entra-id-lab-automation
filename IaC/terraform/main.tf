# Core monitoring backbone: a Log Analytics workspace that receives Entra ID
# Sign-in and Audit logs, so the KQL reports in Reports/KQL/*.ps1 have
# something to query. This is Azure-side infrastructure, not Entra config —
# Entra objects themselves (users, groups, CA policies) stay PowerShell-driven
# in the rest of this repo, except for the optional demo module below.

resource "azurerm_resource_group" "monitoring" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_log_analytics_workspace" "entra_lab" {
  name                = var.workspace_name
  resource_group_name = azurerm_resource_group.monitoring.name
  location            = azurerm_resource_group.monitoring.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
}

# Tenant-level diagnostic setting: exports Entra ID logs to the workspace above.
# Requires Entra ID P1/P2 for most categories, and the applying identity needs
# Security Administrator (or equivalent) on the tenant, plus Contributor on
# this resource group.
resource "azurerm_monitor_aad_diagnostic_setting" "entra_lab" {
  name                       = "diag-entra-lab-to-law"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.entra_lab.id

  dynamic "enabled_log" {
    for_each = var.enabled_log_categories
    content {
      category = enabled_log.value
    }
  }
}
