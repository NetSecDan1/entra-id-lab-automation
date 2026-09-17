output "log_analytics_workspace_id" {
  description = "Workspace (customer) ID — pass this to Reports/KQL/*.ps1 via -WorkspaceId."
  value       = azurerm_log_analytics_workspace.entra_lab.workspace_id
}

output "log_analytics_workspace_resource_id" {
  description = "Full ARM resource ID of the workspace, useful for az monitor / Az.OperationalInsights calls."
  value       = azurerm_log_analytics_workspace.entra_lab.id
}

output "resource_group_name" {
  value = azurerm_resource_group.monitoring.name
}
