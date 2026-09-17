variable "subscription_id" {
  description = "Azure subscription ID that will host the Log Analytics workspace."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant ID (GUID) — the same tenant Setup-TestTenant.ps1 targets."
  type        = string
}

variable "location" {
  description = "Azure region for the resource group and Log Analytics workspace."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Name of the resource group that holds the monitoring/reporting infrastructure."
  type        = string
  default     = "rg-entra-lab-monitoring"
}

variable "workspace_name" {
  description = "Name of the Log Analytics workspace that receives Entra ID Sign-in and Audit logs."
  type        = string
  default     = "law-entra-lab"
}

variable "log_retention_days" {
  description = "Log Analytics data retention, in days. 30 is the free-tier default; raise it if you want longer history for KQL reports."
  type        = number
  default     = 30
}

variable "enabled_log_categories" {
  description = "Entra ID log categories to export into the workspace. Matches the tables the KQL reports in Reports/KQL query against."
  type        = list(string)
  default = [
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "AuditLogs",
    "RiskyUsers",
    "UserRiskEvents",
  ]
}

variable "enable_demo_terraform_ca_policy" {
  description = <<-EOT
    Demonstration-only: also manage one small Conditional Access policy and its
    target group directly via the azuread Terraform provider, to show CA-as-code
    alongside the PowerShell-driven baselines in CAPs/. Off by default because
    it would otherwise create objects that overlap with what Setup-TestTenant.ps1
    already manages — turn it on only if you are NOT also running the PowerShell
    CAP/Groups steps against the same tenant, or you'll end up with duplicate,
    confusingly-named policies and groups.
  EOT
  type        = bool
  default     = false
}
