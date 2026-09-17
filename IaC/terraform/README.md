# IaC: Log Analytics + Entra ID diagnostic export

Terraform that provisions the monitoring backbone the KQL reports in
[`Reports/KQL`](../../Reports/KQL) query against: a Log Analytics workspace,
plus a tenant-level diagnostic setting that streams Entra ID Sign-in and
Audit logs into it.

## What this creates

| Resource | Purpose |
|---|---|
| `azurerm_resource_group.monitoring` | Container for the workspace |
| `azurerm_log_analytics_workspace.entra_lab` | Destination for Entra ID logs; queried by `Reports/KQL/*.ps1` |
| `azurerm_monitor_aad_diagnostic_setting.entra_lab` | Tenant-level export of `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `AuditLogs`, `RiskyUsers`, `UserRiskEvents` |

An optional, **disabled-by-default** module (`entra-demo.tf`) also shows a
Conditional Access policy and its target group managed directly through the
`azuread` provider — purely to demonstrate CA-as-code. Leave
`enable_demo_terraform_ca_policy = false` unless you are testing Terraform in
isolation from the PowerShell-driven CAP baselines, since running both against
the same tenant creates parallel, unrelated objects.

## Prerequisites

- Terraform >= 1.7
- An Azure subscription, and a principal (your own login or a service
  principal) with:
  - `Contributor` on the target subscription or resource group (for the
    workspace + diagnostic setting)
  - `Security Administrator` (or a role that can write tenant diagnostic
    settings) in Entra ID
  - If using the optional demo module: `Application.ReadWrite.All` and
    `Policy.ReadWrite.ConditionalAccess`, consented, for the `azuread` provider
- Entra ID P1/P2 for most of the log categories above to actually populate

## Usage

```bash
cd IaC/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: subscription_id, tenant_id

az login --tenant <tenant_id>
terraform init
terraform plan
terraform apply
```

Then feed the workspace ID to the reporting scripts:

```powershell
$workspaceId = terraform -chdir=IaC/terraform output -raw log_analytics_workspace_id
.\Reports\KQL\Get-RiskySignInsReport.ps1 -WorkspaceId $workspaceId
```

## Notes

- `terraform.tfvars` and `.terraform/` are gitignored — never commit real
  subscription/tenant IDs or state files.
- State is local by default (`terraform.tfstate`). For anything beyond a
  disposable lab, configure a remote backend (`azurerm` backend into a
  storage account) before running `apply`.
- This is additive to, not a replacement for, the PowerShell scripts —
  Entra ID users, groups, and Conditional Access policies stay managed by
  `Setup-TestTenant.ps1` unless you deliberately opt into the demo module.
