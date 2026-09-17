# IAM automation scripts

Graph-native identity/access reports — no Log Analytics workspace required (contrast with [`Reports/KQL`](../Reports/KQL), which needs one). All render through the same `New-HtmlReport` framework.

| Script | What it shows | Key permission |
|---|---|---|
| `Get-RiskyUsersReport.ps1` | Identity Protection risky users + risk detections, cross-referenced with privileged role membership | `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` (P2) |
| `Get-StaleAccountsReport.ps1` | Stale member accounts, disabled-but-licensed accounts, guests overdue for review | `AuditLog.Read.All` |
| `Get-AppCredentialExpiryReport.ps1` | App registration + service principal secrets/certs already expired or expiring soon | `Application.Read.All` |
| `Get-ConditionalAccessGapReport.ps1` | Resolves real CA policy coverage (group/role membership expanded) to find users with no enforced MFA/block/device policy | `Policy.Read.All`, `GroupMember.Read.All` |

```powershell
.\IAM\Get-RiskyUsersReport.ps1 -Open
.\IAM\Get-StaleAccountsReport.ps1 -StaleDays 60 -Open
.\IAM\Get-AppCredentialExpiryReport.ps1 -WarningDays 45 -Open
.\IAM\Get-ConditionalAccessGapReport.ps1 -Open
```

All four reuse `Connect-TestTenant` from `Helpers/Common.ps1`, so they authenticate the same way the rest of this repo does. `Get-ConditionalAccessGapReport.ps1` resolves group membership one level deep only — see its docstring for that limitation before treating a reported gap as absolute.
