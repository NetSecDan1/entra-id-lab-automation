# IAM automation scripts

Graph-native identity/access reports — no Log Analytics workspace required (contrast with [`Reports/KQL`](../Reports/KQL), which needs one). All render through the same `New-HtmlReport` framework.

| Script | What it shows | Key permission |
|---|---|---|
| `Get-RiskyUsersReport.ps1` | Identity Protection risky users + risk detections, cross-referenced with privileged role membership | `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` (P2) |
| `Get-StaleAccountsReport.ps1` | Stale member accounts, disabled-but-licensed accounts, guests overdue for review | `AuditLog.Read.All` |
| `Get-AppCredentialExpiryReport.ps1` | App registration + service principal secrets/certs already expired or expiring soon | `Application.Read.All` |
| `Get-ConditionalAccessGapReport.ps1` | Resolves real CA policy coverage (group/role membership expanded) to find users with no enforced MFA/block/device policy | `Policy.Read.All`, `GroupMember.Read.All` |
| `Get-CAPolicyHealthReport.ps1` | Checklist audit of the whole deployed CA policy set: missing legacy-auth block, missing risk-based policies, break-glass accounts not excluded from a lockout-capable policy, stale report-only policies, no-op/disabled policies | `Policy.Read.All` |
| `Get-PrivilegedRoleUsageReport.ps1` | Standing (permanent) role assignments vs. PIM-eligible, dormant privileged accounts, guests/service principals with a privileged role, over-assigned roles | `RoleManagement.Read.Directory` (P2 for PIM data) |
| `Get-PimActivationHistoryReport.ps1` | PIM activation/request history: who activated what, when, justification, approval status | `RoleManagement.Read.Directory` (P2) |

```powershell
.\IAM\Get-RiskyUsersReport.ps1 -Open
.\IAM\Get-StaleAccountsReport.ps1 -StaleDays 60 -Open
.\IAM\Get-AppCredentialExpiryReport.ps1 -WarningDays 45 -Open
.\IAM\Get-ConditionalAccessGapReport.ps1 -Open
.\IAM\Get-CAPolicyHealthReport.ps1 -Open
.\IAM\Get-PrivilegedRoleUsageReport.ps1 -DormantDays 45 -Open
.\IAM\Get-PimActivationHistoryReport.ps1 -Days 14 -Open
```

All reuse `Connect-TestTenant` from `Helpers/Common.ps1`, so they authenticate the same way the rest of this repo does. `Get-ConditionalAccessGapReport.ps1` resolves group membership one level deep only — see its docstring for that limitation before treating a reported gap as absolute. `Get-CAPolicyHealthReport.ps1` and `Get-ConditionalAccessGapReport.ps1` answer different questions — the first audits the policy set's coverage in the abstract, the second resolves real membership to see who's actually protected.
