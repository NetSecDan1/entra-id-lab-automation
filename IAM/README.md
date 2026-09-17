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
| `Get-AppConsentRiskReport.ps1` | Every application permission and consent grant, risk-ranked by what it actually lets the holder do; ownerless privileged apps; apps independently consented to by multiple users | `Application.Read.All`, `Directory.Read.All` |
| `Get-MfaRegistrationGapReport.ps1` | Who can't do MFA at all, who can only do SMS/voice, which admins aren't phishing-resistant | `AuditLog.Read.All` or `Reports.Read.All` (P1) |
| `Get-GuestAccessReport.ps1` | Guest population and real exposure: guests holding directory roles, never-redeemed invites, dormant guests, consumer-domain guests, and the collaboration policy that let them in | `User.Read.All`, `Directory.Read.All`, `Policy.Read.All` |

```powershell
.\IAM\Get-RiskyUsersReport.ps1 -Open
.\IAM\Get-StaleAccountsReport.ps1 -StaleDays 60 -Open
.\IAM\Get-AppCredentialExpiryReport.ps1 -WarningDays 45 -Open
.\IAM\Get-ConditionalAccessGapReport.ps1 -Open
.\IAM\Get-CAPolicyHealthReport.ps1 -Open
.\IAM\Get-PrivilegedRoleUsageReport.ps1 -DormantDays 45 -Open
.\IAM\Get-PimActivationHistoryReport.ps1 -Days 14 -Open
.\IAM\Get-AppConsentRiskReport.ps1 -Open
.\IAM\Get-MfaRegistrationGapReport.ps1 -Open
.\IAM\Get-GuestAccessReport.ps1 -DormantDays 90 -Open
```

All reuse `Connect-TestTenant` from `Helpers/Common.ps1`, so they authenticate the same way the rest of this repo does. `Get-ConditionalAccessGapReport.ps1` resolves group membership one level deep only — see its docstring for that limitation before treating a reported gap as absolute. `Get-CAPolicyHealthReport.ps1` and `Get-ConditionalAccessGapReport.ps1` answer different questions — the first audits the policy set's coverage in the abstract, the second resolves real membership to see who's actually protected.

## Read-only by design

The three newest reports (`Get-AppConsentRiskReport`, `Get-MfaRegistrationGapReport`, `Get-GuestAccessReport`) use `Connect-GraphReadOnly` from `Reports/Helpers/GraphReadOnly.ps1` rather than `Connect-TestTenant`. The difference matters: `Connect-TestTenant`'s device-code fallback requests `*.ReadWrite.*` scopes because the deployment scripts create objects. A diagnostic report should never hold that consent, so the read-only helper requests `*.Read.All` only.

It also does a **scope preflight**. Without one, a report runs for two minutes, silently returns empty collections for the endpoints you lack consent for, and renders a reassuring all-green page. The preflight turns that into a warning at the top of the run instead.

## "Not checked" is not "clean"

These reports distinguish three outcomes, and never collapse the third into the first:

- **checked, nothing found** — a real pass
- **checked, found something** — a finding, ranked by severity
- **could not check** — missing licence, missing scope, missing table

A check that could not run is reported as `NotChecked` with the reason, and its stat tile reads *not checked* rather than `0`. A tenant without Entra ID P1 shows "dormancy was not evaluated", not "no dormant guests".

## Which report answers which question

| Question | Report |
|---|---|
| Which applications could take over my tenant if compromised? | `Get-AppConsentRiskReport` |
| Would enforcing admin MFA lock anyone out? | `Get-MfaRegistrationGapReport` |
| Who from outside my organisation has access, and does anyone own that decision? | `Get-GuestAccessReport` |
| Does my CA policy set cover the basics? | `Get-CAPolicyHealthReport` |
| Who is actually unprotected right now? | `Get-ConditionalAccessGapReport` |
| What happened, and when? | [`Reports/KQL/Library`](../Reports/KQL/Library) — these read state, those read events |

The Graph reports and the KQL library are complementary, not redundant. Graph shows the **resulting state**, including changes made long before your log retention begins. KQL shows the **events**, including who made a change and from where. A consent grant made two years ago is invisible to the KQL query and obvious to `Get-AppConsentRiskReport`; who granted it and from which IP is the reverse.
