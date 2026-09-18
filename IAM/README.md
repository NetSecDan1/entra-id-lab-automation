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
| `Get-AppRiskInventory.ps1` | **The one-off audit.** Complete client-side app inventory: every permission on every API, credentials including federated identity, ownership both directions, directory roles, optional real usage — scored and intersected | `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory` |
| `Get-ServicePrincipalAzureRoleReport.ps1` | Azure RBAC assignments held by service principals — the second control plane no Entra permission audit covers | Azure `Reader` (not a Graph scope) |

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

# The complete one-off app audit. Preview what it reads before you run it.
.\IAM\Get-AppRiskInventory.ps1 -PreviewCalls
.\IAM\Get-AppRiskInventory.ps1 -WorkspaceId <guid> -ExportJson -Open

# The other control plane
.\IAM\Get-ServicePrincipalAzureRoleReport.ps1 -PreviewCalls
.\IAM\Get-ServicePrincipalAzureRoleReport.ps1 -Open
```

## Auditing risky applications

Two reports, deliberately different in cost and completeness:

| | `Get-AppConsentRiskReport.ps1` | `Get-AppRiskInventory.ps1` |
|---|---|---|
| Enumerates from | the **resource** side (`appRoleAssignedTo`) | the **client** side (`appRoleAssignments`) |
| Graph calls | ~6, seconds | ~4 + one per service principal, minutes |
| Sees permissions on | only the resource APIs you list | **every** API, including custom ones |
| Use it for | routine checks, CI | the real audit |

The difference matters. An app holding `DeviceManagementManagedDevices.ReadWrite.All` on Intune, or any permission on your own API, is invisible to resource-side enumeration unless you happened to list that API. Client-side enumeration cannot miss it.

`Get-AppRiskInventory.ps1` computes the intersection that a permission list never does:

> **high privilege × holds a long-lived credential × nobody owns it × nothing is using it**

An app at that intersection is powerful, exploitable, unaccountable and unmissed. That is usually a very short list, and it is the work queue. Supply `-WorkspaceId` to populate the usage dimension from `AADServicePrincipalSignInLogs`; without it, dormancy is reported as **NotChecked**, never as zero dormant apps.

Three things it finds that the consent report does not:

- **Escalation permissions.** An app with `AppRoleAssignment.ReadWrite.All` has an effective permission set of *everything*, because it can grant itself the rest. Reviewing its other permissions individually is beside the point.
- **Shadow admins.** An application owner can add a credential to their own app and then authenticate as it. Owning a privileged app is equivalent to holding its permissions — and those owners appear on no privileged-role report.
- **Federated identity credentials.** An FIC has no secret and no expiry, so it never shows up in a credential-expiry report. Anything that can present a token from the trusted issuer and subject authenticates as that app.

### The second control plane

`Get-ServicePrincipalAzureRoleReport.ps1` covers Azure RBAC, which is an entirely separate authorisation system with its own API and its own portal. An app can hold zero Graph permissions and still be **Owner on a production subscription** — and every Entra-side report here, including `Get-AppRiskInventory.ps1`, will show it as harmless.

Custom roles are scored from their actual `Actions` list rather than their name, because a custom role called "Readonly Audit" may well permit `Microsoft.Authorization/roleAssignments/write`. An identity appearing high-risk in *both* reports is genuinely dangerous: broad directory permissions and broad Azure control, usually with one non-expiring secret behind both.

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

## Proving it is read-only

`Tests/Test-ReadOnlySafety.ps1` verifies the claim rather than restating it. It connects to nothing and needs no credentials:

```powershell
.\Tests\Test-ReadOnlySafety.ps1
```

It checks that no mutating Graph or Az cmdlet appears in `IAM/` or `Reports/`, that no `*.ReadWrite.*` scope is requested at connect time, that no KQL control command exists in the query library, that `Invoke-GraphPagedRequest` exposes no parameter capable of changing the HTTP method — and that the runtime assertion actually fires when a non-GET is planted, so the safety net is not itself inert.

Three layers back the read-only guarantee:

1. **Structural.** `Invoke-GraphPagedRequest` has no method parameter. GET is not a default that could be overridden; it is the only verb the function can issue.
2. **Runtime.** Every call is recorded. Before a report renders, `Test-GraphCallLogIsReadOnly` asserts nothing but GET was sent and throws if that is ever untrue.
3. **Evidence.** The call log is rendered into the report, so a reviewer can confirm it rather than take your word for it.

`-PreviewCalls` on both app reports prints the exact call plan and exits without connecting — run it first against a tenant you do not own.
