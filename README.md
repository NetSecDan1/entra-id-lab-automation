# Entra ID Lab Automation

PowerShell automation that stands up a fully populated **Microsoft Entra ID (Azure AD) test tenant** from a single config file — realistic users, groups, Conditional Access policies, apps, authentication methods, schema extensions, and the full Entra ID Governance suite (PIM, access reviews, entitlement management, lifecycle workflows).

Built to give a disposable tenant real depth in minutes, so Conditional Access design, governance workflows, and access reviews can be tested against something closer to a production directory than a handful of throwaway accounts.

## Why this exists

Testing Entra ID features properly needs a tenant that actually looks like an org — dozens of users spread across departments, tiered admin groups, dynamic groups, break-glass accounts, named locations, and a Conditional Access baseline — not three test users and a wildcard policy. This project builds that tenant from scratch, idempotently, so it can be re-run safely as it's extended or after a partial failure.

## What it deploys

| Module | Description |
|---|---|
| **Users** | Break-glass accounts (excluded from all CAPs), an admin account, N test users spread across configurable departments, and a blocked/disabled user |
| **Groups** | Tiered security groups (Tier 0/1/2 admins), a dynamic membership group, and department groups |
| **Named Locations** | Trusted IP ranges for Conditional Access |
| **Conditional Access** | Imports the [Joey Verlinden CA baseline](https://github.com/j0eyv/ConditionalAccessBaseline) (~30 policies), deployed report-only by default — or deploy one of three [locally-authored baselines](CAPs/Baselines) instead (see below) |
| **Applications** | Web app, SPA, and daemon app registrations with sensible redirect URIs |
| **Schema Extensions** | Custom directory schema extension app + attributes, with optional sample value assignment |
| **Auth Methods** | Authenticator, FIDO2, Temporary Access Pass, SMS, and SSPR configuration |
| **Auth Strengths** | Custom authentication strength policies |
| **Directory Settings** | Guest access, external collaboration, and group management settings |
| **Licensing** | Direct or group-based license assignment |
| **Admin Units** | Administrative unit scoping |
| **PIM** | Privileged Identity Management role settings (activation duration, approval, justification) |
| **Access Reviews** | Recurring reviews for guests, privileged roles, and admin/executive groups |
| **Lifecycle Workflows** | Joiner/leaver automation |
| **Entitlement Management** | Access package catalog, packages with approval flows, and a guest/vendor collaboration package |
| **Terms of Use / Password Protection / Cross-Tenant Access / Auth Contexts** | Additional security baseline pieces |

Two extra modules for realism and testing:
- **Fun Users** — ~24 pop-culture themed test identities, useful for demos
- **Sign-In Simulation** — scripted sign-in activity to populate logs and reports

## Beyond tenant setup

Five things layered on top of the core tenant-builder:

| Area | What it is |
|---|---|
| **[Custom CA baselines](CAPs/Baselines)** | An alternative to the remote Joey Verlinden import: three locally-authored baselines — `Tiered` (built around this repo's own admin tier groups), `ZeroTrust` (modeled on Microsoft's Zero Trust/SFI guidance), and `SCuBA` (mapped to CISA's M365 baseline MS.AAD.3.x controls). Deploy with `CAPs/Deploy-CAPs-Custom.ps1 -Baseline <name>`. |
| **[IaC](IaC/terraform)** | Terraform for the Azure-side monitoring backbone: a Log Analytics workspace + tenant-level Entra ID diagnostic export, plus an optional demo of Conditional-Access-as-code via the `azuread` provider. |
| **[KQL reports](Reports/KQL)** | Nine PowerShell scripts that query the Log Analytics workspace above with KQL and render the results as a single, self-contained, sortable/searchable HTML dashboard. The renderer (`Reports/Helpers/HtmlReportFramework.ps1`) has zero dependencies, so it's designed to be copy-pasted into any future one-off script too. |
| **[KQL query library](Reports/KQL/Library)** | 36 standalone, documented `.kql` files — password spray, targeted brute force, geodesic impossible travel, MFA fatigue, illicit consent, app credential backdoors, CA policy effectiveness, dormant apps and users, workload identity failures, and the ingestion diagnostics that tell you whether any of it can be trusted. Every file is read-only and pasteable straight into Log Analytics, Sentinel or Defender XDR; `Invoke-KqlLibraryQuery.ps1` lists, parameterizes and renders them without forking the files. |
| **[IAM automations](IAM)** | Ten Graph-native reports needing no Log Analytics workspace: risky users, stale accounts, app credential expiry, real CA coverage-gap analysis, CA policy health, privileged role usage, PIM activation history, plus application consent risk, MFA registration gaps, and guest access exposure. |

## Design principles

- **Idempotent** — every module checks before it creates. Re-run the whole thing, or just one step, after a failure without duplicating objects.
- **Safe by default** — Conditional Access policies deploy `enabledForReportingButNotEnforced`. Nothing locks you out of your own tenant.
- **Break-glass first** — break-glass accounts are created before anything else and excluded from every Conditional Access policy.
- **One config file** — `config/config.json` drives every module: tenant domain, naming, departments, CA ranges, governance timers, access packages.
- **Reporting is read-only, and says when it couldn't look** — every report and query only reads. Diagnostic reports connect with `*.Read.All` scopes only, preflight their permissions, and distinguish *checked and clean* from *could not check*. A missing licence, a missing scope or a missing log table is reported as `NotChecked` with the reason, never as a pass. An empty detection result and a missing table look identical from the outside; these reports refuse to let them read the same.

## Diagnostics quick start

Already have a tenant and a workspace? The reporting side stands alone — it reads, it never deploys.

```powershell
# 1. Can the data be trusted? Missing categories, stale exports, ingestion lag.
.\Reports\KQL\Get-LogIngestionHealthReport.ps1 -Open

# 2. What's in the query library, and what does one actually do?
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -List
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-MfaMethodAfterRiskySignIn -ShowQuery

# 3. Hunt.
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Domain ThreatHunting -Days 30 -Open

# 4. State-of-the-tenant gaps, no workspace required.
.\IAM\Get-AppConsentRiskReport.ps1 -Open
.\IAM\Get-MfaRegistrationGapReport.ps1 -Open
.\IAM\Get-GuestAccessReport.ps1 -Open
```

## Prerequisites

- PowerShell 7+ (`pwsh`)
- [`Microsoft.Graph` PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation): `Install-Module Microsoft.Graph -Scope CurrentUser`
- A Global Administrator (or Privileged Role Administrator) account on the target tenant
- **A disposable/test tenant.** This is a lab tool — do not point it at a production directory.
- If Security Defaults is enabled on the tenant, disable it before enabling Conditional Access policies
- Some Governance modules (PIM, Access Reviews, Entitlement Management, Lifecycle Workflows) require an Entra ID P2 / Governance license on the tenant
- Optional, only if you're using the KQL reports: `Az.Accounts` + `Az.OperationalInsights` PowerShell modules, and a Log Analytics workspace (see [`IaC/terraform`](IaC/terraform))
- Optional, only if you're using the Terraform IaC: Terraform >= 1.7 and an Azure subscription

## Quick start

```powershell
git clone https://github.com/NetSecDan1/entra-id-lab-automation.git
cd entra-id-lab-automation

# Edit config/config.json first — set TenantDomain at minimum
notepad config/config.json

# Full setup
.\Setup-TestTenant.ps1

# Or run a specific mode / subset of steps
.\Setup-TestTenant.ps1 -Mode Governance
.\Setup-TestTenant.ps1 -Steps Users,Groups
```

The default password is read from `config.json`, or overridden via the `ENTRA_LAB_DEFAULT_PASSWORD` environment variable — set that instead of editing the file if you'd rather not keep a password in plain text.

## Modes

| Mode | Steps |
|---|---|
| `Foundation` | Users, Groups, Directory |
| `Security` | Directory, Auth, AuthStrengths, NamedLocations, CAPs |
| `Identity` | Users, Groups, Auth, AuthStrengths, Directory |
| `Applications` | Apps, Schema, AuthStrengths |
| `Governance` | PIM, AdminUnits, AccessReviews, LifecycleWorkflows, EntitlementManagement |
| `Full` (default) | Everything above, plus Licensing, TermsOfUse, PasswordProtection, CrossTenantAccess, AuthContexts |

## Structure

```
Setup-TestTenant.ps1              # Orchestrator — run this
config/config.json                # All configuration lives here
Helpers/Common.ps1                # Shared functions (logging, connection, config validation)
Users/Deploy-Users.ps1            # Break glass, admin, test users, blocked user
Users/Deploy-FunUsers.ps1         # Optional themed test identities
Groups/Deploy-Groups.ps1
NamedLocations/Deploy-NamedLocations.ps1
CAPs/Deploy-CAPs.ps1
Apps/Deploy-Apps.ps1
Schema/Deploy-SchemaExtensions.ps1
Auth/Deploy-AuthMethods.ps1
Auth/Deploy-AuthStrengths.ps1
Directory/Deploy-DirectorySettings.ps1
Licensing/Deploy-Licenses.ps1
AdminUnits/Deploy-AdminUnits.ps1
PIM/Deploy-PIM.ps1
Governance/Deploy-AccessReviews.ps1
Governance/Deploy-LifecycleWorkflows.ps1
Governance/Deploy-EntitlementManagement.ps1
Security/Deploy-TermsOfUse.ps1
Security/Deploy-PasswordProtection.ps1
Security/Deploy-CrossTenantAccess.ps1
Security/Deploy-AuthContexts.ps1
Reports/Get-TenantReport.ps1      # Summarize what's deployed
Simulation/Invoke-SignInSimulation.ps1

CAPs/Baselines/                   # Tiered.json, ZeroTrust.json, SCuBA.json
CAPs/Deploy-CAPs-Custom.ps1
CAPs/Helpers/CAPolicyEngine.ps1
IaC/terraform/                    # Log Analytics workspace + Entra diagnostic export

Reports/KQL/                      # Nine KQL report scripts
Reports/KQL/Library/              # 36 standalone .kql queries, by domain
Reports/KQL/Invoke-KqlLibraryQuery.ps1
Reports/Helpers/HtmlReportFramework.ps1   # The renderer (zero dependencies)
Reports/Helpers/KqlQuery.ps1              # Azure connect + query execution with retry
Reports/Helpers/KqlLibrary.ps1            # Library index / load / parameterize
Reports/Helpers/GraphReadOnly.ps1         # Read-only Graph + scope preflight + findings
IAM/                              # Ten Graph-native reports
```

## Disclaimer

This tool creates real objects (users, groups, Conditional Access policies, apps) via Microsoft Graph. Use it only against a tenant you own and intend for testing. Review `config/config.json` before every run, and never run it against a production directory.

## License

MIT — see [LICENSE](LICENSE).
