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
| **Conditional Access** | Imports the [Joey Verlinden CA baseline](https://github.com/j0eyv/ConditionalAccessBaseline) (~30 policies), deployed report-only by default |
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

## Design principles

- **Idempotent** — every module checks before it creates. Re-run the whole thing, or just one step, after a failure without duplicating objects.
- **Safe by default** — Conditional Access policies deploy `enabledForReportingButNotEnforced`. Nothing locks you out of your own tenant.
- **Break-glass first** — break-glass accounts are created before anything else and excluded from every Conditional Access policy.
- **One config file** — `config/config.json` drives every module: tenant domain, naming, departments, CA ranges, governance timers, access packages.

## Prerequisites

- PowerShell 7+ (`pwsh`)
- [`Microsoft.Graph` PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation): `Install-Module Microsoft.Graph -Scope CurrentUser`
- A Global Administrator (or Privileged Role Administrator) account on the target tenant
- **A disposable/test tenant.** This is a lab tool — do not point it at a production directory.
- If Security Defaults is enabled on the tenant, disable it before enabling Conditional Access policies
- Some Governance modules (PIM, Access Reviews, Entitlement Management, Lifecycle Workflows) require an Entra ID P2 / Governance license on the tenant

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
```

## Disclaimer

This tool creates real objects (users, groups, Conditional Access policies, apps) via Microsoft Graph. Use it only against a tenant you own and intend for testing. Review `config/config.json` before every run, and never run it against a production directory.

## License

MIT — see [LICENSE](LICENSE).
