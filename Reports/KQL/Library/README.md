# KQL query library

36 standalone, documented KQL queries against the Entra ID diagnostic tables in Log Analytics. Every file is **read-only** and **portal-pasteable as-is** — open it, copy the whole thing, paste it into Log Analytics, Sentinel, or Defender XDR advanced hunting. Nothing needs preprocessing.

They can also be listed, parameterized and rendered to HTML through [`../Invoke-KqlLibraryQuery.ps1`](../Invoke-KqlLibraryQuery.ps1), which loads these same files rather than forking them.

```powershell
# the catalog — no connection, no credentials
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -List

# read a query before running it in someone's tenant
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -ShowQuery

# run it
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -Days 14 -Open

# run a whole domain into one report
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics -Open
```

## Start here

Run **`Diagnostics/Log-IngestionHealth.kql`** first on any workspace you did not build yourself.

Every query below shares one failure mode: if the data isn't there, the query returns nothing, and nothing looks exactly like clean. The diagnostics domain exists to break that ambiguity before you trust a result.

## The queries

### Diagnostics — is the data behind the other queries actually arriving?

| Query | What it answers |
|---|---|
| `Log-IngestionHealth` | Which Entra log categories are flowing, which are missing, which went stale |
| `Log-IngestionLatency` | How far behind real time the logs are — matters before you believe "nothing happened recently" |
| `Log-BlindSpotHours` | Hours with zero sign-in rows: usually a stalled export, not a quiet tenant |
| `Log-VolumeAndCost` | Per-table volume, monthly forecast, and burst ratios that flag a table whose behaviour changed |
| `Diag-GraphApiCallers` | Who is calling Graph, how hard, and how often they get throttled |

### Sign-in posture — where the controls aren't

| Query | What it answers |
|---|---|
| `SignIn-SingleFactorSuccess` | Who got in with a password alone, and whether a compliant device compensated |
| `SignIn-PrivilegedWithoutStrongAuth` | The same, narrowed to accounts holding a privileged role |
| `SignIn-ErrorTaxonomy` | Every failing AADSTS code decoded and classified — start here when "users are getting errors" |
| `SignIn-ConditionalAccessNotApplied` | Apps reached successfully with no CA policy enforced at all |
| `SignIn-ReportOnlyWouldBlock` | Who a report-only policy would break — run before enforcing anything |
| `SignIn-LegacyAuthentication` | Legacy auth usage, and critically whether it is still succeeding |
| `SignIn-UnmanagedDeviceAccess` | Successful access from unregistered or non-compliant devices |

### Threat hunting

| Query | What it answers |
|---|---|
| `Threat-PasswordSpray` | One IP, few guesses each, many accounts — pivots on source IP, which is what makes spray visible |
| `Threat-TargetedBruteForce` | The mirror image: many IPs, many attempts, one account |
| `Threat-ImpossibleTravel` | Real great-circle distance and implied speed, not a country-changed heuristic |
| `Threat-MfaFatigue` | Repeated MFA denials followed by an approval — push bombing |
| `Threat-RiskDetectionSummary` | Identity Protection detections, and how many of the flagged sign-ins succeeded anyway |
| `Threat-FirstTimeCountry` | Per-user geographic baseline, then today's genuinely new locations |
| `Threat-SuspiciousConsentGrants` | Consent and permission grants, flagged by how much damage the permission does |
| `Threat-AppCredentialBackdoor` | Secrets, certificates and federated credentials added to existing apps — persistence |
| `Threat-MfaMethodAfterRiskySignIn` | **Highest-signal query here.** Security-info changes within hours of a successful risky sign-in |

### Identity administration

| Query | What it answers |
|---|---|
| `Admin-RoleAssignmentChanges` | Who granted which directory role to whom, with Tier 0 flagged |
| `Admin-BreakGlassAccountUsage` | Emergency account sign-ins and directory actions — *and* whether they've ever been tested |
| `Admin-ConditionalAccessPolicyChanges` | Field-level diff history for CA policies, named locations and auth strengths |
| `Admin-AuthenticationMethodChanges` | Who changed whose security info; self-service vs administrator-performed |
| `Admin-GuestInviteAndRedemption` | Guest invitations grouped by the guest's own external domain |
| `Admin-DirectoryConfigDrift` | Changes to tenant-wide security settings nobody monitors until afterwards |
| `Admin-AfterHoursPrivilegedActivity` | Privileged operations outside business hours, by actor |

### Workload identity

| Query | What it answers |
|---|---|
| `Workload-ServicePrincipalFailures` | App-only sign-in failures with a concrete diagnosis per error code |
| `Workload-ServicePrincipalNewSource` | A service principal authenticating from an IP it has never used — credential theft signal |
| `Workload-ManagedIdentityUsage` | Managed identity inventory and failures (which are authorization, not credential, problems) |

### Hygiene — what to clean up

| Query | What it answers |
|---|---|
| `Hygiene-DormantApplications` | Apps that still exist but stopped being used — standing attack surface |
| `Hygiene-DormantUsers` | Accounts dormant, or that have only ever failed to sign in |
| `Hygiene-ConditionalAccessPolicyEffectiveness` | Policies that look protective but have never enforced anything |
| `Hygiene-NamedLocationEffectiveness` | Named locations that no longer match real traffic |
| `Hygiene-AuthenticationMethodStrength` | What users *actually* authenticate with, classified by phishing resistance |

## How a query file is built

```kql
// =============================================================================
// Name:       Password spray detection
// Domain:     Threat hunting
// Tables:     SigninLogs
// Severity:   critical
// Safety:     READ-ONLY.
// Purpose:    ...
// Tuning:     which `let` values to change and why
// Reading it: what good and bad look like, with thresholds
// Caveat:     what this query CANNOT see
// =============================================================================
let lookback = 7d;
let minTargetedUsers = 5;
SigninLogs
| ...
```

The header is parsed by `Reports/Helpers/KqlLibrary.ps1` to build the catalog, and is valid KQL comment syntax so it costs nothing when pasted into a portal.

**Read the `Caveat` line before acting on a result.** Several of these queries have real blind spots and say so explicitly — an app with zero sign-ins never appears in a dormant-apps result; role membership reconstructed from audit logs misses long-standing admins; an empty risk result on a P1 tenant is a licensing artifact rather than good news. The headers are written so the output never implies more completeness than it has.

### Parameters

Tunables are plain `let name = value;` lines above the first pipeline stage. That is deliberately not a templating syntax — it keeps every file valid KQL on its own.

```powershell
# -Days is sugar for the `lookback` parameter
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -Days 30

# anything else by name; an unknown name is an error, not a silent no-op
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray `
    -Parameters @{ minTargetedUsers = 12; bucket = "24h" }
```

Queries that use a baseline/detection window pair instead of `lookback` (`Threat-FirstTimeCountry`, `Threat-MfaMethodAfterRiskySignIn`, `Workload-ServicePrincipalNewSource`) ignore `-Days` in batch mode rather than failing the batch.

Two parameters must be set for your environment or the query is misleading:

- `Admin-BreakGlassAccountUsage` → `breakGlassPattern` must match your emergency-account naming. It defaults to `"breakglass"`, which is what this repo's `Users/Deploy-Users.ps1` creates.
- `Admin-AfterHoursPrivilegedActivity` → `tzOffsetHours` must be your operations team's UTC offset, or "after hours" means nothing.

## Adding your own

Drop a `.kql` file into the right domain folder with the same header keys. The catalog picks it up automatically — nothing registers queries anywhere.

## Safety

Every query is a read. There is no `.create`, no `.set`, no ingestion command, and nothing in this library writes to Entra ID or to the workspace. The worst a query here can do is cost you query time against a large workspace, which is what the `lookback` parameters are for.
