# KQL reports

PowerShell scripts that query a Log Analytics workspace (Entra ID Sign-in/Audit logs) with KQL and render the results as a single, self-contained HTML dashboard — sortable, searchable, dark-mode aware, no external dependencies.

| Script | What it shows |
|---|---|
| `Get-RiskySignInsReport.ps1` | Medium/high risk sign-ins, cross-referenced against current privileged role membership |
| `Get-LegacyAuthReport.ps1` | Legacy/basic auth usage that's still getting through — run before/after enabling a "block legacy auth" CA policy |
| `Get-ConditionalAccessInsightsReport.ps1` | Per-policy success/failure/not-applied counts, and what report-only policies would have blocked |
| `Get-PasswordSprayReport.ps1` | Invalid-credential failures shaped like a spray (1 IP, many users) or targeted brute force (many IPs, 1 user) |
| `Get-ImpossibleTravelReport.ps1` | Same user, successful sign-ins from two countries closer together in time than travel allows |
| `Get-AdminActivityReport.ps1` | Who changed what: role assignments, CA policy edits, app/group management, by actor and over time |
| `Get-ServicePrincipalSignInReport.ps1` | App-only (daemon/service principal) sign-in volume, failures, and IP spread per app |
| `Get-AuthMethodUsageReport.ps1` | Real-world MFA method mix — phishing-resistant vs. phishable (SMS/voice) vs. single-factor sign-ins |
| `Get-LogIngestionHealthReport.ps1` | **Run this first.** Whether the data behind every other report is actually arriving: missing categories, stale exports, ingestion lag, blind-spot hours, volume and cost |

Plus a **[36-query library](Library)** of standalone `.kql` files covering everything worth having on hand but not worth a dedicated script each — spray, brute force, MFA fatigue, consent abuse, credential backdoors, CA effectiveness, dormant apps and users, workload identity failures. One runner drives all of them:

```powershell
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -List                                  # catalog, no connection
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -ShowQuery  # read it first
.\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics -Open              # run a whole domain
```

## Before you trust an empty result

An empty detection result and a missing table look identical from the outside. `Get-LogIngestionHealthReport.ps1` (or `Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics`) tells you which it is. Run it once on any workspace you did not provision yourself.

## Setup

1. Provision (or point at) a Log Analytics workspace receiving Entra ID logs — see [`IaC/terraform`](../../IaC/terraform).
2. Either pass `-WorkspaceId <guid>` to any script, or set it once in `config.Reporting.LogAnalyticsWorkspaceId`.
3. `Connect-AzAccount` happens automatically on first run if you're not already connected.

```powershell
.\Reports\KQL\Get-RiskySignInsReport.ps1 -Days 14 -Open
```

Reports are written to `Reports/Output/` (gitignored — they contain live tenant data) and can be opened with `-Open`.

## Writing your own

Every query here is different — that's expected, and the framework doesn't care. All it needs is `Rows` (any collection of objects, or a hashtable of `{ "Section title" = $rows }` for multiple tables) and it auto-detects columns, numeric alignment, and status/risk badges.

If the query is one you'd want again, put it in [`Library/`](Library) as a `.kql` file instead of writing a new script — the runner picks it up automatically, and the file stays pasteable into the portal.

`Reports/Helpers/HtmlReportFramework.ps1` has zero dependencies on the rest of this repo. Dot-source it if you're working in this folder; if you're writing a throwaway script somewhere else entirely, copy the `New-HtmlReport` function body out of that file and paste it at the bottom of your script — it'll work standalone. Minimal usage:

```powershell
$rows = Invoke-LabKqlQuery -WorkspaceId $wsId -Query $myKql   # or any Graph/other query
New-HtmlReport -Title "My Report" -Rows $rows -OutputPath ".\out.html" -Open
```

## Helpers

| Helper | What it provides |
|---|---|
| `Helpers/KqlQuery.ps1` | Azure connect, workspace resolution, and `Invoke-LabKqlQuery` — with retry/backoff on throttling, a row cap, and errors that name the query and the likely cause |
| `Helpers/KqlLibrary.ps1` | Indexes the `.kql` library, loads a query by name, rewrites its `let` parameters |
| `Helpers/GraphReadOnly.ps1` | Read-only Graph connect, scope preflight, throttle-safe paging, licence capability detection, and the shared finding type |
| `Helpers/HtmlReportFramework.ps1` | The renderer. Zero dependencies — copy the function out if you need it elsewhere |

`Invoke-LabKqlQuery` retries throttled queries because an un-retried 429, once its exception is swallowed, is indistinguishable from "no results".
