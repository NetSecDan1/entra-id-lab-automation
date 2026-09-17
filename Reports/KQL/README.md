# KQL reports

PowerShell scripts that query a Log Analytics workspace (Entra ID Sign-in/Audit logs) with KQL and render the results as a single, self-contained HTML dashboard — sortable, searchable, dark-mode aware, no external dependencies.

| Script | What it shows |
|---|---|
| `Get-RiskySignInsReport.ps1` | Medium/high risk sign-ins, cross-referenced against current privileged role membership |
| `Get-LegacyAuthReport.ps1` | Legacy/basic auth usage that's still getting through — run before/after enabling a "block legacy auth" CA policy |
| `Get-ConditionalAccessInsightsReport.ps1` | Per-policy success/failure/not-applied counts, and what report-only policies would have blocked |

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

`Reports/Helpers/HtmlReportFramework.ps1` has zero dependencies on the rest of this repo. Dot-source it if you're working in this folder; if you're writing a throwaway script somewhere else entirely, copy the `New-HtmlReport` function body out of that file and paste it at the bottom of your script — it'll work standalone. Minimal usage:

```powershell
$rows = Invoke-LabKqlQuery -WorkspaceId $wsId -Query $myKql   # or any Graph/other query
New-HtmlReport -Title "My Report" -Rows $rows -OutputPath ".\out.html" -Open
```
