<#
.SYNOPSIS
    List, print, or run any query from the curated KQL library and render the
    results as a self-contained HTML report.

.DESCRIPTION
    One entry point for the 36 documented queries in Reports/KQL/Library. Three
    modes, all read-only:

      -List        Show the catalog. No connection, no credentials, no calls.
      -ShowQuery   Print the (parameterized) KQL to the console so you can paste
                   it into Log Analytics, Sentinel, or Defender XDR advanced
                   hunting yourself. Still no connection.
      (default)    Run it against the workspace and write HTML (+ optional CSV
                   and JSON) to Reports/Output.

    -ShowQuery exists because reading a query before running it is the correct
    order of operations in someone else's tenant. Nothing here writes to Entra
    ID or to the workspace - every query is a read.

    Queries can be run one at a time (-Name), or a whole domain in one report
    (-Domain), or the entire library (-All), in which case each query becomes a
    section in a single HTML file.

.PARAMETER Name
    Library query to run, by file name (e.g. "Threat-PasswordSpray"). Partial
    names work if unambiguous.

.PARAMETER Domain
    Run every query in a domain: Diagnostics, SignInPosture, ThreatHunting,
    IdentityAdmin, WorkloadIdentity, Hygiene.

.PARAMETER All
    Run the entire library. Expect this to take several minutes and to hit the
    workspace with 36 queries - use -Domain during normal work.

.PARAMETER Severity
    Further narrow -Domain / -All to one declared severity (info, medium, high,
    critical).

.PARAMETER Days
    Convenience override for the query's `lookback` parameter. Ignored by queries
    that use a baseline/detection window pair instead.

.PARAMETER Parameters
    Explicit overrides for any `let` parameter the query declares, e.g.
    -Parameters @{ minTargetedUsers = 10; bucket = "24h" }. An unknown name is an
    error, not a silent no-op.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID. Falls back to
    config.Reporting.LogAnalyticsWorkspaceId.

.PARAMETER ExportCsv
    Also write one CSV per query section next to the HTML.

.PARAMETER ExportJson
    Also write a JSON file with the rows plus run metadata, for pipelines.

.PARAMETER ContinueOnError
    When running multiple queries, keep going after a failure and report which
    ones failed in the output instead of aborting the batch. On by default for
    -All and -Domain.

.EXAMPLE
    .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -List

    The catalog: 36 queries with domain, severity, tables and tunable parameters.

.EXAMPLE
    .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -ShowQuery

    Prints the KQL. Connects to nothing. Paste it wherever you like.

.EXAMPLE
    .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name Threat-PasswordSpray -Days 14 `
        -Parameters @{ minTargetedUsers = 10 } -Open

.EXAMPLE
    .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics -Open

    Start here on any new workspace - it tells you whether the data behind every
    other query is actually arriving.

.NOTES
    Read-only. Requires Az.Accounts + Az.OperationalInsights and Log Analytics
    Reader on the workspace. The .kql files are the source of truth; this script
    only loads and parameterizes them.
#>
[CmdletBinding(DefaultParameterSetName = "Single")]
param(
    [Parameter(ParameterSetName = "Single", Position = 0)]
    [string]$Name,

    [Parameter(ParameterSetName = "Domain")]
    [string]$Domain,

    [Parameter(ParameterSetName = "All")]
    [switch]$All,

    [Parameter(ParameterSetName = "List")]
    [switch]$List,

    [string]$Severity,
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days,
    [hashtable]$Parameters = @{},
    [switch]$ShowQuery,
    [switch]$ExportCsv,
    [switch]$ExportJson,
    [switch]$ContinueOnError,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Helpers\KqlQuery.ps1"
. "$PSScriptRoot\..\Helpers\KqlLibrary.ps1"
. "$PSScriptRoot\..\Helpers\HtmlReportFramework.ps1"

function Format-KqlCatalog {
    # Explicit widths through Out-String: -AutoSize alone silently drops columns
    # when the host reports a narrow console (CI, redirected output, SSH).
    param([Parameter(ValueFromPipeline)]$Query)
    begin { $collected = @() }
    process { $collected += $Query }
    end {
        $collected |
            Format-Table -Property @{ N = "Name";     E = { $_.Name };          Width = 46 },
                                   @{ N = "Domain";   E = { $_.Domain };        Width = 24 },
                                   @{ N = "Severity"; E = { $_.Severity };      Width = 9 },
                                   @{ N = "Tunables"; E = { $_.ParameterList } } |
            Out-String -Width 220 |
            Write-Host
    }
}

# ---- select which queries to work with --------------------------------------
$index = Get-KqlLibraryIndex -Severity $Severity

switch ($PSCmdlet.ParameterSetName) {
    "List" {
        Write-Status "KQL library: $($index.Count) queries" -Type Header
        $index | Sort-Object Domain, Name | Format-KqlCatalog
        Write-Host ""
        Write-Status "Run one:        .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name <Name> -Open" -Type Info
        Write-Status "Read one first: .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Name <Name> -ShowQuery" -Type Info
        Write-Status "Run a domain:   .\Reports\KQL\Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics -Open" -Type Info
        return
    }
    "Domain" {
        $selected = @(Get-KqlLibraryIndex -Domain $Domain -Severity $Severity)
        if ($selected.Count -eq 0) { throw "No queries in domain '$Domain'. Valid domains: $((Get-KqlLibraryIndex | Select-Object -ExpandProperty Folder -Unique) -join ', ')" }
        $reportTitle = "KQL Library - $Domain"
        if (-not $PSBoundParameters.ContainsKey("ContinueOnError")) { $ContinueOnError = $true }
    }
    "All" {
        $selected = @($index)
        $reportTitle = "KQL Library - full sweep"
        if (-not $PSBoundParameters.ContainsKey("ContinueOnError")) { $ContinueOnError = $true }
    }
    default {
        if (-not $Name) {
            Write-Status "No query specified. Showing the catalog instead." -Type Warning
            Write-Host ""
            $index | Sort-Object Domain, Name | Format-KqlCatalog
            return
        }
        $selected = @(Get-KqlLibraryQuery -Name $Name)
        $reportTitle = $selected[0].Title
    }
}

# ---- build the parameter set applied to every selected query ----------------
$effectiveParameters = @{}
foreach ($key in $Parameters.Keys) { $effectiveParameters[$key] = $Parameters[$key] }
if ($PSBoundParameters.ContainsKey("Days")) { $effectiveParameters["lookback"] = "$($Days)d" }

function Get-ParameterizedQuery {
    param([psobject]$QueryInfo)

    $text = if ($QueryInfo.PSObject.Properties.Name -contains "Query" -and $QueryInfo.Query) {
        $QueryInfo.Query
    } else {
        Get-Content -Path $QueryInfo.Path -Raw
    }

    # Only apply overrides the query actually declares - a lookback override is
    # meaningless for a baseline/detection query and must not fail the batch.
    $applicable = @{}
    foreach ($key in $effectiveParameters.Keys) {
        if ($QueryInfo.Parameters.Contains($key)) { $applicable[$key] = $effectiveParameters[$key] }
        elseif ($PSCmdlet.ParameterSetName -eq "Single") {
            throw "Query '$($QueryInfo.Name)' has no parameter '$key'. It declares: $($QueryInfo.ParameterList)"
        }
    }
    return (Set-KqlQueryParameter -Query $text -Parameters $applicable)
}

# ---- -ShowQuery: print and stop, no connection ------------------------------
if ($ShowQuery) {
    foreach ($queryInfo in $selected) {
        Write-Host ""
        Write-Status "$($queryInfo.Name) - $($queryInfo.Title) [$($queryInfo.Severity)]" -Type Header
        Write-Host (Get-ParameterizedQuery -QueryInfo $queryInfo)
    }
    Write-Host ""
    Write-Status "Printed $(@($selected).Count) query/queries. Nothing was executed and no connection was made." -Type Success
    return
}

# ---- run ---------------------------------------------------------------------
$config = Get-Config -ConfigPath $ConfigPath
$WorkspaceId = Resolve-LabWorkspaceId -WorkspaceId $WorkspaceId -Config $config

Ensure-AzModules
Connect-LabAzure | Out-Null

$sections = [ordered]@{}
$runLog = @()
$totalRows = 0
$failed = 0

foreach ($queryInfo in $selected) {
    $kql = Get-ParameterizedQuery -QueryInfo $queryInfo

    # The query's own ago() filter governs the window. The API timespan is a
    # wider outer bound so it never silently clips a longer baseline window.
    $timespan = New-TimeSpan -Days 90

    $started = Get-Date
    try {
        $rows = @(Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan $timespan -QueryName $queryInfo.Name)
        $sections["$($queryInfo.Title) [$($queryInfo.Severity)]"] = $rows
        $totalRows += $rows.Count
        $runLog += [pscustomobject]@{
            Query    = $queryInfo.Name
            Domain   = $queryInfo.Domain
            Severity = $queryInfo.Severity
            Rows     = $rows.Count
            Status   = if ($rows.Count -gt 0) { "Rows returned" } else { "No rows" }
            Seconds  = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            Detail   = ""
        }
    } catch {
        $failed++
        $message = $_.Exception.Message
        Write-Status "$($queryInfo.Name) failed: $message" -Type Error
        $runLog += [pscustomobject]@{
            Query    = $queryInfo.Name
            Domain   = $queryInfo.Domain
            Severity = $queryInfo.Severity
            Rows     = 0
            Status   = "Failed"
            Seconds  = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            Detail   = ($message -split "`n")[0]
        }
        if (-not $ContinueOnError) { throw }
    }
}

# ---- render ------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$slug = if ($PSCmdlet.ParameterSetName -eq "Single") { $selected[0].Name } elseif ($Domain) { "Domain-$Domain" } else { "FullSweep" }
$outputDir = Join-Path $PSScriptRoot "..\Output"
$outputPath = Join-Path $outputDir "KqlLibrary-$slug-$timestamp.html"

$statTiles = @(
    @{ Label = "Queries run";   Value = @($selected).Count; Tone = "neutral" }
    @{ Label = "Total rows";    Value = $totalRows;         Tone = if ($totalRows -gt 0) { "warn" } else { "good" } }
    @{ Label = "Queries with findings"; Value = @($runLog | Where-Object { $_.Rows -gt 0 }).Count; Tone = if (@($runLog | Where-Object { $_.Rows -gt 0 }).Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Failed queries"; Value = $failed; Tone = if ($failed -gt 0) { "danger" } else { "good" } }
)

if (@($selected).Count -gt 1) {
    $ordered = [ordered]@{ "Run summary" = $runLog }
    foreach ($key in $sections.Keys) { $ordered[$key] = $sections[$key] }
    $sections = $ordered
}

$appliedText = if ($effectiveParameters.Count -gt 0) {
    " | overrides: " + (($effectiveParameters.Keys | ForEach-Object { "$_=$($effectiveParameters[$_])" }) -join ", ")
} else { "" }

New-HtmlReport -Title $reportTitle `
    -Subtitle "$($config.TenantDomain) - workspace $WorkspaceId$appliedText" `
    -StatTiles $statTiles `
    -Rows $sections `
    -FooterNote "Source: Reports/KQL/Library (read-only KQL against Log Analytics). Each section's query, tuning notes and caveats are in the matching .kql file - read the Caveat line before acting on a result." `
    -OutputPath $outputPath `
    -Open:$Open | Out-Null

# ---- optional machine-readable exports --------------------------------------
if ($ExportCsv) {
    foreach ($key in $sections.Keys) {
        $rows = @($sections[$key])
        if ($rows.Count -eq 0) { continue }
        $safeKey = ($key -replace '[^\w\-]', '_')
        $csvPath = Join-Path $outputDir "KqlLibrary-$slug-$safeKey-$timestamp.csv"
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Status "CSV written: $csvPath" -Type Success
    }
}

if ($ExportJson) {
    $jsonPath = Join-Path $outputDir "KqlLibrary-$slug-$timestamp.json"
    [pscustomobject]@{
        GeneratedAt   = (Get-Date).ToString("o")
        Tenant        = $config.TenantDomain
        WorkspaceId   = $WorkspaceId
        Overrides     = $effectiveParameters
        QueriesRun    = @($selected | Select-Object Name, Title, Domain, Severity, Tables)
        RunSummary    = $runLog
        Results       = $sections
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Status "JSON written: $jsonPath" -Type Success
}

if ($failed -gt 0) {
    Write-Status "$failed query/queries failed - see the Run summary section. A failure is usually a missing table: run -Domain Diagnostics to check ingestion." -Type Warning
}
