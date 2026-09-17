<#
.SYNOPSIS
    Is the log data behind every other report actually arriving? Run this first
    on any workspace you did not build yourself.

.DESCRIPTION
    Every detection query in this repo has the same failure mode: if the data
    isn't there, the query returns nothing, and nothing looks exactly like
    "clean". This report exists to break that ambiguity before you trust a
    result.

    It runs the four Diagnostics queries from Reports/KQL/Library and turns them
    into findings with thresholds attached:

      Table coverage  - which Entra ID diagnostic categories are flowing, which
                        are missing entirely, and which have gone stale. A
                        required category that is MISSING is a blind spot, and
                        is reported as Critical rather than as a clean table.
      Ingestion lag   - how far behind real time the logs are, so you know
                        whether "no events in the last hour" means anything.
      Blind-spot hours- hours with zero sign-in rows, which usually means the
                        export stalled rather than that nobody signed in.
      Volume and cost - per-table volume, a monthly forecast, and burst ratios
                        that flag a table which suddenly changed behaviour.

    The findings are deliberately blunt about the difference between "checked
    and clean" and "could not check". The second is never reported as the first.

    READ-ONLY. Four KQL reads and nothing else.

.PARAMETER Days
    Evaluation window for coverage and blind-spot analysis. Default 7.

.PARAMETER StaleMinutes
    A flowing table with no rows for longer than this is reported as stale.
    Default 240. Raise it for a quiet lab, lower it for a busy production tenant.

.PARAMETER MaxAcceptableLatencyMinutes
    P95 ingestion latency above this is reported as a finding. Default 30.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID. Falls back to
    config.Reporting.LogAnalyticsWorkspaceId.

.EXAMPLE
    .\Reports\KQL\Get-LogIngestionHealthReport.ps1 -Open

.EXAMPLE
    .\Reports\KQL\Get-LogIngestionHealthReport.ps1 -Days 30 -StaleMinutes 60 -Open

.NOTES
    Requires Az.Accounts + Az.OperationalInsights and Log Analytics Reader on the
    workspace. Read-only - it queries the workspace and changes nothing.

    The underlying queries live in Reports/KQL/Library/Diagnostics and can be run
    on their own with Invoke-KqlLibraryQuery.ps1 -Domain Diagnostics.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 7,
    [int]$StaleMinutes = 240,
    [int]$MaxAcceptableLatencyMinutes = 30,
    [string]$OutputPath,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Helpers\KqlQuery.ps1"
. "$PSScriptRoot\..\Helpers\KqlLibrary.ps1"
. "$PSScriptRoot\..\Helpers\GraphReadOnly.ps1"
. "$PSScriptRoot\..\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
$WorkspaceId = Resolve-LabWorkspaceId -WorkspaceId $WorkspaceId -Config $config

Ensure-AzModules
Connect-LabAzure | Out-Null

function Invoke-LibraryQuery {
    param([string]$QueryName, [hashtable]$Overrides = @{})

    $queryInfo = Get-KqlLibraryQuery -Name $QueryName
    $applicable = @{}
    foreach ($key in $Overrides.Keys) {
        if ($queryInfo.Parameters.Contains($key)) { $applicable[$key] = $Overrides[$key] }
    }
    $kql = Set-KqlQueryParameter -Query $queryInfo.Query -Parameters $applicable

    try {
        return @(Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan (New-TimeSpan -Days 90) -QueryName $QueryName)
    } catch {
        Write-Status "$QueryName failed: $($_.Exception.Message)" -Type Error
        return $null   # null means "could not check", distinct from an empty result
    }
}

Write-Status "Checking Entra ID log ingestion health" -Type Header

$coverage  = Invoke-LibraryQuery -QueryName "Log-IngestionHealth"  -Overrides @{ lookback = "$($Days)d"; staleMinutes = $StaleMinutes }
$latency   = Invoke-LibraryQuery -QueryName "Log-IngestionLatency" -Overrides @{ lookback = "24h" }
$blindSpot = Invoke-LibraryQuery -QueryName "Log-BlindSpotHours"   -Overrides @{ lookback = "$($Days)d" }
$volume    = Invoke-LibraryQuery -QueryName "Log-VolumeAndCost"    -Overrides @{ lookback = "30d" }

$findings = @()

# ---- table coverage ---------------------------------------------------------
if ($null -eq $coverage) {
    $findings += New-Finding -Severity NotChecked -Category "Table coverage" `
        -Finding "The coverage query could not run" `
        -Evidence "Log-IngestionHealth failed against workspace $WorkspaceId." `
        -Recommendation "Confirm the workspace ID and that the signed-in identity holds Log Analytics Reader."
} else {
    $missingRequired = @($coverage | Where-Object { $_.Status -like "MISSING*" -and [string]$_.Requirement -like "Required*" })
    $missingOther    = @($coverage | Where-Object { $_.Status -like "MISSING*" -and [string]$_.Requirement -notlike "Required*" })
    $stale           = @($coverage | Where-Object { $_.Status -like "STALE*" })
    $healthy         = @($coverage | Where-Object { $_.Status -eq "OK" })

    if ($missingRequired.Count -gt 0) {
        $findings += New-Finding -Severity Critical -Category "Table coverage" `
            -Finding "$($missingRequired.Count) required log category/categories are not reaching this workspace" `
            -Subject (($missingRequired | Select-Object -ExpandProperty TableName) -join "; ") `
            -Count $missingRequired.Count `
            -Evidence "No rows in the last $Days day(s). Any detection query over these tables returns an empty result that is indistinguishable from a clean one." `
            -Recommendation "Enable the matching categories in the Entra ID tenant diagnostic setting (see IaC/terraform, which configures the full export) and re-run this report before trusting anything else."
    }

    if ($stale.Count -gt 0) {
        $findings += New-Finding -Severity High -Category "Table coverage" `
            -Finding "$($stale.Count) table(s) have received no rows for over $StaleMinutes minutes" `
            -Subject (($stale | Select-Object -ExpandProperty TableName) -join "; ") `
            -Count $stale.Count `
            -Evidence "Data was arriving and then stopped - an export that broke rather than one that was never configured." `
            -Recommendation "Check the tenant diagnostic setting still targets this workspace, and that the workspace has not hit a daily ingestion cap."
    }

    if ($missingOther.Count -gt 0) {
        $findings += New-Finding -Severity Info -Category "Table coverage" `
            -Finding "$($missingOther.Count) optional or premium category/categories are absent" `
            -Subject (($missingOther | Select-Object -ExpandProperty TableName) -join "; ") `
            -Count $missingOther.Count `
            -Evidence "These are Optional, Recommended or P2-licensed categories. Absence may be expected." `
            -Recommendation "P2 tables missing on a P1 tenant is normal. Recommended ones - MicrosoftGraphActivityLogs in particular - are worth enabling."
    }

    if ($missingRequired.Count -eq 0 -and $stale.Count -eq 0) {
        $findings += New-Finding -Severity Info -Category "Table coverage" `
            -Finding "All required log categories are flowing" `
            -Count $healthy.Count `
            -Evidence "$($healthy.Count) table(s) healthy over the last $Days day(s)." `
            -Recommendation "Queries over these tables can be trusted to have data behind them."
    }
}

# ---- latency ----------------------------------------------------------------
if ($null -eq $latency) {
    $findings += New-Finding -Severity NotChecked -Category "Ingestion latency" `
        -Finding "The latency query could not run" `
        -Recommendation "Latency is unknown, so a recent-events query may be reporting on data that has not landed yet."
} elseif ($latency.Count -eq 0) {
    $findings += New-Finding -Severity NotChecked -Category "Ingestion latency" `
        -Finding "No rows to measure latency against in the last 24 hours" `
        -Evidence "Either the tenant was genuinely idle, or ingestion has stopped - see the table coverage findings." `
        -Recommendation "Correlate with the blind-spot hours section before concluding the tenant was simply quiet."
} else {
    $worstP95 = (@($latency | Measure-Object -Property P95Minutes -Maximum).Maximum)
    if ($null -ne $worstP95 -and $worstP95 -gt $MaxAcceptableLatencyMinutes) {
        $findings += New-Finding -Severity Medium -Category "Ingestion latency" `
            -Finding "P95 ingestion latency peaked at $worstP95 minutes in the last 24 hours" `
            -Count ([int]$worstP95) `
            -Evidence "Threshold is $MaxAcceptableLatencyMinutes minutes. Events are landing well behind real time." `
            -Recommendation "Treat 'no events recently' as unproven until latency recovers. If it persists, the export is backlogged rather than the tenant being quiet."
    } else {
        $findings += New-Finding -Severity Info -Category "Ingestion latency" `
            -Finding "Ingestion latency is within threshold (P95 peak $worstP95 minutes)" `
            -Evidence "Threshold is $MaxAcceptableLatencyMinutes minutes." `
            -Recommendation "Recent-window queries are reliable."
    }
}

# ---- blind spots ------------------------------------------------------------
if ($null -eq $blindSpot) {
    $findings += New-Finding -Severity NotChecked -Category "Blind spots" `
        -Finding "The blind-spot query could not run"
} elseif ($blindSpot.Count -gt 0) {
    $totalHours = $Days * 24
    $pct = [math]::Round(100.0 * $blindSpot.Count / $totalHours, 1)
    $severity = if ($pct -gt 20) { "High" } elseif ($pct -gt 5) { "Medium" } else { "Low" }
    $findings += New-Finding -Severity $severity -Category "Blind spots" `
        -Finding "$($blindSpot.Count) of $totalHours hour(s) had zero sign-in rows ($pct%)" `
        -Count $blindSpot.Count `
        -Evidence "Detection queries covering those hours reported nothing because there was nothing to report on." `
        -Recommendation "In a lab with genuinely idle overnight periods this is expected - check whether the gaps cluster at night. Contiguous runs during business hours are an export outage."
} else {
    $findings += New-Finding -Severity Info -Category "Blind spots" `
        -Finding "No hours without sign-in data in the last $Days day(s)" `
        -Recommendation "Continuous coverage - detection queries over this window had data throughout."
}

# ---- volume -----------------------------------------------------------------
if ($null -eq $volume) {
    $findings += New-Finding -Severity NotChecked -Category "Volume" -Finding "The volume query could not run"
} else {
    $bursty = @($volume | Where-Object { $null -ne $_.BurstRatio -and [double]$_.BurstRatio -ge 5 })
    if ($bursty.Count -gt 0) {
        $findings += New-Finding -Severity Low -Category "Volume" `
            -Finding "$($bursty.Count) table(s) had a day at 5x or more their average volume" `
            -Subject (($bursty | Select-Object -ExpandProperty TableName) -join "; ") `
            -Count $bursty.Count `
            -Evidence "A large single-day spike usually means a new integration, a sign-in storm, or an automation loop." `
            -Recommendation "Identify the cause before it becomes a cost surprise. Diag-GraphApiCallers.kql finds a chatty application."
    }

    $totalMonthlyGb = (@($volume | Measure-Object -Property EstimatedMonthlyGB -Sum).Sum)
    if ($null -ne $totalMonthlyGb) {
        $findings += New-Finding -Severity Info -Category "Volume" `
            -Finding "Estimated ingestion: $([math]::Round($totalMonthlyGb, 2)) GB/month across $($volume.Count) table(s)" `
            -Evidence "Upper bound from uncompressed row size - Basic Logs and commitment tiers change the billed figure." `
            -Recommendation "Multiply by your workspace's per-GB rate for a rough monthly cost."
    }
}

function ConvertTo-SafeRows {
    # A failed query is $null, which is not the same as an empty result. Render
    # it as an empty section; the Findings table already says it wasn't checked.
    param($Rows)
    if ($null -eq $Rows) { return @() }
    return @($Rows)
}

$findings = @($findings | Sort-Finding)

# ---- render ------------------------------------------------------------------
$criticalCount = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
$notCheckedCount = @($findings | Where-Object { $_.Severity -eq "NotChecked" }).Count
$healthyTables = if ($coverage) { @($coverage | Where-Object { $_.Status -eq "OK" }).Count } else { 0 }
$totalTables   = if ($coverage) { @($coverage).Count } else { 0 }

$statTiles = @(
    @{ Label = "Tables healthy"; Value = "$healthyTables / $totalTables"; Tone = if ($totalTables -gt 0 -and $healthyTables -eq $totalTables) { "good" } elseif ($healthyTables -gt 0) { "warn" } else { "danger" } }
    @{ Label = "Blind-spot hours"; Value = if ($null -eq $blindSpot) { "not checked" } else { $blindSpot.Count }; Tone = if ($null -eq $blindSpot) { "neutral" } elseif ($blindSpot.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Critical findings"; Value = $criticalCount; Tone = if ($criticalCount -gt 0) { "danger" } else { "good" } }
    @{ Label = "Checks not run"; Value = $notCheckedCount; Tone = if ($notCheckedCount -gt 0) { "warn" } else { "good" } }
)

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Output\LogIngestionHealth-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
}

New-HtmlReport -Title "Entra ID Log Ingestion Health" `
    -Subtitle "$($config.TenantDomain) - workspace $WorkspaceId - $Days day window" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                             = $findings
        "Table coverage"                       = (ConvertTo-SafeRows $coverage)
        "Hours with no sign-in data"           = (ConvertTo-SafeRows $blindSpot)
        "Ingestion latency (last 24h, hourly)" = (ConvertTo-SafeRows $latency)
        "Volume and estimated cost (30d)"      = (ConvertTo-SafeRows $volume)
    }) `
    -FooterNote "Source: the four Diagnostics queries in Reports/KQL/Library (read-only KQL). Run this before trusting an empty result from any other report - an empty detection result and a missing table look identical from the outside." `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

if ($criticalCount -gt 0) {
    Write-Status "$criticalCount critical ingestion finding(s). Other reports over the affected tables are not trustworthy until this is fixed." -Type Error
}
