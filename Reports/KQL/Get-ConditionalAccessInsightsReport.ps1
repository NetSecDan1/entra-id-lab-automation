<#
.SYNOPSIS
    Breaks down what your Conditional Access policies actually did to real
    sign-in traffic: per-policy success/failure/not-applied counts, plus
    report-only policies that would have blocked or interrupted sign-in
    had they been enforced.

.DESCRIPTION
    Expands the ConditionalAccessPolicies dynamic column on SigninLogs so
    you can see, per policy display name, how often it applied and what it
    did — the fastest way to tell whether a newly-deployed report-only
    policy (see any CAPs/ baseline) is scoped the way you expect before you
    flip it to enforced.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID. Falls back to
    config.Reporting.LogAnalyticsWorkspaceId if not supplied.

.PARAMETER Days
    Lookback window in days. Default 7.

.EXAMPLE
    .\Reports\KQL\Get-ConditionalAccessInsightsReport.ps1 -WorkspaceId <guid> -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 7,
    [switch]$Open
)

. "$PSScriptRoot\..\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Helpers\KqlQuery.ps1"
. "$PSScriptRoot\..\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
if (-not $WorkspaceId) {
    $WorkspaceId = if ($config.Reporting -and $config.Reporting.LogAnalyticsWorkspaceId) { [string]$config.Reporting.LogAnalyticsWorkspaceId } else { $null }
}
if (-not $WorkspaceId) {
    throw "No workspace ID provided. Pass -WorkspaceId, or set config.Reporting.LogAnalyticsWorkspaceId. See IaC/terraform to provision one."
}

Ensure-AzModules
Connect-LabAzure | Out-Null

$byPolicyKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| mv-expand CA = ConditionalAccessPolicies
| extend PolicyName = tostring(CA.displayName), PolicyResult = tostring(CA.result)
| where isnotempty(PolicyName)
| summarize Total = count(),
            Success = countif(PolicyResult in ("success", "reportOnlySuccess")),
            Failure = countif(PolicyResult in ("failure", "reportOnlyFailure")),
            NotApplied = countif(PolicyResult in ("notApplied", "reportOnlyNotApplied")),
            ReportOnlyWouldInterrupt = countif(PolicyResult == "reportOnlyInterrupted")
        by PolicyName
| order by Total desc
"@

$overallKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| summarize Count = count() by ConditionalAccessStatus
| order by Count desc
"@

$byPolicyRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $byPolicyKql -Timespan (New-TimeSpan -Days $Days)
$overallRows  = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $overallKql  -Timespan (New-TimeSpan -Days $Days)

$totalEvaluated = ($overallRows | Measure-Object -Property Count -Sum).Sum
$failureCount   = ($overallRows | Where-Object { $_.ConditionalAccessStatus -eq "failure" } | Measure-Object -Property Count -Sum).Sum
$notApplicable  = ($overallRows | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" } | Measure-Object -Property Count -Sum).Sum
$wouldInterrupt = ($byPolicyRows | Measure-Object -Property ReportOnlyWouldInterrupt -Sum).Sum

$statTiles = @(
    @{ Label = "Sign-ins evaluated ($Days d)"; Value = [int]($totalEvaluated | ForEach-Object { $_ }); Tone = "neutral" }
    @{ Label = "Blocked by CA (failure)"; Value = [int]($failureCount | ForEach-Object { $_ }); Tone = if ($failureCount -gt 0) { "warn" } else { "good" } }
    @{ Label = "No policy applied"; Value = [int]($notApplicable | ForEach-Object { $_ }); Tone = if ($notApplicable -gt 0) { "warn" } else { "good" } }
    @{ Label = "Report-only would-block"; Value = [int]($wouldInterrupt | ForEach-Object { $_ }); Tone = if ($wouldInterrupt -gt 0) { "danger" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Output\ConditionalAccessInsights-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Conditional Access Insights" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Outcomes by policy" = $byPolicyRows
        "Overall sign-in CA status" = $overallRows
    }) `
    -FooterNote "Source: SigninLogs (Log Analytics), ConditionalAccessPolicies expanded per sign-in. 'Report-only would-block' surfaces policies safe to flip to enforced only after review." `
    -OutputPath $outputPath `
    -Open:$Open
