<#
.SYNOPSIS
    App-only (service principal / daemon app) sign-in activity and failures
    — the traffic Deploy-Apps.ps1's daemon app, and anything else using
    client-credentials flow, generates.

.DESCRIPTION
    Service principals don't get MFA challenges, so their sign-in health is
    judged differently: volume by app, failure rate, and how many distinct
    IPs each one authenticates from (a daemon app suddenly appearing from a
    new IP range, or from many IPs at once, is a stronger signal than the
    same pattern for an interactive user).

.EXAMPLE
    .\Reports\KQL\Get-ServicePrincipalSignInReport.ps1 -WorkspaceId <guid> -Open
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

$summaryKql = @"
ServicePrincipalSignInLogs
| where TimeGenerated > ago($($Days)d)
| extend Status = iff(tostring(ResultType) == "0", "Success", "Failure")
| summarize Attempts = count(), Failures = countif(Status == "Failure"), DistinctIPs = dcount(IPAddress), LastSeen = max(TimeGenerated)
        by ServicePrincipalName, AppId
| order by Failures desc, Attempts desc
"@

$failureDetailKql = @"
ServicePrincipalSignInLogs
| where TimeGenerated > ago($($Days)d)
| where tostring(ResultType) != "0"
| project TimeGenerated, ServicePrincipalName, AppId, IPAddress, ResultType, ResultDescription
| order by TimeGenerated desc
| take 300
"@

$summaryRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $summaryKql       -Timespan (New-TimeSpan -Days $Days)
$failureRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $failureDetailKql -Timespan (New-TimeSpan -Days $Days)

$totalFailures = ($summaryRows | Measure-Object -Property Failures -Sum).Sum
$multiIpSps    = @($summaryRows | Where-Object { $_.DistinctIPs -gt 3 })

$statTiles = @(
    @{ Label = "Service principals seen"; Value = @($summaryRows).Count; Tone = "neutral" }
    @{ Label = "Total failed app-only sign-ins"; Value = [int]($totalFailures | ForEach-Object { $_ }); Tone = if ($totalFailures -gt 0) { "warn" } else { "good" } }
    @{ Label = "SPs authenticating from >3 IPs"; Value = $multiIpSps.Count; Tone = if ($multiIpSps.Count -gt 0) { "warn" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Output\ServicePrincipalSignIns-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Service Principal Sign-In Activity" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "By service principal" = $summaryRows
        "Recent failures (up to 300)" = $failureRows
    }) `
    -FooterNote "Source: ServicePrincipalSignInLogs (Log Analytics). Enable this category in the diagnostic setting (see IaC/terraform) if it returns no rows." `
    -OutputPath $outputPath `
    -Open:$Open
