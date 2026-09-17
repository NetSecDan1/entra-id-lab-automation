<#
.SYNOPSIS
    Finds legacy/basic authentication usage that's still slipping through —
    the protocols Conditional Access "block legacy auth" policies target.

.DESCRIPTION
    Legacy auth (IMAP, POP3, SMTP AUTH, older Exchange ActiveSync, etc.)
    can't carry MFA, so any usage found here is either an exception that
    needs closing, a gap in CA policy scope, or evidence a block policy
    isn't actually catching what you think it is. Useful to run before AND
    after deploying the "block legacy auth" policy in any of the CAPs
    baselines to confirm it's actually taking effect.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID. Falls back to
    config.Reporting.LogAnalyticsWorkspaceId if not supplied.

.PARAMETER Days
    Lookback window in days. Default 14.

.EXAMPLE
    .\Reports\KQL\Get-LegacyAuthReport.ps1 -WorkspaceId <guid> -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 14,
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

$legacyClientApps = '"Exchange ActiveSync", "Other clients", "IMAP4", "POP3", "SMTP", "Authenticated SMTP", "MAPI Over HTTP", "Offline Address Book"'

$summaryKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ClientAppUsed in ($legacyClientApps)
| extend Status = iff(tostring(ResultType) == "0", "Success", "Failure")
| summarize Attempts = count(), Successes = countif(Status == "Success"), LastSeen = max(TimeGenerated)
        by UserPrincipalName, ClientAppUsed
| order by Attempts desc
"@

$detailKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ClientAppUsed in ($legacyClientApps)
| extend Status = iff(tostring(ResultType) == "0", "Success", "Failure")
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress, City, Country, Status, ConditionalAccessStatus
| order by TimeGenerated desc
| take 500
"@

$summaryRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $summaryKql -Timespan (New-TimeSpan -Days $Days)
$detailRows  = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $detailKql  -Timespan (New-TimeSpan -Days $Days)

$totalAttempts   = ($summaryRows | Measure-Object -Property Attempts -Sum).Sum
$totalSuccesses  = ($summaryRows | Measure-Object -Property Successes -Sum).Sum
$distinctUsers   = @($summaryRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

$statTiles = @(
    @{ Label = "Legacy auth attempts ($Days d)"; Value = [int]($totalAttempts | ForEach-Object { $_ }); Tone = if ($totalAttempts -gt 0) { "warn" } else { "good" } }
    @{ Label = "Successful (not blocked)"; Value = [int]($totalSuccesses | ForEach-Object { $_ }); Tone = if ($totalSuccesses -gt 0) { "danger" } else { "good" } }
    @{ Label = "Distinct users"; Value = $distinctUsers; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Output\LegacyAuth-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Legacy Authentication Usage" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "By user and protocol" = $summaryRows
        "Recent events (up to 500)" = $detailRows
    }) `
    -FooterNote "Source: SigninLogs (Log Analytics). A 'Success' here means legacy auth was NOT blocked — check CA policy scope for that user/app." `
    -OutputPath $outputPath `
    -Open:$Open
