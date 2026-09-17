<#
.SYNOPSIS
    Flags successful sign-ins where the same user's country changed between
    two consecutive sign-ins faster than travel could explain.

.DESCRIPTION
    Sorts each user's successful sign-ins chronologically and uses KQL's
    prev() window function to compare each sign-in's country against that
    same user's previous one. A country change inside a short window
    (default under 4 hours) is the classic "impossible travel" signal —
    good evidence of a shared/leaked credential or a session token replay.

    Simpler than a true geo-distance model (no lat/long velocity math), but
    catches the same core pattern with a single KQL query and no external
    lookups.

.PARAMETER MaxHours
    Country changes faster than this many hours are flagged. Default 4.

.EXAMPLE
    .\Reports\KQL\Get-ImpossibleTravelReport.ps1 -WorkspaceId <guid> -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 7,
    [double]$MaxHours = 4,
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

$kql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PrevUser = prev(UserPrincipalName), PrevCountry = prev(Country), PrevTime = prev(TimeGenerated), PrevIP = prev(IPAddress)
| where UserPrincipalName == PrevUser and Country != PrevCountry
| extend HoursBetween = round(datetime_diff('minute', TimeGenerated, PrevTime) / 60.0, 2)
| where HoursBetween >= 0 and HoursBetween < $MaxHours
| project TimeGenerated, UserPrincipalName, FromCountry = PrevCountry, ToCountry = Country, HoursBetween, FromIP = PrevIP, ToIP = IPAddress, AppDisplayName
| order by HoursBetween asc
"@

$rows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan (New-TimeSpan -Days $Days)
$distinctUsers = @($rows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

$statTiles = @(
    @{ Label = "Suspicious transitions"; Value = @($rows).Count; Tone = if (@($rows).Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Distinct users affected"; Value = $distinctUsers; Tone = if ($distinctUsers -gt 0) { "warn" } else { "good" } }
    @{ Label = "Threshold"; Value = "< $MaxHours h between countries"; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Output\ImpossibleTravel-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Impossible Travel" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{ "Suspicious country transitions" = $rows }) `
    -FooterNote "Source: SigninLogs (Log Analytics). Country-only comparison via consecutive sign-ins per user — no distance/velocity model, so verify before acting (VPN egress changes trigger the same signal)." `
    -OutputPath $outputPath `
    -Open:$Open
