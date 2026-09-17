<#
.SYNOPSIS
    Password spray (one IP, many users) and targeted brute-force (many IPs,
    one user) detection from failed sign-ins.

.DESCRIPTION
    Filters SigninLogs to ResultType 50126 (invalid username or password) —
    the clearest credential-guessing signal — then looks for the two shapes
    that distinguish spray from brute force: a single source IP failing
    against an unusually wide spread of distinct users (spray, low-and-slow
    to dodge per-account lockout), versus a single user account taking a
    high volume of failures from multiple IPs (targeted brute force).

.PARAMETER MinDistinctUsersPerIp
    Minimum distinct users failed against from one IP to flag it as a
    suspected spray source. Default 5.

.PARAMETER MinFailuresPerUser
    Minimum failed attempts against one user to flag them as targeted.
    Default 10.

.EXAMPLE
    .\Reports\KQL\Get-PasswordSprayReport.ps1 -WorkspaceId <guid> -Days 3 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 3,
    [int]$MinDistinctUsersPerIp = 5,
    [int]$MinFailuresPerUser = 10,
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

$byIpKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ResultType == "50126"
| summarize FailedAttempts = count(), DistinctUsers = dcount(UserPrincipalName), LastSeen = max(TimeGenerated) by IPAddress
| where DistinctUsers >= $MinDistinctUsersPerIp
| order by DistinctUsers desc
"@

$byUserKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ResultType == "50126"
| summarize FailedAttempts = count(), DistinctIPs = dcount(IPAddress), LastSeen = max(TimeGenerated) by UserPrincipalName
| where FailedAttempts >= $MinFailuresPerUser
| order by FailedAttempts desc
"@

$sprayIps      = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $byIpKql   -Timespan (New-TimeSpan -Days $Days)
$targetedUsers = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $byUserKql -Timespan (New-TimeSpan -Days $Days)

$statTiles = @(
    @{ Label = "Suspected spray source IPs"; Value = @($sprayIps).Count; Tone = if (@($sprayIps).Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Suspected targeted users"; Value = @($targetedUsers).Count; Tone = if (@($targetedUsers).Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Lookback window"; Value = "$Days day(s)"; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Output\PasswordSpray-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Password Spray & Brute Force Detection" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s), invalid-credential failures only" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Spray sources (1 IP -> many users)"     = $sprayIps
        "Targeted accounts (many IPs -> 1 user)" = $targetedUsers
    }) `
    -FooterNote "Source: SigninLogs (Log Analytics), ResultType 50126 (invalid username or password). Thresholds: >=$MinDistinctUsersPerIp users/IP, >=$MinFailuresPerUser failures/user." `
    -OutputPath $outputPath `
    -Open:$Open
