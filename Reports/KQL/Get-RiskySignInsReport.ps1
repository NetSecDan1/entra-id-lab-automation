<#
.SYNOPSIS
    Risky sign-ins (Log Analytics KQL) cross-referenced against privileged
    role membership (Microsoft Graph), rendered as one HTML report.

.DESCRIPTION
    Queries SigninLogs in a Log Analytics workspace for medium/high risk
    sign-ins over the lookback window, then pulls current privileged role
    membership via Graph so you can immediately see which risky sign-ins
    belong to an admin — the highest-value correlation for triage.

    Requires the workspace populated by IaC/terraform (see its README) or
    any Log Analytics workspace already receiving Entra ID Sign-in logs.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID. Falls back to
    config.Reporting.LogAnalyticsWorkspaceId if not supplied.

.PARAMETER Days
    Lookback window in days. Default 7.

.EXAMPLE
    .\Reports\KQL\Get-RiskySignInsReport.ps1 -WorkspaceId <guid> -Days 14 -Open
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

$kql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where RiskLevelDuringSignIn in ("medium", "high") or RiskLevelAggregated in ("medium", "high")
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, City, Country,
          RiskLevelDuringSignIn, RiskLevelAggregated, RiskState, RiskDetail,
          ResultType, ResultDescription, ConditionalAccessStatus
| order by TimeGenerated desc
"@

$riskySignIns = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan (New-TimeSpan -Days $Days)

Write-Status "Cross-referencing against privileged role membership (Graph)" -Type Header
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

$privilegedRoleNames = @(
    "Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "Conditional Access Administrator", "User Administrator", "Application Administrator",
    "Cloud Application Administrator", "Authentication Administrator", "Helpdesk Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Billing Administrator"
)

$privilegedUpns = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$roleAssignments = @()
foreach ($roleName in $privilegedRoleNames) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if (-not $role) { continue }
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
    foreach ($member in $members) {
        $user = Get-MgUser -UserId $member.Id -Property "userPrincipalName,displayName" -ErrorAction SilentlyContinue
        if ($user) {
            [void]$privilegedUpns.Add($user.UserPrincipalName)
            $roleAssignments += [pscustomobject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Role              = $roleName
            }
        }
    }
}

$riskySignInsAnnotated = $riskySignIns | ForEach-Object {
    $_ | Select-Object *, @{ Name = "IsPrivileged"; Expression = { $privilegedUpns.Contains($_.UserPrincipalName) } }
}
$privilegedRisky = @($riskySignInsAnnotated | Where-Object { $_.IsPrivileged })

$highRiskCount   = @($riskySignIns | Where-Object { $_.RiskLevelDuringSignIn -eq "high" -or $_.RiskLevelAggregated -eq "high" }).Count
$distinctUsers   = @($riskySignIns | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

$statTiles = @(
    @{ Label = "Risky sign-ins ($Days d)"; Value = @($riskySignIns).Count; Tone = if (@($riskySignIns).Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "High risk"; Value = $highRiskCount; Tone = if ($highRiskCount -gt 0) { "danger" } else { "good" } }
    @{ Label = "Distinct users affected"; Value = $distinctUsers; Tone = "neutral" }
    @{ Label = "Privileged users at risk"; Value = $privilegedRisky.Count; Tone = if ($privilegedRisky.Count -gt 0) { "danger" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Output\RiskySignIns-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Risky Sign-Ins & Privileged Role Exposure" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Privileged users with a risky sign-in" = $privilegedRisky
        "All risky sign-ins"                    = $riskySignInsAnnotated
        "Current privileged role membership"    = $roleAssignments
    }) `
    -FooterNote "Source: SigninLogs (Log Analytics) + Microsoft Graph directory role membership." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
