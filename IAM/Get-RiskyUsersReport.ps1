<#
.SYNOPSIS
    Identity Protection risky users and risk detections, cross-referenced
    against privileged role membership — pure Microsoft Graph, no Log
    Analytics workspace required.

.DESCRIPTION
    Complements Reports/KQL/Get-RiskySignInsReport.ps1: that script looks at
    per-sign-in risk from raw sign-in log events, while this one reads
    Identity Protection's own aggregated user-risk state directly from
    Graph (identityProtection/riskyUsers + riskDetections). Useful when you
    don't have a Log Analytics workspace wired up, or want Identity
    Protection's own verdict rather than raw sign-in telemetry.

    Requires Entra ID P2 for meaningful risk data.

.EXAMPLE
    .\IAM\Get-RiskyUsersReport.ps1 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$Open
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Status "Fetching risky users (Identity Protection)" -Type Header
$riskyUsers = @(Get-MgRiskyUser -All -ErrorAction SilentlyContinue)

Write-Status "Fetching risk detections" -Type Header
$riskDetections = @(Get-MgRiskDetection -All -ErrorAction SilentlyContinue)

Write-Status "Cross-referencing against privileged role membership" -Type Header
$privilegedRoleNames = @(
    "Global Administrator", "Privileged Role Administrator", "Security Administrator",
    "Conditional Access Administrator", "User Administrator", "Application Administrator",
    "Cloud Application Administrator", "Authentication Administrator", "Helpdesk Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Billing Administrator"
)
$privilegedUpns = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($roleName in $privilegedRoleNames) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if (-not $role) { continue }
    foreach ($member in (Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue)) {
        $user = Get-MgUser -UserId $member.Id -Property "userPrincipalName" -ErrorAction SilentlyContinue
        if ($user) { [void]$privilegedUpns.Add($user.UserPrincipalName) }
    }
}

$riskyUserRows = $riskyUsers | Select-Object `
    @{N="UserPrincipalName"; E={$_.UserPrincipalName}}, `
    @{N="RiskLevel"; E={$_.RiskLevel}}, `
    @{N="RiskState"; E={$_.RiskState}}, `
    @{N="RiskDetail"; E={$_.RiskDetail}}, `
    @{N="RiskLastUpdated"; E={$_.RiskLastUpdatedDateTime}}, `
    @{N="IsPrivileged"; E={$privilegedUpns.Contains($_.UserPrincipalName)}}

$detectionRows = $riskDetections | Select-Object `
    @{N="DetectedDateTime"; E={$_.DetectedDateTime}}, `
    @{N="UserPrincipalName"; E={$_.UserPrincipalName}}, `
    @{N="RiskType"; E={$_.RiskEventType}}, `
    @{N="RiskLevel"; E={$_.RiskLevel}}, `
    @{N="RiskState"; E={$_.RiskState}}, `
    @{N="Activity"; E={$_.Activity}}, `
    @{N="IPAddress"; E={$_.IpAddress}} |
    Sort-Object DetectedDateTime -Descending

$privilegedAtRisk = @($riskyUserRows | Where-Object { $_.IsPrivileged -and $_.RiskState -notin @("dismissed", "remediated") })
$activeRisky      = @($riskyUserRows | Where-Object { $_.RiskState -notin @("dismissed", "remediated") })
$highRisk         = @($activeRisky | Where-Object { $_.RiskLevel -eq "high" })

$statTiles = @(
    @{ Label = "Active risky users"; Value = $activeRisky.Count; Tone = if ($activeRisky.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "High risk"; Value = $highRisk.Count; Tone = if ($highRisk.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Privileged users at risk"; Value = $privilegedAtRisk.Count; Tone = if ($privilegedAtRisk.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Risk detections (all time)"; Value = $detectionRows.Count; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\RiskyUsers-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Risky Users & Privileged Role Exposure" `
    -Subtitle "$($config.TenantDomain) — Identity Protection, current state" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Privileged users currently at risk" = $privilegedAtRisk
        "All risky users"                    = $riskyUserRows
        "Risk detections"                    = $detectionRows
    }) `
    -FooterNote "Source: Microsoft Graph identityProtection/riskyUsers + riskDetections. Requires Entra ID P2." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
