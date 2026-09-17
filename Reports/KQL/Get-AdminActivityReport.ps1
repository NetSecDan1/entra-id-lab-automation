<#
.SYNOPSIS
    Who changed what: directory role assignments, Conditional Access policy
    edits, application/group management — the operations an access review
    or incident response timeline actually cares about.

.DESCRIPTION
    Reads AuditLogs (not SigninLogs) for the sensitive categories
    RoleManagement, Policy, ApplicationManagement, and GroupManagement,
    resolving the actor (user or app) and target object per event, plus a
    by-actor/by-operation summary to spot one account making an unusual
    volume of privileged changes.

.EXAMPLE
    .\Reports\KQL\Get-AdminActivityReport.ps1 -WorkspaceId <guid> -Days 14 -Open
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

$sensitiveCategories = '"RoleManagement", "Policy", "ApplicationManagement", "GroupManagement"'

$detailKql = @"
AuditLogs
| where TimeGenerated > ago($($Days)d)
| where Category in ($sensitiveCategories)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName), InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, Category, OperationName, Result, Target
| order by TimeGenerated desc
| take 500
"@

$summaryKql = @"
AuditLogs
| where TimeGenerated > ago($($Days)d)
| where Category in ($sensitiveCategories)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName), InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| summarize Changes = count(), Operations = make_set(OperationName, 5) by Actor, Category
| order by Changes desc
"@

$detailRows  = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $detailKql  -Timespan (New-TimeSpan -Days $Days)
$summaryRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $summaryKql -Timespan (New-TimeSpan -Days $Days)

$roleChanges   = @($detailRows | Where-Object { $_.Category -eq "RoleManagement" }).Count
$policyChanges = @($detailRows | Where-Object { $_.Category -eq "Policy" }).Count
$distinctActors = @($detailRows | Select-Object -ExpandProperty Actor -Unique).Count

$statTiles = @(
    @{ Label = "Privileged changes ($Days d)"; Value = @($detailRows).Count; Tone = "neutral" }
    @{ Label = "Role assignment changes"; Value = $roleChanges; Tone = if ($roleChanges -gt 0) { "warn" } else { "good" } }
    @{ Label = "Conditional Access policy changes"; Value = $policyChanges; Tone = if ($policyChanges -gt 0) { "warn" } else { "good" } }
    @{ Label = "Distinct actors"; Value = $distinctActors; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Output\AdminActivity-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Privileged Admin Activity" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s), RoleManagement / Policy / ApplicationManagement / GroupManagement" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "By actor" = $summaryRows
        "Recent events (up to 500)" = $detailRows
    }) `
    -FooterNote "Source: AuditLogs (Log Analytics). Actor resolved from InitiatedBy.user or InitiatedBy.app." `
    -OutputPath $outputPath `
    -Open:$Open
