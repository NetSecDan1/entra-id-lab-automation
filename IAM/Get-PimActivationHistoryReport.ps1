<#
.SYNOPSIS
    PIM activation/request history: who activated what role, when, with
    what justification, and whether it needed approval — actual usage of
    the PIM configuration Deploy-PIM.ps1 sets up, not just its settings.

.DESCRIPTION
    Reads roleAssignmentScheduleRequests, which captures every PIM action
    (self-activation, admin assignment, extension, renewal) with its
    justification and approval status. Useful for confirming eligible
    admins are actually using PIM activation rather than staying
    permanently elevated, and for spotting activation requests that were
    denied or are still pending approval.

    Requires Entra ID P2.

.PARAMETER Days
    Lookback window in days. Default 30.

.EXAMPLE
    .\IAM\Get-PimActivationHistoryReport.ps1 -Days 14 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$Days = 30,
    [switch]$Open
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Status "Fetching role definitions" -Type Header
$roleDefs = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue)
$roleDefMap = @{}
foreach ($rd in $roleDefs) { $roleDefMap[$rd.Id] = $rd.DisplayName }

Write-Status "Fetching PIM activation/request history" -Type Header
$cutoff = (Get-Date).AddDays(-$Days)
$requests = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -All -ErrorAction SilentlyContinue |
    Where-Object { $_.CreatedDateTime -and [datetime]$_.CreatedDateTime -ge $cutoff })

$principalCache = @{}
function Resolve-PrincipalUpn {
    param([string]$Id)
    if ($principalCache.ContainsKey($Id)) { return $principalCache[$Id] }
    $user = Get-MgUser -UserId $Id -Property "userPrincipalName" -ErrorAction SilentlyContinue
    $resolved = if ($user) { $user.UserPrincipalName } else {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $Id -Property "displayName" -ErrorAction SilentlyContinue
        if ($sp) { "$($sp.DisplayName) (service principal)" } else { "(unresolved: $Id)" }
    }
    $principalCache[$Id] = $resolved
    return $resolved
}

$rows = $requests | ForEach-Object {
    [pscustomobject]@{
        CreatedDateTime = $_.CreatedDateTime
        Requestor       = Resolve-PrincipalUpn -Id $_.PrincipalId
        Role            = $roleDefMap[$_.RoleDefinitionId]
        Action          = $_.Action
        Status          = $_.Status
        Justification   = $_.Justification
        StartDateTime   = $_.ScheduleInfo.StartDateTime
        EndDateTime     = $_.ScheduleInfo.Expiration.EndDateTime
    }
} | Sort-Object CreatedDateTime -Descending

$activations = @($rows | Where-Object { $_.Action -in @("selfActivate", "adminAssign") })
$pending     = @($rows | Where-Object { $_.Status -eq "PendingApproval" })
$denied      = @($rows | Where-Object { $_.Status -eq "Denied" })
$distinctRequestors = @($rows | Select-Object -ExpandProperty Requestor -Unique).Count

$byRole = $activations | Group-Object Role | Select-Object @{N="Role"; E={$_.Name}}, @{N="Activations"; E={$_.Count}} | Sort-Object Activations -Descending

$statTiles = @(
    @{ Label = "Activations ($Days d)"; Value = $activations.Count; Tone = "neutral" }
    @{ Label = "Distinct requestors"; Value = $distinctRequestors; Tone = "neutral" }
    @{ Label = "Pending approval"; Value = $pending.Count; Tone = if ($pending.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Denied"; Value = $denied.Count; Tone = if ($denied.Count -gt 0) { "warn" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\PimActivationHistory-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "PIM Activation History" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "By role"        = $byRole
        "All requests"   = $rows
    }) `
    -FooterNote "Source: Microsoft Graph roleManagement/directory/roleAssignmentScheduleRequests. Requires Entra ID P2." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
