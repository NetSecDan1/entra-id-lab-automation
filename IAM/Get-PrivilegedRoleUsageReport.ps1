<#
.SYNOPSIS
    Standing (permanent) privileged role assignments vs. PIM-eligible ones,
    dormant privileged accounts, and guests/service principals holding
    privileged roles — the access-review questions that matter most.

.DESCRIPTION
    "Who has a privileged role" (Get-RiskyUsersReport.ps1's cross-reference)
    is a different question from "how is that privileged access actually
    granted and used." This report answers the second one:

      - Standing access: active role assignments with no PIM eligibility
        behind them (AssignmentType "Assigned", not "Activated") — the
        highest-risk shape, since there's no time-bound activation step.
      - PIM eligible but not currently active: healthy shape, informational.
      - Dormant privileged accounts: standing/active privileged assignment
        held by a user who hasn't signed in in -DormantDays.
      - Guests or service principals holding a privileged role at all —
        usually worth a second look regardless of assignment type.
      - Over-assigned roles: any role with more members than -MaxHealthyMembers
        (Microsoft's own guidance: keep Global Administrator to 2-4 people).

.PARAMETER DormantDays
    Flag a privileged account as dormant if no sign-in in this many days.
    Default 60.

.PARAMETER MaxHealthyMembers
    Roles with more members than this are flagged as over-assigned.
    Default 5.

.EXAMPLE
    .\IAM\Get-PrivilegedRoleUsageReport.ps1 -DormantDays 45 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$DormantDays = 60,
    [int]$MaxHealthyMembers = 5,
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

Write-Status "Fetching active role assignments (standing + PIM-activated)" -Type Header
$activeInstances = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue)

Write-Status "Fetching PIM-eligible assignments" -Type Header
$eligibleInstances = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue)
$eligiblePrincipalRolePairs = [System.Collections.Generic.HashSet[string]]::new()
foreach ($e in $eligibleInstances) { [void]$eligiblePrincipalRolePairs.Add("$($e.PrincipalId)|$($e.RoleDefinitionId)") }

Write-Status "Resolving principals (this can take a moment)" -Type Header
$principalCache = @{}
function Resolve-Principal {
    param([string]$Id)
    if ($principalCache.ContainsKey($Id)) { return $principalCache[$Id] }

    $user = Get-MgUser -UserId $Id -Property "id,displayName,userPrincipalName,userType,signInActivity" -ErrorAction SilentlyContinue
    if ($user) {
        $result = [pscustomobject]@{ Kind = "User"; DisplayName = $user.DisplayName; Identifier = $user.UserPrincipalName; UserType = $user.UserType; LastSignIn = $user.SignInActivity.LastSignInDateTime }
        $principalCache[$Id] = $result
        return $result
    }

    $sp = Get-MgServicePrincipal -ServicePrincipalId $Id -Property "id,displayName,appId" -ErrorAction SilentlyContinue
    if ($sp) {
        $result = [pscustomobject]@{ Kind = "Service Principal"; DisplayName = $sp.DisplayName; Identifier = $sp.AppId; UserType = $null; LastSignIn = $null }
        $principalCache[$Id] = $result
        return $result
    }

    $result = [pscustomobject]@{ Kind = "Unknown"; DisplayName = "(unresolved: $Id)"; Identifier = $Id; UserType = $null; LastSignIn = $null }
    $principalCache[$Id] = $result
    return $result
}

$dormantCutoff = (Get-Date).AddDays(-$DormantDays)
$assignmentRows = @()
foreach ($instance in $activeInstances) {
    $principal = Resolve-Principal -Id $instance.PrincipalId
    $isViaPim  = $eligiblePrincipalRolePairs.Contains("$($instance.PrincipalId)|$($instance.RoleDefinitionId)")
    $isStanding = (-not $isViaPim) -and (-not $instance.EndDateTime)

    $lastSignIn = $principal.LastSignIn
    $isDormant = $principal.Kind -eq "User" -and ($null -eq $lastSignIn -or [datetime]$lastSignIn -lt $dormantCutoff)

    $assignmentRows += [pscustomobject]@{
        Role              = $roleDefMap[$instance.RoleDefinitionId]
        PrincipalKind     = $principal.Kind
        DisplayName       = $principal.DisplayName
        Identifier        = $principal.Identifier
        UserType          = $principal.UserType
        AssignmentShape   = if ($isViaPim) { "PIM-activated" } else { "Standing (permanent)" }
        LastSignIn        = if ($lastSignIn) { $lastSignIn } else { "Never" }
        Dormant           = $isDormant
    }
}

$standingAssignments = @($assignmentRows | Where-Object { $_.AssignmentShape -eq "Standing (permanent)" })
$dormantPrivileged   = @($assignmentRows | Where-Object { $_.Dormant })
$guestsPrivileged    = @($assignmentRows | Where-Object { $_.UserType -eq "Guest" })
$spsPrivileged       = @($assignmentRows | Where-Object { $_.PrincipalKind -eq "Service Principal" })

$roleMemberCounts = $assignmentRows | Group-Object Role | Select-Object @{N="Role"; E={$_.Name}}, @{N="MemberCount"; E={$_.Count}}
$overAssignedRoles = @($roleMemberCounts | Where-Object { $_.MemberCount -gt $MaxHealthyMembers } | Sort-Object MemberCount -Descending)

$statTiles = @(
    @{ Label = "Standing (permanent) assignments"; Value = $standingAssignments.Count; Tone = if ($standingAssignments.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "PIM-eligible role instances"; Value = $eligibleInstances.Count; Tone = "good" }
    @{ Label = "Dormant privileged accounts (>$DormantDays d)"; Value = $dormantPrivileged.Count; Tone = if ($dormantPrivileged.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Guests / SPs with privileged roles"; Value = ($guestsPrivileged.Count + $spsPrivileged.Count); Tone = if (($guestsPrivileged.Count + $spsPrivileged.Count) -gt 0) { "warn" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\PrivilegedRoleUsage-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Privileged Role Usage & Standing Access" `
    -Subtitle "$($config.TenantDomain) — dormant threshold $DormantDays day(s), over-assignment threshold >$MaxHealthyMembers members" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Dormant privileged accounts"          = $dormantPrivileged
        "Standing (permanent) assignments"     = $standingAssignments
        "Guests or service principals with a privileged role" = @($guestsPrivileged) + @($spsPrivileged)
        "Over-assigned roles"                  = $overAssignedRoles
        "All active privileged assignments"    = $assignmentRows
    }) `
    -FooterNote "Source: Microsoft Graph roleManagement/directory (assignment + eligibility schedule instances). Requires Entra ID P2 for PIM data — without it, everything shows as 'Standing (permanent)'." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
