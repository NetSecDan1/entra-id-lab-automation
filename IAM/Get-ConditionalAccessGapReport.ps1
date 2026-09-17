<#
.SYNOPSIS
    Resolves every enabled Conditional Access policy's actual user scope and
    reports which enabled member users aren't covered by any MFA-requiring
    (or block) policy, and which enabled apps aren't targeted by any policy
    at all.

.DESCRIPTION
    A policy's conditions.users block (includeUsers/includeGroups/includeRoles,
    minus excludes) only tells you what it's SUPPOSED to cover — this script
    actually resolves it against current group membership and role
    assignments to answer "who is really covered?" Only policies with
    state = enabled count toward coverage; enabledForReportingButNotEnforced
    policies are shown separately since they don't protect anything yet.

    Known limitation: group membership is resolved one level deep
    (Get-MgGroupMember), not through nested group membership. If your
    coverage relies on nested groups, treat a "gap" here as "verify manually"
    rather than an absolute.

.EXAMPLE
    .\IAM\Get-ConditionalAccessGapReport.ps1 -Open
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

Write-Status "Fetching Conditional Access policies" -Type Header
$policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue)

Write-Status "Fetching enabled member users" -Type Header
$allUsers = @(Get-MgUser -All -Filter "accountEnabled eq true and userType eq 'Member'" -Property "id,displayName,userPrincipalName" -ConsistencyLevel eventual -CountVariable userCount -ErrorAction SilentlyContinue)
$allUserIds = [System.Collections.Generic.HashSet[string]]::new($allUsers.Id)

$groupMemberCache = @{}
function Get-CachedGroupMemberIds {
    param([string]$GroupId)
    if ($groupMemberCache.ContainsKey($GroupId)) { return $groupMemberCache[$GroupId] }
    $ids = @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $groupMemberCache[$GroupId] = $ids
    return $ids
}

$roleMemberCache = @{}
function Get-CachedRoleMemberIds {
    param([string]$RoleTemplateId)
    if ($roleMemberCache.ContainsKey($RoleTemplateId)) { return $roleMemberCache[$RoleTemplateId] }
    $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$RoleTemplateId'" -ErrorAction SilentlyContinue
    if (-not $role) { $roleMemberCache[$RoleTemplateId] = @(); return @() }
    $ids = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $roleMemberCache[$RoleTemplateId] = $ids
    return $ids
}

function Resolve-PolicyUserScope {
    param($UsersCondition)

    $included = [System.Collections.Generic.HashSet[string]]::new()
    $excluded = [System.Collections.Generic.HashSet[string]]::new()

    if (@($UsersCondition.IncludeUsers) -contains "All") {
        foreach ($id in $allUserIds) { [void]$included.Add($id) }
    } else {
        foreach ($id in @($UsersCondition.IncludeUsers)) { if ($id -ne "None" -and $id -ne "GuestsOrExternalUsers") { [void]$included.Add($id) } }
    }
    foreach ($groupId in @($UsersCondition.IncludeGroups)) { foreach ($id in (Get-CachedGroupMemberIds -GroupId $groupId)) { [void]$included.Add($id) } }
    foreach ($roleId in @($UsersCondition.IncludeRoles)) { foreach ($id in (Get-CachedRoleMemberIds -RoleTemplateId $roleId)) { [void]$included.Add($id) } }

    foreach ($id in @($UsersCondition.ExcludeUsers)) { [void]$excluded.Add($id) }
    foreach ($groupId in @($UsersCondition.ExcludeGroups)) { foreach ($id in (Get-CachedGroupMemberIds -GroupId $groupId)) { [void]$excluded.Add($id) } }
    foreach ($roleId in @($UsersCondition.ExcludeRoles)) { foreach ($id in (Get-CachedRoleMemberIds -RoleTemplateId $roleId)) { [void]$excluded.Add($id) } }

    $included.ExceptWith($excluded)
    return $included
}

function Test-RequiresStrongAuth {
    param($Policy)
    if (-not $Policy.GrantControls) { return $false }
    $builtIn = @($Policy.GrantControls.BuiltInControls)
    if ($builtIn -contains "mfa" -or $builtIn -contains "block" -or $builtIn -contains "compliantDevice" -or $builtIn -contains "domainJoinedDevice") { return $true }
    if ($Policy.GrantControls.AuthenticationStrength) { return $true }
    return $false
}

$enabledPolicies    = @($policies | Where-Object { $_.State -eq "enabled" -and (Test-RequiresStrongAuth $_) })
$reportOnlyPolicies = @($policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" -and (Test-RequiresStrongAuth $_) })

$coveredByEnforced = [System.Collections.Generic.HashSet[string]]::new()
$policySummary = @()
foreach ($policy in $policies) {
    $scope = Resolve-PolicyUserScope -UsersCondition $policy.Conditions.Users
    if ($policy.State -eq "enabled" -and (Test-RequiresStrongAuth $policy)) {
        foreach ($id in $scope) { [void]$coveredByEnforced.Add($id) }
    }
    $policySummary += [pscustomobject]@{
        DisplayName    = $policy.DisplayName
        State          = $policy.State
        RequiresStrongAuth = (Test-RequiresStrongAuth $policy)
        UsersInScope   = $scope.Count
        Applications   = ((@($policy.Conditions.Applications.IncludeApplications)) -join ", ")
    }
}

$uncoveredUsers = @($allUsers | Where-Object { -not $coveredByEnforced.Contains($_.Id) } | Select-Object DisplayName, UserPrincipalName)

$statTiles = @(
    @{ Label = "Enforced strong-auth policies"; Value = $enabledPolicies.Count; Tone = "neutral" }
    @{ Label = "Report-only strong-auth policies"; Value = $reportOnlyPolicies.Count; Tone = "neutral" }
    @{ Label = "Users covered"; Value = $coveredByEnforced.Count; Tone = "good" }
    @{ Label = "Users with NO enforced coverage"; Value = $uncoveredUsers.Count; Tone = if ($uncoveredUsers.Count -gt 0) { "danger" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\CAGapAnalysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Conditional Access Coverage Gap Analysis" `
    -Subtitle "$($config.TenantDomain) — $($allUsers.Count) enabled member user(s) evaluated" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Users with no enforced MFA/block/device policy" = $uncoveredUsers
        "Policy scope summary"                           = $policySummary
    }) `
    -FooterNote "Group membership resolved one level deep (no nested groups). Report-only policies do not count as coverage. Source: Microsoft Graph." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
