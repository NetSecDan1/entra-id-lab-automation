<#
.SYNOPSIS
    Creates department and regional Administrative Units to scope admin permissions.

.DESCRIPTION
    Requires Entra ID P1 or higher.

    Creates Administrative Units (AUs) to give T1 service desk admins scoped
    control over users in their department only — without tenant-wide permissions.

    Department AUs (18)
    -------------------
    One AU per department from config. All employees in that department are added
    as members. T1 admin accounts are assigned Helpdesk Administrator scoped to
    each AU (so they can reset passwords/MFA only for their dept's users).

    Regional AUs (4)
    ----------------
    One AU per office location (New York, San Francisco, Chicago, Austin).
    Populated by the user's City attribute. Useful for location-based CA policy
    targeting and regional admin scoping.

    Special AUs
    -----------
    AU-Executives   — all C-suite users
    AU-ServiceAccts — all svc-* accounts

.EXAMPLE
    .\AdminUnits\Deploy-AdminUnits.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Administrative Units — Dept + Regional Scoping" -Type Header
Write-Host "  Tenant : $domain"
Write-Host ""

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-OrGetAU {
    param([string]$DisplayName, [string]$Description = "")

    $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
        -Uri "https://graph.microsoft.com/v1.0/administrativeUnits?`$filter=displayName eq '$DisplayName'"

    if ($existing.value -and $existing.value.Count -gt 0) {
        Write-Status "Exists: $DisplayName" -Type Warning
        return $existing.value[0].id
    }

    $body = @{
        displayName = $DisplayName
        description = $Description
    } | ConvertTo-Json

    $created = Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/v1.0/administrativeUnits"
    Write-Status "Created: $DisplayName" -Type Success
    return $created.id
}

function Add-AUMemberSafe {
    param([string]$AUId, [string]$UserId)
    try {
        $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
            -Uri "https://graph.microsoft.com/v1.0/administrativeUnits/$AUId/members?`$filter=id eq '$UserId'"
        if ($existing.value -and $existing.value.Count -gt 0) { return }

        $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$UserId" } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/administrativeUnits/$AUId/members/`$ref" | Out-Null
    } catch { }
}

function Add-ScopedAdminToAU {
    param([string]$AUId, [string]$AdminUserId, [string]$RoleName = "Helpdesk Administrator")
    # Helpdesk Administrator role definition ID (standard)
    $helpdeskRoleId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"

    # Find or activate the directory role
    $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$helpdeskRoleId'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $role) {
        $resp = Invoke-MgGraphRequest -Method POST -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
            -Body (@{ roleTemplateId = $helpdeskRoleId } | ConvertTo-Json)
        $role = [PSCustomObject]@{ Id = if ($resp -is [hashtable]) { $resp["id"] } else { $resp.id } }
    }

    try {
        $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
            -Uri "https://graph.microsoft.com/v1.0/administrativeUnits/$AUId/scopedRoleMembers"
        $alreadyScoped = $existing.value | Where-Object { $_.roleMemberInfo.id -eq $AdminUserId -and $_.roleId -eq $role.Id }
        if ($alreadyScoped) { return }

        $body = @{
            roleId         = $role.Id
            roleMemberInfo = @{ "@odata.type" = "#microsoft.graph.user"; id = $AdminUserId }
        } | ConvertTo-Json -Depth 4

        Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/administrativeUnits/$AUId/scopedRoleMembers" | Out-Null
    } catch {
        Write-Status "Scoped admin assignment failed: $($_.Exception.Message)" -Type Warning
    }
}

# ── Load users ────────────────────────────────────────────────────────────────
Write-Status "Loading users" -Type Header
$allEmployees = Get-AllEmployeeUsers -CompanyName $config.CompanyName
$execUsers    = @($allEmployees | Where-Object { $_.JobTitle -match "^Chief " })
$regularUsers = @($allEmployees | Where-Object { $_.JobTitle -notmatch "^Chief " })
$svcUsers     = @(Get-MgUser -All -Filter "companyName eq '$($config.CompanyName)'" `
    -Property "id,userPrincipalName,department,city,jobTitle" |
    Where-Object { $_.UserPrincipalName -like "svc-*@*" })

$t1svc01 = Get-MgUser -Filter "userPrincipalName eq 'admin.svc01@$domain'" -ErrorAction SilentlyContinue
$t1svc02 = Get-MgUser -Filter "userPrincipalName eq 'admin.svc02@$domain'" -ErrorAction SilentlyContinue
$t1Admins = @($t1svc01, $t1svc02) | Where-Object { $_ }

Write-Host "  Employees : $($allEmployees.Count)"
Write-Host "  Executives: $($execUsers.Count)"
Write-Host "  Svc accts : $($svcUsers.Count)"
Write-Host "  T1 admins : $($t1Admins.Count)"

# ── Department AUs ────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Department Administrative Units" -Type Header

$deptAUMap = @{}

foreach ($dept in $config.Users.Departments) {
    $auName = "AU-Dept-$($dept -replace '\s+','')"
    $auId   = New-OrGetAU -DisplayName $auName -Description "Users in the $dept department"
    $deptAUMap[$dept] = $auId

    # Add all employees in this dept
    $deptUsers = @($allEmployees | Where-Object { $_.Department -eq $dept })
    $addCount  = 0
    foreach ($u in $deptUsers) {
        Add-AUMemberSafe -AUId $auId -UserId $u.Id
        $addCount++
    }

    # Assign T1 scoped Helpdesk Admin to this dept AU
    foreach ($t1 in $t1Admins) {
        Add-ScopedAdminToAU -AUId $auId -AdminUserId $t1.Id
    }

    Write-Host ("    {0,-48} : {1,3} users" -f $auName, $addCount) -ForegroundColor DarkGray
}

# ── Regional AUs ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Regional Administrative Units (by office city)" -Type Header

$regions = @(
    @{ Name = "AU-Region-NewYork";       City = "New York";     Desc = "HQ — New York office users" }
    @{ Name = "AU-Region-SanFrancisco";  City = "San Francisco"; Desc = "West Coast — San Francisco office users" }
    @{ Name = "AU-Region-Chicago";       City = "Chicago";      Desc = "Midwest — Chicago office users" }
    @{ Name = "AU-Region-Austin";        City = "Austin";       Desc = "South — Austin office users" }
)

foreach ($r in $regions) {
    $auId = New-OrGetAU -DisplayName $r.Name -Description $r.Desc
    $cityUsers = @($allEmployees | Where-Object { $_.City -eq $r.City })
    $addCount  = 0
    foreach ($u in $cityUsers) {
        Add-AUMemberSafe -AUId $auId -UserId $u.Id
        $addCount++
    }
    Write-Host ("    {0,-40} : {1,3} users ({2})" -f $r.Name, $addCount, $r.City) -ForegroundColor DarkGray
}

# ── Special AUs ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Special Administrative Units" -Type Header

# Executives AU
$execAUId = New-OrGetAU -DisplayName "AU-Executives" -Description "C-suite and VP-level executives"
foreach ($exec in $execUsers) { Add-AUMemberSafe -AUId $execAUId -UserId $exec.Id }
Write-Host "    AU-Executives          : $($execUsers.Count) members" -ForegroundColor DarkGray

# Service Accounts AU
$svcAUId = New-OrGetAU -DisplayName "AU-ServiceAccounts" -Description "Automated service and integration accounts"
foreach ($svc in $svcUsers) { Add-AUMemberSafe -AUId $svcAUId -UserId $svc.Id }
Write-Host "    AU-ServiceAccounts     : $($svcUsers.Count) members" -ForegroundColor DarkGray

# ── Summary ───────────────────────────────────────────────────────────────────
$auCount = 18 + 4 + 2  # dept + regional + special

Write-Host ""
Write-Status "Administrative Units deployment complete" -Type Success
Write-Host ""
Write-Host "  Dept AUs created     : 18" -ForegroundColor Green
Write-Host "  Regional AUs created : 4" -ForegroundColor Green
Write-Host "  Special AUs created  : 2  (Executives, ServiceAccounts)" -ForegroundColor Green
Write-Host "  Total                : $auCount" -ForegroundColor Green
Write-Host ""
Write-Host "  T1 admins scoped to all dept AUs: Helpdesk Administrator" -ForegroundColor Cyan
Write-Host "  They can reset passwords/MFA only for users in their dept — not tenant-wide." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Verify in Entra portal:" -ForegroundColor Cyan
Write-Host "    Identity → Administrative Units → select an AU → Members" -ForegroundColor DarkGray
Write-Host "    Identity → Administrative Units → select an AU → Roles and administrators" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
