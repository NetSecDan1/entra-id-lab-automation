<#
.SYNOPSIS
    Assigns available licenses to test users in the tenant.

.DESCRIPTION
    This script:
      1. Lists all available SKUs with remaining units
      2. Prompts you to choose which SKU to assign (or auto-assigns if only one exists)
      3. Assigns the chosen SKU to all enabled test users (testuser01..N + testadmin)
      4. Optionally sets up group-based licensing (requires Azure AD P1)

    Group-based licensing is preferred for production but direct assignment
    is used here for simplicity and broader compatibility.

    Run Deploy-Users.ps1 and Deploy-Groups.ps1 first.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath  = "$PSScriptRoot\..\config\config.json",

    # Optionally pass a SKU ID directly to skip the interactive prompt
    [string]$SkuId       = "",

    # If true, use group-based licensing instead of direct assignment
    [switch]$UseGroupBased
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain
$u      = $config.Users

# ── Show available SKUs ───────────────────────────────────────────────────────
Write-Status "Available license SKUs in tenant" -Type Header
$skus = Get-MgSubscribedSku | Where-Object {
    $_.PrepaidUnits.Enabled -gt 0 -and
    $_.ConsumedUnits -lt $_.PrepaidUnits.Enabled
}

if (-not $skus) {
    Write-Status "No licenses with available units found in this tenant." -Type Error
    Write-Host "  Purchase licenses or use a developer subscription (M365 E5 Dev is free for testing)." -ForegroundColor Yellow
    return
}

Write-Host ""
$i = 0
foreach ($sku in $skus) {
    $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
    Write-Host "  [$i] $($sku.SkuPartNumber) — available: $available / $($sku.PrepaidUnits.Enabled)  (ID: $($sku.SkuId))"
    $i++
}
Write-Host ""

# ── Select SKU ────────────────────────────────────────────────────────────────
if ($SkuId -eq "" ) {
    if ($skus.Count -eq 1) {
        $selectedSku = $skus[0]
        Write-Status "Auto-selecting only available SKU: $($selectedSku.SkuPartNumber)" -Type Info
    } else {
        $choice = Read-Host "Enter SKU index to assign (or press Enter to skip licensing)"
        if ($choice -eq "") {
            Write-Status "Licensing skipped." -Type Warning
            return
        }
        $selectedSku = $skus[[int]$choice]
    }
} else {
    $selectedSku = $skus | Where-Object { $_.SkuId -eq $SkuId }
    if (-not $selectedSku) {
        Write-Status "SKU ID '$SkuId' not found in available SKUs." -Type Error
        return
    }
}

Write-Status "Assigning: $($selectedSku.SkuPartNumber) ($($selectedSku.SkuId))" -Type Info
$licensePayload = @{
    addLicenses    = @(@{ skuId = $selectedSku.SkuId })
    removeLicenses = @()
}

# ── Collect target users ──────────────────────────────────────────────────────
# Query by companyName — compatible with firstname.lastname UPN format
$employeeUsers = Get-AllEmployeeUsers -CompanyName $config.CompanyName
$targetUpns    = @("$($u.AdminUpn)@$domain") + @($employeeUsers.UserPrincipalName | Where-Object { $_ })

# ── Direct assignment ─────────────────────────────────────────────────────────
if (-not $UseGroupBased) {
    Write-Status "Direct license assignment to $($targetUpns.Count) users" -Type Header
    $available = $selectedSku.PrepaidUnits.Enabled - $selectedSku.ConsumedUnits
    if ($targetUpns.Count -gt $available) {
        Write-Status "Not enough licenses! Need $($targetUpns.Count), have $available." -Type Error
        return
    }
    foreach ($upn in $targetUpns) {
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $user) {
            Write-Status "User not found: $upn" -Type Warning
            continue
        }
        # Check if already licensed
        $existing = Get-MgUserLicenseDetail -UserId $user.Id |
            Where-Object { $_.SkuId -eq $selectedSku.SkuId }
        if ($existing) {
            Write-Status "Already licensed: $upn" -Type Warning
            continue
        }
        # Ensure usage location is set
        if (-not $user.UsageLocation) {
            Update-MgUser -UserId $user.Id -UsageLocation $u.UsageLocation
        }
        Set-MgUserLicense -UserId $user.Id -BodyParameter $licensePayload | Out-Null
        Write-Status "Licensed: $upn" -Type Success
    }
}

# ── Group-based licensing (requires Azure AD Premium P1) ─────────────────────
else {
    Write-Status "Group-based licensing for SG-All-TestUsers" -Type Header
    $groupName  = $config.Groups.AllUsers
    $grp = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
    if (-not $grp) {
        Write-Status "Group '$groupName' not found — run Deploy-Groups.ps1 first." -Type Error
        return
    }

    try {
        # Assign license to group
        $body = @{
            assignedLicenses = @(
                @{
                    disabledPlans = @()
                    skuId         = $selectedSku.SkuId
                }
            )
        }
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/groups/$($grp.Id)/assignLicense" `
            -Body ($body | ConvertTo-Json -Depth 5) `
            -ContentType "application/json" | Out-Null
        Write-Status "Group license assigned to '$groupName'" -Type Success
        Write-Host "  License propagation runs in the background — check Entra portal in a few minutes." -ForegroundColor Yellow
    } catch {
        Write-Status "Group-based licensing failed (requires P1): $_" -Type Error
        Write-Host "  Retry without -UseGroupBased for direct assignment." -ForegroundColor Yellow
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Status "Licensing complete" -Type Success
Write-Host ""
Write-Host "  SKU assigned : $($selectedSku.SkuPartNumber)"
Write-Host "  Users        : $($targetUpns.Count)"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    # Check a user's licenses" -ForegroundColor DarkGray
Write-Host "    Get-MgUserLicenseDetail -UserId 'testuser01@$domain'" -ForegroundColor Cyan
Write-Host "    # Remove a license from a user" -ForegroundColor DarkGray
Write-Host "    Set-MgUserLicense -UserId 'testuser01@$domain' -BodyParameter @{ addLicenses=@(); removeLicenses=@('$($selectedSku.SkuId)') }" -ForegroundColor Cyan
