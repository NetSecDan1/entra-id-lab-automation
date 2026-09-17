<#
.SYNOPSIS
    Read-only health report for the Entra test tenant.

.DESCRIPTION
    Connects to Microsoft Graph (read-only scopes) and prints a summary of:
      - Organization info
      - Users (total, enabled, admin accounts)
      - Groups (count by type, CA baseline coverage)
      - Conditional Access policies (count by state)
      - App registrations
      - Authentication methods
      - Security Defaults
      - Licensing

    Does not create or modify any resources.

.PARAMETER ConfigPath
    Path to config.json (default: .\config\config.json)

.EXAMPLE
    .\Reports\Get-TenantReport.ps1
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
Write-Status "Entra Test Tenant — Health Report" -Type Header
Write-Host "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Domain    : $domain" -ForegroundColor DarkGray
Write-Host ""

# ── Organization ──────────────────────────────────────────────────────────────
Write-Status "Organization" -Type Header
$org = Get-MgOrganization | Select-Object -First 1
Write-Host "  Display Name  : $($org.DisplayName)"
Write-Host "  Tenant ID     : $($org.Id)"
Write-Host "  Domains       : $($org.VerifiedDomains.Name -join ', ')"
Write-Host "  Created       : $($org.CreatedDateTime)"

# ── Security Defaults ─────────────────────────────────────────────────────────
Write-Status "Security Defaults" -Type Header
try {
    $sd = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    $sdState = if ($sd.isEnabled) { "ENABLED (CAPs will not apply!)" } else { "Disabled (good)" }
    $sdColor = if ($sd.isEnabled) { "Red" } else { "Green" }
    Write-Host "  State : $sdState" -ForegroundColor $sdColor
} catch {
    Write-Host "  Could not read security defaults: $_" -ForegroundColor Yellow
}

# ── Users ─────────────────────────────────────────────────────────────────────
Write-Status "Users" -Type Header
$allUsers      = Get-MgUser -All -Property "id,displayName,accountEnabled,userPrincipalName,department,jobTitle,companyName"
$enabledUsers  = @($allUsers | Where-Object { $_.AccountEnabled -eq $true })
$disabledUsers = @($allUsers | Where-Object { $_.AccountEnabled -eq $false })
$guestUsers    = @($allUsers | Where-Object { $_.UserPrincipalName -like "*#EXT#*" })
$svcAccounts   = @($allUsers | Where-Object { $_.UserPrincipalName -like "svc-*" })
$execUsers     = @($allUsers | Where-Object { $_.JobTitle -match "^Chief " })

Write-Host "  Total          : $($allUsers.Count)"
Write-Host "  Enabled        : $($enabledUsers.Count)"
Write-Host "  Disabled       : $($disabledUsers.Count)"
Write-Host "  Guests         : $($guestUsers.Count)"
Write-Host "  C-Suite        : $($execUsers.Count)"
Write-Host "  Service accts  : $($svcAccounts.Count)"

$bgUpn  = "$($config.Users.BreakGlassUpn)@$domain"
$bgUser = $allUsers | Where-Object { $_.UserPrincipalName -eq $bgUpn }
Write-Host "  Break Glass 1 : $(if ($bgUser) { 'Present' } else { 'MISSING' })" -ForegroundColor $(if ($bgUser) { 'Green' } else { 'Red' })

if ($config.Users.BreakGlassUpn2) {
    $bg2Upn  = "$($config.Users.BreakGlassUpn2)@$domain"
    $bg2User = $allUsers | Where-Object { $_.UserPrincipalName -eq $bg2Upn }
    Write-Host "  Break Glass 2 : $(if ($bg2User) { 'Present' } else { 'MISSING' })" -ForegroundColor $(if ($bg2User) { 'Green' } else { 'Red' })
}

# ── Groups ────────────────────────────────────────────────────────────────────
Write-Status "Groups" -Type Header
$allGroups     = Get-MgGroup -All -Property "id,displayName,groupTypes,securityEnabled,membershipRule"
$secGroups     = @($allGroups | Where-Object { $_.SecurityEnabled -and $_.GroupTypes -notcontains "DynamicMembership" -and $_.GroupTypes -notcontains "Unified" })
$dynGroups     = @($allGroups | Where-Object { $_.GroupTypes -contains "DynamicMembership" })
$m365Groups    = @($allGroups | Where-Object { $_.GroupTypes -contains "Unified" })

Write-Host "  Total            : $($allGroups.Count)"
Write-Host "  Security (assigned) : $($secGroups.Count)"
Write-Host "  Dynamic          : $($dynGroups.Count)"
Write-Host "  Microsoft 365    : $($m365Groups.Count)"

$caBreakGlass = $allGroups | Where-Object { $_.DisplayName -eq "CA-BreakGlassAccounts - Exclude" }
Write-Host "  CA-BreakGlassAccounts - Exclude : $(if ($caBreakGlass) { 'Present' } else { 'MISSING' })" `
    -ForegroundColor $(if ($caBreakGlass) { 'Green' } else { 'Red' })

$caBaselineGroupCount = @($allGroups | Where-Object { $_.DisplayName -match '^CA[0-9]' -or $_.DisplayName -match '^CA-' }).Count
Write-Host "  CA baseline groups : $caBaselineGroupCount"

# ── Conditional Access ────────────────────────────────────────────────────────
Write-Status "Conditional Access Policies" -Type Header
try {
    $caps = Get-MgIdentityConditionalAccessPolicy -All
    $capEnabled     = @($caps | Where-Object { $_.State -eq "enabled" })
    $capReportOnly  = @($caps | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" })
    $capDisabled    = @($caps | Where-Object { $_.State -eq "disabled" })

    Write-Host "  Total       : $($caps.Count)"
    Write-Host "  Enforced    : $($capEnabled.Count)"    -ForegroundColor $(if ($capEnabled.Count -gt 0)    { 'Green'  } else { 'Yellow' })
    Write-Host "  Report-only : $($capReportOnly.Count)" -ForegroundColor $(if ($capReportOnly.Count -gt 0)  { 'Yellow' } else { 'Gray'   })
    Write-Host "  Disabled    : $($capDisabled.Count)"   -ForegroundColor $(if ($capDisabled.Count -gt 0)    { 'Red'    } else { 'Gray'   })

    if ($caps.Count -eq 0) {
        Write-Host "  No CA policies found — run Deploy-CAPs.ps1." -ForegroundColor Red
    }
} catch {
    Write-Host "  Could not read CA policies: $_" -ForegroundColor Yellow
}

# ── Named Locations ───────────────────────────────────────────────────────────
Write-Status "Named Locations" -Type Header
try {
    $namedLocs = Get-MgIdentityConditionalAccessNamedLocation -All
    Write-Host "  Total : $($namedLocs.Count)"
    foreach ($loc in $namedLocs) {
        Write-Host "    - $($loc.DisplayName)" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  Could not read named locations: $_" -ForegroundColor Yellow
}

# ── App Registrations ─────────────────────────────────────────────────────────
Write-Status "App Registrations" -Type Header
$apps = Get-MgApplication -All -Property "id,displayName,appId,signInAudience,createdDateTime"
Write-Host "  Total : $($apps.Count)"
foreach ($app in $apps | Sort-Object DisplayName) {
    Write-Host "    - $($app.DisplayName) ($($app.SignInAudience))" -ForegroundColor DarkGray
}

# ── Authentication Methods ────────────────────────────────────────────────────
Write-Status "Authentication Methods" -Type Header
try {
    $authPolicy = Get-MgPolicyAuthenticationMethodPolicy
    $methods = $authPolicy.AuthenticationMethodConfigurations
    foreach ($method in $methods | Sort-Object Id) {
        $stateColor = if ($method.State -eq "enabled") { "Green" } else { "DarkGray" }
        Write-Host ("  {0,-42} : {1}" -f $method.Id, $method.State) -ForegroundColor $stateColor
    }
} catch {
    Write-Host "  Could not read auth methods: $_" -ForegroundColor Yellow
}

# ── Licensing ─────────────────────────────────────────────────────────────────
Write-Status "Licensing" -Type Header
try {
    $skus = Get-MgSubscribedSku
    foreach ($sku in $skus) {
        $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
        $color = if ($available -gt 0) { "Green" } elseif ($available -eq 0) { "Yellow" } else { "Red" }
        Write-Host ("  {0,-40} : {1} used / {2} total  ({3} available)" -f `
            $sku.SkuPartNumber, $sku.ConsumedUnits, $sku.PrepaidUnits.Enabled, $available) -ForegroundColor $color
    }
} catch {
    Write-Host "  Could not read licenses: $_" -ForegroundColor Yellow
}

# ── Recommendations ───────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Recommendations" -Type Header
$recs = [System.Collections.Generic.List[string]]::new()

if (-not $bgUser)                    { $recs.Add("Break glass account 1 is missing — run Deploy-Users.ps1.") }
if ($config.Users.BreakGlassUpn2 -and -not $bg2User) { $recs.Add("Break glass account 2 is missing — run Deploy-Users.ps1.") }
if (-not $caBreakGlass)              { $recs.Add("CA-BreakGlassAccounts - Exclude group missing — run Deploy-Groups.ps1.") }
if ($caps.Count -eq 0)               { $recs.Add("No Conditional Access policies found — run Deploy-CAPs.ps1.") }
if ($capEnabled.Count -eq 0 -and $caps.Count -gt 0) { $recs.Add("All CA policies are report-only or disabled — consider enforcing after review.") }

if ($recs.Count -eq 0) {
    Write-Host "  No issues found." -ForegroundColor Green
} else {
    foreach ($rec in $recs) {
        Write-Host "  [!] $rec" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Status "Report complete." -Type Success
Disconnect-MgGraph | Out-Null
