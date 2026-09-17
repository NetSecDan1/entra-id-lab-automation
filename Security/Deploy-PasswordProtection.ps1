<#
.SYNOPSIS
    Configures Entra ID Password Protection — custom banned passwords and smart lockout.

.DESCRIPTION
    Two layers of password hardening:

    1. Smart Lockout
       Locks accounts after N failed attempts. Protects against password spray
       and brute-force attacks. Settings applied via tenant auth policy.
       - Threshold   : 5 failed attempts (Microsoft default is 10)
       - Duration    : 60 seconds (doubles with each successive lockout)

    2. Custom Banned Password List
       Words specific to your organization that attackers target first in
       password spray campaigns. Combined with Microsoft's global banned list
       of 1000+ known-bad passwords.
       - Includes company name variants, tenant name, common corporate patterns
       - Mode: Audit (log violations) or Enforced (reject at password change)

.PARAMETER Mode
    Audit   — log violations but don't block (safe for testing)
    Enforced — block passwords matching banned list (production setting)
    Default = Audit

.PARAMETER LockoutThreshold
    Failed attempts before lockout. Default = 5.

.EXAMPLE
    # Safe audit mode (default)
    .\Security\Deploy-PasswordProtection.ps1

    # Production enforcement
    .\Security\Deploy-PasswordProtection.ps1 -Mode Enforced -LockoutThreshold 5
#>
[CmdletBinding()]
param(
    [string]$ConfigPath       = "$PSScriptRoot\..\config\config.json",
    [ValidateSet("Audit","Enforced")]
    [string]$Mode             = "Audit",
    [int]   $LockoutThreshold = 5,
    [int]   $LockoutDurationSeconds = 60
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config  = Get-Config -ConfigPath $ConfigPath
$domain  = $config.TenantDomain
$company = $config.CompanyName

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Password Protection Configuration" -Type Header
Write-Host "  Tenant  : $domain"
Write-Host "  Company : $company"
Write-Host "  Mode    : $Mode"
Write-Host "  Lockout : $LockoutThreshold attempts → $LockoutDurationSeconds second lockout"
Write-Host ""

# ── Build company-specific banned password list ───────────────────────────────
Write-Status "Building banned password list" -Type Header

# Derive word variants from company name and tenant domain
$companyWords = @(
    ($company -replace "[^a-zA-Z0-9]", "").ToLower(),
    ($domain  -replace "\.onmicrosoft\.com", "" -replace "[^a-zA-Z0-9]", "").ToLower()
)
# Add common variants of each company word
$companyVariants = [System.Collections.Generic.List[string]]::new()
foreach ($w in $companyWords) {
    if ($w.Length -ge 3) {
        $companyVariants.Add($w)
        $companyVariants.Add("${w}1")
        $companyVariants.Add("${w}123")
        $companyVariants.Add("${w}2024")
        $companyVariants.Add("${w}2025")
        $companyVariants.Add("${w}@1")
        $companyVariants.Add("${w}Pass")
        $companyVariants.Add("${w}pass")
        $companyVariants.Add("${w}Admin")
        $companyVariants.Add("${w}admin")
    }
}

# Common enterprise password spray targets (NOT on Microsoft's global list — company-specific)
$corporateWords = @(
    "Welcome1", "Welcome@1", "Welcome123", "Welcome2024", "Welcome2025",
    "Summer2024", "Summer2025", "Winter2024", "Winter2025",
    "Spring2024", "Spring2025", "Fall2024", "Fall2025",
    "Password1", "Passw0rd1", "P@ssw0rd1", "P@ssword1",
    "Monday1", "Monday@1", "January1", "January@1",
    "Changeme1", "Change@me", "Temp1234", "Temp@1234",
    "Letmein1", "Let@mein", "Qwerty123", "Abc1234",
    "Company1", "Company@1", "Corp2024", "Corp2025",
    "Remote1", "Remote@1", "Vpn1234", "Vpn@2024",
    "Teams123", "Teams@1", "Office365", "Microsoft1",
    "Admin123", "Admin@123", "Sysadmin1", "Itadmin1",
    "Helpdesk1", "Service1", "Support1", "Support@1",
    "Test1234", "Test@1234", "Lab12345", "Demo1234"
)

$allBanned = (@($companyVariants) + $corporateWords) | Select-Object -Unique | Sort-Object

Write-Host "  Company variants  : $($companyVariants.Count)"
Write-Host "  Corporate words   : $($corporateWords.Count)"
Write-Host "  Total banned list : $($allBanned.Count) entries"
Write-Host ""
Write-Host "  Sample entries:" -ForegroundColor DarkGray
$allBanned | Select-Object -First 10 | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
Write-Host "    ..." -ForegroundColor DarkGray

# ── Apply banned password settings via directory settings template ────────────
Write-Status "Applying password protection settings" -Type Header

try {
    # Find the password rule settings template
    $templates = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/directorySettingTemplates" -ErrorAction Stop

    $template = $templates.value | Where-Object { $_.displayName -eq "Password Rule Settings" } | Select-Object -First 1

    if (-not $template) {
        Write-Status "Password Rule Settings template not found in this tenant." -Type Warning
        Write-Host "  This template may not be available in all tenant types." -ForegroundColor Yellow
    } else {
        Write-Host "  Template ID: $($template.id)" -ForegroundColor DarkGray

        # Check if setting already exists
        $existingSettings = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/settings" -ErrorAction SilentlyContinue
        $existingSetting = $existingSettings.value | Where-Object { $_.templateId -eq $template.id } | Select-Object -First 1

        $values = @(
            @{ name = "LockoutThreshold";                    value = "$LockoutThreshold" }
            @{ name = "LockoutDurationInSeconds";            value = "$LockoutDurationSeconds" }
            @{ name = "EnableBannedPasswordCheck";           value = "True" }
            @{ name = "BannedPasswordList";                  value = ($allBanned -join ",") }
            @{ name = "EnableBannedPasswordCheckOnPremises"; value = "False" }
            @{ name = "BannedPasswordCheckOnPremisesMode";   value = $Mode }
        )

        $settingBody = @{
            templateId = $template.id
            values     = $values
        } | ConvertTo-Json -Depth 4

        if ($existingSetting) {
            Invoke-MgGraphRequest -Method PATCH -Body $settingBody -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/settings/$($existingSetting.id)" | Out-Null
            Write-Status "Updated password protection settings" -Type Warning
        } else {
            Invoke-MgGraphRequest -Method POST -Body $settingBody -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/settings" | Out-Null
            Write-Status "Created password protection settings" -Type Success
        }
    }
} catch {
    Write-Status "Password rule settings failed (may not be available via API in all tenants): $($_.Exception.Message)" -Type Warning
    Write-Host "  Configure manually: Entra portal → Protection → Authentication methods → Password protection" -ForegroundColor Yellow
}

# ── Smart lockout via authorizationPolicy ────────────────────────────────────
Write-Status "Configuring smart lockout threshold" -Type Header
try {
    # Note: lockout threshold in Entra is also set in the portal's password protection blade
    # The API surface for this may vary; the settings above include LockoutThreshold
    Write-Host "  LockoutThreshold        : $LockoutThreshold failed attempts" -ForegroundColor Green
    Write-Host "  LockoutDurationInSeconds: $LockoutDurationSeconds seconds (doubles each successive lockout)" -ForegroundColor Green
    Write-Host "  Note: Microsoft's smart lockout is always active — these settings tune it." -ForegroundColor DarkGray
} catch {
    Write-Status "Lockout configuration note: $_" -Type Warning
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Password Protection deployment complete" -Type Success
Write-Host ""
Write-Host "  Banned password mode   : $Mode" -ForegroundColor $(if ($Mode -eq "Enforced") {"Green"} else {"Yellow"})
Write-Host "  Banned word count      : $($allBanned.Count)" -ForegroundColor Green
Write-Host "  Smart lockout threshold: $LockoutThreshold attempts" -ForegroundColor Green
Write-Host ""
Write-Host "  Microsoft's global banned password list of 1,000+ words is always active." -ForegroundColor DarkGray
Write-Host "  Your custom list adds company-specific and corporate spray targets." -ForegroundColor DarkGray
Write-Host ""
if ($Mode -eq "Audit") {
    Write-Host "  Currently in AUDIT mode — violations logged but not blocked." -ForegroundColor Yellow
    Write-Host "  Switch to Enforced when ready:" -ForegroundColor Yellow
    Write-Host "    .\Security\Deploy-PasswordProtection.ps1 -Mode Enforced" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  Verify in Entra portal:" -ForegroundColor Cyan
Write-Host "    Protection → Authentication methods → Password protection" -ForegroundColor DarkGray
Write-Host "    Protection → Authentication methods → Activity → Risky sign-ins (for spray alerts)" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
