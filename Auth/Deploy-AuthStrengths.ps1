<#
.SYNOPSIS
    Creates custom Authentication Strength policies for phishing-resistant and
    tiered MFA enforcement.

.DESCRIPTION
    Authentication Strengths define which MFA combinations are acceptable for
    a given Conditional Access policy grant control. Custom strengths let you
    enforce phishing-resistant methods for high-risk scenarios while allowing
    standard push for regular users.

    Strengths created
    -----------------
    Phishing-Resistant MFA
        FIDO2 security key, Windows Hello for Business, device-bound passkey
        → Use in CA policies for admin roles and high-value apps
        → Immune to real-time phishing, AiTM attacks, token theft

    Corporate Standard MFA
        Microsoft Authenticator (push or passkey), TOTP software token
        → Use for regular employee access requiring MFA
        → Satisfies CA000 (All users MFA)

    Hardware Token Only
        FIDO2 + Windows Hello (no phone-based MFA)
        → Use for CA policies targeting PAW users and break glass admins
        → Highest assurance level

    These strengths are referenced by name in CA policy grant controls:
    grantControls.authenticationStrength.id = <strength ID>

.EXAMPLE
    .\Auth\Deploy-AuthStrengths.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Custom Authentication Strength Policies" -Type Header
Write-Host ""

# Authentication method combination strings accepted by Graph API
# Full list: https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy
$combinations = @{
    FIDO2                    = "fido2"
    WindowsHello             = "windowsHelloForBusiness"
    DevicePasskey            = "deviceBasedPush"                  # Authenticator passkey (device-bound)
    AuthenticatorPush        = "microsoftAuthenticatorPush"       # Push notification (phone approver)
    SoftwareOATH             = "softwareOath"                     # TOTP apps (Authenticator, Authy)
    TemporaryAccessPass      = "temporaryAccessPassOneTime"        # TAP (one-time)
    TemporaryAccessPassMulti = "temporaryAccessPassMultiUse"       # TAP (multi-use)
    VoiceCall                = "voiceApproval"
    SMS                      = "sms"
}

function New-OrUpdateAuthStrength {
    param(
        [string]  $DisplayName,
        [string]  $Description,
        [string[]]$AllowedCombinations
    )

    $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
        -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies?`$filter=displayName eq '$DisplayName'"

    $body = @{
        displayName          = $DisplayName
        description          = $Description
        allowedCombinations  = @($AllowedCombinations)
    } | ConvertTo-Json -Depth 4

    if ($existing.value -and $existing.value.Count -gt 0) {
        $policyId = $existing.value[0].id
        try {
            Invoke-MgGraphRequest -Method PATCH -Body $body -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies/$policyId" | Out-Null
            Write-Status "Updated: $DisplayName" -Type Warning
        } catch {
            Write-Status "Update failed: $($_.Exception.Message)" -Type Warning
        }
        return $policyId
    }

    try {
        $created = Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies"
        Write-Status "Created: $DisplayName" -Type Success
        $policyId = if ($created -is [hashtable]) { $created["id"] } else { $created.id }

        Write-Host ("    Allowed combinations:") -ForegroundColor DarkGray
        $AllowedCombinations | ForEach-Object { Write-Host ("      - $_") -ForegroundColor DarkGray }

        return $policyId
    } catch {
        Write-Status "Failed to create '$DisplayName': $($_.Exception.Message)" -Type Error
        return $null
    }
}

# ── 1. Phishing-Resistant MFA ─────────────────────────────────────────────────
Write-Status "1. Phishing-Resistant MFA" -Type Header

$phishResistantId = New-OrUpdateAuthStrength `
    -DisplayName "Phishing-Resistant MFA" `
    -Description "Requires hardware-backed or cryptographic credentials that are immune to phishing and AiTM attacks. Satisfies CA105 (admin phishing-resistant MFA requirement)." `
    -AllowedCombinations @(
        $combinations.FIDO2,
        $combinations.WindowsHello,
        $combinations.DevicePasskey
    )

# ── 2. Corporate Standard MFA ─────────────────────────────────────────────────
Write-Host ""
Write-Status "2. Corporate Standard MFA" -Type Header

$corporateMfaId = New-OrUpdateAuthStrength `
    -DisplayName "Corporate Standard MFA" `
    -Description "Accepts Microsoft Authenticator (push or device passkey) and TOTP software tokens. For regular employee MFA requirements in CA000 and CA200 series." `
    -AllowedCombinations @(
        $combinations.FIDO2,
        $combinations.WindowsHello,
        $combinations.DevicePasskey,
        $combinations.AuthenticatorPush,
        $combinations.SoftwareOATH
    )

# ── 3. Hardware Token Only (PAW / break glass) ────────────────────────────────
Write-Host ""
Write-Status "3. Hardware Token Only" -Type Header

$hardwareOnlyId = New-OrUpdateAuthStrength `
    -DisplayName "Hardware Token Only" `
    -Description "FIDO2 and Windows Hello for Business only. No phone-based MFA. Required for PAW users and any access from privileged admin workstations." `
    -AllowedCombinations @(
        $combinations.FIDO2,
        $combinations.WindowsHello
    )

# ── 4. First-Time Access (includes TAP) ───────────────────────────────────────
Write-Host ""
Write-Status "4. First-Time Access (with TAP)" -Type Header

$firstTimeId = New-OrUpdateAuthStrength `
    -DisplayName "First-Time Access" `
    -Description "Includes Temporary Access Pass for onboarding flows. Used in joiner lifecycle workflow CA policy exclusions for day-1 TAP sign-in." `
    -AllowedCombinations @(
        $combinations.FIDO2,
        $combinations.WindowsHello,
        $combinations.DevicePasskey,
        $combinations.AuthenticatorPush,
        $combinations.SoftwareOATH,
        $combinations.TemporaryAccessPass,
        $combinations.TemporaryAccessPassMulti
    )

# ── Print all custom auth strengths ───────────────────────────────────────────
Write-Host ""
Write-Status "All authentication strength policies in tenant" -Type Header

$allStrengths = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies"

foreach ($s in $allStrengths.value | Sort-Object displayName) {
    $isBuiltIn = if ($s.policyType -eq "builtIn") { " [built-in]" } else { " [custom]" }
    $color     = if ($s.policyType -eq "builtIn") { "DarkGray" } else { "Green" }
    Write-Host ("  {0,-40} {1}" -f $s.displayName, $isBuiltIn) -ForegroundColor $color
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Auth Strengths deployment complete" -Type Success
Write-Host ""
Write-Host "  Custom strengths created:" -ForegroundColor Green
Write-Host "    Phishing-Resistant MFA  — FIDO2, Windows Hello, Device Passkey" -ForegroundColor DarkGray
Write-Host "    Corporate Standard MFA  — Authenticator push/passkey + TOTP + hardware" -ForegroundColor DarkGray
Write-Host "    Hardware Token Only     — FIDO2 and Windows Hello only (no phone)" -ForegroundColor DarkGray
Write-Host "    First-Time Access       — all methods including TAP (onboarding)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Reference these in CA policies:" -ForegroundColor Cyan
Write-Host '    grantControls = @{ authenticationStrength = @{ id = "<strength ID>" } }' -ForegroundColor DarkGray
Write-Host "    Entra portal → Protection → Authentication strengths" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Recommended CA policy mappings:" -ForegroundColor Cyan
Write-Host "    CA105 (Admin phishing-resistant)  → Phishing-Resistant MFA" -ForegroundColor DarkGray
Write-Host "    CA000/CA200 (All users MFA)       → Corporate Standard MFA" -ForegroundColor DarkGray
Write-Host "    PAW policy (privileged workstation)→ Hardware Token Only" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
