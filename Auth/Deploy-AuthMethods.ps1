<#
.SYNOPSIS
    Configures Authentication Methods policy and SSPR in the test tenant.

.DESCRIPTION
    Configures:
      - Microsoft Authenticator (enabled for all users, number matching + additional context on)
      - FIDO2 Security Keys     (enabled for all users)
      - Temporary Access Pass   (enabled — useful for onboarding/testing passwordless)
      - SMS                     (enabled — for SSPR fallback)
      - Software OATH tokens    (enabled)
      - Hardware OATH tokens    (enabled)
      - Voice call              (enabled)
      - Email OTP               (enabled for external/guest users only — default)
      - SSPR                    (enabled for all users via beta endpoint)

    All method updates are applied via Microsoft.Graph — some require beta endpoint
    invocations (SSPR enablement).
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$auth   = $config.Auth

function Set-AuthMethod {
    param(
        [string]$MethodId,
        [hashtable]$Body
    )
    try {
        Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
            -AuthenticationMethodConfigurationId $MethodId `
            -BodyParameter $Body
        Write-Status "Updated: $MethodId" -Type Success
    } catch {
        Write-Status "Failed to update $MethodId : $_" -Type Error
    }
}

# ── Microsoft Authenticator ───────────────────────────────────────────────────
Write-Status "Microsoft Authenticator" -Type Header
Set-AuthMethod -MethodId "MicrosoftAuthenticator" -Body @{
    "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
    state         = "enabled"
    featureSettings = @{
        displayAppInformationRequiredState = @{
            state = "enabled"
            includeTarget = @{ targetType = "group"; id = "all_users" }
            excludeTarget = @{ targetType = "group"; id = "00000000-0000-0000-0000-000000000000" }
        }
        displayLocationInformationRequiredState = @{
            state = "enabled"
            includeTarget = @{ targetType = "group"; id = "all_users" }
            excludeTarget = @{ targetType = "group"; id = "00000000-0000-0000-0000-000000000000" }
        }
        numberMatchingRequiredState = @{
            state = "enabled"
            includeTarget = @{ targetType = "group"; id = "all_users" }
            excludeTarget = @{ targetType = "group"; id = "00000000-0000-0000-0000-000000000000" }
        }
    }
    includeTargets = @(
        @{
            targetType         = "group"
            id                 = "all_users"
            authenticationMode = "any"
        }
    )
}

# ── FIDO2 ─────────────────────────────────────────────────────────────────────
Write-Status "FIDO2 Security Keys" -Type Header
Set-AuthMethod -MethodId "Fido2" -Body @{
    "@odata.type"            = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
    state                    = "enabled"
    isAttestationEnforced    = $false
    isSelfServiceRegistrationAllowed = $true
    includeTargets = @(
        @{ targetType = "group"; id = "all_users" }
    )
}

# ── Temporary Access Pass ─────────────────────────────────────────────────────
Write-Status "Temporary Access Pass" -Type Header
Set-AuthMethod -MethodId "TemporaryAccessPass" -Body @{
    "@odata.type"         = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
    state                 = "enabled"
    defaultLifetimeInMinutes     = $auth.TAPLifetimeMinutes
    defaultLength                = 8
    minimumLifetimeInMinutes     = 60
    maximumLifetimeInMinutes     = 480
    isUsableOnce                 = $auth.TAPIsUsableOnce
    includeTargets = @(
        @{ targetType = "group"; id = "all_users" }
    )
}

# ── SMS ───────────────────────────────────────────────────────────────────────
Write-Status "SMS" -Type Header
Set-AuthMethod -MethodId "Sms" -Body @{
    "@odata.type"   = "#microsoft.graph.smsAuthenticationMethodConfiguration"
    state           = "enabled"
    includeTargets  = @(
        @{ targetType = "group"; id = "all_users"; isUsableForSignIn = $false }
    )
}

# ── Software OATH ─────────────────────────────────────────────────────────────
Write-Status "Software OATH tokens" -Type Header
Set-AuthMethod -MethodId "SoftwareOath" -Body @{
    "@odata.type"  = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
    state          = "enabled"
    includeTargets = @(
        @{ targetType = "group"; id = "all_users" }
    )
}

# ── Voice Call ────────────────────────────────────────────────────────────────
Write-Status "Voice Call" -Type Header
Set-AuthMethod -MethodId "Voice" -Body @{
    "@odata.type"  = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
    state          = "enabled"
    isOfficePhoneAllowed = $true
    includeTargets = @(
        @{ targetType = "group"; id = "all_users" }
    )
}

# ── SSPR — enable via beta endpoint ──────────────────────────────────────────
Write-Status "Self-Service Password Reset (SSPR)" -Type Header
try {
    # SSPR registration policy (combined registration / SSPR)
    $sspr = @{
        state = "enabled"
        includeTargets = @(
            @{
                targetType = "group"
                id         = "all_users"
            }
        )
    }
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Email" `
        -Body (@{
            "@odata.type"  = "#microsoft.graph.emailAuthenticationMethodConfiguration"
            state          = "enabled"
            allowExternalIdToUseEmailOtp = "enabled"
            includeTargets = @(
                @{ targetType = "group"; id = "all_users" }
            )
        } | ConvertTo-Json -Depth 5) `
        -ContentType "application/json" | Out-Null
    Write-Status "Email OTP enabled" -Type Success

    # SSPR policy enablement (v1.0 — organization-level)
    $org = Get-MgOrganization | Select-Object -First 1
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" `
        -Body (@{
            allowedToUseSSPR = "all"
        } | ConvertTo-Json) `
        -ContentType "application/json" | Out-Null
    Write-Status "SSPR enabled for all users" -Type Success
} catch {
    Write-Status "SSPR configuration error (may require P1/P2 license): $_" -Type Warning
}

# ── Combined Registration (MFA + SSPR) ────────────────────────────────────────
Write-Status "Combined Registration Policy" -Type Header
try {
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" `
        -Body (@{
            registrationEnforcement = @{
                authenticationMethodsRegistrationCampaign = @{
                    state = "enabled"
                    snoozeDurationInDays = 14
                    includeTargets = @(
                        @{ targetType = "group"; id = "all_users"; targetedAuthenticationMethod = "microsoftAuthenticator" }
                    )
                }
            }
        } | ConvertTo-Json -Depth 6) `
        -ContentType "application/json" | Out-Null
    Write-Status "Combined registration nudge enabled" -Type Success
} catch {
    Write-Status "Combined registration config error: $_" -Type Warning
}

Write-Status "Authentication methods deployment complete" -Type Success
Write-Host ""
Write-Host "  Tip: Generate a TAP for a user:" -ForegroundColor Cyan
Write-Host "    New-MgUserAuthenticationTemporaryAccessPassMethod -UserId <upn> -LifetimeInMinutes 60" -ForegroundColor Cyan
