<#
.SYNOPSIS
    Authentication method registration gaps: who cannot do MFA at all, who can
    only do the weak kinds, and which admins are not phishing-resistant.

.DESCRIPTION
    "We have MFA" is usually a statement about policy. This is the statement
    about reality: per-user registration state read from the Entra ID
    authentication methods report, ranked by how exposed each gap leaves you.

    The distinction that matters, and that most MFA dashboards blur:

      Not MFA-capable        - the account has no usable second factor at all.
                               A Conditional Access policy requiring MFA will
                               either block this user or, far worse, be scoped
                               around them.
      Weak methods only      - registered, but only SMS or voice. Defeated by SIM
                               swap and by any real-time phishing proxy. It
                               satisfies an MFA requirement while providing much
                               less than one implies.
      Not phishing-resistant - no FIDO2, passkey, Windows Hello or certificate.
                               Acceptable for most users today; not acceptable
                               for an administrator.

    Admins are evaluated separately throughout, because an admin with SMS-only
    MFA is a materially different risk from a standard user with the same.

    Pairs with the sign-in side: this report shows what users COULD authenticate
    with; Reports/KQL/Library/Hygiene/Hygiene-AuthenticationMethodStrength.kql
    shows what they ACTUALLY used. The two disagree more often than expected -
    registration is a ceiling, not a floor.

    READ-ONLY. Every call is a GET.

.PARAMETER IncludeGuests
    Include guest (B2B) accounts. Off by default - guests normally authenticate
    against their home tenant's policies, so their registration state here is
    misleading.

.PARAMETER MaxUsersListed
    Cap on how many users are listed per gap section, to keep the HTML readable
    in a large tenant. The counts and findings always reflect the full set.

.EXAMPLE
    .\IAM\Get-MfaRegistrationGapReport.ps1 -Open

.EXAMPLE
    .\IAM\Get-MfaRegistrationGapReport.ps1 -IncludeGuests -MaxUsersListed 2000 -Open

.NOTES
    Scopes: AuditLog.Read.All or Reports.Read.All (plus User.Read.All to resolve
    account state). Requires Entra ID P1 or P2 - the registration report is a
    premium feature. Without it this report says NOT CHECKED rather than
    reporting zero gaps.

    Read-only: nothing here registers, resets or removes an authentication method.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$IncludeGuests,
    [int]$MaxUsersListed = 500,
    [string]$OutputPath,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\GraphReadOnly.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-GraphReadOnly | Out-Null

$preflight = Test-GraphScope -Required @("AuditLog.Read.All", "User.Read.All")
if (-not $preflight.AllPresent) { Write-Status $preflight.Summary -Type Warning }

# ---------------------------------------------------------------------------
# Method classification
# ---------------------------------------------------------------------------
# Values returned in methodsRegistered. Microsoft has renamed several of these
# over time, so matching is by substring and the unmatched ones are surfaced
# rather than silently bucketed as "fine".
$phishingResistant = @("fido2SecurityKey", "windowsHelloForBusiness", "passKeyDeviceBound",
                       "passKeyDeviceBoundAuthenticator", "x509Certificate",
                       "x509CertificateSingleFactor", "x509CertificateMultiFactor")
$strongPhishable   = @("microsoftAuthenticatorPush", "microsoftAuthenticatorPasswordless",
                       "softwareOneTimePasscode", "hardwareOneTimePasscode", "mobilePhone-notification")
$weakMethods       = @("sms", "mobileSMS", "alternateMobilePhone", "voiceMobile", "voiceAlternateMobile",
                       "voiceOffice", "officePhone", "mobilePhone")

function Test-MethodIn {
    param([string[]]$Methods, [string[]]$Candidates)
    foreach ($method in @($Methods)) {
        foreach ($candidate in $Candidates) {
            if ($method -and $method -like "*$candidate*") { return $true }
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Pull the registration report
# ---------------------------------------------------------------------------
Write-Status "Reading authentication method registration details" -Type Header
$registrationDetails = @(Invoke-GraphPagedRequest -Uri "v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999" -TolerateFailure)

$reportUnavailable = ($registrationDetails.Count -eq 0)
if ($reportUnavailable) {
    Write-Status "The registration report returned nothing. This is normally a licensing gap (Entra ID P1/P2 required) or a missing AuditLog.Read.All / Reports.Read.All scope - NOT a tenant with zero users." -Type Warning
}

$users = foreach ($detail in $registrationDetails) {
    $methods = @($detail.methodsRegistered)
    $userType = [string]$detail.userType

    [pscustomobject]@{
        UserPrincipalName   = [string]$detail.userPrincipalName
        DisplayName         = [string]$detail.userDisplayName
        UserType            = if ($userType) { $userType } else { "member" }
        IsAdmin             = [bool]$detail.isAdmin
        IsMfaCapable        = [bool]$detail.isMfaCapable
        IsMfaRegistered     = [bool]$detail.isMfaRegistered
        IsPasswordlessCapable = [bool]$detail.isPasswordlessCapable
        IsSsprCapable       = [bool]$detail.isSsprCapable
        IsSsprRegistered    = [bool]$detail.isSsprRegistered
        DefaultMfaMethod    = [string]$detail.defaultMfaMethod
        MethodCount         = $methods.Count
        MethodsRegistered   = ($methods -join ", ")
        HasPhishingResistant = (Test-MethodIn -Methods $methods -Candidates $phishingResistant)
        HasStrongPhishable   = (Test-MethodIn -Methods $methods -Candidates $strongPhishable)
        HasWeakOnly          = ((Test-MethodIn -Methods $methods -Candidates $weakMethods) -and
                                -not (Test-MethodIn -Methods $methods -Candidates $phishingResistant) -and
                                -not (Test-MethodIn -Methods $methods -Candidates $strongPhishable))
        LastUpdated         = [string]$detail.lastUpdatedDateTime
    }
}

$users = @($users)
if (-not $IncludeGuests) { $users = @($users | Where-Object { $_.UserType -ne "guest" }) }

Write-Status "$($users.Count) user(s) evaluated" -Type Success

# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------
$admins              = @($users | Where-Object { $_.IsAdmin })
$notMfaCapable       = @($users | Where-Object { -not $_.IsMfaCapable })
$adminsNotMfaCapable = @($admins | Where-Object { -not $_.IsMfaCapable })
$weakOnly            = @($users | Where-Object { $_.HasWeakOnly })
$adminsWeakOnly      = @($admins | Where-Object { $_.HasWeakOnly })
$adminsNotPhishingResistant = @($admins | Where-Object { -not $_.HasPhishingResistant })
$phishingResistantUsers     = @($users | Where-Object { $_.HasPhishingResistant })
$singleMethod        = @($users | Where-Object { $_.IsMfaCapable -and $_.MethodCount -le 1 })
$ssprGap             = @($users | Where-Object { -not $_.IsSsprRegistered })

$phishingResistantPct = if ($users.Count -gt 0) { [math]::Round(100.0 * $phishingResistantUsers.Count / $users.Count, 1) } else { 0 }
$mfaCapablePct        = if ($users.Count -gt 0) { [math]::Round(100.0 * @($users | Where-Object { $_.IsMfaCapable }).Count / $users.Count, 1) } else { 0 }

# Method popularity, for the "what are people actually registering" view.
$methodDistribution = @(
    $users |
        ForEach-Object { ($_.MethodsRegistered -split ",\s*") } |
        Where-Object { $_ } |
        Group-Object |
        Sort-Object Count -Descending |
        ForEach-Object {
            $classification = if (Test-MethodIn -Methods @($_.Name) -Candidates $phishingResistant) { "1 - Phishing-resistant" }
                              elseif (Test-MethodIn -Methods @($_.Name) -Candidates $strongPhishable) { "2 - Strong but phishable" }
                              elseif (Test-MethodIn -Methods @($_.Name) -Candidates $weakMethods)     { "3 - Weak (SMS or voice)" }
                              else { "4 - Unclassified - check whether this is a new method name" }
            [pscustomobject]@{
                Method         = $_.Name
                Classification = $classification
                Users          = $_.Count
                PercentOfUsers = if ($users.Count -gt 0) { [math]::Round(100.0 * $_.Count / $users.Count, 1) } else { 0 }
            }
        }
)

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
$findings = @()

if ($reportUnavailable) {
    $findings += New-Finding -Severity NotChecked -Category "Data availability" `
        -Finding "The authentication method registration report returned no data" `
        -Evidence "reports/authenticationMethods/userRegistrationDetails returned zero rows." `
        -Recommendation "Confirm Entra ID P1/P2 licensing and that the session holds AuditLog.Read.All or Reports.Read.All. Do not read this report as 'no gaps' until it does."
} else {
    if ($adminsNotMfaCapable.Count -gt 0) {
        $findings += New-Finding -Severity Critical -Category "Admin MFA" `
            -Finding "$($adminsNotMfaCapable.Count) administrator(s) are not MFA-capable" `
            -Subject (($adminsNotMfaCapable | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join "; ") `
            -Count $adminsNotMfaCapable.Count `
            -Evidence "These accounts hold a directory role and have no usable second factor." `
            -Recommendation "Register a strong method before enforcing admin MFA, or the enforcement policy will lock them out - or be scoped around them, which is worse."
    }

    if ($adminsWeakOnly.Count -gt 0) {
        $findings += New-Finding -Severity Critical -Category "Admin MFA" `
            -Finding "$($adminsWeakOnly.Count) administrator(s) can only use SMS or voice" `
            -Subject (($adminsWeakOnly | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join "; ") `
            -Count $adminsWeakOnly.Count `
            -Evidence "SMS and voice are defeated by SIM swap and by real-time phishing proxies. For an administrator this is close to no MFA." `
            -Recommendation "Move admins to phishing-resistant methods and require them with an authentication strength policy."
    }

    if ($adminsNotPhishingResistant.Count -gt 0) {
        $findings += New-Finding -Severity High -Category "Admin MFA" `
            -Finding "$($adminsNotPhishingResistant.Count) of $($admins.Count) administrator(s) have no phishing-resistant method" `
            -Subject (($adminsNotPhishingResistant | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join "; ") `
            -Count $adminsNotPhishingResistant.Count `
            -Evidence "No FIDO2 key, passkey, Windows Hello for Business or certificate registered." `
            -Recommendation "Issue phishing-resistant credentials to admins first - it is the highest-value place to spend the rollout effort."
    }

    if ($notMfaCapable.Count -gt 0) {
        $findings += New-Finding -Severity High -Category "MFA coverage" `
            -Finding "$($notMfaCapable.Count) user(s) are not MFA-capable" `
            -Subject (($notMfaCapable | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join "; ") `
            -Count $notMfaCapable.Count `
            -Evidence "$mfaCapablePct% of evaluated users are MFA-capable." `
            -Recommendation "Drive registration with a registration campaign before tightening Conditional Access, so enforcement does not turn into a helpdesk incident."
    }

    if ($weakOnly.Count -gt 0) {
        $findings += New-Finding -Severity Medium -Category "Method strength" `
            -Finding "$($weakOnly.Count) user(s) have only weak methods registered (SMS or voice)" `
            -Count $weakOnly.Count `
            -Evidence "These users satisfy an MFA requirement while providing substantially less assurance than one implies." `
            -Recommendation "Target them for Authenticator or passkey enrollment. Consider disabling SMS as a method once the population is small enough."
    }

    if ($singleMethod.Count -gt 0) {
        $findings += New-Finding -Severity Medium -Category "Resilience" `
            -Finding "$($singleMethod.Count) MFA-capable user(s) have only one method registered" `
            -Count $singleMethod.Count `
            -Evidence "A lost phone locks these users out entirely and sends them to the helpdesk - which is itself a social-engineering surface." `
            -Recommendation "Encourage a second method during registration."
    }

    if ($ssprGap.Count -gt 0) {
        $findings += New-Finding -Severity Low -Category "SSPR" `
            -Finding "$($ssprGap.Count) user(s) are not registered for self-service password reset" `
            -Count $ssprGap.Count `
            -Evidence "Password resets for these users go through the helpdesk." `
            -Recommendation "Complete SSPR registration to reduce helpdesk-mediated credential changes."
    }

    $unclassified = @($methodDistribution | Where-Object { $_.Classification -like "4 *" })
    if ($unclassified.Count -gt 0) {
        $findings += New-Finding -Severity Info -Category "Catalog" `
            -Finding "$($unclassified.Count) registered method name(s) are not in this report's classification list" `
            -Subject (($unclassified | Select-Object -ExpandProperty Method) -join "; ") `
            -Count $unclassified.Count `
            -Evidence "Microsoft renames and adds authentication methods over time." `
            -Recommendation "Add them to the phishingResistant / strongPhishable / weakMethods lists at the top of this script so they are classified rather than ignored."
    }

    if ($findings.Count -eq 0) {
        $findings += New-Finding -Severity Info -Category "Summary" `
            -Finding "No registration gaps found" `
            -Evidence "$($users.Count) users evaluated, $phishingResistantPct% phishing-resistant." `
            -Recommendation "Re-run after onboarding waves."
    }
}

if (-not $IncludeGuests) {
    $findings += New-Finding -Severity NotChecked -Category "Scope" `
        -Finding "Guest (B2B) accounts were excluded" `
        -Evidence "Guests normally authenticate against their home tenant's policies, so their registration state in this tenant is misleading." `
        -Recommendation "Use -IncludeGuests if your guests authenticate locally, and see IAM/Get-GuestAccessReport.ps1 for guest exposure generally."
}

$findings = @($findings | Sort-Finding)

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
# When the underlying report is unavailable every count is zero, and a green
# tile reading "0 admins without MFA" would be a lie. Show "n/a" instead.
$statTiles = if ($reportUnavailable) {
    @(
        @{ Label = "Users evaluated"; Value = 0; Tone = "danger" }
        @{ Label = "MFA-capable"; Value = "n/a"; Tone = "neutral" }
        @{ Label = "Phishing-resistant"; Value = "n/a"; Tone = "neutral" }
        @{ Label = "Admins not MFA-capable"; Value = "not checked"; Tone = "neutral" }
        @{ Label = "Admins without phishing-resistant"; Value = "not checked"; Tone = "neutral" }
        @{ Label = "Weak-method-only users"; Value = "not checked"; Tone = "neutral" }
    )
} else {
    @(
        @{ Label = "Users evaluated"; Value = $users.Count; Tone = "neutral" }
        @{ Label = "MFA-capable"; Value = "$mfaCapablePct%"; Tone = if ($mfaCapablePct -ge 99) { "good" } elseif ($mfaCapablePct -ge 90) { "warn" } else { "danger" } }
        @{ Label = "Phishing-resistant"; Value = "$phishingResistantPct%"; Tone = if ($phishingResistantPct -ge 50) { "good" } elseif ($phishingResistantPct -gt 0) { "warn" } else { "danger" } }
        @{ Label = "Admins not MFA-capable"; Value = $adminsNotMfaCapable.Count; Tone = if ($adminsNotMfaCapable.Count -gt 0) { "danger" } else { "good" } }
        @{ Label = "Admins without phishing-resistant"; Value = $adminsNotPhishingResistant.Count; Tone = if ($adminsNotPhishingResistant.Count -gt 0) { "warn" } else { "good" } }
        @{ Label = "Weak-method-only users"; Value = $weakOnly.Count; Tone = if ($weakOnly.Count -gt 0) { "warn" } else { "good" } }
    )
}

$displayColumns = @("UserPrincipalName", "DisplayName", "UserType", "IsAdmin", "IsMfaCapable",
                    "HasPhishingResistant", "DefaultMfaMethod", "MethodCount", "MethodsRegistered",
                    "IsSsprRegistered", "LastUpdated")

function Select-ForDisplay {
    param([array]$Rows)
    return @($Rows | Select-Object -First $MaxUsersListed | Select-Object $displayColumns)
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Reports\Output\MfaRegistrationGaps-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
}

$truncationNote = if ($users.Count -gt $MaxUsersListed) {
    " User lists are capped at $MaxUsersListed rows per section; tile counts and findings reflect all $($users.Count) users."
} else { "" }

$subtitle = if ($reportUnavailable) {
    "$($config.TenantDomain) - REGISTRATION REPORT UNAVAILABLE, see Findings. Nothing below was checked."
} else {
    "$($config.TenantDomain) - $($users.Count) users, $($admins.Count) with a directory role"
}

New-HtmlReport -Title "Authentication Method Registration Gaps" `
    -Subtitle $subtitle `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                                        = $findings
        "Administrators who are not MFA-capable"          = (Select-ForDisplay $adminsNotMfaCapable)
        "Administrators with only weak methods"           = (Select-ForDisplay $adminsWeakOnly)
        "Administrators without a phishing-resistant method" = (Select-ForDisplay $adminsNotPhishingResistant)
        "Users who are not MFA-capable"                   = (Select-ForDisplay $notMfaCapable)
        "Users with only weak methods (SMS or voice)"     = (Select-ForDisplay $weakOnly)
        "MFA-capable users with a single method"          = (Select-ForDisplay $singleMethod)
        "Registered method distribution"                  = $methodDistribution
    }) `
    -FooterNote "Source: Microsoft Graph reports/authenticationMethods/userRegistrationDetails (GET). Registration is a ceiling, not a floor - for what users actually authenticated with, run Reports/KQL/Library/Hygiene/Hygiene-AuthenticationMethodStrength.kql.$truncationNote" `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

Disconnect-MgGraph | Out-Null
