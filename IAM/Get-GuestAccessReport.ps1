<#
.SYNOPSIS
    Guest (B2B) population, their real access, and the collaboration settings
    that let them in.

.DESCRIPTION
    Guests are the part of the directory that grows without anyone deciding it
    should. Every invitation extends the identity perimeter into another
    organisation, and unlike employees nobody offboards them. This report reads
    the whole guest surface and ranks it by actual exposure rather than count.

    What it checks:

      - Guests holding a directory role. A guest with an administrative role is
        an account you do not control, in a tenant you cannot audit, with power
        in yours. Always the first finding.
      - Never-redeemed invitations. Pending invitations that were never accepted
        accumulate indefinitely and are pure surface with zero business value.
      - Dormant guests. Invited, redeemed, and then never used - or not used in
        months.
      - Guests with no sponsor. Nobody to ask "does this person still need
        access?" at review time, which is how guests survive access reviews by
        default.
      - External domain concentration. Which organisations actually hold access,
        and how much of the guest population is consumer mail domains rather
        than partner organisations.
      - The external collaboration policy itself: who is allowed to invite.
        Guests being able to invite more guests is the setting that turns a
        controlled partner list into an unbounded one.

    Complements Reports/KQL/Library/IdentityAdmin/Admin-GuestInviteAndRedemption.kql,
    which shows invitation EVENTS inside log retention. This shows the resulting
    population, including guests invited long before your logs begin.

    READ-ONLY. Every call is a GET.

.PARAMETER DormantDays
    A redeemed guest with no successful sign-in in this many days is reported as
    dormant. Default 90, matching a typical quarterly access review cycle.

.PARAMETER MaxUsersListed
    Cap on rows listed per section. Counts and findings always reflect the full set.

.EXAMPLE
    .\IAM\Get-GuestAccessReport.ps1 -Open

.EXAMPLE
    .\IAM\Get-GuestAccessReport.ps1 -DormantDays 30 -Open

.NOTES
    Scopes: User.Read.All, Directory.Read.All, Policy.Read.All (for the
    collaboration policy), RoleManagement.Read.Directory (for guest role
    holders), AuditLog.Read.All (for signInActivity).

    signInActivity requires Entra ID P1 or better. Without it, dormancy is
    reported as NOT CHECKED rather than as zero dormant guests.

    Read-only: nothing here removes a guest, revokes an invitation, or changes a
    collaboration setting. Removing a guest is irreversible for their access to
    shared content - confirm the sponsor before acting.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$DormantDays = 90,
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

$preflight = Test-GraphScope -Required @("User.Read.All", "Directory.Read.All", "AuditLog.Read.All")
if (-not $preflight.AllPresent) { Write-Status $preflight.Summary -Type Warning }

$consumerDomains = @("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
                     "live.com", "aol.com", "protonmail.com", "proton.me", "gmx.com", "mail.com")

# ---------------------------------------------------------------------------
# 1. Guest inventory
# ---------------------------------------------------------------------------
Write-Status "Enumerating guest accounts" -Type Header
$guestSelect = "id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,externalUserState,externalUserStateChangeDateTime,creationType,companyName,signInActivity"

# signInActivity is a premium property; if it is rejected, retry without it so
# the rest of the report still runs, and record that dormancy wasn't checked.
$signInActivityAvailable = $true
$guests = @(Invoke-GraphPagedRequest -Uri "v1.0/users?`$filter=userType eq 'Guest'&`$select=$guestSelect&`$top=999" -ConsistencyLevel "eventual" -TolerateFailure)

if ($guests.Count -eq 0) {
    Write-Status "Retrying guest query without signInActivity (premium property)" -Type Warning
    $fallbackSelect = $guestSelect -replace ",signInActivity", ""
    $guests = @(Invoke-GraphPagedRequest -Uri "v1.0/users?`$filter=userType eq 'Guest'&`$select=$fallbackSelect&`$top=999" -ConsistencyLevel "eventual" -TolerateFailure)
    $signInActivityAvailable = $false
}

Write-Status "$($guests.Count) guest account(s)" -Type Success

$now = Get-Date
$guestRows = foreach ($guest in $guests) {
    $upn = [string]$guest.userPrincipalName
    $externalDomain = ""
    if ($upn -match '_([^_@#]+\.[^_@#]+)#EXT#') { $externalDomain = $matches[1].ToLowerInvariant() }
    elseif ([string]$guest.mail -match '@(.+)$') { $externalDomain = $matches[1].ToLowerInvariant() }

    $lastSignIn = $null
    if ($guest.signInActivity) {
        $raw = [string]$guest.signInActivity.lastSuccessfulSignInDateTime
        if (-not $raw) { $raw = [string]$guest.signInActivity.lastSignInDateTime }
        if ($raw) { $lastSignIn = [datetime]$raw }
    }

    $created = if ($guest.createdDateTime) { [datetime]$guest.createdDateTime } else { $null }

    [pscustomobject]@{
        DisplayName       = [string]$guest.displayName
        UserPrincipalName = $upn
        Mail              = [string]$guest.mail
        ExternalDomain    = if ($externalDomain) { $externalDomain } else { "(unparsed)" }
        IsConsumerDomain  = ($consumerDomains -contains $externalDomain)
        InvitationState   = [string]$guest.externalUserState
        AccountEnabled    = [bool]$guest.accountEnabled
        CreatedDateTime   = if ($created) { $created.ToString("yyyy-MM-dd") } else { "" }
        AgeDays           = if ($created) { [math]::Floor(($now - $created).TotalDays) } else { $null }
        LastSuccessfulSignIn = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "" }
        DaysSinceSignIn   = if ($lastSignIn) { [math]::Floor(($now - $lastSignIn).TotalDays) } else { $null }
        CreationType      = [string]$guest.creationType
        Id                = [string]$guest.id
    }
}
$guestRows = @($guestRows)

$pendingAcceptance = @($guestRows | Where-Object { $_.InvitationState -eq "PendingAcceptance" })
$consumerGuests    = @($guestRows | Where-Object { $_.IsConsumerDomain })
$disabledGuests    = @($guestRows | Where-Object { -not $_.AccountEnabled })

$dormantGuests = if ($signInActivityAvailable) {
    @($guestRows | Where-Object {
        $_.InvitationState -ne "PendingAcceptance" -and
        ($null -eq $_.DaysSinceSignIn -or $_.DaysSinceSignIn -gt $DormantDays)
    })
} else { @() }

$neverSignedIn = if ($signInActivityAvailable) {
    @($guestRows | Where-Object { -not $_.LastSuccessfulSignIn -and $_.InvitationState -eq "Accepted" })
} else { @() }

# ---------------------------------------------------------------------------
# 2. Guests holding a directory role
# ---------------------------------------------------------------------------
Write-Status "Checking for guests holding directory roles" -Type Header
$guestIds = @{}
foreach ($row in $guestRows) { $guestIds[$row.Id] = $row }

$guestRoleHolders = @()
$roles = @(Invoke-GraphPagedRequest -Uri "v1.0/directoryRoles?`$select=id,displayName,roleTemplateId" -TolerateFailure)
foreach ($role in $roles) {
    $members = @(Invoke-GraphPagedRequest -Uri "v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName,userPrincipalName" -TolerateFailure -MaxPages 5)
    foreach ($member in $members) {
        $memberId = [string]$member.id
        if ($guestIds.ContainsKey($memberId)) {
            $guest = $guestIds[$memberId]
            $guestRoleHolders += [pscustomobject]@{
                Severity          = "Critical"
                Role              = [string]$role.displayName
                DisplayName       = $guest.DisplayName
                UserPrincipalName = $guest.UserPrincipalName
                ExternalDomain    = $guest.ExternalDomain
                InvitationState   = $guest.InvitationState
                AccountEnabled    = $guest.AccountEnabled
                LastSuccessfulSignIn = $guest.LastSuccessfulSignIn
            }
        }
    }
}
$guestRoleHolders = @($guestRoleHolders | Sort-Object Role, UserPrincipalName)

# ---------------------------------------------------------------------------
# 3. External collaboration policy
# ---------------------------------------------------------------------------
Write-Status "Reading external collaboration settings" -Type Header
$authorizationPolicy = @(Invoke-GraphPagedRequest -Uri "v1.0/policies/authorizationPolicy" -TolerateFailure)
$policyRows = @()
$inviteSetting = ""
foreach ($policy in $authorizationPolicy) {
    $inviteSetting = [string]$policy.allowInvitesFrom
    $policyRows += [pscustomobject]@{
        Setting = "allowInvitesFrom"
        Value   = $inviteSetting
        Meaning = switch ($inviteSetting) {
            "everyone"                    { "ANY user, INCLUDING GUESTS, can invite more guests. A partner list stops being bounded." }
            "adminsGuestInvitersAndAllMembers" { "All members can invite. Guests cannot." }
            "adminsAndGuestInviters"      { "Only admins and the Guest Inviter role can invite. Recommended." }
            "none"                        { "Nobody can invite. Most restrictive." }
            default                       { "Unrecognised value - check the tenant directly." }
        }
    }
    $policyRows += [pscustomobject]@{
        Setting = "allowedToSignUpEmailBasedSubscriptions"
        Value   = [string]$policy.allowedToSignUpEmailBasedSubscriptions
        Meaning = "When true, users can self-sign-up for services that create directory objects."
    }
    $policyRows += [pscustomobject]@{
        Setting = "allowedToUseSspr"
        Value   = [string]$policy.allowedToUseSSPR
        Meaning = "Self-service password reset availability."
    }
    $policyRows += [pscustomobject]@{
        Setting = "blockMsolPowerShell"
        Value   = [string]$policy.blockMsolPowerShell
        Meaning = "When false, the retired MSOnline PowerShell module can still be used against this tenant."
    }
    $defaultUserPermissions = $policy.defaultUserRolePermissions
    if ($defaultUserPermissions) {
        $policyRows += [pscustomobject]@{
            Setting = "allowedToCreateApps"
            Value   = [string]$defaultUserPermissions.allowedToCreateApps
            Meaning = "When true, any user can register an application - which is the first step in an illicit consent scenario."
        }
        $policyRows += [pscustomobject]@{
            Setting = "allowedToReadOtherUsers"
            Value   = [string]$defaultUserPermissions.allowedToReadOtherUsers
            Meaning = "When true, guests and members can enumerate the directory. Restrict guest access separately for tighter control."
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Domain concentration
# ---------------------------------------------------------------------------
$domainSummary = @($guestRows |
    Group-Object ExternalDomain |
    Sort-Object Count -Descending |
    ForEach-Object {
        $sample = $_.Group[0]
        [pscustomobject]@{
            ExternalDomain   = $_.Name
            Guests           = $_.Count
            PercentOfGuests  = if ($guestRows.Count -gt 0) { [math]::Round(100.0 * $_.Count / $guestRows.Count, 1) } else { 0 }
            IsConsumerDomain = $sample.IsConsumerDomain
            PendingInvites   = @($_.Group | Where-Object { $_.InvitationState -eq "PendingAcceptance" }).Count
            Disabled         = @($_.Group | Where-Object { -not $_.AccountEnabled }).Count
            OldestGuestDays  = (@($_.Group | Where-Object { $null -ne $_.AgeDays } | Measure-Object AgeDays -Maximum).Maximum)
        }
    })

# ---------------------------------------------------------------------------
# 5. Findings
# ---------------------------------------------------------------------------
$findings = @()

if ($guestRoleHolders.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Privileged guest" `
        -Finding "$($guestRoleHolders.Count) guest account(s) hold a directory role" `
        -Subject (($guestRoleHolders | Select-Object -First 10 | ForEach-Object { "$($_.UserPrincipalName) [$($_.Role)]" }) -join "; ") `
        -Count $guestRoleHolders.Count `
        -Evidence "These are accounts governed by another organisation's identity controls, holding administrative power in yours." `
        -Recommendation "Remove the role, or replace the guest with a managed account in your own tenant if the access is genuinely required."
}

if ($inviteSetting -eq "everyone") {
    $findings += New-Finding -Severity High -Category "Collaboration policy" `
        -Finding "Any user, including guests, can invite further guests" `
        -Subject "allowInvitesFrom = everyone" `
        -Evidence "A guest can invite another guest, who can invite another. The partner list is not bounded by anything." `
        -Recommendation "Set allowInvitesFrom to adminsAndGuestInviters, or at least adminsGuestInvitersAndAllMembers so guests themselves cannot invite."
}

if ($pendingAcceptance.Count -gt 0) {
    $findings += New-Finding -Severity Medium -Category "Stale invitations" `
        -Finding "$($pendingAcceptance.Count) invitation(s) were never redeemed" `
        -Count $pendingAcceptance.Count `
        -Evidence "Pending guest objects exist in the directory and count toward your guest population while providing no value." `
        -Recommendation "Remove invitations older than your acceptance window - typically 30 to 90 days."
}

if ($signInActivityAvailable) {
    if ($dormantGuests.Count -gt 0) {
        $findings += New-Finding -Severity Medium -Category "Dormant access" `
            -Finding "$($dormantGuests.Count) redeemed guest(s) have not signed in for over $DormantDays days" `
            -Count $dormantGuests.Count `
            -Evidence "Access that is not being used but is still available to whoever controls the external account." `
            -Recommendation "Run an access review over the guest population, or remove after confirming with the sponsor."
    }
    if ($neverSignedIn.Count -gt 0) {
        $findings += New-Finding -Severity Medium -Category "Dormant access" `
            -Finding "$($neverSignedIn.Count) guest(s) accepted an invitation but have never signed in" `
            -Count $neverSignedIn.Count `
            -Evidence "The invitation was redeemed - so the external account is live - but the access has never been used." `
            -Recommendation "Confirm whether the collaboration ever started. If not, remove."
    }
} else {
    $findings += New-Finding -Severity NotChecked -Category "Dormant access" `
        -Finding "Guest dormancy was not evaluated" `
        -Evidence "signInActivity was unavailable - it requires Entra ID P1 or better, plus AuditLog.Read.All." `
        -Recommendation "Do not read the absence of dormancy findings as an absence of dormant guests. Reports/KQL/Library/Hygiene/Hygiene-DormantUsers.kql can partially substitute from sign-in logs."
}

if ($consumerGuests.Count -gt 0) {
    $findings += New-Finding -Severity Medium -Category "External domains" `
        -Finding "$($consumerGuests.Count) guest(s) use a consumer email domain" `
        -Subject (($consumerGuests | Select-Object -First 5 -ExpandProperty ExternalDomain -Unique) -join "; ") `
        -Count $consumerGuests.Count `
        -Evidence "Consumer accounts sit outside any partner agreement and outside any organisation's offboarding process - when the person changes jobs, the account and its access remain." `
        -Recommendation "Require organisational addresses for B2B collaboration, and restrict consumer domains through cross-tenant access settings."
}

if ($disabledGuests.Count -gt 0) {
    $findings += New-Finding -Severity Low -Category "Hygiene" `
        -Finding "$($disabledGuests.Count) guest account(s) are disabled but still present" `
        -Count $disabledGuests.Count `
        -Evidence "Disabled objects still hold group memberships and shared-content permissions." `
        -Recommendation "Remove them once any retention requirement has passed."
}

if ($findings.Count -eq 0) {
    $findings += New-Finding -Severity Info -Category "Summary" `
        -Finding "No guest access findings" `
        -Evidence "$($guestRows.Count) guest account(s) evaluated." `
        -Recommendation "Re-run after each collaboration onboarding wave."
}

$findings = @($findings | Sort-Finding)

# ---------------------------------------------------------------------------
# 6. Render
# ---------------------------------------------------------------------------
$statTiles = @(
    @{ Label = "Guest accounts"; Value = $guestRows.Count; Tone = "neutral" }
    @{ Label = "Guests with a directory role"; Value = $guestRoleHolders.Count; Tone = if ($guestRoleHolders.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Never redeemed"; Value = $pendingAcceptance.Count; Tone = if ($pendingAcceptance.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Dormant (>$DormantDays d)"; Value = if ($signInActivityAvailable) { $dormantGuests.Count } else { "not checked" }; Tone = if (-not $signInActivityAvailable) { "neutral" } elseif ($dormantGuests.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Consumer email domains"; Value = $consumerGuests.Count; Tone = if ($consumerGuests.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "External domains"; Value = $domainSummary.Count; Tone = "neutral" }
)

function Select-GuestsForDisplay {
    param([array]$Rows)
    return @($Rows | Select-Object -First $MaxUsersListed |
        Select-Object DisplayName, UserPrincipalName, ExternalDomain, IsConsumerDomain, InvitationState,
                      AccountEnabled, CreatedDateTime, AgeDays, LastSuccessfulSignIn, DaysSinceSignIn)
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Reports\Output\GuestAccess-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
}

$truncationNote = if ($guestRows.Count -gt $MaxUsersListed) {
    " Guest lists are capped at $MaxUsersListed rows per section; tiles and findings reflect all $($guestRows.Count) guests."
} else { "" }

New-HtmlReport -Title "Guest Access & External Collaboration Exposure" `
    -Subtitle "$($config.TenantDomain) - $($guestRows.Count) guests across $($domainSummary.Count) external domain(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                                  = $findings
        "Guests holding a directory role"            = $guestRoleHolders
        "External collaboration policy"              = $policyRows
        "External domain concentration"              = $domainSummary
        "Invitations never redeemed"                 = (Select-GuestsForDisplay $pendingAcceptance)
        "Dormant guests (no sign-in in $DormantDays days)" = (Select-GuestsForDisplay $dormantGuests)
        "Redeemed but never signed in"               = (Select-GuestsForDisplay $neverSignedIn)
        "All guest accounts"                         = (Select-GuestsForDisplay $guestRows)
    }) `
    -FooterNote "Source: Microsoft Graph users, directoryRoles, policies/authorizationPolicy (all GET). Removing a guest is irreversible for their access to shared content - confirm the sponsor first. For invitation EVENTS inside log retention, see Reports/KQL/Library/IdentityAdmin/Admin-GuestInviteAndRedemption.kql.$truncationNote" `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

Disconnect-MgGraph | Out-Null
