<#
.SYNOPSIS
    Checklist-style audit of the CA policies actually deployed in the
    tenant right now (any baseline, any mix) — finds the big structural and
    risk gaps: missing coverage, dangerous exclusions, and dead weight.

.DESCRIPTION
    Different from Get-ConditionalAccessGapReport.ps1 (which resolves real
    user coverage for existing policies) — this one asks a different
    question: "does the policy SET as a whole cover the things a baseline
    should?" Runs a fixed checklist against whatever policies exist,
    independent of which CAPs/Baselines/*.json (if any) produced them:

      - Legacy authentication blocked anywhere?
      - Baseline MFA required for all users anywhere?
      - Admin/privileged roles required to use strong auth (MFA or
        authentication strength) anywhere?
      - High-risk sign-ins / high-risk users blocked anywhere? (Identity
        Protection, requires P2 — reported as "not checked" if absent)
      - Guest/external users restricted anywhere?
      - Managed device required anywhere?
      - Break-glass accounts excluded from every policy that could lock
        them out (grant = block, or requires MFA/device/auth strength) —
        flags the single most dangerous CA misconfiguration: no working
        emergency access account.
      - Report-only policies sitting unreviewed past a staleness threshold
      - Disabled policies (dead weight) and no-op policies (no real grant
        or session controls)

.PARAMETER StaleReportOnlyDays
    Report-only policies older than this are flagged as overdue for review.
    Default 30.

.EXAMPLE
    .\IAM\Get-CAPolicyHealthReport.ps1 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$StaleReportOnlyDays = 30,
    [switch]$Open
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Status "Fetching Conditional Access policies" -Type Header
$policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue)
$enabled  = @($policies | Where-Object { $_.State -eq "enabled" })

function Test-GrantMatches {
    param($Policy, [string[]]$AnyOfBuiltIn, [bool]$OrAuthStrength = $false)
    if (-not $Policy.GrantControls) { return $false }
    $builtIn = @($Policy.GrantControls.BuiltInControls)
    if (($builtIn | Where-Object { $AnyOfBuiltIn -contains $_ }).Count -gt 0) { return $true }
    if ($OrAuthStrength -and $Policy.GrantControls.AuthenticationStrength) { return $true }
    return $false
}

function Test-TargetsAllUsers {
    param($Policy)
    return (@($Policy.Conditions.Users.IncludeUsers) -contains "All")
}

function Test-TargetsRoles {
    param($Policy)
    return (@($Policy.Conditions.Users.IncludeRoles).Count -gt 0)
}

function Test-CouldLockOut {
    param($Policy)
    if ($Policy.State -ne "enabled") { return $false }
    if (Test-GrantMatches -Policy $Policy -AnyOfBuiltIn @("block")) { return $true }
    if (Test-GrantMatches -Policy $Policy -AnyOfBuiltIn @("mfa", "compliantDevice", "domainJoinedDevice") -OrAuthStrength $true) {
        return (Test-TargetsAllUsers -Policy $Policy) -or (@($Policy.Conditions.Users.IncludeGroups).Count -gt 0) -or (Test-TargetsRoles -Policy $Policy)
    }
    return $false
}

$legacyAuthBlocked = @($enabled | Where-Object {
    (@($_.Conditions.ClientAppTypes) -contains "exchangeActiveSync" -or @($_.Conditions.ClientAppTypes) -contains "other") -and
    (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("block"))
})

$baselineMfaAllUsers = @($enabled | Where-Object {
    (Test-TargetsAllUsers -Policy $_) -and (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("mfa") -OrAuthStrength $true)
})

$adminStrongAuth = @($enabled | Where-Object {
    (Test-TargetsRoles -Policy $_) -and (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("mfa", "compliantDevice", "domainJoinedDevice") -OrAuthStrength $true)
})

$highRiskSignInBlocked = @($enabled | Where-Object {
    @($_.Conditions.SignInRiskLevels) -contains "high" -and (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("block", "mfa"))
})

$highRiskUserBlocked = @($enabled | Where-Object {
    @($_.Conditions.UserRiskLevels) -contains "high" -and (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("block", "mfa", "passwordChange"))
})

$guestsRestricted = @($enabled | Where-Object {
    @($_.Conditions.Users.IncludeUsers) -contains "GuestsOrExternalUsers" -or
    ($_.Conditions.Users.IncludeGuestsOrExternalUsers -and $_.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes)
})

$deviceRequiredAnywhere = @($enabled | Where-Object { Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("compliantDevice", "domainJoinedDevice") })

Write-Status "Checking break-glass exclusion coverage" -Type Header
$breakGlassUpns = @($config.Users.BreakGlassUpn, $config.Users.BreakGlassUpn2) | Where-Object { $_ } | ForEach-Object { "$_@$($config.TenantDomain)" }
$breakGlassIds = @()
foreach ($upn in $breakGlassUpns) {
    $u = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
    if ($u) { $breakGlassIds += $u.Id }
}

$lockoutRiskPolicies = @()
foreach ($policy in ($enabled | Where-Object { Test-CouldLockOut $_ })) {
    $excluded = @($policy.Conditions.Users.ExcludeUsers)
    $missingExclusion = @($breakGlassIds | Where-Object { $excluded -notcontains $_ })
    if ($missingExclusion.Count -gt 0) {
        $lockoutRiskPolicies += [pscustomobject]@{
            DisplayName = $policy.DisplayName
            GrantSummary = ((@($policy.GrantControls.BuiltInControls)) -join ", ")
            BreakGlassExcluded = $false
        }
    }
}

$now = Get-Date
$staleReportOnly = @($policies | Where-Object {
    $_.State -eq "enabledForReportingButNotEnforced" -and $_.CreatedDateTime -and
    ((New-TimeSpan -Start ([datetime]$_.CreatedDateTime) -End $now).TotalDays -gt $StaleReportOnlyDays)
} | Select-Object DisplayName, CreatedDateTime, @{N="AgeDays"; E={[math]::Floor((New-TimeSpan -Start ([datetime]$_.CreatedDateTime) -End $now).TotalDays)}})

$disabledPolicies = @($policies | Where-Object { $_.State -eq "disabled" } | Select-Object DisplayName, CreatedDateTime)

$noOpPolicies = @($policies | Where-Object {
    -not (Test-GrantMatches -Policy $_ -AnyOfBuiltIn @("block","mfa","compliantDevice","domainJoinedDevice","passwordChange") -OrAuthStrength $true) -and
    -not $_.SessionControls
} | Select-Object DisplayName, State)

function New-Check {
    param([string]$Name, [bool]$Pass, [array]$SupportingPolicies)
    [pscustomobject]@{
        Check   = $Name
        Result  = if ($Pass) { "Pass" } else { "Gap" }
        Evidence = if (@($SupportingPolicies).Count -gt 0) { (@($SupportingPolicies | Select-Object -ExpandProperty DisplayName) -join "; ") } else { "(none found)" }
    }
}

$checks = @(
    New-Check -Name "Legacy authentication blocked" -Pass ($legacyAuthBlocked.Count -gt 0) -SupportingPolicies $legacyAuthBlocked
    New-Check -Name "Baseline MFA required for all users" -Pass ($baselineMfaAllUsers.Count -gt 0) -SupportingPolicies $baselineMfaAllUsers
    New-Check -Name "Admin/privileged roles require strong auth" -Pass ($adminStrongAuth.Count -gt 0) -SupportingPolicies $adminStrongAuth
    New-Check -Name "High-risk sign-ins blocked/challenged (P2)" -Pass ($highRiskSignInBlocked.Count -gt 0) -SupportingPolicies $highRiskSignInBlocked
    New-Check -Name "High-risk users blocked/remediated (P2)" -Pass ($highRiskUserBlocked.Count -gt 0) -SupportingPolicies $highRiskUserBlocked
    New-Check -Name "Guest/external users restricted" -Pass ($guestsRestricted.Count -gt 0) -SupportingPolicies $guestsRestricted
    New-Check -Name "Managed device required somewhere" -Pass ($deviceRequiredAnywhere.Count -gt 0) -SupportingPolicies $deviceRequiredAnywhere
)

$statTiles = @(
    @{ Label = "Checklist gaps"; Value = @($checks | Where-Object { $_.Result -eq "Gap" }).Count; Tone = if (@($checks | Where-Object { $_.Result -eq "Gap" }).Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Policies that could lock out break-glass"; Value = $lockoutRiskPolicies.Count; Tone = if ($lockoutRiskPolicies.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Report-only policies overdue for review"; Value = $staleReportOnly.Count; Tone = if ($staleReportOnly.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "No-op / disabled policies"; Value = ($noOpPolicies.Count + $disabledPolicies.Count); Tone = if (($noOpPolicies.Count + $disabledPolicies.Count) -gt 0) { "warn" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\CAPolicyHealth-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Conditional Access Policy Health Check" `
    -Subtitle "$($config.TenantDomain) — $($policies.Count) policies evaluated ($($enabled.Count) enabled)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Policies that could lock out break-glass (no exclusion)" = $lockoutRiskPolicies
        "Coverage checklist"                                      = $checks
        "Report-only policies overdue for review"                 = $staleReportOnly
        "Disabled policies"                                       = $disabledPolicies
        "No-op policies (no real grant/session controls)"         = $noOpPolicies
    }) `
    -FooterNote "Source: Microsoft Graph identity/conditionalAccess/policies. Checklist evaluates the enabled policy set as a whole, independent of which baseline (if any) produced it." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
