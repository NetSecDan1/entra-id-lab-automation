<#
.SYNOPSIS
    Finds stale sign-ins, disabled-but-still-licensed accounts, and guests
    overdue for review — the accounts an access review or offboarding sweep
    would normally catch, surfaced ahead of time.

.DESCRIPTION
    Three buckets, each a governance gap in its own right:
      - Stale members : accountEnabled, but no sign-in in -StaleDays (or never)
      - Disabled but licensed : accountEnabled = false with an active license
                                 assignment still burning a seat
      - Overdue guests : userType Guest, created longer ago than
                          config.Governance.GuestReviewIntervalMonths, i.e.
                          past due for the access review cadence this repo
                          configures in Deploy-AccessReviews.ps1

    Needs AuditLog.Read.All for signInActivity — already requested by
    Connect-TestTenant's device-code fallback scope list.

.PARAMETER StaleDays
    Days without sign-in before a member account counts as stale. Default 90.

.EXAMPLE
    .\IAM\Get-StaleAccountsReport.ps1 -StaleDays 60 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$StaleDays = 90,
    [switch]$Open
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Status "Fetching all users (this can take a moment on larger tenants)" -Type Header
$allUsers = Get-MgUser -All -Property "id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses,signInActivity" -ErrorAction SilentlyContinue

$staleCutoff = (Get-Date).AddDays(-$StaleDays)
$guestReviewMonths = if ($config.Governance -and $config.Governance.GuestReviewIntervalMonths) { [int]$config.Governance.GuestReviewIntervalMonths } else { 3 }
$guestOverdueCutoff = (Get-Date).AddMonths(-$guestReviewMonths)

$staleMembers = @($allUsers | Where-Object {
    $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" -and
    ($null -eq $_.SignInActivity.LastSignInDateTime -or [datetime]$_.SignInActivity.LastSignInDateTime -lt $staleCutoff)
} | Select-Object DisplayName, UserPrincipalName,
    @{N="LastSignIn"; E={ if ($_.SignInActivity.LastSignInDateTime) { $_.SignInActivity.LastSignInDateTime } else { "Never" } }},
    @{N="AccountCreated"; E={$_.CreatedDateTime}})

$disabledLicensed = @($allUsers | Where-Object { $_.AccountEnabled -eq $false -and @($_.AssignedLicenses).Count -gt 0 } |
    Select-Object DisplayName, UserPrincipalName, @{N="LicenseCount"; E={@($_.AssignedLicenses).Count}})

$overdueGuests = @($allUsers | Where-Object {
    $_.UserType -eq "Guest" -and $_.CreatedDateTime -and [datetime]$_.CreatedDateTime -lt $guestOverdueCutoff
} | Select-Object DisplayName, UserPrincipalName,
    @{N="AccountCreated"; E={$_.CreatedDateTime}},
    @{N="LastSignIn"; E={ if ($_.SignInActivity.LastSignInDateTime) { $_.SignInActivity.LastSignInDateTime } else { "Never" } }})

$statTiles = @(
    @{ Label = "Stale members (>$StaleDays d)"; Value = $staleMembers.Count; Tone = if ($staleMembers.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Disabled but licensed"; Value = $disabledLicensed.Count; Tone = if ($disabledLicensed.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Guests overdue for review"; Value = $overdueGuests.Count; Tone = if ($overdueGuests.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Total users scanned"; Value = @($allUsers).Count; Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\StaleAccounts-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Stale Accounts & Guest Review Gaps" `
    -Subtitle "$($config.TenantDomain) — stale threshold $StaleDays days, guest review cadence $guestReviewMonths month(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Disabled but still licensed" = $disabledLicensed
        "Stale member accounts"       = $staleMembers
        "Guests overdue for review"   = $overdueGuests
    }) `
    -FooterNote "Source: Microsoft Graph /users with signInActivity. 'Never' means no interactive or non-interactive sign-in recorded in the sign-in activity retention window." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
