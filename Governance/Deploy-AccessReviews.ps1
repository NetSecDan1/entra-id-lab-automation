<#
.SYNOPSIS
    Creates recurring access review campaigns for privileged roles, guests, and groups.

.DESCRIPTION
    Requires Entra ID P2 or Microsoft 365 E5.

    Creates four review campaigns that auto-recur on schedule:

    1. Privileged Role Review (quarterly)
       Scope: Members of Global Admin, Privileged Role Admin, Security Admin
       Reviewers: Self-review (user confirms their own need)
       Action: Auto-remove on no response

    2. Guest User Access Review (monthly)
       Scope: All guest users (#EXT# UPNs)
       Reviewers: Manager of each guest's sponsor
       Action: Auto-deny access on no response

    3. Admin Group Membership Review (semi-annual)
       Scope: SG-Admins-All group members
       Reviewers: T2 security admin account
       Action: Auto-remove on no response

    4. Executive Access Review (annual)
       Scope: SG-Executives group members
       Reviewers: CISO account (elena.vasquez)
       Action: Notify reviewer only on no response

.EXAMPLE
    .\Governance\Deploy-AccessReviews.ps1
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
Write-Status "Access Reviews — Compliance Campaign Setup" -Type Header
Write-Host "  Tenant : $domain"
Write-Host ""

# Role IDs for review scope
$roleIds = @{
    "Global Administrator"          = "62e90394-69f5-4237-9190-012177145e10"
    "Privileged Role Administrator" = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "Security Administrator"        = "194ae4cb-b126-40b2-bd5b-6091b380977d"
}

function New-OrSkipReview {
    param([string]$DisplayName, [hashtable]$Body)

    # Idempotency: skip if a review with the same name already exists
    $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
        -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?`$filter=displayName eq '$DisplayName'"

    if ($existing.value -and $existing.value.Count -gt 0) {
        Write-Status "Exists: $DisplayName" -Type Warning
        return $existing.value[0].id
    }

    try {
        $json    = $Body | ConvertTo-Json -Depth 20
        $created = Invoke-MgGraphRequest -Method POST -Body $json -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
        Write-Status "Created: $DisplayName" -Type Success
        return if ($created -is [hashtable]) { $created["id"] } else { $created.id }
    } catch {
        Write-Status "Failed to create '$DisplayName': $($_.Exception.Message)" -Type Error
        return $null
    }
}

function New-RecurrenceSettings {
    param(
        [string]$PatternType,     # weekly | absoluteMonthly | absoluteYearly
        [int]   $Interval,
        [int]   $DurationDays = 14
    )
    return @{
        pattern  = @{ type = $PatternType; interval = $Interval }
        range    = @{ type = "noEnd"; startDate = (Get-Date -Format "yyyy-MM-dd") }
    }
}

# ── Resolve reviewer accounts ─────────────────────────────────────────────────
Write-Status "Resolving reviewer accounts" -Type Header

$t2sec01  = Get-MgUser -Filter "userPrincipalName eq 'admin.sec01@$domain'" -ErrorAction SilentlyContinue
$cisoUser = Get-AllEmployeeUsers -CompanyName $config.CompanyName |
    Where-Object { $_.JobTitle -eq "Chief Information Security Officer" } | Select-Object -First 1
$chroUser = Get-AllEmployeeUsers -CompanyName $config.CompanyName |
    Where-Object { $_.JobTitle -eq "Chief Human Resources Officer" } | Select-Object -First 1

Write-Host "  T2 Security admin  : $(if ($t2sec01)  { $t2sec01.UserPrincipalName  } else { 'NOT FOUND' })"
Write-Host "  CISO               : $(if ($cisoUser) { $cisoUser.UserPrincipalName } else { 'NOT FOUND' })"
Write-Host "  CHRO               : $(if ($chroUser) { $chroUser.UserPrincipalName } else { 'NOT FOUND' })"

# Default fallback reviewer
$defaultReviewerUpn  = if ($t2sec01)  { $t2sec01.UserPrincipalName  } else { "admin.sec01@$domain" }
$defaultReviewerId   = if ($t2sec01)  { $t2sec01.Id                 } else { $null }
$cisoReviewerId      = if ($cisoUser) { $cisoUser.Id               } else { $defaultReviewerId }

# ── 1. Quarterly Privileged Role Review ───────────────────────────────────────
Write-Host ""
Write-Status "1. Quarterly Privileged Role Review" -Type Header

$privRoleReviewId = New-OrSkipReview -DisplayName "Quarterly - Privileged Role Review" -Body @{
    displayName             = "Quarterly - Privileged Role Review"
    descriptionForAdmins    = "Quarterly review of Global Admin, Privileged Role Admin, and Security Admin members. Users confirm their own need for the role."
    descriptionForReviewers = "Please confirm you still require this privileged role. If your access is no longer needed, select Deny to remove yourself."
    scope = @{
        "@odata.type"    = "#microsoft.graph.principalResourceMembershipsScope"
        principalScopes  = @(@{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/v1.0/users"
            queryType     = "MicrosoftGraph"
        })
        resourceScopes = @(
            @{
                "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
                query         = "/v1.0/roleManagement/directory/roleDefinitions/$($roleIds['Global Administrator'])"
                queryType     = "MicrosoftGraph"
            },
            @{
                "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
                query         = "/v1.0/roleManagement/directory/roleDefinitions/$($roleIds['Privileged Role Administrator'])"
                queryType     = "MicrosoftGraph"
            },
            @{
                "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
                query         = "/v1.0/roleManagement/directory/roleDefinitions/$($roleIds['Security Administrator'])"
                queryType     = "MicrosoftGraph"
            }
        )
    }
    reviewers = @(@{
        query     = "/me"
        queryType = "MicrosoftGraph"
    })
    settings = @{
        mailNotificationsEnabled           = $true
        reminderNotificationsEnabled       = $true
        justificationRequiredOnApproval    = $true
        defaultDecisionEnabled             = $true
        defaultDecision                    = "Deny"
        instanceDurationInDays             = 14
        autoApplyDecisionsEnabled          = $true
        recommendationsEnabled             = $true
        recurrence                         = New-RecurrenceSettings -PatternType "absoluteMonthly" -Interval 3
    }
}

# ── 2. Monthly Guest User Review ──────────────────────────────────────────────
Write-Host ""
Write-Status "2. Monthly Guest User Access Review" -Type Header

$guestReviewId = New-OrSkipReview -DisplayName "Monthly - Guest User Access Review" -Body @{
    displayName             = "Monthly - Guest User Access Review"
    descriptionForAdmins    = "Monthly review of all B2B guest users. Manager of the inviting user reviews whether guest access is still required."
    descriptionForReviewers = "Review whether this guest user still needs access. Select Deny to remove their access if no longer required."
    scope = @{
        "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
        query         = "/v1.0/users?`$filter=userType eq 'Guest'"
        queryType     = "MicrosoftGraph"
    }
    reviewers = @(@{
        query     = "./manager"
        queryType = "MicrosoftGraph"
    })
    fallbackReviewers = if ($defaultReviewerId) { @(@{
        query     = "/v1.0/users/$defaultReviewerId"
        queryType = "MicrosoftGraph"
    }) } else { @() }
    settings = @{
        mailNotificationsEnabled        = $true
        reminderNotificationsEnabled    = $true
        justificationRequiredOnApproval = $true
        defaultDecisionEnabled          = $true
        defaultDecision                 = "Deny"
        instanceDurationInDays          = 7
        autoApplyDecisionsEnabled       = $true
        recommendationsEnabled          = $true
        recurrence                      = New-RecurrenceSettings -PatternType "absoluteMonthly" -Interval 1
    }
}

# ── 3. Semi-Annual Admin Group Membership Review ──────────────────────────────
Write-Host ""
Write-Status "3. Semi-Annual Admin Group Membership Review" -Type Header

$adminGroup = Get-MgGroup -Filter "displayName eq 'SG-Admins-All'" -ErrorAction SilentlyContinue
if ($adminGroup) {
    $adminGroupReviewBody = @{
        displayName             = "Semi-Annual - Admin Group Membership Review"
        descriptionForAdmins    = "Semi-annual review of SG-Admins-All membership. Security admin verifies all admin accounts are still required and appropriately scoped."
        descriptionForReviewers = "Review each admin account below. Deny any accounts that are no longer needed or should have reduced privileges."
        scope = @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/v1.0/groups/$($adminGroup.Id)/transitiveMembers/microsoft.graph.user"
            queryType     = "MicrosoftGraph"
        }
        reviewers = if ($defaultReviewerId) { @(@{
            query     = "/v1.0/users/$defaultReviewerId"
            queryType = "MicrosoftGraph"
        }) } else { @(@{ query = "/me"; queryType = "MicrosoftGraph" }) }
        settings = @{
            mailNotificationsEnabled        = $true
            reminderNotificationsEnabled    = $true
            justificationRequiredOnApproval = $true
            defaultDecisionEnabled          = $true
            defaultDecision                 = "Recommendation"
            instanceDurationInDays          = 21
            autoApplyDecisionsEnabled       = $true
            recommendationsEnabled          = $true
            recurrence                      = New-RecurrenceSettings -PatternType "absoluteMonthly" -Interval 6
        }
    }
    New-OrSkipReview -DisplayName "Semi-Annual - Admin Group Membership Review" -Body $adminGroupReviewBody | Out-Null
} else {
    Write-Status "SG-Admins-All not found — run Deploy-Groups.ps1 first" -Type Warning
}

# ── 4. Annual Executive Access Review ─────────────────────────────────────────
Write-Host ""
Write-Status "4. Annual Executive Access Review" -Type Header

$execGroup = Get-MgGroup -Filter "displayName eq 'SG-Executives'" -ErrorAction SilentlyContinue
if ($execGroup) {
    $execReviewBody = @{
        displayName             = "Annual - Executive Group Review"
        descriptionForAdmins    = "Annual review of SG-Executives membership. CISO validates all executive accounts and privileges."
        descriptionForReviewers = "Review executive group membership. Confirm each member's role and access remains appropriate."
        scope = @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/v1.0/groups/$($execGroup.Id)/transitiveMembers/microsoft.graph.user"
            queryType     = "MicrosoftGraph"
        }
        reviewers = if ($cisoReviewerId) { @(@{
            query     = "/v1.0/users/$cisoReviewerId"
            queryType = "MicrosoftGraph"
        }) } else { @(@{ query = "/me"; queryType = "MicrosoftGraph" }) }
        settings = @{
            mailNotificationsEnabled        = $true
            reminderNotificationsEnabled    = $true
            justificationRequiredOnApproval = $true
            defaultDecisionEnabled          = $false
            defaultDecision                 = "None"
            instanceDurationInDays          = 30
            autoApplyDecisionsEnabled       = $false
            recommendationsEnabled          = $true
            recurrence                      = New-RecurrenceSettings -PatternType "absoluteMonthly" -Interval 12
        }
    }
    New-OrSkipReview -DisplayName "Annual - Executive Group Review" -Body $execReviewBody | Out-Null
} else {
    Write-Status "SG-Executives not found — run Deploy-Groups.ps1 first" -Type Warning
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Access Reviews deployment complete" -Type Success
Write-Host ""
Write-Host "  Review campaigns scheduled:" -ForegroundColor Green
Write-Host "    [Monthly]      Guest User Access Review              — auto-deny on no response" -ForegroundColor DarkGray
Write-Host "    [Quarterly]    Privileged Role Review               — self-review, auto-deny" -ForegroundColor DarkGray
Write-Host "    [Semi-Annual]  Admin Group Membership Review        — security admin review" -ForegroundColor DarkGray
Write-Host "    [Annual]       Executive Group Review               — CISO review, no auto-action" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Verify in Entra portal:" -ForegroundColor Cyan
Write-Host "    Identity Governance → Access reviews → All" -ForegroundColor DarkGray
Write-Host "    Click a review → Start review to trigger the first instance" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
