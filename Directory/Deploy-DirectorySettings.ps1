<#
.SYNOPSIS
    Configures tenant-level directory settings for the test tenant.

.DESCRIPTION
    Applies:
      - External Collaboration (B2B guest access restrictions)
      - Self-service group management settings
      - User consent settings (app consent policy)
      - LinkedIn account connections (disabled for test tenant)
      - Authorization policy (default user role permissions)
      - Password protection settings (display only — read from org)

    Uses both v1.0 and beta Graph endpoints where needed.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$dir    = $config.Directory

# ── Organization / Tenant Info ────────────────────────────────────────────────
Write-Status "Organization info" -Type Header
$org = Get-MgOrganization | Select-Object -First 1
Write-Host "  Tenant ID   : $($org.Id)"
Write-Host "  Display Name: $($org.DisplayName)"
Write-Host "  Domains     : $($org.VerifiedDomains.Name -join ', ')"

# ── External Collaboration (Guest Access) ─────────────────────────────────────
Write-Status "External collaboration / guest settings" -Type Header
try {
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
        -Body (@{
            allowInvitesFrom                  = $dir.AllowInvitesFrom   # "adminsAndGuestInviters" | "admins" | "everyone" | "none"
            allowEmailVerifiedUsersToJoinOrganization = $dir.AllowEmailVerifiedUsers
            guestUserRoleId                   = "10dae51f-b6af-4016-8d66-8c2a99b929b3"  # Guest User (most restrictive)
            # Options:
            #   10dae51f-b6af-4016-8d66-8c2a99b929b3  = Restricted Guest User
            #   bf6f3900-7bcd-4af5-a1c5-24c3e82f6f05  = Guest User
            #   a0b1b346-4d3e-4e8b-98f8-753987be4970  = Member User (same as members — broad access)
        } | ConvertTo-Json) `
        -ContentType "application/json" | Out-Null
    Write-Status "Guest access policy updated (allowInvitesFrom: $($dir.AllowInvitesFrom))" -Type Success
} catch {
    Write-Status "Authorization policy update failed: $_" -Type Warning
}

# ── External Collaboration Settings (B2B) ─────────────────────────────────────
Write-Status "B2B external collaboration settings" -Type Header
try {
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/policies/externalIdentitiesPolicy" `
        -Body (@{
            allowExternalIdentitiesToLeave      = $true
            allowDeletedIdentitiesDataRemoval   = $false
        } | ConvertTo-Json) `
        -ContentType "application/json" | Out-Null
    Write-Status "External identities policy updated" -Type Success
} catch {
    Write-Status "External identities policy update failed (may need P1): $_" -Type Warning
}

# ── Self-Service Group Management ─────────────────────────────────────────────
Write-Status "Self-service group management" -Type Header
try {
    # Check if directory setting exists
    $settings = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groupSettings" |
        Select-Object -ExpandProperty value

    $groupSettingTemplateId = "62375ab9-6b52-47ed-826b-58e47e0e304b"  # Group.Unified template

    $unifiedSetting = $settings | Where-Object { $_.templateId -eq $groupSettingTemplateId }

    $desiredValues = @(
        @{ name = "EnableGroupCreation";              value = "true"  }
        @{ name = "EnableMSStandardBlockedWords";     value = "false" }
        @{ name = "AllowGuestsToBeGroupOwner";        value = "false" }
        @{ name = "AllowGuestsToAccessGroups";        value = "true"  }
        @{ name = "AllowToAddGuests";                 value = "true"  }
        @{ name = "UsageGuidelinesUrl";               value = ""      }
        @{ name = "ClassificationList";               value = "General,Confidential,Highly Confidential" }
        @{ name = "DefaultClassification";            value = "General" }
        @{ name = "PrefixSuffixNamingRequirement";    value = ""      }
        @{ name = "CustomBlockedWordsList";           value = ""      }
        @{ name = "EnableMIPLabels";                  value = "false" }
        @{ name = "NewUnifiedGroupWritebackDefault";  value = "false" }
    )

    if ($unifiedSetting) {
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/groupSettings/$($unifiedSetting.id)" `
            -Body (@{ values = $desiredValues } | ConvertTo-Json -Depth 4) `
            -ContentType "application/json" | Out-Null
        Write-Status "Updated existing group settings" -Type Success
    } else {
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/groupSettings" `
            -Body (@{
                templateId = $groupSettingTemplateId
                values     = $desiredValues
            } | ConvertTo-Json -Depth 4) `
            -ContentType "application/json" | Out-Null
        Write-Status "Created group settings (Group.Unified template)" -Type Success
    }
} catch {
    Write-Status "Group settings update failed: $_" -Type Warning
}

# ── User Consent / App Consent Policy ────────────────────────────────────────
Write-Status "App consent policy" -Type Header
try {
    # Set default user consent to: users can consent to apps for verified publishers only
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
        -Body (@{
            permissionGrantPolicyIdsAssignedToDefaultUserRole = @(
                "ManagePermissionGrantsForSelf.microsoft-user-default-low"
                # Options:
                #   ManagePermissionGrantsForSelf.microsoft-user-default-legacy     = allow all
                #   ManagePermissionGrantsForSelf.microsoft-user-default-low        = verified publishers
                #   (empty array)                                                   = no user consent
            )
        } | ConvertTo-Json -Depth 3) `
        -ContentType "application/json" | Out-Null
    Write-Status "User consent set to 'verified publishers only'" -Type Success
} catch {
    Write-Status "Consent policy update failed: $_" -Type Warning
}

# ── Default User Role Permissions ─────────────────────────────────────────────
Write-Status "Default user role permissions" -Type Header
try {
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
        -Body (@{
            defaultUserRolePermissions = @{
                allowedToCreateApps             = $false   # prevent users registering apps
                allowedToCreateSecurityGroups   = $true
                allowedToCreateTenants          = $false
                allowedToReadBitlockerKeysForOwnedDevice = $true
                allowedToReadOtherUsers         = $true
            }
        } | ConvertTo-Json -Depth 4) `
        -ContentType "application/json" | Out-Null
    Write-Status "Default user permissions updated (app registration disabled for non-admins)" -Type Success
} catch {
    Write-Status "Default user permissions update failed: $_" -Type Warning
}

# ── LinkedIn Integration ───────────────────────────────────────────────────────
Write-Status "LinkedIn account connections" -Type Header
try {
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/organization/$($org.Id)" `
        -Body (@{ isLinkedInAccountEnabled = $false } | ConvertTo-Json) `
        -ContentType "application/json" | Out-Null
    Write-Status "LinkedIn connections disabled" -Type Success
} catch {
    Write-Status "LinkedIn setting skipped: $_" -Type Warning
}

# ── Security Defaults ─────────────────────────────────────────────────────────
Write-Status "Security Defaults" -Type Header
try {
    $secDefaults = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    Write-Host "  Security Defaults currently: $($secDefaults.isEnabled)" -ForegroundColor $(if ($secDefaults.isEnabled) { "Yellow" } else { "Green" })
    if ($secDefaults.isEnabled) {
        Write-Host "  WARNING: Security Defaults is ON. Conditional Access policies will NOT apply." -ForegroundColor Yellow
        Write-Host "  Disable it in Entra portal > Properties > Manage Security defaults, or run:" -ForegroundColor Yellow
        Write-Host '    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -Body ''{"isEnabled":false}'' -ContentType "application/json"' -ForegroundColor Cyan
    }
} catch {
    Write-Status "Could not read security defaults: $_" -Type Warning
}

Write-Status "Directory settings deployment complete" -Type Success
