<#
.SYNOPSIS
    Hardens Cross-Tenant Access settings to control B2B inbound and outbound access.

.DESCRIPTION
    Cross-Tenant Access Policy (XTAP) controls:

    Inbound trust settings (DEFAULT — applies to ALL external tenants)
    ----------------------------------------------------------------
    isMfaAccepted               = false  ← external MFA claims not trusted
                                           guests MUST re-authenticate MFA in YOUR tenant
    isCompliantDeviceAccepted   = false  ← external device compliance not trusted
    isHybridAADJoinedDeviceAccepted = false  ← external HAADJ not trusted

    This closes a critical security gap: without this, an attacker who compromises
    a user in a TRUSTED external tenant can bypass your CA policies using that
    tenant's weaker MFA or unmanaged device trust.

    Outbound settings
    -----------------
    Allows employees to collaborate with external tenants by default.
    Specific tenant overrides can be added for known partners.

    Tenant-specific overrides
    -------------------------
    Microsoft tenants (00000001-...) receive a trusted override allowing MFA
    passthrough — so employees can access M365 admin portals normally.

.EXAMPLE
    .\Security\Deploy-CrossTenantAccess.ps1
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
Write-Status "Cross-Tenant Access Policy Hardening" -Type Header
Write-Host "  Tenant : $domain"
Write-Host ""

# ── Read current default settings ─────────────────────────────────────────────
Write-Status "Reading current cross-tenant access default settings" -Type Header

try {
    $current = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
        -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"
    Write-Host "  Current inbound MFA trust          : $($current.inboundTrust.isMfaAccepted)" -ForegroundColor DarkGray
    Write-Host "  Current inbound device trust       : $($current.inboundTrust.isCompliantDeviceAccepted)" -ForegroundColor DarkGray
    Write-Host "  Current inbound HAADJ trust        : $($current.inboundTrust.isHybridAzureADJoinedDeviceAccepted)" -ForegroundColor DarkGray
} catch {
    Write-Status "Could not read default settings: $($_.Exception.Message)" -Type Warning
}

# ── Harden default inbound trust settings ────────────────────────────────────
Write-Host ""
Write-Status "Hardening default inbound trust (no external MFA/device pass-through)" -Type Header

$defaultPolicy = @{
    inboundTrust = @{
        isMfaAccepted                          = $false
        isCompliantDeviceAccepted              = $false
        isHybridAzureADJoinedDeviceAccepted    = $false
    }
    b2bCollaborationInbound = @{
        usersAndGroups = @{
            accessType = "allowed"
            targets    = @(@{ target = "AllUsers"; targetType = "user" })
        }
        applications = @{
            accessType = "allowed"
            targets    = @(@{ target = "AllApplications"; targetType = "application" })
        }
    }
    b2bCollaborationOutbound = @{
        usersAndGroups = @{
            accessType = "allowed"
            targets    = @(@{ target = "AllUsers"; targetType = "user" })
        }
        applications = @{
            accessType = "allowed"
            targets    = @(@{ target = "AllApplications"; targetType = "application" })
        }
    }
} | ConvertTo-Json -Depth 8

try {
    Invoke-MgGraphRequest -Method PATCH -Body $defaultPolicy -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" | Out-Null
    Write-Status "Default inbound trust hardened" -Type Success
    Write-Host "  isMfaAccepted                    → false (external guests must complete YOUR MFA)" -ForegroundColor Green
    Write-Host "  isCompliantDeviceAccepted        → false (external device compliance not trusted)" -ForegroundColor Green
    Write-Host "  isHybridAzureADJoinedDeviceAccepted → false (external HAADJ not trusted)" -ForegroundColor Green
    Write-Host "  B2B inbound/outbound collaboration → allowed (admin-invited guests still work)" -ForegroundColor Green
} catch {
    Write-Status "Default policy update failed: $($_.Exception.Message)" -Type Error
}

# ── Configure tenant-specific overrides ──────────────────────────────────────
Write-Host ""
Write-Status "Configuring tenant-specific overrides" -Type Header

function New-TenantOverride {
    param(
        [string]$TenantId,
        [string]$TenantName,
        [bool]  $TrustMfa = $false,
        [bool]  $TrustCompliance = $false,
        [string]$InboundAccess = "allowed",
        [string]$OutboundAccess = "allowed"
    )

    # Check if override already exists
    try {
        $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
            -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners/$TenantId"
        if ($existing) {
            Write-Status "Override already exists: $TenantName ($TenantId)" -Type Warning
            return
        }
    } catch { }

    $body = @{
        tenantId     = $TenantId
        inboundTrust = @{
            isMfaAccepted                       = $TrustMfa
            isCompliantDeviceAccepted           = $TrustCompliance
            isHybridAzureADJoinedDeviceAccepted = $false
        }
        b2bCollaborationInbound = @{
            usersAndGroups = @{
                accessType = $InboundAccess
                targets    = @(@{ target = "AllUsers"; targetType = "user" })
            }
            applications = @{
                accessType = $InboundAccess
                targets    = @(@{ target = "AllApplications"; targetType = "application" })
            }
        }
        b2bCollaborationOutbound = @{
            usersAndGroups = @{
                accessType = $OutboundAccess
                targets    = @(@{ target = "AllUsers"; targetType = "user" })
            }
            applications = @{
                accessType = $OutboundAccess
                targets    = @(@{ target = "AllApplications"; targetType = "application" })
            }
        }
    } | ConvertTo-Json -Depth 8

    try {
        Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners" | Out-Null
        Write-Status "Override created: $TenantName" -Type Success
        Write-Host "    Trust MFA: $TrustMfa | Trust Compliance: $TrustCompliance | Access: $InboundAccess/$OutboundAccess" -ForegroundColor DarkGray
    } catch {
        Write-Status "Override failed for $TenantName`: $($_.Exception.Message)" -Type Warning
    }
}

# Microsoft's own tenants — trust MFA so employees can access admin portals properly
# These are well-known Microsoft tenant IDs used for M365 service access
New-TenantOverride `
    -TenantId "f8cdef31-a31e-4b4a-93e4-5f571e91255a" `
    -TenantName "Microsoft (microsoftonline.com)" `
    -TrustMfa $true -TrustCompliance $false `
    -InboundAccess "allowed" -OutboundAccess "allowed"

# ── Print final state ─────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Current cross-tenant access configuration" -Type Header

try {
    $final = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"
    Write-Host "  DEFAULT POLICY:" -ForegroundColor Cyan
    Write-Host "    Inbound MFA trust     : $($final.inboundTrust.isMfaAccepted)" -ForegroundColor $(if ($final.inboundTrust.isMfaAccepted -eq $false) {"Green"} else {"Red"})
    Write-Host "    Inbound device trust  : $($final.inboundTrust.isCompliantDeviceAccepted)" -ForegroundColor $(if ($final.inboundTrust.isCompliantDeviceAccepted -eq $false) {"Green"} else {"Red"})
    Write-Host "    Inbound HAADJ trust   : $($final.inboundTrust.isHybridAzureADJoinedDeviceAccepted)" -ForegroundColor $(if ($final.inboundTrust.isHybridAzureADJoinedDeviceAccepted -eq $false) {"Green"} else {"Red"})

    $partners = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners"
    if ($partners.value) {
        Write-Host ""
        Write-Host "  TENANT OVERRIDES ($($partners.value.Count)):" -ForegroundColor Cyan
        foreach ($p in $partners.value) {
            Write-Host "    $($p.tenantId)  MFA trust: $($p.inboundTrust.isMfaAccepted)" -ForegroundColor DarkGray
        }
    }
} catch {
    Write-Status "Could not read final state: $($_.Exception.Message)" -Type Warning
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Cross-Tenant Access deployment complete" -Type Success
Write-Host ""
Write-Host "  Security impact:" -ForegroundColor Green
Write-Host "    Guest users from external tenants now MUST complete MFA in YOUR tenant" -ForegroundColor DarkGray
Write-Host "    External device compliance/HAADJ claims are NOT trusted" -ForegroundColor DarkGray
Write-Host "    This prevents AiTM lateral movement via trusted B2B partners" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  To add a trusted partner tenant (e.g. subsidiary, auditor):" -ForegroundColor Cyan
Write-Host "    Entra portal → External Identities → Cross-tenant access → Organizational settings" -ForegroundColor DarkGray
Write-Host "    Add their tenant ID and configure trust settings as appropriate" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
