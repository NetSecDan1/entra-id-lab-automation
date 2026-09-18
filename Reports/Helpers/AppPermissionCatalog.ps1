<#
.SYNOPSIS
    Shared risk catalog for Microsoft Graph and Office 365 application
    permissions, plus the escalation set that matters most.

.DESCRIPTION
    Single source of truth for "how bad is this permission", used by both
    IAM/Get-AppConsentRiskReport.ps1 (fast resource-side triage) and
    IAM/Get-AppRiskInventory.ps1 (complete client-side audit). Keeping one copy
    means the two reports cannot quietly disagree about what counts as risky.

    Tiering is by what the permission actually lets the holder DO, not by how
    the portal labels it. Critical means holding it is equivalent to, or a short
    step from, tenant takeover.

    The escalation set is called out separately because those permissions are
    qualitatively different: they do not just grant access to data, they grant
    the ability to acquire MORE permissions. An app with
    AppRoleAssignment.ReadWrite.All does not need any other permission today,
    because it can give itself any permission tomorrow.

    This file contains data and pure functions only - it connects to nothing.

.EXAMPLE
    . .\Reports\Helpers\AppPermissionCatalog.ps1
    Get-PermissionRisk -Permission "Mail.ReadWrite"
#>

# Permissions that let the holder acquire further privilege. Treat presence of
# any one of these as terminal - the app's effective permission set is "all of
# them", regardless of what else it was granted.
$script:TenantTakeoverPermissions = @(
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAuthentication.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

$script:AppPermissionRiskCatalog = @{
    # --- Tenant takeover, or a direct path to it ---------------------------
    "RoleManagement.ReadWrite.Directory"     = @{ Tier = "Critical"; Why = "Can grant itself or anyone else Global Administrator" }
    "AppRoleAssignment.ReadWrite.All"        = @{ Tier = "Critical"; Why = "Can grant itself any other application permission - escalation to anything" }
    "Application.ReadWrite.All"              = @{ Tier = "Critical"; Why = "Can add credentials to any app, including far more privileged ones" }
    "Application.ReadWrite.OwnedBy"          = @{ Tier = "Critical"; Why = "Can add credentials to apps it owns - escalation if it owns a privileged app" }
    "Directory.ReadWrite.All"                = @{ Tier = "Critical"; Why = "Full read/write over directory objects" }
    "PrivilegedAccess.ReadWrite.AzureAD"     = @{ Tier = "Critical"; Why = "Can manipulate PIM role eligibility and activation" }
    "PrivilegedAuthentication.ReadWrite.All" = @{ Tier = "Critical"; Why = "Can reset credentials for privileged accounts" }
    "Policy.ReadWrite.ConditionalAccess"     = @{ Tier = "Critical"; Why = "Can disable or weaken the CA policies protecting everyone else" }
    "Domain.ReadWrite.All"                   = @{ Tier = "Critical"; Why = "Can add a federated domain - a known tenant-takeover path" }
    "full_access_as_app"                     = @{ Tier = "Critical"; Why = "Full access to every mailbox in the tenant (Exchange)" }
    "Sites.FullControl.All"                  = @{ Tier = "Critical"; Why = "Full control of every SharePoint site and OneDrive" }
    "RoleManagement.ReadWrite.Exchange"      = @{ Tier = "Critical"; Why = "Can assign Exchange administrative roles" }
    "DeviceManagementRBAC.ReadWrite.All"     = @{ Tier = "Critical"; Why = "Can assign Intune administrative roles" }

    # --- Mass data access ---------------------------------------------------
    "Mail.ReadWrite"                         = @{ Tier = "High"; Why = "As an application permission: read and modify every mailbox" }
    "Mail.Read"                              = @{ Tier = "High"; Why = "As an application permission: read every mailbox" }
    "Mail.Send"                              = @{ Tier = "High"; Why = "Send mail as any user - phishing from inside your own domain" }
    "MailboxSettings.ReadWrite"              = @{ Tier = "High"; Why = "Can set inbox forwarding rules - classic exfiltration persistence" }
    "Files.ReadWrite.All"                    = @{ Tier = "High"; Why = "Read and modify all files across OneDrive and SharePoint" }
    "Files.Read.All"                         = @{ Tier = "High"; Why = "Read all files across OneDrive and SharePoint" }
    "Sites.ReadWrite.All"                    = @{ Tier = "High"; Why = "Read and modify all SharePoint content" }
    "Sites.Manage.All"                       = @{ Tier = "High"; Why = "Create and delete SharePoint lists and sites" }
    "User.ReadWrite.All"                     = @{ Tier = "High"; Why = "Modify any user, including attributes used by dynamic groups and CA policies" }
    "Group.ReadWrite.All"                    = @{ Tier = "High"; Why = "Modify any group, including groups that grant access or role assignment" }
    "GroupMember.ReadWrite.All"              = @{ Tier = "High"; Why = "Add itself or anyone to any group, including privileged ones" }
    "Directory.AccessAsUser.All"             = @{ Tier = "High"; Why = "Acts with the signed-in user's full directory permissions" }
    "Exchange.ManageAsApp"                   = @{ Tier = "High"; Why = "Run Exchange management operations as an application" }
    "Chat.ReadWrite.All"                     = @{ Tier = "High"; Why = "Read and send Teams chat across the tenant" }
    "Chat.Read.All"                          = @{ Tier = "High"; Why = "Read all Teams chat messages" }
    "ChannelMessage.Read.All"                = @{ Tier = "High"; Why = "Read all Teams channel messages" }
    "Notes.ReadWrite.All"                    = @{ Tier = "High"; Why = "Read and modify all OneNote content" }
    "Calendars.ReadWrite"                    = @{ Tier = "High"; Why = "Read and modify all calendars" }
    "Device.ReadWrite.All"                   = @{ Tier = "High"; Why = "Modify device objects, including compliance-relevant state" }
    "DeviceManagementConfiguration.ReadWrite.All" = @{ Tier = "High"; Why = "Modify Intune configuration and compliance policies" }
    "DeviceManagementManagedDevices.ReadWrite.All" = @{ Tier = "High"; Why = "Modify and act on managed devices, including remote actions" }
    "IdentityRiskyUser.ReadWrite.All"        = @{ Tier = "High"; Why = "Can dismiss risk on compromised accounts, hiding an intrusion" }
    "UserAuthenticationMethod.ReadWrite.All" = @{ Tier = "High"; Why = "Can register authentication methods for other users" }

    # --- Broad read: reconnaissance value ------------------------------------
    "User.Read.All"                          = @{ Tier = "Medium"; Why = "Full user directory read - reconnaissance for targeting" }
    "Group.Read.All"                         = @{ Tier = "Medium"; Why = "Full group read, including membership" }
    "Directory.Read.All"                     = @{ Tier = "Medium"; Why = "Broad directory read" }
    "AuditLog.Read.All"                      = @{ Tier = "Medium"; Why = "Read sign-in and audit logs - reveals defender activity" }
    "Policy.Read.All"                        = @{ Tier = "Medium"; Why = "Read security policy configuration, including CA policy detail" }
    "Application.Read.All"                   = @{ Tier = "Medium"; Why = "Enumerate all applications and their permissions" }
    "RoleManagement.Read.Directory"          = @{ Tier = "Medium"; Why = "Enumerate who holds which privileged role" }
    "Reports.Read.All"                       = @{ Tier = "Medium"; Why = "Read usage and activity reports across the tenant" }
    "Member.Read.Hidden"                     = @{ Tier = "Medium"; Why = "Read membership of groups whose membership is hidden" }
}

<#
.SYNOPSIS
    Returns the risk tier and rationale for a permission value.

.DESCRIPTION
    Accepts a bare permission ("Mail.ReadWrite") or a fully qualified one
    ("https://graph.microsoft.com/Mail.ReadWrite"). Unknown permissions are not
    assumed safe: an unrecognised *.ReadWrite.* still returns Medium with a note
    to review it manually, because the catalog will always lag Microsoft.
#>
function Get-PermissionRisk {
    [CmdletBinding()]
    param([string]$Permission)

    $key = ([string]$Permission -replace '^.*/', '').Trim()
    if ([string]::IsNullOrWhiteSpace($key)) {
        return [pscustomobject]@{ Tier = "Low"; Rank = 3; Why = ""; InCatalog = $false }
    }

    if ($script:AppPermissionRiskCatalog.ContainsKey($key)) {
        $entry = $script:AppPermissionRiskCatalog[$key]
        return [pscustomobject]@{
            Tier      = $entry.Tier
            Rank      = (Get-RiskRank -Tier $entry.Tier)
            Why       = $entry.Why
            InCatalog = $true
        }
    }

    if ($key -match '\.ReadWrite\.|\.Manage\.|\.FullControl\.') {
        return [pscustomobject]@{
            Tier      = "Medium"
            Rank      = 2
            Why       = "Write permission not in the risk catalog - review manually and add it"
            InCatalog = $false
        }
    }

    return [pscustomobject]@{ Tier = "Low"; Rank = 3; Why = ""; InCatalog = $false }
}

<#
.SYNOPSIS
    Numeric rank for a tier, so findings sort by severity rather than alphabet.
#>
function Get-RiskRank {
    [CmdletBinding()]
    param([string]$Tier)
    switch ($Tier) {
        "Critical" { return 0 }
        "High"     { return 1 }
        "Medium"   { return 2 }
        default    { return 3 }
    }
}

<#
.SYNOPSIS
    True if the permission lets its holder acquire further permissions.
#>
function Test-IsEscalationPermission {
    [CmdletBinding()]
    param([string]$Permission)
    $key = ([string]$Permission -replace '^.*/', '').Trim()
    return ($script:TenantTakeoverPermissions -contains $key)
}

function Get-TenantTakeoverPermissions { return @($script:TenantTakeoverPermissions) }

function Get-AppPermissionCatalogSize { return $script:AppPermissionRiskCatalog.Count }
