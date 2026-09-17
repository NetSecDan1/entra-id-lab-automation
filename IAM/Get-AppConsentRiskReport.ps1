<#
.SYNOPSIS
    Risk-ranks every application permission and consent grant in the tenant, and
    finds the ownerless, over-privileged and unused service principals behind them.

.DESCRIPTION
    Illicit consent grant is the identity attack that survives everything else.
    A password reset, an MFA re-registration and a session revocation all leave a
    consented application holding a long-lived token. Yet app permissions are the
    least-reviewed surface in most tenants, because the portal shows them one
    application at a time and never ranks them.

    This report reads the whole surface at once and sorts it by how much damage
    the grant would do:

      - Application (app-only) permissions on high-value APIs. These have no user
        in the loop, are not subject to Conditional Access in the usual sense,
        and apply tenant-wide. Mail.ReadWrite as an application permission means
        every mailbox.
      - Tenant-wide delegated grants (consentType = AllPrincipals) - an admin
        consented on behalf of every user at once.
      - Per-user delegated grants (consentType = Principal) - the residue of
        users consenting to third-party apps themselves. A cluster of users
        consenting to the same unfamiliar app in a short window is a phishing
        campaign.
      - Service principals with no owner. Nobody is accountable for them, nobody
        reviews them, and nobody notices when their credentials are used.

    Complements the KQL side rather than repeating it:
    Reports/KQL/Library/ThreatHunting/Threat-SuspiciousConsentGrants.kql shows
    consent EVENTS inside your log retention window. This shows the resulting
    STATE, including grants made years before your logs start.

    READ-ONLY. Every call is a GET.

.PARAMETER ResourceAppIds
    Which resource APIs to enumerate application permissions against. Defaults to
    Microsoft Graph, the legacy Azure AD Graph, Exchange Online and SharePoint -
    the four that matter most. Add your own APIs' appIds to widen it.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft's own first-party service principals. Off by default: a
    tenant has hundreds and they drown the findings that are actually yours.

.PARAMETER OutputPath
    Override the report path. Defaults to a timestamped file in Reports/Output.

.EXAMPLE
    .\IAM\Get-AppConsentRiskReport.ps1 -Open

.EXAMPLE
    .\IAM\Get-AppConsentRiskReport.ps1 -IncludeMicrosoftApps -Open

    Widen to first-party apps when hunting, after you have triaged your own.

.NOTES
    Scopes: Application.Read.All, Directory.Read.All (covers oauth2PermissionGrants
    and appRoleAssignedTo). Read-only - nothing here revokes or modifies a grant.

    Blast radius of acting on this report: revoking a consent grant breaks the
    application immediately for every user it covered. Identify the owner and the
    business use before removing anything.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [string[]]$ResourceAppIds = @(
        "00000003-0000-0000-c000-000000000000",   # Microsoft Graph
        "00000002-0000-0000-c000-000000000000",   # Azure AD Graph (deprecated, still consented in many tenants)
        "00000002-0000-0ff1-ce00-000000000000",   # Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000"    # Office 365 SharePoint Online
    ),
    [switch]$IncludeMicrosoftApps,
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

$preflight = Test-GraphScope -Required @("Application.Read.All", "Directory.Read.All")
if (-not $preflight.AllPresent) { Write-Status $preflight.Summary -Type Warning }

# ---------------------------------------------------------------------------
# Permission risk catalog.
#
# Tiered by what the permission actually lets the holder do, not by how the
# portal labels it. "Critical" means holding it is equivalent to, or a short
# step from, tenant takeover.
# ---------------------------------------------------------------------------
$permissionRisk = @{
    # Tenant takeover or a direct path to it
    "RoleManagement.ReadWrite.Directory" = @{ Tier = "Critical"; Why = "Can grant itself or anyone else Global Administrator" }
    "AppRoleAssignment.ReadWrite.All"    = @{ Tier = "Critical"; Why = "Can grant itself any other application permission - privilege escalation to anything" }
    "Application.ReadWrite.All"          = @{ Tier = "Critical"; Why = "Can add credentials to any app, including highly privileged ones" }
    "Directory.ReadWrite.All"            = @{ Tier = "Critical"; Why = "Full read/write over directory objects" }
    "PrivilegedAccess.ReadWrite.AzureAD" = @{ Tier = "Critical"; Why = "Can manipulate PIM role eligibility and activation" }
    "Policy.ReadWrite.ConditionalAccess" = @{ Tier = "Critical"; Why = "Can disable or weaken the Conditional Access policies protecting everyone" }
    "full_access_as_app"                 = @{ Tier = "Critical"; Why = "Full access to every mailbox in the tenant (Exchange)" }
    "Sites.FullControl.All"              = @{ Tier = "Critical"; Why = "Full control of every SharePoint site and OneDrive" }
    "Domain.ReadWrite.All"               = @{ Tier = "Critical"; Why = "Can add a federated domain - a known tenant-takeover path" }
    "PrivilegedAuthentication.ReadWrite.All" = @{ Tier = "Critical"; Why = "Can reset credentials for privileged accounts" }

    # Mass data access
    "Mail.ReadWrite"                     = @{ Tier = "High"; Why = "As an application permission: read and modify every mailbox" }
    "Mail.Read"                          = @{ Tier = "High"; Why = "As an application permission: read every mailbox" }
    "Mail.Send"                          = @{ Tier = "High"; Why = "Send mail as any user - phishing from inside your own domain" }
    "MailboxSettings.ReadWrite"          = @{ Tier = "High"; Why = "Can set inbox forwarding rules - classic exfiltration persistence" }
    "Files.ReadWrite.All"                = @{ Tier = "High"; Why = "Read and modify all files across OneDrive and SharePoint" }
    "Files.Read.All"                     = @{ Tier = "High"; Why = "Read all files across OneDrive and SharePoint" }
    "Sites.ReadWrite.All"                = @{ Tier = "High"; Why = "Read and modify all SharePoint content" }
    "User.ReadWrite.All"                 = @{ Tier = "High"; Why = "Modify any user, including attributes used by dynamic groups and CA policies" }
    "Group.ReadWrite.All"                = @{ Tier = "High"; Why = "Modify any group, including groups that grant access or role assignment" }
    "GroupMember.ReadWrite.All"          = @{ Tier = "High"; Why = "Add itself or anyone to any group, including privileged ones" }
    "Directory.AccessAsUser.All"         = @{ Tier = "High"; Why = "Acts with the signed-in user's full directory permissions" }
    "Exchange.ManageAsApp"               = @{ Tier = "High"; Why = "Run Exchange management operations as an application" }
    "Chat.ReadWrite"                     = @{ Tier = "High"; Why = "Read and send Teams chat on behalf of users" }
    "Notes.ReadWrite.All"                = @{ Tier = "High"; Why = "Read and modify all OneNote content" }
    "Calendars.ReadWrite"                = @{ Tier = "High"; Why = "Read and modify all calendars" }

    # Broad read of the directory - reconnaissance value
    "User.Read.All"                      = @{ Tier = "Medium"; Why = "Full user directory read - reconnaissance for targeting" }
    "Group.Read.All"                     = @{ Tier = "Medium"; Why = "Full group read, including membership" }
    "Directory.Read.All"                 = @{ Tier = "Medium"; Why = "Broad directory read" }
    "AuditLog.Read.All"                  = @{ Tier = "Medium"; Why = "Read sign-in and audit logs - reveals defender activity" }
    "Policy.Read.All"                    = @{ Tier = "Medium"; Why = "Read security policy configuration, including CA policy detail" }
    "Application.Read.All"               = @{ Tier = "Medium"; Why = "Enumerate all applications and their permissions" }
}

function Get-PermissionRisk {
    param([string]$Permission)
    $key = ($Permission -replace '^.*/', '').Trim()
    if ($permissionRisk.ContainsKey($key)) {
        return [pscustomobject]@{ Tier = $permissionRisk[$key].Tier; Why = $permissionRisk[$key].Why }
    }
    # Unknown *.ReadWrite.* is still worth flagging above an unknown read.
    if ($key -match '\.ReadWrite\.') { return [pscustomobject]@{ Tier = "Medium"; Why = "Write permission not in the risk catalog - review manually" } }
    return [pscustomobject]@{ Tier = "Low"; Why = "" }
}

# ---------------------------------------------------------------------------
# 1. Service principal inventory
# ---------------------------------------------------------------------------
Write-Status "Enumerating service principals" -Type Header
$spSelect = "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,signInAudience,tags,createdDateTime,publisherName,verifiedPublisher"
$allServicePrincipals = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals?`$select=$spSelect&`$top=999")
Write-Status "$($allServicePrincipals.Count) service principals in the tenant" -Type Success

$microsoftTenantIds = @("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47")
$spById = @{}
foreach ($sp in $allServicePrincipals) { $spById[[string]$sp.id] = $sp }

function Test-IsMicrosoftApp {
    param($ServicePrincipal)
    if (-not $ServicePrincipal) { return $false }
    $owner = [string]$ServicePrincipal.appOwnerOrganizationId
    return ($microsoftTenantIds -contains $owner)
}

# ---------------------------------------------------------------------------
# 2. Application (app-only) permissions against the high-value resource APIs
# ---------------------------------------------------------------------------
Write-Status "Resolving application permissions on $($ResourceAppIds.Count) resource API(s)" -Type Header
$appPermissionRows = @()

foreach ($resourceAppId in $ResourceAppIds) {
    $resourceSp = @($allServicePrincipals | Where-Object { [string]$_.appId -eq $resourceAppId }) | Select-Object -First 1
    if (-not $resourceSp) {
        Write-Status "Resource API $resourceAppId has no service principal in this tenant - skipping" -Type Info
        continue
    }

    # appRoles live on the resource SP and map appRoleId -> permission value.
    $resourceDetail = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$($resourceSp.id)?`$select=id,displayName,appRoles" -TolerateFailure)
    $appRoleMap = @{}
    foreach ($detail in $resourceDetail) {
        foreach ($role in @($detail.appRoles)) { $appRoleMap[[string]$role.id] = [string]$role.value }
    }

    $assignments = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$($resourceSp.id)/appRoleAssignedTo?`$top=999" -TolerateFailure)
    Write-Status "$($resourceSp.displayName): $($assignments.Count) application permission grant(s)" -Type Info

    foreach ($assignment in $assignments) {
        $clientSp = $spById[[string]$assignment.principalId]
        if (-not $IncludeMicrosoftApps -and (Test-IsMicrosoftApp -ServicePrincipal $clientSp)) { continue }

        $permission = if ($appRoleMap.ContainsKey([string]$assignment.appRoleId)) { $appRoleMap[[string]$assignment.appRoleId] } else { "(unresolved appRoleId $($assignment.appRoleId))" }
        $risk = Get-PermissionRisk -Permission $permission

        $appPermissionRows += [pscustomobject]@{
            Risk           = $risk.Tier
            RiskRank       = switch ($risk.Tier) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }
            Application    = [string]$assignment.principalDisplayName
            AppId          = if ($clientSp) { [string]$clientSp.appId } else { "" }
            Permission     = $permission
            ResourceApi    = [string]$assignment.resourceDisplayName
            WhyItMatters   = $risk.Why
            Publisher      = if ($clientSp) { [string]$clientSp.publisherName } else { "" }
            AppEnabled     = if ($clientSp) { [bool]$clientSp.accountEnabled } else { $null }
            GrantedOn      = [string]$assignment.createdDateTime
            ServicePrincipalId = [string]$assignment.principalId
        }
    }
}

$criticalAppPermissions = @($appPermissionRows | Where-Object { $_.Risk -in @("Critical", "High") } | Sort-Object RiskRank, Application)

# ---------------------------------------------------------------------------
# 3. Delegated permission grants (oauth2PermissionGrants)
# ---------------------------------------------------------------------------
Write-Status "Enumerating delegated permission grants" -Type Header
$grants = @(Invoke-GraphPagedRequest -Uri "v1.0/oauth2PermissionGrants?`$top=999" -TolerateFailure)
Write-Status "$($grants.Count) delegated grant(s)" -Type Success

$delegatedRows = @()
foreach ($grant in $grants) {
    $clientSp = $spById[[string]$grant.clientId]
    if (-not $IncludeMicrosoftApps -and (Test-IsMicrosoftApp -ServicePrincipal $clientSp)) { continue }

    $resourceSp = $spById[[string]$grant.resourceId]
    $scopes = @(([string]$grant.scope).Trim() -split '\s+' | Where-Object { $_ })

    $worst = [pscustomobject]@{ Tier = "Low"; Why = "" }
    $worstRank = 3
    foreach ($scope in $scopes) {
        $risk = Get-PermissionRisk -Permission $scope
        $rank = switch ($risk.Tier) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }
        if ($rank -lt $worstRank) { $worstRank = $rank; $worst = $risk }
    }

    $delegatedRows += [pscustomobject]@{
        Risk         = $worst.Tier
        RiskRank     = $worstRank
        ConsentType  = [string]$grant.consentType
        Application  = if ($clientSp) { [string]$clientSp.displayName } else { "(service principal $($grant.clientId) not found)" }
        AppId        = if ($clientSp) { [string]$clientSp.appId } else { "" }
        ResourceApi  = if ($resourceSp) { [string]$resourceSp.displayName } else { [string]$grant.resourceId }
        ScopeCount   = $scopes.Count
        Scopes       = ($scopes -join ", ")
        WhyItMatters = $worst.Why
        Publisher    = if ($clientSp) { [string]$clientSp.publisherName } else { "" }
        PrincipalId  = [string]$grant.principalId
        ServicePrincipalId = [string]$grant.clientId
    }
}

$tenantWideDelegated = @($delegatedRows | Where-Object { $_.ConsentType -eq "AllPrincipals" } | Sort-Object RiskRank, Application)
$userConsented       = @($delegatedRows | Where-Object { $_.ConsentType -eq "Principal" } | Sort-Object RiskRank, Application)

# Users consenting to the same app independently is the illicit-consent signature.
$userConsentClusters = @($userConsented |
    Group-Object Application |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object {
        $sample = $_.Group[0]
        [pscustomobject]@{
            Risk           = $sample.Risk
            RiskRank       = $sample.RiskRank
            Application    = $_.Name
            AppId          = $sample.AppId
            UsersConsented = $_.Count
            Publisher      = $sample.Publisher
            Scopes         = $sample.Scopes
            WhyItMatters   = "$($_.Count) users individually consented to this app. Verify it is expected - a cluster of independent consents to an unfamiliar app is the illicit consent grant pattern."
        }
    } | Sort-Object RiskRank, @{ Expression = "UsersConsented"; Descending = $true })

# ---------------------------------------------------------------------------
# 4. Ownerless service principals holding permissions
# ---------------------------------------------------------------------------
Write-Status "Checking ownership of privileged service principals" -Type Header
# Both collections already carry the service principal's object id, so resolve
# nothing here - looking it up again by appId inside a nested Where-Object would
# rebind $_ to the service principal and silently match everything.
$privilegedSpIds = @(
    @($criticalAppPermissions | Select-Object -ExpandProperty ServicePrincipalId) +
    @($tenantWideDelegated | Where-Object { $_.RiskRank -le 1 } | Select-Object -ExpandProperty ServicePrincipalId)
) | Where-Object { $_ } | Sort-Object -Unique

$ownerlessRows = @()
foreach ($spId in $privilegedSpIds) {
    $owners = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName" -TolerateFailure -MaxPages 2)
    $sp = $spById[[string]$spId]
    if ($owners.Count -eq 0) {
        $ownerlessRows += [pscustomobject]@{
            Risk         = "High"
            Application  = if ($sp) { [string]$sp.displayName } else { $spId }
            AppId        = if ($sp) { [string]$sp.appId } else { "" }
            Type         = if ($sp) { [string]$sp.servicePrincipalType } else { "" }
            Created      = if ($sp) { [string]$sp.createdDateTime } else { "" }
            WhyItMatters = "Holds a high-impact permission and has no owner. Nobody is accountable for reviewing it, and nobody would notice its credentials being used."
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Findings summary
# ---------------------------------------------------------------------------
$criticalCount = @($appPermissionRows | Where-Object { $_.Risk -eq "Critical" }).Count
$highCount     = @($appPermissionRows | Where-Object { $_.Risk -eq "High" }).Count

$findings = @()

foreach ($group in @($appPermissionRows | Where-Object { $_.Risk -eq "Critical" } | Group-Object Permission)) {
    $findings += New-Finding -Severity Critical -Category "Application permission" `
        -Finding "$($group.Name) granted to $($group.Count) application(s)" `
        -Subject (($group.Group | Select-Object -ExpandProperty Application -Unique) -join "; ") `
        -Count $group.Count `
        -Evidence $group.Group[0].WhyItMatters `
        -Recommendation "Confirm each holder needs it. Application permissions apply tenant-wide with no user in the loop."
}

foreach ($group in @($appPermissionRows | Where-Object { $_.Risk -eq "High" } | Group-Object Permission)) {
    $findings += New-Finding -Severity High -Category "Application permission" `
        -Finding "$($group.Name) granted to $($group.Count) application(s)" `
        -Subject (($group.Group | Select-Object -ExpandProperty Application -Unique) -join "; ") `
        -Count $group.Count `
        -Evidence $group.Group[0].WhyItMatters `
        -Recommendation "Scope down to the least-privilege alternative where one exists (for example Mail.ReadBasic, or application access policies for Exchange)."
}

if ($userConsentClusters.Count -gt 0) {
    $findings += New-Finding -Severity High -Category "Consent" `
        -Finding "$($userConsentClusters.Count) application(s) independently consented to by multiple users" `
        -Subject (($userConsentClusters | Select-Object -First 5 -ExpandProperty Application) -join "; ") `
        -Count $userConsentClusters.Count `
        -Evidence "Multiple users granted the same third-party app access to their own data without admin involvement." `
        -Recommendation "Review each app. Consider restricting user consent to verified publishers and low-impact permissions, with an admin consent workflow for the rest."
}

if ($ownerlessRows.Count -gt 0) {
    $findings += New-Finding -Severity High -Category "Ownership" `
        -Finding "$($ownerlessRows.Count) privileged service principal(s) have no owner" `
        -Subject (($ownerlessRows | Select-Object -First 5 -ExpandProperty Application) -join "; ") `
        -Count $ownerlessRows.Count `
        -Evidence "High-impact permissions held by applications nobody is accountable for." `
        -Recommendation "Assign an owner to each, or remove the application if it is no longer used."
}

$legacyAadGraph = @($appPermissionRows | Where-Object { $_.ResourceApi -match "Windows Azure Active Directory|Azure Active Directory Graph" })
if ($legacyAadGraph.Count -gt 0) {
    $findings += New-Finding -Severity Medium -Category "Deprecated API" `
        -Finding "$($legacyAadGraph.Count) permission grant(s) still target the retired Azure AD Graph API" `
        -Subject (($legacyAadGraph | Select-Object -First 5 -ExpandProperty Application) -join "; ") `
        -Count $legacyAadGraph.Count `
        -Evidence "Azure AD Graph is retired. Applications depending on it will break, and its permissions are not visible in the newer consent experiences." `
        -Recommendation "Migrate the applications to Microsoft Graph and remove the legacy grants."
}

if ($findings.Count -eq 0) {
    $findings += New-Finding -Severity Info -Category "Summary" `
        -Finding "No critical or high-risk application permissions found" `
        -Evidence "Evaluated $($appPermissionRows.Count) application permission grant(s) and $($delegatedRows.Count) delegated grant(s)." `
        -Recommendation "Re-run after any new app integration."
}

if (-not $IncludeMicrosoftApps) {
    $findings += New-Finding -Severity NotChecked -Category "Scope" `
        -Finding "Microsoft first-party applications were excluded" `
        -Evidence "Default behaviour: a tenant carries hundreds of first-party service principals which would drown the findings that are yours to act on." `
        -Recommendation "Re-run with -IncludeMicrosoftApps when hunting rather than reviewing."
}

$findings = @($findings | Sort-Finding)

# ---------------------------------------------------------------------------
# 6. Render
# ---------------------------------------------------------------------------
$statTiles = @(
    @{ Label = "Critical app permissions"; Value = $criticalCount; Tone = if ($criticalCount -gt 0) { "danger" } else { "good" } }
    @{ Label = "High-risk app permissions"; Value = $highCount; Tone = if ($highCount -gt 0) { "warn" } else { "good" } }
    @{ Label = "Tenant-wide delegated grants"; Value = $tenantWideDelegated.Count; Tone = if ($tenantWideDelegated.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "User-consented apps"; Value = $userConsented.Count; Tone = if ($userConsented.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Ownerless privileged apps"; Value = $ownerlessRows.Count; Tone = if ($ownerlessRows.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Service principals total"; Value = $allServicePrincipals.Count; Tone = "neutral" }
)

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Reports\Output\AppConsentRisk-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
}

$scopeNote = if ($IncludeMicrosoftApps) { "including Microsoft first-party apps" } else { "excluding Microsoft first-party apps" }

New-HtmlReport -Title "Application Consent & Permission Risk" `
    -Subtitle "$($config.TenantDomain) - $($allServicePrincipals.Count) service principals, $scopeNote" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                                              = $findings
        "Critical and high-risk application permissions"        = $criticalAppPermissions
        "Privileged service principals with no owner"           = $ownerlessRows
        "Apps independently consented to by multiple users"     = $userConsentClusters
        "Tenant-wide delegated grants (admin consent for all)"  = $tenantWideDelegated
        "Per-user delegated grants"                             = $userConsented
        "All application permissions evaluated"                 = @($appPermissionRows | Sort-Object RiskRank, Application)
    }) `
    -FooterNote "Source: Microsoft Graph servicePrincipals, appRoleAssignedTo, oauth2PermissionGrants (all GET). Revoking a grant breaks the application immediately for everyone it covered - identify the owner and business use first. For consent EVENTS inside your log retention window, see Reports/KQL/Library/ThreatHunting/Threat-SuspiciousConsentGrants.kql." `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

Disconnect-MgGraph | Out-Null
