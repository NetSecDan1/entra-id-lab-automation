<#
.SYNOPSIS
    Complete, read-only risk inventory of every application and service
    principal in the tenant - permissions, credentials, ownership, directory
    roles and (optionally) real usage - scored and ranked in one pass.

.DESCRIPTION
    The thorough one. IAM/Get-AppConsentRiskReport.ps1 enumerates from the
    RESOURCE side (one call per API, fast) and therefore only sees permissions
    granted on the APIs you list. This script enumerates from the CLIENT side -
    every service principal's own appRoleAssignments - so an app holding
    permissions on Intune, Teams, Dynamics, or your own custom API cannot hide
    from it. That completeness costs one Graph call per service principal, which
    is why this is the one-off audit and that one is the routine check.

    It answers the question that a permission list alone never does: which apps
    should I actually deal with first? By intersecting four independent signals:

        high privilege  x  holds a long-lived credential
                        x  nobody owns it
                        x  nothing is using it

    An app at that intersection is powerful, exploitable, unaccountable and
    unmissed. That is usually a very short list, and it is the real work queue.

    What it inventories:

      - Application permissions (app-only), client-side, across ALL resource
        APIs - no hardcoded API list, no blind spot.
      - Delegated permission grants, tenant-wide and per-user.
      - Escalation permissions called out separately. An app holding
        AppRoleAssignment.ReadWrite.All or RoleManagement.ReadWrite.Directory
        has an EFFECTIVE permission set of "everything", because it can grant
        itself the rest. Its other permissions are almost beside the point.
      - Credentials: client secrets, certificates, AND federated identity
        credentials. An FIC has no secret and no expiry, so it never shows up in
        a credential-expiry report - and it lets an external workload
        authenticate as the app with no stored secret at all.
      - Ownership in both directions: privileged apps with NO owner (nobody
        accountable), and - more interesting - WHO owns the privileged apps.
        An application owner can add a credential to their own app and then act
        as it. Owning a privileged app is therefore equivalent to holding its
        permissions. Those owners are shadow admins and rarely appear on anyone's
        privileged-access list.
      - Directory roles assigned directly to service principals.
      - Multi-tenant apps and unverified publishers.
      - Optional real usage, joined from AADServicePrincipalSignInLogs when a
        Log Analytics workspace is supplied. Without it, dormancy is reported as
        NOT CHECKED rather than as zero dormant apps.

.PARAMETER PreviewCalls
    Print the exact Graph call plan and an estimated call count, then exit.
    Connects to nothing and reads nothing. Run this first against an unfamiliar
    tenant so you know the blast radius of the read before you make it.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party service principals. Off by default - a tenant
    carries hundreds, they dominate the call count, and they are not yours to
    remediate. Turn it on when hunting rather than reviewing.

.PARAMETER MaxServicePrincipals
    Safety ceiling on how many service principals are deep-inspected. Default
    1000. If the tenant has more, the report says so loudly rather than
    silently inspecting a subset.

.PARAMETER WorkspaceId
    Optional Log Analytics workspace (customer) ID. When supplied, app-only
    sign-in activity is joined in so dormancy becomes a real signal. Falls back
    to config.Reporting.LogAnalyticsWorkspaceId. Omit it and dormancy is
    reported as NotChecked.

.PARAMETER DormantDays
    An app with no app-only sign-in in this many days counts as dormant.
    Default 30. Only meaningful when a workspace is supplied.

.PARAMETER AllCredentials
    Fetch federated identity credentials for EVERY application rather than only
    the privileged ones. Slower, complete.

.PARAMETER PassThru
    Emit the inventory objects to the pipeline as well as writing the report, so
    this composes into other automation.

.EXAMPLE
    .\IAM\Get-AppRiskInventory.ps1 -PreviewCalls

    Shows what it would read. Makes no connection. Always safe to run.

.EXAMPLE
    .\IAM\Get-AppRiskInventory.ps1 -Open

    The one-off audit. Read-only.

.EXAMPLE
    .\IAM\Get-AppRiskInventory.ps1 -WorkspaceId <guid> -DormantDays 60 -ExportJson -Open

    With usage joined in, so the four-way intersection is fully populated.

.EXAMPLE
    $apps = .\IAM\Get-AppRiskInventory.ps1 -PassThru
    $apps | Where-Object { $_.RiskTier -eq "Critical" } | Export-Csv .\triage.csv

.NOTES
    SAFETY
    This script cannot write to the tenant. Not "does not" - cannot. Every Graph
    call goes through Invoke-GraphPagedRequest, which has no method parameter to
    set: GET is not a default that could be overridden, it is the only verb the
    function can issue. Every call is recorded, and before the report renders,
    Test-GraphCallLogIsReadOnly asserts that nothing but GET was sent and throws
    if that is ever untrue. The call log is rendered into the report as evidence
    you can hand to a reviewer.

    Scopes requested are read-only: Application.Read.All, Directory.Read.All,
    RoleManagement.Read.Directory, AuditLog.Read.All. No consent to any
    *.ReadWrite.* scope is requested or needed.

    COST
    Roughly 4 + N + M + O calls, where N is the number of inspected service
    principals, M the distinct resource APIs they hold permissions on, and O the
    privileged apps whose owners and federated credentials are fetched. Use
    -PreviewCalls for the estimate against your own tenant. Throttling is handled
    with backoff, so a large tenant runs slowly rather than failing.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$PreviewCalls,
    [switch]$IncludeMicrosoftApps,
    [int]$MaxServicePrincipals = 1000,
    [string]$WorkspaceId,
    [int]$DormantDays = 30,
    [switch]$AllCredentials,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$ExportJson,
    [switch]$PassThru,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\GraphReadOnly.ps1"
. "$PSScriptRoot\..\Reports\Helpers\AppPermissionCatalog.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"
# Only used when -WorkspaceId is supplied, but dot-sourced here so every
# dependency is visible at the top. Dot-sourcing defines functions; it does not
# install or connect to anything.
. "$PSScriptRoot\..\Reports\Helpers\KqlQuery.ps1"

# ---------------------------------------------------------------------------
# -PreviewCalls: describe the read, make no connection.
# ---------------------------------------------------------------------------
if ($PreviewCalls) {
    Write-Status "Graph call plan - nothing below is executed, no connection is made" -Type Header
    $plan = @(
        [pscustomobject]@{ Step = 1; Method = "GET"; Endpoint = "v1.0/servicePrincipals";                          Calls = "1 (paged)"; Purpose = "Service principal inventory" }
        [pscustomobject]@{ Step = 2; Method = "GET"; Endpoint = "v1.0/applications";                               Calls = "1 (paged)"; Purpose = "Registrations: credentials, audience, publisher" }
        [pscustomobject]@{ Step = 3; Method = "GET"; Endpoint = "v1.0/servicePrincipals/{id}/appRoleAssignments";  Calls = "1 per inspected SP"; Purpose = "Application permissions held (client-side, complete)" }
        [pscustomobject]@{ Step = 4; Method = "GET"; Endpoint = "v1.0/servicePrincipals/{resourceId}";             Calls = "1 per distinct resource API (cached)"; Purpose = "Resolve appRoleId to a permission name" }
        [pscustomobject]@{ Step = 5; Method = "GET"; Endpoint = "v1.0/oauth2PermissionGrants";                     Calls = "1 (paged)"; Purpose = "Delegated grants" }
        [pscustomobject]@{ Step = 6; Method = "GET"; Endpoint = "v1.0/directoryRoles + /members";                  Calls = "1 + 1 per active role"; Purpose = "Directory roles held by service principals" }
        [pscustomobject]@{ Step = 7; Method = "GET"; Endpoint = "v1.0/servicePrincipals/{id}/owners";              Calls = "1 per privileged app"; Purpose = "Accountability and shadow-admin owners" }
        [pscustomobject]@{ Step = 8; Method = "GET"; Endpoint = "v1.0/applications/{id}/owners";                   Calls = "1 per privileged app"; Purpose = "Owners who could add credentials to the registration" }
        [pscustomobject]@{ Step = 9; Method = "GET"; Endpoint = "v1.0/applications/{id}/federatedIdentityCredentials"; Calls = "0 if `$expand works, else 1 per privileged app"; Purpose = "Secretless credentials" }
    )
    $plan | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host ""
    Write-Status "Every call is GET. There is no write path in this script." -Type Success
    Write-Status "Optional: -WorkspaceId adds one read-only KQL query against AADServicePrincipalSignInLogs." -Type Info
    Write-Status "Run without -PreviewCalls to execute." -Type Info
    return
}

$config = Get-Config -ConfigPath $ConfigPath

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-GraphReadOnly | Out-Null
Reset-GraphCallLog

$preflight = Test-GraphScope -Required @("Application.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory")
if (-not $preflight.AllPresent) { Write-Status $preflight.Summary -Type Warning }

$microsoftTenantIds = @("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47")

# ---------------------------------------------------------------------------
# 1. Service principals and applications
# ---------------------------------------------------------------------------
Write-Status "Enumerating service principals" -Type Header
$spSelect = "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,signInAudience,createdDateTime,publisherName,verifiedPublisher,tags,appRoleAssignmentRequired"
$allServicePrincipals = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals?`$select=$spSelect&`$top=999")
Write-Status "$($allServicePrincipals.Count) service principal(s) in the tenant" -Type Success

$inspectTargets = @($allServicePrincipals | Where-Object {
    $IncludeMicrosoftApps -or ($microsoftTenantIds -notcontains [string]$_.appOwnerOrganizationId)
})

$truncatedInspection = $false
if ($inspectTargets.Count -gt $MaxServicePrincipals) {
    $truncatedInspection = $true
    Write-Status "$($inspectTargets.Count) service principals exceed the -MaxServicePrincipals ceiling of $MaxServicePrincipals. Inspecting the first $MaxServicePrincipals - this inventory is INCOMPLETE." -Type Warning
    $inspectTargets = @($inspectTargets | Select-Object -First $MaxServicePrincipals)
}
Write-Status "Deep-inspecting $($inspectTargets.Count) service principal(s)" -Type Info

Write-Status "Enumerating application registrations" -Type Header
$appSelect = "id,appId,displayName,signInAudience,createdDateTime,verifiedPublisher,passwordCredentials,keyCredentials"
$applications = @(Invoke-GraphPagedRequest -Uri "v1.0/applications?`$select=$appSelect&`$expand=federatedIdentityCredentials&`$top=999" -TolerateFailure)

# $expand on a collection is not uniformly supported and its behaviour has
# changed across Graph versions. Probe the actual response rather than assume.
$ficExpandWorked = $false
if ($applications.Count -gt 0) {
    $probe = $applications[0]
    $ficExpandWorked = ($probe -is [System.Collections.IDictionary]) -and $probe.Contains("federatedIdentityCredentials")
}
if ($applications.Count -eq 0) {
    Write-Status "Expanded application query returned nothing - retrying without `$expand" -Type Warning
    $applications = @(Invoke-GraphPagedRequest -Uri "v1.0/applications?`$select=$appSelect&`$top=999" -TolerateFailure)
}
Write-Status "$($applications.Count) application registration(s); federatedIdentityCredentials via `$expand: $ficExpandWorked" -Type Success

$appByAppId = @{}
foreach ($app in $applications) { if ($app.appId) { $appByAppId[[string]$app.appId] = $app } }

$spById = @{}
foreach ($sp in $allServicePrincipals) { $spById[[string]$sp.id] = $sp }

# ---------------------------------------------------------------------------
# 2. Application permissions, client-side. The completeness fix.
# ---------------------------------------------------------------------------
Write-Status "Resolving application permissions per service principal (client-side)" -Type Header
$appRoleCache = @{}          # resourceSpId -> @{ appRoleId -> permission value }

function Get-ResourceAppRoleMap {
    param([string]$ResourceSpId)

    if ($appRoleCache.ContainsKey($ResourceSpId)) { return $appRoleCache[$ResourceSpId] }

    $map = @{}
    $detail = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$ResourceSpId`?`$select=id,displayName,appRoles" -TolerateFailure -MaxPages 1)
    foreach ($item in $detail) {
        foreach ($role in @($item.appRoles)) { $map[[string]$role.id] = [string]$role.value }
    }
    $appRoleCache[$ResourceSpId] = $map
    return $map
}

$permissionRows = @()
$processed = 0
foreach ($sp in $inspectTargets) {
    $processed++
    if ($processed % 25 -eq 0 -or $processed -eq $inspectTargets.Count) {
        Write-Progress -Activity "Reading application permissions" -Status "$processed of $($inspectTargets.Count)" -PercentComplete (100.0 * $processed / $inspectTargets.Count)
    }

    $assignments = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999" -TolerateFailure -MaxPages 5)
    foreach ($assignment in $assignments) {
        $resourceId = [string]$assignment.resourceId
        $roleMap = Get-ResourceAppRoleMap -ResourceSpId $resourceId
        $permission = if ($roleMap.ContainsKey([string]$assignment.appRoleId)) {
            $roleMap[[string]$assignment.appRoleId]
        } else {
            "(unresolved appRoleId $($assignment.appRoleId))"
        }

        $risk = Get-PermissionRisk -Permission $permission
        $permissionRows += [pscustomobject]@{
            RiskTier           = $risk.Tier
            RiskRank           = $risk.Rank
            IsEscalation       = (Test-IsEscalationPermission -Permission $permission)
            Application        = [string]$sp.displayName
            AppId              = [string]$sp.appId
            ServicePrincipalId = [string]$sp.id
            Permission         = $permission
            ResourceApi        = [string]$assignment.resourceDisplayName
            GrantType          = "Application (app-only)"
            WhyItMatters       = $risk.Why
            InCatalog          = $risk.InCatalog
            GrantedOn          = [string]$assignment.createdDateTime
        }
    }
}
Write-Progress -Activity "Reading application permissions" -Completed
Write-Status "$($permissionRows.Count) application permission grant(s) across $($appRoleCache.Count) resource API(s)" -Type Success

# ---------------------------------------------------------------------------
# 3. Delegated grants
# ---------------------------------------------------------------------------
Write-Status "Enumerating delegated permission grants" -Type Header
$grants = @(Invoke-GraphPagedRequest -Uri "v1.0/oauth2PermissionGrants?`$top=999" -TolerateFailure)

$delegatedRows = @()
foreach ($grant in $grants) {
    $clientSp = $spById[[string]$grant.clientId]
    if (-not $IncludeMicrosoftApps -and $clientSp -and ($microsoftTenantIds -contains [string]$clientSp.appOwnerOrganizationId)) { continue }

    $resourceSp = $spById[[string]$grant.resourceId]
    $scopes = @(([string]$grant.scope).Trim() -split '\s+' | Where-Object { $_ })

    $worstRank = 3
    $worstTier = "Low"
    $worstWhy = ""
    $hasEscalation = $false
    foreach ($scope in $scopes) {
        $risk = Get-PermissionRisk -Permission $scope
        if ($risk.Rank -lt $worstRank) { $worstRank = $risk.Rank; $worstTier = $risk.Tier; $worstWhy = $risk.Why }
        if (Test-IsEscalationPermission -Permission $scope) { $hasEscalation = $true }
    }

    $delegatedRows += [pscustomobject]@{
        RiskTier           = $worstTier
        RiskRank           = $worstRank
        IsEscalation       = $hasEscalation
        ConsentType        = [string]$grant.consentType
        Application        = if ($clientSp) { [string]$clientSp.displayName } else { "(service principal $($grant.clientId) not in tenant)" }
        AppId              = if ($clientSp) { [string]$clientSp.appId } else { "" }
        ServicePrincipalId = [string]$grant.clientId
        ResourceApi        = if ($resourceSp) { [string]$resourceSp.displayName } else { [string]$grant.resourceId }
        ScopeCount         = $scopes.Count
        Scopes             = ($scopes -join ", ")
        GrantType          = if ([string]$grant.consentType -eq "AllPrincipals") { "Delegated (tenant-wide)" } else { "Delegated (single user)" }
        WhyItMatters       = $worstWhy
        PrincipalId        = [string]$grant.principalId
    }
}
Write-Status "$($delegatedRows.Count) delegated grant(s) in scope" -Type Success

# ---------------------------------------------------------------------------
# 4. Directory roles held by service principals
# ---------------------------------------------------------------------------
Write-Status "Checking directory roles assigned to service principals" -Type Header
$spRoleHolders = @{}
$roles = @(Invoke-GraphPagedRequest -Uri "v1.0/directoryRoles?`$select=id,displayName,roleTemplateId" -TolerateFailure)
foreach ($role in $roles) {
    $members = @(Invoke-GraphPagedRequest -Uri "v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName" -TolerateFailure -MaxPages 5)
    foreach ($member in $members) {
        $memberId = [string]$member.id
        if ($spById.ContainsKey($memberId)) {
            if (-not $spRoleHolders.ContainsKey($memberId)) { $spRoleHolders[$memberId] = @() }
            $spRoleHolders[$memberId] += [string]$role.displayName
        }
    }
}
Write-Status "$($spRoleHolders.Count) service principal(s) hold a directory role" -Type Success

# ---------------------------------------------------------------------------
# 5. Which apps are privileged? Everything after this is bounded to that set.
# ---------------------------------------------------------------------------
$privilegedSpIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($row in @($permissionRows | Where-Object { $_.RiskRank -le 1 -or $_.IsEscalation })) { [void]$privilegedSpIds.Add($row.ServicePrincipalId) }
foreach ($row in @($delegatedRows  | Where-Object { $_.RiskRank -le 1 -or $_.IsEscalation })) { [void]$privilegedSpIds.Add($row.ServicePrincipalId) }
foreach ($spId in $spRoleHolders.Keys) { [void]$privilegedSpIds.Add([string]$spId) }

Write-Status "$($privilegedSpIds.Count) privileged app(s) identified - fetching ownership and credentials for those" -Type Header

# ---------------------------------------------------------------------------
# 6. Ownership, both directions
# ---------------------------------------------------------------------------
$ownershipBySpId = @{}
$ownerIndex = @{}            # owner UPN -> list of privileged apps they own

$ownerProcessed = 0
foreach ($spId in $privilegedSpIds) {
    $ownerProcessed++
    Write-Progress -Activity "Reading ownership" -Status "$ownerProcessed of $($privilegedSpIds.Count)" -PercentComplete (100.0 * $ownerProcessed / [math]::Max(1, $privilegedSpIds.Count))

    $sp = $spById[[string]$spId]
    $ownerSelect = "id,displayName,userPrincipalName"

    $spOwners = @(Invoke-GraphPagedRequest -Uri "v1.0/servicePrincipals/$spId/owners?`$select=$ownerSelect" -TolerateFailure -MaxPages 3)

    $appOwners = @()
    $application = if ($sp -and $sp.appId) { $appByAppId[[string]$sp.appId] } else { $null }
    if ($application) {
        $appOwners = @(Invoke-GraphPagedRequest -Uri "v1.0/applications/$($application.id)/owners?`$select=$ownerSelect" -TolerateFailure -MaxPages 3)
    }

    $ownerNames = @(@($spOwners) + @($appOwners) |
        ForEach-Object { $name = [string]$_.userPrincipalName; if (-not $name) { $name = [string]$_.displayName }; $name } |
        Where-Object { $_ } | Sort-Object -Unique)

    $ownershipBySpId[[string]$spId] = [pscustomobject]@{
        SpOwnerCount  = @($spOwners).Count
        AppOwnerCount = @($appOwners).Count
        Owners        = $ownerNames
        HasOwner      = ($ownerNames.Count -gt 0)
        # Only an owner of the APPLICATION can add credentials to it. An owner of
        # the service principal alone cannot, so the escalation path is narrower.
        CanAddCredentials = (@($appOwners).Count -gt 0)
    }

    foreach ($owner in @($appOwners)) {
        $name = [string]$owner.userPrincipalName
        if (-not $name) { $name = [string]$owner.displayName }
        if (-not $name) { continue }
        if (-not $ownerIndex.ContainsKey($name)) { $ownerIndex[$name] = @() }
        $ownerIndex[$name] += if ($sp) { [string]$sp.displayName } else { [string]$spId }
    }
}
Write-Progress -Activity "Reading ownership" -Completed

# ---------------------------------------------------------------------------
# 7. Credentials, including federated identity credentials
# ---------------------------------------------------------------------------
Write-Status "Reading credentials (secrets, certificates, federated identity)" -Type Header
$now = Get-Date
$credentialBySpId = @{}

$ficTargets = if ($AllCredentials) { @($applications) } else {
    @($applications | Where-Object {
        $appIdValue = [string]$_.appId
        $matchSp = @($allServicePrincipals | Where-Object { [string]$_.appId -eq $appIdValue } | Select-Object -First 1)
        $matchSp.Count -gt 0 -and $privilegedSpIds.Contains([string]$matchSp[0].id)
    })
}

$ficByAppObjectId = @{}
if ($ficExpandWorked) {
    foreach ($app in $applications) {
        $ficByAppObjectId[[string]$app.id] = @($app["federatedIdentityCredentials"])
    }
} else {
    $ficProcessed = 0
    foreach ($app in $ficTargets) {
        $ficProcessed++
        Write-Progress -Activity "Reading federated identity credentials" -Status "$ficProcessed of $($ficTargets.Count)" -PercentComplete (100.0 * $ficProcessed / [math]::Max(1, $ficTargets.Count))
        $ficByAppObjectId[[string]$app.id] = @(Invoke-GraphPagedRequest -Uri "v1.0/applications/$($app.id)/federatedIdentityCredentials" -TolerateFailure -MaxPages 2)
    }
    Write-Progress -Activity "Reading federated identity credentials" -Completed
}

foreach ($sp in $allServicePrincipals) {
    $application = if ($sp.appId) { $appByAppId[[string]$sp.appId] } else { $null }

    $secrets = @()
    $certs = @()
    $fics = @()
    if ($application) {
        $secrets = @($application.passwordCredentials)
        $certs   = @($application.keyCredentials)
        $fics    = @($ficByAppObjectId[[string]$application.id])
    }
    # Service principals can carry their own credentials independently of the
    # registration - a detail that hides credentials from registration-only audits.
    $secrets += @($sp.passwordCredentials)
    $certs   += @($sp.keyCredentials)

    $validSecrets = @($secrets | Where-Object { $_ -and (-not $_.endDateTime -or [datetime]$_.endDateTime -gt $now) })
    $validCerts   = @($certs   | Where-Object { $_ -and (-not $_.endDateTime -or [datetime]$_.endDateTime -gt $now) })

    $credentialBySpId[[string]$sp.id] = [pscustomobject]@{
        ActiveSecrets = $validSecrets.Count
        ActiveCerts   = $validCerts.Count
        FederatedCredentials = @($fics).Count
        FederatedIssuers = (@($fics | ForEach-Object { [string]$_.issuer } | Where-Object { $_ } | Sort-Object -Unique) -join "; ")
        HasAnyCredential = (($validSecrets.Count + $validCerts.Count + @($fics).Count) -gt 0)
        EarliestExpiry = (@($validSecrets + $validCerts | Where-Object { $_.endDateTime } | ForEach-Object { [datetime]$_.endDateTime } | Sort-Object | Select-Object -First 1))
    }
}

# ---------------------------------------------------------------------------
# 8. Optional usage join from Log Analytics
# ---------------------------------------------------------------------------
$usageByAppId = @{}
$usageChecked = $false

if (-not $WorkspaceId -and $config.PSObject.Properties.Name -contains "Reporting" -and $config.Reporting) {
    $fromConfig = [string]$config.Reporting.LogAnalyticsWorkspaceId
    if (-not [string]::IsNullOrWhiteSpace($fromConfig)) { $WorkspaceId = $fromConfig }
}

if ($WorkspaceId) {
    Write-Status "Joining app-only sign-in activity from Log Analytics" -Type Header
    try {
        Ensure-AzModules
        Connect-LabAzure | Out-Null
        $usageKql = @"
AADServicePrincipalSignInLogs
| where TimeGenerated > ago($(($DormantDays + 60))d)
| summarize SignIns = count(),
            Successes = countif(tostring(ResultType) == "0"),
            LastSignIn = max(TimeGenerated)
        by AppId
"@
        $usageRows = @(Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $usageKql -Timespan (New-TimeSpan -Days ($DormantDays + 60)) -QueryName "ServicePrincipalUsage")
        foreach ($row in $usageRows) { $usageByAppId[[string]$row.AppId] = $row }
        $usageChecked = $true
        Write-Status "Usage joined for $($usageByAppId.Count) app(s)" -Type Success
    } catch {
        Write-Status "Usage join failed: $($_.Exception.Message). Dormancy will be reported as NOT CHECKED." -Type Warning
    }
} else {
    Write-Status "No workspace supplied - dormancy will be reported as NOT CHECKED, not as zero dormant apps" -Type Info
}

# ---------------------------------------------------------------------------
# 9. Score
# ---------------------------------------------------------------------------
Write-Status "Scoring" -Type Header

$inventory = foreach ($sp in $inspectTargets) {
    $spId = [string]$sp.id
    $appIdValue = [string]$sp.appId

    $appPerms = @($permissionRows | Where-Object { $_.ServicePrincipalId -eq $spId })
    $delPerms = @($delegatedRows  | Where-Object { $_.ServicePrincipalId -eq $spId })
    $allPerms = @($appPerms) + @($delPerms)

    $worstRank = 3
    foreach ($p in $allPerms) { if ($p.RiskRank -lt $worstRank) { $worstRank = $p.RiskRank } }
    $worstTier = switch ($worstRank) { 0 { "Critical" } 1 { "High" } 2 { "Medium" } default { "Low" } }

    $escalationPerms = @($allPerms | Where-Object { $_.IsEscalation } | Select-Object -ExpandProperty Permission -Unique)
    $ownership = if ($ownershipBySpId.ContainsKey($spId)) { $ownershipBySpId[$spId] } else { $null }
    $credentials = $credentialBySpId[$spId]
    $roles = if ($spRoleHolders.ContainsKey($spId)) { @($spRoleHolders[$spId]) } else { @() }

    $usage = if ($appIdValue -and $usageByAppId.ContainsKey($appIdValue)) { $usageByAppId[$appIdValue] } else { $null }
    $lastSignIn = if ($usage -and $usage.LastSignIn) { [datetime]$usage.LastSignIn } else { $null }
    $daysSinceSignIn = if ($lastSignIn) { [math]::Floor(($now - $lastSignIn).TotalDays) } else { $null }
    $isDormant = if (-not $usageChecked) { $null } else { ($null -eq $lastSignIn -or $daysSinceSignIn -gt $DormantDays) }

    $isMultiTenant = ([string]$sp.signInAudience -in @("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"))
    $verified = $null -ne $sp.verifiedPublisher -and [string]$sp.verifiedPublisher.displayName

    # Score components are additive and every one is named in RiskFactors, so the
    # number is explainable rather than a black box. Sorting is the point; the
    # factor list is what you actually act on.
    $score = 0
    $factors = @()

    switch ($worstRank) {
        0 { $score += 40; $factors += "Critical permission" }
        1 { $score += 25; $factors += "High-risk permission" }
        2 { $score += 10; $factors += "Medium permission" }
    }
    if ($escalationPerms.Count -gt 0) { $score += 25; $factors += "Escalation permission ($($escalationPerms -join ', '))" }
    if ($roles.Count -gt 0)           { $score += 20; $factors += "Holds directory role ($($roles -join ', '))" }
    if ($credentials -and $credentials.ActiveSecrets -gt 0)        { $score += 10; $factors += "$($credentials.ActiveSecrets) active client secret(s)" }
    if ($credentials -and $credentials.FederatedCredentials -gt 0) { $score += 10; $factors += "$($credentials.FederatedCredentials) federated identity credential(s)" }
    if ($credentials -and $credentials.ActiveCerts -gt 0)          { $score += 5;  $factors += "$($credentials.ActiveCerts) active certificate(s)" }
    if ($ownership -and -not $ownership.HasOwner -and $worstRank -le 1) { $score += 15; $factors += "No owner" }
    if ($isMultiTenant)  { $score += 10; $factors += "Multi-tenant app" }
    if (-not $verified -and ($microsoftTenantIds -notcontains [string]$sp.appOwnerOrganizationId)) { $score += 5; $factors += "No verified publisher" }
    if ($isDormant -eq $true -and $worstRank -le 1) { $score += 15; $factors += "Dormant (no app-only sign-in in $DormantDays days)" }

    $tier = if ($score -ge 70) { "Critical" } elseif ($score -ge 45) { "High" } elseif ($score -ge 25) { "Medium" } elseif ($score -gt 0) { "Low" } else { "Info" }

    [pscustomobject]@{
        RiskTier             = $tier
        RiskScore            = $score
        RiskRank             = (Get-RiskRank -Tier $tier)
        Application          = [string]$sp.displayName
        AppId                = $appIdValue
        ServicePrincipalId   = $spId
        Enabled              = [bool]$sp.accountEnabled
        WorstPermissionTier  = $worstTier
        AppPermissions       = $appPerms.Count
        DelegatedGrants      = $delPerms.Count
        EscalationPermissions = ($escalationPerms -join ", ")
        DirectoryRoles       = ($roles -join ", ")
        ActiveSecrets        = if ($credentials) { $credentials.ActiveSecrets } else { 0 }
        ActiveCerts          = if ($credentials) { $credentials.ActiveCerts } else { 0 }
        FederatedCredentials = if ($credentials) { $credentials.FederatedCredentials } else { 0 }
        FederatedIssuers     = if ($credentials) { $credentials.FederatedIssuers } else { "" }
        Owners               = if ($ownership) { ($ownership.Owners -join "; ") } else { "" }
        OwnerCanAddCredentials = if ($ownership) { $ownership.CanAddCredentials } else { $false }
        MultiTenant          = $isMultiTenant
        VerifiedPublisher    = [bool]$verified
        LastAppOnlySignIn    = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } elseif ($usageChecked) { "never in window" } else { "not checked" }
        DaysSinceSignIn      = $daysSinceSignIn
        IsDormant            = $isDormant
        RiskFactors          = ($factors -join " | ")
        CreatedDateTime      = [string]$sp.createdDateTime
    }
}

$inventory = @($inventory | Sort-Object @{ Expression = "RiskScore"; Descending = $true }, Application)

# The four-way intersection this report exists to compute.
$intersection = @($inventory | Where-Object {
    $_.WorstPermissionTier -in @("Critical", "High") -and
    (($_.ActiveSecrets + $_.ActiveCerts + $_.FederatedCredentials) -gt 0) -and
    [string]::IsNullOrWhiteSpace($_.Owners) -and
    ($_.IsDormant -eq $true -or -not $usageChecked)
})

$escalationApps = @($inventory | Where-Object { $_.EscalationPermissions })
$roleHoldingApps = @($inventory | Where-Object { $_.DirectoryRoles })
$ficApps = @($inventory | Where-Object { $_.FederatedCredentials -gt 0 })
$ownerlessPrivileged = @($inventory | Where-Object { $_.WorstPermissionTier -in @("Critical", "High") -and [string]::IsNullOrWhiteSpace($_.Owners) })

# Shadow admins: owners of applications that hold escalation permissions.
$shadowAdmins = @()
foreach ($ownerName in $ownerIndex.Keys) {
    $ownedApps = @($ownerIndex[$ownerName] | Sort-Object -Unique)
    $ownedPrivileged = @($ownedApps | Where-Object { $name = $_; @($escalationApps | Where-Object { $_.Application -eq $name }).Count -gt 0 })
    if ($ownedPrivileged.Count -gt 0) {
        $shadowAdmins += [pscustomobject]@{
            Owner               = $ownerName
            OwnsPrivilegedApps  = $ownedPrivileged.Count
            Applications        = ($ownedPrivileged -join "; ")
            WhyItMatters        = "Owns the registration of an app holding an escalation permission. An application owner can add a credential to that app and then authenticate as it, so this account effectively holds those permissions without appearing on any privileged-role list."
        }
    }
}
$shadowAdmins = @($shadowAdmins | Sort-Object @{ Expression = "OwnsPrivilegedApps"; Descending = $true }, Owner)

# ---------------------------------------------------------------------------
# 10. Findings
# ---------------------------------------------------------------------------
$findings = @()

if ($intersection.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Intersection" `
        -Finding "$($intersection.Count) app(s) are privileged, credentialed, ownerless$(if ($usageChecked) { ' and dormant' })" `
        -Subject (($intersection | Select-Object -First 10 -ExpandProperty Application) -join "; ") `
        -Count $intersection.Count `
        -Evidence "Powerful enough to matter, holds a usable credential, nobody is accountable for it$(if ($usageChecked) { ', and nothing is using it' }). This is the work queue." `
        -Recommendation "Start here. Confirm with the business that each is genuinely unused, then remove the credential before removing the app - that is reversible, deletion is not."
}

if ($escalationApps.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Escalation" `
        -Finding "$($escalationApps.Count) app(s) hold a permission that can acquire further permissions" `
        -Subject (($escalationApps | Select-Object -First 10 -ExpandProperty Application) -join "; ") `
        -Count $escalationApps.Count `
        -Evidence "Their effective permission set is 'everything', because they can grant themselves the rest. Reviewing their other permissions individually is beside the point." `
        -Recommendation "Treat each as a Tier 0 asset: named owner, credential rotation, and monitoring on its sign-ins. Remove the escalation permission unless the app genuinely administers the directory."
}

if ($shadowAdmins.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Shadow admin" `
        -Finding "$($shadowAdmins.Count) account(s) own the registration of an app with escalation permissions" `
        -Subject (($shadowAdmins | Select-Object -First 10 -ExpandProperty Owner) -join "; ") `
        -Count $shadowAdmins.Count `
        -Evidence "An application owner can add a credential to their own app and authenticate as it. These accounts hold those permissions in practice while appearing on no privileged-role report." `
        -Recommendation "Include application ownership in privileged access reviews. Where the owner does not need to manage the registration, remove the ownership rather than the permission."
}

if ($roleHoldingApps.Count -gt 0) {
    $findings += New-Finding -Severity High -Category "Directory role" `
        -Finding "$($roleHoldingApps.Count) service principal(s) hold a directory role directly" `
        -Subject (($roleHoldingApps | Select-Object -First 10 | ForEach-Object { "$($_.Application) [$($_.DirectoryRoles)]" }) -join "; ") `
        -Count $roleHoldingApps.Count `
        -Evidence "Directory roles on a workload identity are easy to miss in the portal and are not covered by PIM in the same way user assignments are." `
        -Recommendation "Confirm each is required. Prefer a narrowly scoped application permission over a directory role where one exists."
}

if ($ficApps.Count -gt 0) {
    $findings += New-Finding -Severity Medium -Category "Federated credentials" `
        -Finding "$($ficApps.Count) app(s) use federated identity credentials" `
        -Subject (($ficApps | Select-Object -First 10 | ForEach-Object { "$($_.Application) <- $($_.FederatedIssuers)" }) -join "; ") `
        -Count $ficApps.Count `
        -Evidence "An FIC has no secret and no expiry, so it never appears in a credential-expiry report. Anything that can present a token from the trusted issuer and subject can authenticate as this app." `
        -Recommendation "Verify every issuer and subject is one you recognise. A wildcard or overly broad subject on a privileged app is equivalent to a leaked secret that never expires."
}

if ($ownerlessPrivileged.Count -gt 0) {
    $findings += New-Finding -Severity High -Category "Ownership" `
        -Finding "$($ownerlessPrivileged.Count) privileged app(s) have no owner" `
        -Subject (($ownerlessPrivileged | Select-Object -First 10 -ExpandProperty Application) -join "; ") `
        -Count $ownerlessPrivileged.Count `
        -Evidence "Nobody is accountable for reviewing them and nobody would notice their credentials being used." `
        -Recommendation "Assign an owner to each, or remove the application. An unowned privileged app is a decision nobody has revisited."
}

$uncatalogued = @($permissionRows | Where-Object { -not $_.InCatalog -and $_.Permission -notlike "(unresolved*" } | Select-Object -ExpandProperty Permission -Unique)
if ($uncatalogued.Count -gt 0) {
    $findings += New-Finding -Severity Info -Category "Catalog" `
        -Finding "$($uncatalogued.Count) granted permission(s) are not in the risk catalog" `
        -Subject (($uncatalogued | Select-Object -First 15) -join "; ") `
        -Count $uncatalogued.Count `
        -Evidence "The catalog will always lag Microsoft's permission list, and these were scored conservatively rather than ignored." `
        -Recommendation "Add the ones that matter to Reports/Helpers/AppPermissionCatalog.ps1 so future runs rank them correctly."
}

if (-not $usageChecked) {
    $findings += New-Finding -Severity NotChecked -Category "Usage" `
        -Finding "App usage and dormancy were not evaluated" `
        -Evidence "No Log Analytics workspace was supplied, so AADServicePrincipalSignInLogs could not be joined. Dormancy is one of the four signals this report is built around." `
        -Recommendation "Re-run with -WorkspaceId <guid> to populate it. Without it, treat the intersection section as 'privileged, credentialed and ownerless' only."
}

if (-not $IncludeMicrosoftApps) {
    $findings += New-Finding -Severity NotChecked -Category "Scope" `
        -Finding "Microsoft first-party applications were excluded" `
        -Evidence "Default behaviour - a tenant carries hundreds and they dominate both the call count and the output." `
        -Recommendation "Re-run with -IncludeMicrosoftApps when hunting rather than reviewing."
}

if ($truncatedInspection) {
    $findings += New-Finding -Severity High -Category "Completeness" `
        -Finding "Inspection was capped at $MaxServicePrincipals service principals - this inventory is incomplete" `
        -Evidence "The tenant has more in-scope service principals than the ceiling allows." `
        -Recommendation "Re-run with a higher -MaxServicePrincipals. Do not treat the absence of a finding as evidence of absence until you do."
}

if ($findings.Count -eq 0) {
    $findings += New-Finding -Severity Info -Category "Summary" `
        -Finding "No application risk findings" `
        -Evidence "$($inventory.Count) app(s) inspected, $($permissionRows.Count) application permission(s) and $($delegatedRows.Count) delegated grant(s) evaluated." `
        -Recommendation "Re-run after each new app integration."
}

$findings = @($findings | Sort-Finding)

# ---------------------------------------------------------------------------
# 11. Read-only assertion, then render
# ---------------------------------------------------------------------------
$readOnlyProof = Test-GraphCallLogIsReadOnly -ThrowOnViolation
Write-Status "Read-only verified: $($readOnlyProof.ReadCalls) GET call(s), $($readOnlyProof.WriteCalls) write call(s)" -Type Success

$callSummary = @(Get-GraphCallLog |
    Group-Object Method, Endpoint |
    ForEach-Object {
        $parts = $_.Name -split ", ", 2
        [pscustomobject]@{
            Method   = $parts[0]
            Endpoint = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            Calls    = $_.Count
            TotalRows = (@($_.Group | Measure-Object Rows -Sum).Sum)
            Outcomes = ((@($_.Group | Select-Object -ExpandProperty Outcome -Unique)) -join ", ")
        }
    } | Sort-Object @{ Expression = "Calls"; Descending = $true })

$criticalApps = @($inventory | Where-Object { $_.RiskTier -eq "Critical" })
$highApps     = @($inventory | Where-Object { $_.RiskTier -eq "High" })

$statTiles = @(
    @{ Label = "Apps inspected"; Value = $inventory.Count; Tone = "neutral" }
    @{ Label = "Critical risk"; Value = $criticalApps.Count; Tone = if ($criticalApps.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Escalation-capable"; Value = $escalationApps.Count; Tone = if ($escalationApps.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Shadow admins (app owners)"; Value = $shadowAdmins.Count; Tone = if ($shadowAdmins.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Privileged + credentialed + ownerless"; Value = $intersection.Count; Tone = if ($intersection.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Federated credentials"; Value = $ficApps.Count; Tone = if ($ficApps.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Dormant"; Value = if ($usageChecked) { @($inventory | Where-Object { $_.IsDormant -eq $true }).Count } else { "not checked" }; Tone = if (-not $usageChecked) { "neutral" } else { "warn" } }
    @{ Label = "Graph writes issued"; Value = $readOnlyProof.WriteCalls; Tone = if ($readOnlyProof.WriteCalls -eq 0) { "good" } else { "danger" } }
)

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Reports\Output\AppRiskInventory-$timestamp.html"
}

$scopeNote = if ($IncludeMicrosoftApps) { "including Microsoft first-party" } else { "excluding Microsoft first-party" }
$usageNote = if ($usageChecked) { "usage joined from Log Analytics" } else { "usage NOT checked" }

New-HtmlReport -Title "Application Risk Inventory" `
    -Subtitle "$($config.TenantDomain) - $($inventory.Count) apps inspected, $scopeNote, $usageNote" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                                                = $findings
        "Work queue: privileged + credentialed + ownerless$(if ($usageChecked) { ' + dormant' })" = $intersection
        "Apps that can escalate their own permissions"             = @($escalationApps | Select-Object Application, AppId, RiskScore, EscalationPermissions, Owners, ActiveSecrets, FederatedCredentials, LastAppOnlySignIn)
        "Shadow admins: owners of escalation-capable apps"         = $shadowAdmins
        "Service principals holding a directory role"              = @($roleHoldingApps | Select-Object Application, AppId, DirectoryRoles, RiskScore, Owners, ActiveSecrets, LastAppOnlySignIn)
        "Apps using federated identity credentials"                = @($ficApps | Select-Object Application, AppId, FederatedCredentials, FederatedIssuers, RiskScore, Owners)
        "Privileged apps with no owner"                            = @($ownerlessPrivileged | Select-Object Application, AppId, WorstPermissionTier, RiskScore, ActiveSecrets, FederatedCredentials, LastAppOnlySignIn)
        "Full inventory, scored"                                   = $inventory
        "All application permissions (client-side, complete)"       = @($permissionRows | Sort-Object RiskRank, Application)
        "All delegated grants"                                     = @($delegatedRows | Sort-Object RiskRank, Application)
        "Read-only evidence: every Graph call issued"              = $callSummary
    }) `
    -FooterNote "Read-only. $($readOnlyProof.ReadCalls) GET calls, $($readOnlyProof.WriteCalls) writes - see the evidence section. Enumeration is client-side (per service principal), so permissions on any resource API are included, not just a hardcoded list. Removing a permission or credential breaks the app immediately - identify the owner and business use first." `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

# ---------------------------------------------------------------------------
# 12. Machine-readable exports
# ---------------------------------------------------------------------------
$outputDir = Split-Path -Parent $OutputPath

if ($ExportCsv) {
    $csvPath = Join-Path $outputDir "AppRiskInventory-$timestamp.csv"
    $inventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Status "CSV written: $csvPath" -Type Success
}

if ($ExportJson) {
    $jsonPath = Join-Path $outputDir "AppRiskInventory-$timestamp.json"
    [pscustomobject]@{
        GeneratedAt          = (Get-Date).ToString("o")
        Tenant               = $config.TenantDomain
        ScopeIncludedMicrosoft = [bool]$IncludeMicrosoftApps
        UsageChecked         = $usageChecked
        InspectionTruncated  = $truncatedInspection
        ReadOnlyProof        = $readOnlyProof
        Findings             = $findings
        WorkQueue            = $intersection
        Inventory            = $inventory
        ApplicationPermissions = $permissionRows
        DelegatedGrants      = $delegatedRows
        ShadowAdmins         = $shadowAdmins
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Status "JSON written: $jsonPath" -Type Success
}

Disconnect-MgGraph | Out-Null

if ($PassThru) { return $inventory }
