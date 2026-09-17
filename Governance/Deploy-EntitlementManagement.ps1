<#
.SYNOPSIS
    Deploys Entra ID Governance Entitlement Management — a catalog, self-service
    access packages, and their request / approval / expiration / review policies.

.DESCRIPTION
    Requires Microsoft Entra ID Governance or Entra ID P2.

    Builds an end-to-end "request access" experience on top of the security groups
    created by Deploy-Groups.ps1:

      Catalog: "Corp Access Packages"  (externally visible)
        │
        ├─ ITSM Platform Access      → grants SG-App-ITSM
        │     requestor : SG-All-Employees   approval : manager (fallback CISO)
        │     expires   : 180 days           review   : quarterly, remove on deny
        │
        ├─ CRM Platform Access       → grants SG-App-CRM
        │     requestor : SG-All-Employees   approval : manager (fallback CISO)
        │     expires   : 180 days           review   : quarterly
        │
        ├─ GRC & Audit Tooling       → grants SG-App-GRC   (sensitive access)
        │     requestor : SG-All-Employees   approval : CISO only
        │     expires   : 90 days            review   : quarterly
        │
        └─ Vendor Collaboration Access (guest) → grants SG-App-CRM
              requestor : connected org "Fabrikam Partners" (fabrikam.com)
              approval  : internal sponsor (fallback CISO)
              expires   : 30 days

    Every object is created idempotently (looked up by display name first).
    Re-running the script is safe and only fills in what is missing.

    All settings are data-driven from config.json → Governance.EntitlementManagement.
    Remove or edit the Packages array there to change what gets deployed.

.PARAMETER ConfigPath
    Path to config.json (default: ..\config\config.json)

.PARAMETER SkipGuestPackage
    Do not create the connected organization or the guest access package.

.EXAMPLE
    .\Governance\Deploy-EntitlementManagement.ps1

.EXAMPLE
    .\Setup-TestTenant.ps1 -Steps EntitlementManagement
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$SkipGuestPackage,

    # Force interactive Microsoft Graph PowerShell sign-in (browser / device code).
    # Needed because the Azure CLI app is NOT pre-authorized for
    # EntitlementManagement.* on Microsoft Graph (AADSTS65002), so the shared
    # Connect-TestTenant az-token path cannot manage access packages.
    [switch]$Interactive,
    [switch]$DeviceCode
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain

$emScopes = @(
    "EntitlementManagement.ReadWrite.All",
    "Group.Read.All","User.Read.All","Directory.Read.All"
)

function Disconnect-Safe {
    # Disconnect-MgGraph emits a noisy warning when it tries to clear the persisted
    # MSAL cache using a bare-domain tenant id ("...must be a well-formed URI").
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null } catch { }
}

function Connect-ForEntitlementManagement {
    param([switch]$Interactive, [switch]$DeviceCode)

    $ctx = Get-MgContext
    if ($ctx -and ($ctx.Scopes -contains "EntitlementManagement.ReadWrite.All")) {
        Write-Status "Using existing Graph session: $($ctx.Account)" -Type Success
        return
    }

    if ($Interactive -or $DeviceCode) {
        $p = @{ Scopes = $emScopes; NoWelcome = $true; TenantId = $domain }
        if ($DeviceCode) { $p.UseDeviceAuthentication = $true }
        Connect-MgGraph @p
        return
    }

    # Try silent — picks up a persisted token cache from a prior interactive sign-in.
    if (Test-Path (Join-Path $HOME ".graph")) {
        try {
            Connect-MgGraph -Scopes $emScopes -NoWelcome -TenantId $domain -ErrorAction Stop
            $ctx = Get-MgContext
            if ($ctx -and ($ctx.Scopes -contains "EntitlementManagement.ReadWrite.All")) {
                Write-Status "Reused cached Graph session: $($ctx.Account)" -Type Success
                return
            }
        } catch { }
    }

    # Last resort: the shared az-token path (will 403 on EM; preflight explains).
    Connect-TestTenant
}

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-ForEntitlementManagement -Interactive:$Interactive -DeviceCode:$DeviceCode

Write-Host ""
Write-Status "Entitlement Management — Access Packages & Policies" -Type Header
Write-Host "  Tenant : $domain"
Write-Host ""

# ── Config ───────────────────────────────────────────────────────────────────
$emRoot = $null
if ($config.PSObject.Properties.Name -contains "Governance" -and
    $config.Governance.PSObject.Properties.Name -contains "EntitlementManagement") {
    $emRoot = $config.Governance.EntitlementManagement
}
if (-not $emRoot) {
    Write-Status "config.Governance.EntitlementManagement block missing — nothing to deploy." -Type Warning
    Write-Status "Add the block to config.json (see script header) and re-run." -Type Info
    Disconnect-Safe
    return
}

$emBase        = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement"

# ── Preflight: confirm the token can reach Entitlement Management ─────────────
# The Azure CLI app (used by Connect-TestTenant's token cache) needs the delegated
# permission EntitlementManagement.ReadWrite.All admin-consented in the tenant.
try {
    Invoke-MgGraphRequest -Method GET -Uri "$emBase/catalogs?`$top=1" -ErrorAction Stop | Out-Null
} catch {
    $statusCode = $null
    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
    if ($statusCode -eq 403 -or "$($_.Exception.Message)" -match "403|Forbidden|UnAuthorized|not authorized") {
        Write-Status "This Graph token cannot reach Entitlement Management." -Type Error
        Write-Host ""
        Write-Host "  The Azure CLI app is not pre-authorized for EntitlementManagement.* on" -ForegroundColor DarkGray
        Write-Host "  Microsoft Graph, so 'az login --scope' fails with AADSTS65002." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Re-run this script with interactive Graph PowerShell sign-in:" -ForegroundColor Yellow
        Write-Host "    .\Governance\Deploy-EntitlementManagement.ps1 -Interactive" -ForegroundColor Cyan
        Write-Host "  or, headless:" -ForegroundColor Yellow
        Write-Host "    .\Governance\Deploy-EntitlementManagement.ps1 -DeviceCode" -ForegroundColor Cyan
        Write-Host "  A Global Admin consents to EntitlementManagement.ReadWrite.All once;" -ForegroundColor DarkGray
        Write-Host "  the session is cached for subsequent runs." -ForegroundColor DarkGray
        Write-Host ""
    Disconnect-Safe
        return
    }
    throw
}
$catalogName   = if ($emRoot.CatalogName) { [string]$emRoot.CatalogName } else { "Corp Access Packages" }
$catalogDesc   = if ($emRoot.CatalogDescription) { [string]$emRoot.CatalogDescription } `
                 else { "Self-service access packages for internal teams and external vendors." }
$approvalDays  = if ($emRoot.ApprovalTimeoutDays) { [int]$emRoot.ApprovalTimeoutDays } else { 7 }
$reviewMonths  = if ($emRoot.AccessReviewIntervalMonths) { [int]$emRoot.AccessReviewIntervalMonths } else { 3 }
$fallbackTitle = if ($emRoot.FallbackApproverJobTitle) { [string]$emRoot.FallbackApproverJobTitle } `
                 else { "Chief Information Security Officer" }

# ── Small Graph helpers ──────────────────────────────────────────────────────
function Get-Prop { param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [hashtable]) { if ($Obj.ContainsKey($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Invoke-EM {
    param([string]$Method, [string]$Uri, $Body)
    $params = @{ Method = $Method; Uri = $Uri; ContentType = "application/json" }
    if ($PSBoundParameters.ContainsKey("Body") -and $null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 25)
    }
    return Invoke-MgGraphRequest @params
}

function Get-EMCollection {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next
        foreach ($v in (Get-Prop $page "value")) { $items.Add($v) | Out-Null }
        $next = Get-Prop $page "@odata.nextLink"
    }
    return $items
}

function Format-Duration { param([int]$Days)
    if ($Days -le 0) { return $null }
    return "P${Days}D"
}

# ── Resolve approver / reviewer accounts ─────────────────────────────────────
Write-Status "Resolving approver accounts" -Type Header

$fallbackApprover = Get-AllEmployeeUsers -CompanyName $config.CompanyName |
    Where-Object { $_.JobTitle -eq $fallbackTitle } | Select-Object -First 1

if (-not $fallbackApprover) {
    $adminUpn = if ($config.Users.AdminUpn) { "$($config.Users.AdminUpn)@$domain" } else { "testadmin@$domain" }
    $fallbackApprover = Get-MgUser -Filter "userPrincipalName eq '$adminUpn'" -ErrorAction SilentlyContinue
}
$fallbackApproverId = if ($fallbackApprover) { $fallbackApprover.Id } else { $null }
Write-Host "  Fallback approver : $(if ($fallbackApprover) { $fallbackApprover.UserPrincipalName } else { 'NOT FOUND — approvals will use requestor manager only' })"

# ── Catalog ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "1. Catalog: $catalogName" -Type Header

$catalog = (Get-EMCollection "$emBase/catalogs?`$filter=displayName eq '$($catalogName -replace "'","''")'") | Select-Object -First 1
if ($catalog) {
    Write-Status "Exists: $catalogName" -Type Warning
} else {
    $catalog = Invoke-EM POST "$emBase/catalogs" @{
        displayName         = $catalogName
        description         = $catalogDesc
        catalogType         = "userManaged"
        state               = "published"
        isExternallyVisible = $true
    }
    Write-Status "Created catalog: $catalogName" -Type Success
}
$catalogId = Get-Prop $catalog "id"

# ── Add a security group to the catalog as a resource, return its role/scope ──
function Add-CatalogGroupResource {
    param([string]$GroupName)

    $group = Get-MgGroup -Filter "displayName eq '$($GroupName -replace "'","''")'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) {
        Write-Status "  Group not found: $GroupName — run Deploy-Groups.ps1 first" -Type Warning
        return $null
    }

    $resources = Get-EMCollection "$emBase/catalogs/$catalogId/resources?`$filter=originSystem eq 'AadGroup'"
    $resource  = $resources | Where-Object { (Get-Prop $_ "originId") -eq $group.Id } | Select-Object -First 1

    if (-not $resource) {
        Invoke-EM POST "$emBase/resourceRequests" @{
            requestType = "adminAdd"
            catalogId   = $catalogId
            resource    = @{
                originId     = $group.Id
                originSystem = "AadGroup"
                displayName  = $group.DisplayName
                description  = "Membership of $($group.DisplayName)"
            }
        } | Out-Null
        Write-Status "  Added catalog resource: $GroupName" -Type Success

        for ($i = 0; $i -lt 12 -and -not $resource; $i++) {
            Start-Sleep -Seconds 3
            $resources = Get-EMCollection "$emBase/catalogs/$catalogId/resources?`$filter=originSystem eq 'AadGroup'"
            $resource  = $resources | Where-Object { (Get-Prop $_ "originId") -eq $group.Id } | Select-Object -First 1
        }
    } else {
        Write-Status "  Catalog resource exists: $GroupName" -Type Warning
    }
    if (-not $resource) {
        Write-Status "  Timed out waiting for catalog resource to register: $GroupName" -Type Error
        return $null
    }

    $resourceId = Get-Prop $resource "id"
    $roles = Get-EMCollection ("$emBase/catalogs/$catalogId/resourceRoles?`$filter=(originSystem eq 'AadGroup' and resource/id eq '$resourceId')&`$expand=resource")
    $memberRole = $roles | Where-Object { (Get-Prop $_ "displayName") -eq "Member" } | Select-Object -First 1
    if (-not $memberRole) { $memberRole = $roles | Select-Object -First 1 }
    if (-not $memberRole) {
        Write-Status "  No resource role returned for $GroupName" -Type Error
        return $null
    }

    return [PSCustomObject]@{
        GroupId       = $group.Id
        GroupName     = $group.DisplayName
        ResourceId    = $resourceId
        RoleOriginId  = Get-Prop $memberRole "originId"
        RoleName      = Get-Prop $memberRole "displayName"
    }
}

# ── Access package + its single resource-role grant ─────────────────────────
function New-AccessPackage {
    param([string]$Name, [string]$Description, $GroupResource, [bool]$Hidden = $false)

    $ap = (Get-EMCollection "$emBase/accessPackages?`$filter=displayName eq '$($Name -replace "'","''")'") | Select-Object -First 1
    if ($ap) {
        Write-Status "  Exists: $Name" -Type Warning
    } else {
        $ap = Invoke-EM POST "$emBase/accessPackages" @{
            displayName            = $Name
            description            = $Description
            isHidden               = $Hidden
            "catalog@odata.bind"   = "$emBase/catalogs/$catalogId"
        }
        Write-Status "  Created access package: $Name" -Type Success
    }
    $apId = Get-Prop $ap "id"

    if ($GroupResource) {
        $existingScopes = Get-EMCollection "$emBase/accessPackages/$apId/resourceRoleScopes?`$expand=scope,role"
        $already = $existingScopes | Where-Object {
            (Get-Prop (Get-Prop $_ "role") "originId") -eq $GroupResource.RoleOriginId
        }
        if ($already) {
            Write-Status "  Resource grant exists: $($GroupResource.GroupName)" -Type Warning
        } else {
            Invoke-EM POST "$emBase/accessPackages/$apId/resourceRoleScopes" @{
                role = @{
                    displayName  = $GroupResource.RoleName
                    originSystem = "AadGroup"
                    originId     = $GroupResource.RoleOriginId
                    resource     = @{
                        id           = $GroupResource.ResourceId
                        originId     = $GroupResource.GroupId
                        originSystem = "AadGroup"
                    }
                }
                scope = @{
                    displayName  = "Root"
                    originSystem = "AadGroup"
                    originId     = $GroupResource.GroupId
                    isRootScope  = $true
                }
            } | Out-Null
            Write-Status "  Granted $($GroupResource.RoleName) of $($GroupResource.GroupName)" -Type Success
        }
    }
    return $apId
}

# ── Assignment (request) policy ─────────────────────────────────────────────
function New-AssignmentPolicy {
    param(
        [string]$AccessPackageId,
        [string]$PolicyName,
        [string]$Description,
        [hashtable]$AllowedTargets,   # { scope = "..."; targets = @(...) }
        [int]$AccessDurationDays,
        [bool]$RequireApproval,
        [string]$ApproverType,        # manager | fallbackOnly | internalSponsor
        [bool]$EnableAccessReview
    )

    $existing = (Get-EMCollection "$emBase/assignmentPolicies?`$filter=displayName eq '$($PolicyName -replace "'","''")'") | Select-Object -First 1
    if ($existing) {
        Write-Status "  Policy exists: $PolicyName" -Type Warning
        return
    }

    $duration = Format-Duration $AccessDurationDays
    $expiration = if ($duration) { @{ type = "afterDuration"; duration = $duration } } else { @{ type = "noExpiration" } }

    # ---- approvers ----
    $stages = @()
    if ($RequireApproval) {
        $primary = @()
        switch ($ApproverType) {
            "manager" {
                $primary += @{ "@odata.type" = "#microsoft.graph.requestorManager"; managerLevel = 1 }
            }
            "internalSponsor" {
                $primary += @{ "@odata.type" = "#microsoft.graph.internalSponsors"; isBackup = $false }
            }
            default {
                if ($fallbackApproverId) {
                    $primary += @{ "@odata.type" = "#microsoft.graph.singleUser"; userId = $fallbackApproverId }
                }
            }
        }
        $fallback = @()
        if ($fallbackApproverId -and $ApproverType -ne "fallbackOnly") {
            $fallback += @{ "@odata.type" = "#microsoft.graph.singleUser"; userId = $fallbackApproverId }
        }
        if ($primary.Count -eq 0) {
            # nobody to approve — degrade to no approval rather than create a broken policy
            Write-Status "  No approver resolvable — creating '$PolicyName' without approval" -Type Warning
            $RequireApproval = $false
        } else {
            $stages = @(@{
                durationBeforeAutomaticDenial     = "P${approvalDays}D"
                isApproverJustificationRequired   = $true
                isEscalationEnabled               = $false
                durationBeforeEscalation          = "PT0S"
                primaryApprovers                  = $primary
                fallbackPrimaryApprovers          = $fallback
                escalationApprovers               = @()
                fallbackEscalationApprovers       = @()
            })
        }
    }

    $body = @{
        displayName            = $PolicyName
        description            = $Description
        allowedTargetScope     = $AllowedTargets.scope
        specificAllowedTargets = $AllowedTargets.targets
        expiration             = $expiration
        "accessPackage@odata.bind" = "$emBase/accessPackages/$AccessPackageId"
        requestorSettings = @{
            enableTargetsToSelfAddAccess    = $true
            enableTargetsToSelfUpdateAccess = $false
            enableTargetsToSelfRemoveAccess = $true
            allowCustomAssignmentSchedule   = $false
        }
        requestApprovalSettings = @{
            isApprovalRequiredForAdd    = $RequireApproval
            isApprovalRequiredForUpdate = $false
            stages                      = $stages
        }
    }

    if ($EnableAccessReview -and $fallbackApproverId) {
        $startIso = (Get-Date).ToString("yyyy-MM-ddT00:00:00Z")
        $body.reviewSettings = @{
            isEnabled                      = $true
            expirationBehavior             = "removeAccess"
            isRecommendationEnabled        = $true
            isReviewerJustificationRequired = $true
            isSelfReview                   = $false
            schedule = @{
                startDateTime = $startIso
                expiration    = @{ type = "afterDuration"; duration = "P14D" }
                recurrence    = @{
                    pattern = @{ type = "absoluteMonthly"; interval = $reviewMonths; dayOfMonth = 1 }
                    range   = @{ type = "noEnd"; startDate = (Get-Date -Format "yyyy-MM-dd") }
                }
            }
            primaryReviewers = @(@{ "@odata.type" = "#microsoft.graph.singleUser"; userId = $fallbackApproverId })
        }
    }

    try {
        Invoke-EM POST "$emBase/assignmentPolicies" $body | Out-Null
        Write-Status "  Created policy: $PolicyName" -Type Success
    } catch {
        Write-Status "  Policy create failed ($PolicyName): $($_.Exception.Message)" -Type Error
    }
}

# ── Build internal packages ────────────────────────────────────────────────
Write-Host ""
Write-Status "2. Internal access packages" -Type Header

$requestorGroupCache = @{}
function Resolve-RequestorTarget {
    param([string]$GroupName, [string]$Scope)
    if ($Scope -and $Scope -ne "specificDirectoryUsers") {
        return @{ scope = $Scope; targets = @() }
    }
    if (-not $requestorGroupCache.ContainsKey($GroupName)) {
        $g = Get-MgGroup -Filter "displayName eq '$($GroupName -replace "'","''")'" -ErrorAction SilentlyContinue | Select-Object -First 1
        $requestorGroupCache[$GroupName] = $g
    }
    $grp = $requestorGroupCache[$GroupName]
    if (-not $grp) {
        Write-Status "  Requestor group not found ($GroupName) — falling back to allMemberUsers" -Type Warning
        return @{ scope = "allMemberUsers"; targets = @() }
    }
    return @{
        scope   = "specificDirectoryUsers"
        targets = @(@{ "@odata.type" = "#microsoft.graph.groupMembers"; groupId = $grp.Id })
    }
}

$packages = @()
if ($emRoot.PSObject.Properties.Name -contains "Packages") { $packages = @($emRoot.Packages) }

foreach ($pkg in $packages) {
    $pkgName = [string]$pkg.Name
    Write-Host ""
    Write-Status "  → $pkgName" -Type Info

    $groupRes = $null
    if ($pkg.GroupResource) {
        $groupRes = Add-CatalogGroupResource -GroupName ([string]$pkg.GroupResource)
    }

    $apId = New-AccessPackage -Name $pkgName -Description ([string]$pkg.Description) -GroupResource $groupRes

    $reqGroup = if ($pkg.PSObject.Properties.Name -contains "RequestorGroup") { [string]$pkg.RequestorGroup } else { $null }
    $reqScope = if ($pkg.PSObject.Properties.Name -contains "RequestorScope") { [string]$pkg.RequestorScope } else { $null }
    $targets  = Resolve-RequestorTarget -GroupName $reqGroup -Scope $reqScope

    $durDays  = if ($pkg.PSObject.Properties.Name -contains "AccessDurationDays") { [int]$pkg.AccessDurationDays } else { 180 }
    $reqAppr  = [bool]$pkg.RequireApproval
    $apprType = if ($pkg.PSObject.Properties.Name -contains "ApproverType") { [string]$pkg.ApproverType } else { "manager" }
    $review   = if ($pkg.PSObject.Properties.Name -contains "EnableAccessReview") { [bool]$pkg.EnableAccessReview } else { $false }

    New-AssignmentPolicy -AccessPackageId $apId `
        -PolicyName "$pkgName - Request Policy" `
        -Description "Self-service request policy for $pkgName" `
        -AllowedTargets $targets `
        -AccessDurationDays $durDays `
        -RequireApproval $reqAppr `
        -ApproverType $apprType `
        -EnableAccessReview $review
}

# ── Guest package + connected organization ─────────────────────────────────
$guest = $null
if ($emRoot.PSObject.Properties.Name -contains "GuestPackage") { $guest = $emRoot.GuestPackage }

if ($SkipGuestPackage) {
    Write-Host ""
    Write-Status "3. Guest package skipped (-SkipGuestPackage)" -Type Warning
} elseif ($guest -and [bool]$guest.Enabled) {
    Write-Host ""
    Write-Status "3. Guest access package: $($guest.Name)" -Type Header

    $connOrgId = $null
    $co = $guest.ConnectedOrganization
    if ($co -and [bool]$co.Enabled) {
        $coName = [string]$co.DisplayName
        $existingCo = (Get-EMCollection "$emBase/connectedOrganizations?`$filter=displayName eq '$($coName -replace "'","''")'") | Select-Object -First 1
        if ($existingCo) {
            Write-Status "  Connected org exists: $coName" -Type Warning
            $connOrgId = Get-Prop $existingCo "id"
        } else {
            try {
                $newCo = Invoke-EM POST "$emBase/connectedOrganizations" @{
                    displayName     = $coName
                    description     = "External partner organization (test lab)"
                    state           = "configured"
                    identitySources = @(@{
                        "@odata.type" = "#microsoft.graph.domainIdentitySource"
                        domainName    = [string]$co.DomainName
                        displayName   = [string]$co.DomainName
                    })
                }
                $connOrgId = Get-Prop $newCo "id"
                Write-Status "  Created connected org: $coName ($($co.DomainName))" -Type Success
            } catch {
                Write-Status "  Connected org create failed: $($_.Exception.Message)" -Type Error
            }
        }
    }

    $guestGroupRes = $null
    if ($guest.GroupResource) {
        $guestGroupRes = Add-CatalogGroupResource -GroupName ([string]$guest.GroupResource)
    }
    $guestApId = New-AccessPackage -Name ([string]$guest.Name) -Description ([string]$guest.Description) -GroupResource $guestGroupRes

    if ($connOrgId) {
        $guestTargets = @{
            scope   = "specificConnectedOrganizationUsers"
            targets = @(@{ "@odata.type" = "#microsoft.graph.connectedOrganizationMembers"; connectedOrganizationId = $connOrgId })
        }
    } else {
        $guestTargets = @{ scope = "allExternalUsers"; targets = @() }
    }

    $guestDur = if ($guest.PSObject.Properties.Name -contains "AccessDurationDays") { [int]$guest.AccessDurationDays } else { 30 }

    New-AssignmentPolicy -AccessPackageId $guestApId `
        -PolicyName "$($guest.Name) - Request Policy" `
        -Description "External vendor request policy — internal sponsor approval" `
        -AllowedTargets $guestTargets `
        -AccessDurationDays $guestDur `
        -RequireApproval $true `
        -ApproverType "internalSponsor" `
        -EnableAccessReview $false
} else {
    Write-Host ""
    Write-Status "3. Guest package disabled in config" -Type Warning
}

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Entitlement Management deployment complete" -Type Success
Write-Host ""
$allPkgs = Get-EMCollection "$emBase/accessPackages?`$filter=catalog/id eq '$catalogId'"
Write-Host "  Catalog          : $catalogName" -ForegroundColor Green
Write-Host "  Access packages  : $(@($allPkgs).Count)" -ForegroundColor Green
foreach ($p in $allPkgs) {
    Write-Host "    - $(Get-Prop $p 'displayName')" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  My Access portal : https://myaccess.microsoft.com/" -ForegroundColor Cyan
Write-Host "  Admin view       : Entra portal → Identity Governance → Entitlement management → Access packages" -ForegroundColor DarkGray
Write-Host "  Try it           : sign in as a test user → My Access → Request the ITSM or CRM package" -ForegroundColor DarkGray

    Disconnect-Safe
