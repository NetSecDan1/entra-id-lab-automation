<#
.SYNOPSIS
    Read-only Microsoft Graph connection, scope preflight, throttle-safe paging,
    and a normalized finding type for the diagnostic reports.

.DESCRIPTION
    Helpers/Common.ps1 has Connect-TestTenant, which the deployment scripts use.
    Its device-code fallback requests ReadWrite scopes because those scripts
    create objects. A diagnostic report should never hold that consent, so this
    file provides the read-only equivalent and a few things the reports need:

      Connect-GraphReadOnly     - connect with *.Read.All scopes only
      Test-GraphScope           - preflight: say up front which scopes are
                                  missing, instead of failing mid-report
      Invoke-GraphPagedRequest  - follow @odata.nextLink, honour 429 Retry-After
      Get-GraphTenantCapability - detect P1/P2 so a report can say "not checked"
                                  rather than implying a clean pass
      New-Finding               - one shape for every finding across reports
      Sort-Finding              - order findings by real severity, not alphabet

    The scope preflight matters more than it looks. Without it a report runs for
    two minutes, silently returns empty collections for the endpoints the caller
    lacks consent for, and renders a reassuring all-green page. Test-GraphScope
    turns that into a warning at the top of the run.

    Everything here is READ-ONLY.

.EXAMPLE
    Connect-GraphReadOnly
    $preflight = Test-GraphScope -Required @("Application.Read.All", "Policy.Read.All")
    if (-not $preflight.AllPresent) { Write-Status $preflight.Summary -Type Warning }
#>

# Read-only scopes covering every diagnostic report in this repo. Deliberately
# no *.ReadWrite.* entries - if a new report needs one, it isn't a diagnostic.
$script:GraphReadOnlyScopes = @(
    "User.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "Directory.Read.All",
    "Application.Read.All",
    "Policy.Read.All",
    "Policy.Read.ConditionalAccess",
    "RoleManagement.Read.Directory",
    "RoleManagement.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Organization.Read.All"
)
# Note: oauth2PermissionGrants and appRoleAssignedTo are read under
# Directory.Read.All above. There is deliberately no DelegatedPermissionGrant.*
# entry here - the only widely available variant of that scope is ReadWrite.

function Get-GraphReadOnlyScopes { return $script:GraphReadOnlyScopes }

<#
.SYNOPSIS
    Connects to Microsoft Graph with read-only scopes.

.DESCRIPTION
    Mirrors Connect-TestTenant's authentication path (Az CLI token cache first,
    device code as fallback) but never requests a write scope. If a Graph session
    is already open it is reused rather than reconnected - reconnecting would
    discard a broader existing consent for no benefit.

.PARAMETER Scopes
    Override the default read-only scope set.

.PARAMETER TenantDomain
    Tenant to authenticate against. Defaults to config.json's TenantDomain.

.PARAMETER Force
    Reconnect even if a session already exists.
#>
function Connect-GraphReadOnly {
    [CmdletBinding()]
    param(
        [string[]]$Scopes = $script:GraphReadOnlyScopes,
        [string]$TenantDomain,
        [switch]$Force
    )

    $existing = $null
    try { $existing = Get-MgContext -ErrorAction SilentlyContinue } catch { $existing = $null }

    if ($existing -and -not $Force) {
        Write-Host "[+] Reusing existing Graph session: $($existing.Account) (tenant $($existing.TenantId))" -ForegroundColor Green
        return $existing
    }

    if (-not $TenantDomain) {
        try { $TenantDomain = (Get-Config).TenantDomain } catch { $TenantDomain = $null }
    }

    $tokenJson = $null
    if ($TenantDomain) {
        $tokenJson = az account get-access-token --resource https://graph.microsoft.com --tenant $TenantDomain 2>$null
    }

    if ($tokenJson) {
        $token       = ($tokenJson | ConvertFrom-Json).accessToken
        $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
        Connect-MgGraph -AccessToken $secureToken -NoWelcome
        Write-Host "[+] Connected via Az CLI token cache (read-only reports)" -ForegroundColor Green
    } else {
        Write-Host "[!] Az CLI token not found - falling back to device code with READ-ONLY scopes" -ForegroundColor Yellow
        Write-Host "[*] Seed the cache once with: az login --use-device-code --tenant $TenantDomain" -ForegroundColor Cyan
        Connect-MgGraph -Scopes $Scopes -NoWelcome -UseDeviceAuthentication
    }

    $context = Get-MgContext
    Write-Host "[+] Graph: $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green
    return $context
}

<#
.SYNOPSIS
    Checks the current Graph session for the scopes a report needs.

.DESCRIPTION
    Returns an object describing which required scopes are present and which are
    missing, so a report can warn clearly at the start rather than rendering
    empty sections that look like clean results.

    A token acquired through the Az CLI cache, or an app-only token using
    application permissions, may not enumerate scopes the same way a delegated
    consent does. In that case this reports Inconclusive rather than claiming
    scopes are missing - a false "you lack permission" warning is its own kind
    of noise.

.PARAMETER Required
    Scope names the report needs.

.PARAMETER AcceptAlternatives
    Treat a broader scope as satisfying a narrower one (Directory.Read.All
    covers most directory reads). On by default.
#>
function Test-GraphScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Required,
        [bool]$AcceptAlternatives = $true
    )

    $context = $null
    try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch { $context = $null }

    if (-not $context) {
        return [pscustomobject]@{
            AllPresent   = $false
            Inconclusive = $false
            Present      = @()
            Missing      = @($Required)
            Summary      = "No Graph session. Call Connect-GraphReadOnly first."
        }
    }

    $granted = @($context.Scopes)
    if ($granted.Count -eq 0) {
        return [pscustomobject]@{
            AllPresent   = $true
            Inconclusive = $true
            Present      = @()
            Missing      = @()
            Summary      = "Token does not enumerate scopes (app-only or cached token). Permissions not verified up front - a section that comes back empty may be a permission problem rather than a clean result."
        }
    }

    # Directory.Read.All is the practical superset for most directory object reads.
    $broadeners = @{
        "User.Read.All"                 = @("Directory.Read.All")
        "Group.Read.All"                = @("Directory.Read.All")
        "GroupMember.Read.All"          = @("Directory.Read.All", "Group.Read.All")
        "Application.Read.All"          = @("Directory.Read.All")
        "Policy.Read.ConditionalAccess" = @("Policy.Read.All")
        "RoleManagement.Read.Directory" = @("RoleManagement.Read.All", "Directory.Read.All")
        "Organization.Read.All"         = @("Directory.Read.All")
    }

    $present = @()
    $missing = @()
    foreach ($scope in $Required) {
        $satisfied = $granted -contains $scope
        if (-not $satisfied -and $AcceptAlternatives -and $broadeners.ContainsKey($scope)) {
            $satisfied = @($broadeners[$scope] | Where-Object { $granted -contains $_ }).Count -gt 0
        }
        if ($satisfied) { $present += $scope } else { $missing += $scope }
    }

    $summary = if ($missing.Count -eq 0) {
        "All $($Required.Count) required scope(s) granted."
    } else {
        "Missing scope(s): $($missing -join ', '). Sections needing them will be empty - that is a permission gap, not a clean result. Reconnect with: Connect-GraphReadOnly -Force"
    }

    return [pscustomobject]@{
        AllPresent   = ($missing.Count -eq 0)
        Inconclusive = $false
        Present      = @($present)
        Missing      = @($missing)
        Summary      = $summary
    }
}

<#
.SYNOPSIS
    GETs a Graph URL and follows paging, honouring throttling.

.DESCRIPTION
    Some of the endpoints these reports need (oauth2PermissionGrants,
    reports/authenticationMethods, appRoleAssignedTo) are easier and faster to
    read over REST than through per-object SDK cmdlets. This does that safely:
    follows @odata.nextLink to the end, retries 429 using the service's own
    Retry-After header, and caps total pages so a mis-scoped query cannot spin
    forever against a large directory.

.PARAMETER Uri
    Full Graph URL, or a path fragment like "v1.0/oauth2PermissionGrants".

.PARAMETER MaxPages
    Safety ceiling on pages followed. Default 200.

.PARAMETER ConsistencyLevel
    Set to "eventual" for advanced queries ($count, $search, some $filter forms).

.PARAMETER TolerateFailure
    Return an empty collection and warn instead of throwing. Use for optional
    sections (P2-only endpoints) so one missing feature doesn't kill the report.
#>
function Invoke-GraphPagedRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxPages = 200,
        [string]$ConsistencyLevel,
        [switch]$TolerateFailure
    )

    if ($Uri -notmatch '^https://') { $Uri = "https://graph.microsoft.com/$($Uri.TrimStart('/'))" }

    $headers = @{}
    if ($ConsistencyLevel) { $headers["ConsistencyLevel"] = $ConsistencyLevel }

    $all = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0

    while ($next -and $page -lt $MaxPages) {
        $page++
        $attempt = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                if ($headers.Count -gt 0) {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers -ErrorAction Stop
                } else {
                    $response = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
                }
                break
            } catch {
                $message = $_.Exception.Message
                $isThrottle = $message -match "429|throttl|too many requests"
                $isTransient = $message -match "503|504|gateway|temporarily"

                if (($isThrottle -or $isTransient) -and $attempt -le 4) {
                    $wait = [math]::Min(60, [math]::Pow(2, $attempt))
                    Write-Host "[!] Graph throttled/transient on page $page - waiting ${wait}s (attempt $attempt)" -ForegroundColor Yellow
                    Start-Sleep -Seconds $wait
                    continue
                }

                if ($TolerateFailure) {
                    Write-Host "[!] Graph request failed and was tolerated: $Uri`n    $message" -ForegroundColor Yellow
                    return @()
                }
                throw "Graph GET failed: $Uri`n$message"
            }
        }

        # Invoke-MgGraphRequest returns a Hashtable in SDK v2, but tolerate a
        # PSObject shape too rather than depending on the deserializer.
        $hasValue = if ($response -is [System.Collections.IDictionary]) { $response.Contains("value") }
                    else { $null -ne $response -and ($response.PSObject.Properties.Name -contains "value") }

        if ($hasValue) {
            foreach ($item in @($response["value"])) { [void]$all.Add($item) }
        } elseif ($null -ne $response) {
            [void]$all.Add($response)   # single-object endpoint, not a collection
        }

        $next = if ($response -is [System.Collections.IDictionary] -and $response.Contains('@odata.nextLink')) {
            [string]$response['@odata.nextLink']
        } else { $null }
    }

    if ($next) {
        Write-Host "[!] Stopped after $MaxPages pages - results are TRUNCATED for $Uri" -ForegroundColor Yellow
    }

    return $all.ToArray()
}

<#
.SYNOPSIS
    Detects which Entra ID capabilities the tenant is licensed for.

.DESCRIPTION
    Several checks are only meaningful with Entra ID P1 or P2. Without this, a
    report on a P1 tenant shows "no risky users" - which reads as good news but
    actually means Identity Protection was never queried. Reports use this to
    label those sections "not checked" instead.

    Detection is by service plan, then by a probe call, because a service plan
    can be present but unassigned.
#>
function Get-GraphTenantCapability {
    [CmdletBinding()]
    param()

    $plans = @()
    try {
        $skus = Invoke-GraphPagedRequest -Uri "v1.0/subscribedSkus" -TolerateFailure
        foreach ($sku in $skus) {
            foreach ($plan in @($sku.servicePlans)) {
                if ($plan.provisioningStatus -eq "Success") { $plans += [string]$plan.servicePlanName }
            }
        }
    } catch { $plans = @() }

    $plans = @($plans | Sort-Object -Unique)

    $hasP1 = @($plans | Where-Object { $_ -match "AAD_PREMIUM|AAD_PREMIUM_P1" }).Count -gt 0
    $hasP2 = @($plans | Where-Object { $_ -match "AAD_PREMIUM_P2" }).Count -gt 0

    # A service plan can be present on the tenant but assigned to nobody, so probe.
    $identityProtectionWorks = $false
    try {
        $probe = Invoke-GraphPagedRequest -Uri "v1.0/identityProtection/riskyUsers?`$top=1" -TolerateFailure -MaxPages 1
        $identityProtectionWorks = ($null -ne $probe)
    } catch { $identityProtectionWorks = $false }

    return [pscustomobject]@{
        ServicePlans            = $plans
        HasEntraIdP1            = $hasP1
        HasEntraIdP2            = $hasP2
        IdentityProtectionUsable = $identityProtectionWorks
        PimUsable               = $hasP2
        Notes                   = if (-not $hasP2) {
                                      "No Entra ID P2 detected. Identity Protection and PIM sections are NOT CHECKED - an empty result there is a licensing artifact, not a clean bill of health."
                                  } else { "Entra ID P2 detected - Identity Protection and PIM checks are meaningful." }
    }
}

<#
.SYNOPSIS
    Builds one normalized finding object.

.DESCRIPTION
    Every diagnostic report in this repo emits findings in the same shape, so
    they sort, filter and render identically and can be concatenated across
    reports without reconciliation.

.PARAMETER Severity
    Critical | High | Medium | Low | Info | NotChecked

    NotChecked is a first-class value on purpose. A check that could not run
    (missing licence, missing scope, missing table) must never be recorded as a
    pass.
#>
function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info", "NotChecked")]
        [string]$Severity,

        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Finding,
        [string]$Subject = "",
        [string]$Evidence = "",
        [string]$Recommendation = "",
        [int]$Count = 0
    )

    $rank = switch ($Severity) {
        "Critical"   { 0 }
        "High"       { 1 }
        "Medium"     { 2 }
        "Low"        { 3 }
        "NotChecked" { 4 }
        default      { 5 }
    }

    return [pscustomobject]@{
        Severity       = $Severity
        SeverityRank   = $rank
        Category       = $Category
        Finding        = $Finding
        Subject        = $Subject
        Count          = $Count
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
}

<#
.SYNOPSIS
    Sorts findings by severity rank, then by count descending.
#>
function Sort-Finding {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Finding)

    begin { $collected = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $Finding) { [void]$collected.Add($Finding) } }
    end { return @($collected | Sort-Object SeverityRank, @{ Expression = "Count"; Descending = $true }, Category) }
}
