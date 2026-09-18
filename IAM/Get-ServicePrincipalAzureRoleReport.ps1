<#
.SYNOPSIS
    Azure RBAC role assignments held by service principals and managed
    identities - the control plane that Entra app permission audits miss entirely.

.DESCRIPTION
    Entra ID application permissions and Azure RBAC are two separate authorisation
    systems with separate APIs, separate portals and separate audit trails. An app
    can hold zero Graph permissions and still be Owner on a production
    subscription, and every Entra-side permission report in this repo - including
    IAM/Get-AppRiskInventory.ps1 - will show it as harmless. This report covers
    that second plane.

    It answers: which non-human identities can act on Azure resources, how
    broadly, and which of them can escalate their own access?

    The Azure escalation set is small and specific:

      Owner                              - full control, including granting roles
      User Access Administrator          - can grant itself or anyone any role
      Role Based Access Control Administrator - same, narrower but sufficient

    An identity holding any of those at subscription or management group scope
    is equivalent to a subscription-level administrator, and unlike a human
    admin it has no MFA, no Conditional Access in the usual sense, and often a
    non-expiring credential behind it.

    Scope is ranked, because the same role means very different things at
    different levels. Management group > subscription > resource group >
    resource, and an assignment inherited from a management group applies to
    every subscription beneath it.

    READ-ONLY. Every call is a Get-Az* cmdlet. There is no New-, Set-, Remove- or
    Update- anywhere in this script.

.PARAMETER SubscriptionId
    Limit to specific subscriptions. Default: every subscription the signed-in
    identity can see. Note that is a property of YOUR access - a subscription you
    cannot see is not audited, and the report says so rather than implying full
    coverage.

.PARAMETER IncludeInherited
    Include assignments inherited from a parent scope. On by default, because an
    inherited Owner is exactly as powerful as a direct one. Turn it off to see
    only assignments made at the subscription itself.

.PARAMETER PreviewCalls
    Print the call plan and exit. Connects to nothing.

.EXAMPLE
    .\IAM\Get-ServicePrincipalAzureRoleReport.ps1 -PreviewCalls

.EXAMPLE
    .\IAM\Get-ServicePrincipalAzureRoleReport.ps1 -Open

.EXAMPLE
    .\IAM\Get-ServicePrincipalAzureRoleReport.ps1 -SubscriptionId "1111-...","2222-..." -ExportJson -Open

.NOTES
    Requires Az.Accounts and Az.Resources, and Reader on the subscriptions you
    want covered. Reader is sufficient - this never needs a write role.

    Pair it with IAM/Get-AppRiskInventory.ps1. An identity appearing as high risk
    in both is genuinely dangerous: broad directory permissions AND broad Azure
    resource control, usually with one non-expiring secret behind both.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [string[]]$SubscriptionId,
    [bool]$IncludeInherited = $true,
    [switch]$PreviewCalls,
    [string]$OutputPath,
    [switch]$ExportCsv,
    [switch]$ExportJson,
    [switch]$PassThru,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\GraphReadOnly.ps1"
# Get-RiskRank and the shared severity ordering live here.
. "$PSScriptRoot\..\Reports\Helpers\AppPermissionCatalog.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

if ($PreviewCalls) {
    Write-Status "Azure RBAC call plan - nothing below is executed, no connection is made" -Type Header
    @(
        [pscustomobject]@{ Step = 1; Cmdlet = "Get-AzContext";        Purpose = "Confirm an existing Azure session (never creates one silently)" }
        [pscustomobject]@{ Step = 2; Cmdlet = "Get-AzSubscription";   Purpose = "Subscriptions visible to the signed-in identity" }
        [pscustomobject]@{ Step = 3; Cmdlet = "Set-AzContext";        Purpose = "Switch the CLIENT-SIDE subscription context. Changes nothing in Azure." }
        [pscustomobject]@{ Step = 4; Cmdlet = "Get-AzRoleAssignment"; Purpose = "Role assignments per subscription, filtered to service principals" }
        [pscustomobject]@{ Step = 5; Cmdlet = "Get-AzRoleDefinition";  Purpose = "Actual Actions list for any role outside the catalog (cached, once per role)" }
    ) | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
    Write-Host ""
    Write-Status "All reads. Set-AzContext is a local session setting, not an Azure mutation." -Type Success
    return
}

$config = Get-Config -ConfigPath $ConfigPath

# ---------------------------------------------------------------------------
# Azure connection
# ---------------------------------------------------------------------------
foreach ($module in @("Az.Accounts", "Az.Resources")) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Status "Installing $module (CurrentUser scope)" -Type Warning
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $module -ErrorAction Stop
}

$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Status "No Azure session - connecting" -Type Info
    Connect-AzAccount | Out-Null
    $context = Get-AzContext
}
Write-Status "Azure: $($context.Account.Id)" -Type Success

$subscriptions = if ($SubscriptionId) {
    @(Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $SubscriptionId -contains $_.Id })
} else {
    @(Get-AzSubscription -ErrorAction SilentlyContinue)
}

if ($subscriptions.Count -eq 0) {
    throw "No subscriptions visible. Either the signed-in identity has no Azure access, or -SubscriptionId matched nothing. This report cannot audit what it cannot see."
}
Write-Status "$($subscriptions.Count) subscription(s) in scope" -Type Success

# ---------------------------------------------------------------------------
# Role risk model
# ---------------------------------------------------------------------------
# Roles that let the holder grant further access. Holding any of these means the
# identity's effective permission set is "anything in that scope".
$escalationRoles = @("Owner", "User Access Administrator", "Role Based Access Control Administrator")

$roleRisk = @{
    "Owner"                                  = @{ Tier = "Critical"; Why = "Full control including the ability to grant roles to anyone" }
    "User Access Administrator"              = @{ Tier = "Critical"; Why = "Can grant itself or anyone any role - escalation to Owner at will" }
    "Role Based Access Control Administrator"= @{ Tier = "Critical"; Why = "Can assign roles within the scope - escalation path" }
    "Contributor"                            = @{ Tier = "High";     Why = "Full control of resources (cannot grant roles, but can alter or destroy anything)" }
    "Key Vault Administrator"                = @{ Tier = "Critical"; Why = "Full control of key vault contents - the secrets other systems depend on" }
    "Key Vault Secrets Officer"              = @{ Tier = "High";     Why = "Read and write key vault secrets" }
    "Key Vault Secrets User"                 = @{ Tier = "High";     Why = "Read key vault secrets" }
    "Key Vault Certificates Officer"         = @{ Tier = "High";     Why = "Manage certificates used for authentication" }
    "Storage Blob Data Owner"                = @{ Tier = "High";     Why = "Full control of blob data, including POSIX ACLs" }
    "Storage Blob Data Contributor"          = @{ Tier = "High";     Why = "Read and write all blob data in scope" }
    "Storage Account Contributor"            = @{ Tier = "High";     Why = "Manage storage accounts, including retrieving access keys" }
    "Virtual Machine Contributor"            = @{ Tier = "High";     Why = "Manage VMs, including run-command execution on them" }
    "Managed Identity Operator"              = @{ Tier = "High";     Why = "Can assign managed identities to resources - a known escalation primitive" }
    "Managed Identity Contributor"           = @{ Tier = "High";     Why = "Create and manage managed identities" }
    "Automation Contributor"                 = @{ Tier = "High";     Why = "Can run arbitrary runbooks, often under a privileged identity" }
    "Log Analytics Contributor"              = @{ Tier = "Medium";   Why = "Can modify or delete log data - anti-forensics" }
    "Monitoring Contributor"                 = @{ Tier = "Medium";   Why = "Can alter diagnostic settings, including turning off log export" }
    "Reader"                                 = @{ Tier = "Low";      Why = "" }
}

# Role definitions are inspected rather than guessed at. A custom role's NAME
# tells you nothing about its permissions - "Contoso Custom Deployer" could be
# Reader or it could be Owner with extra steps - so for anything outside the
# catalog this reads the actual Actions list. That is one cached call per
# distinct role and it is the difference between an audit and a guess.
$script:roleDefinitionCache = @{}

function Get-AzureRoleDefinitionFacts {
    param([string]$RoleName)

    if ($script:roleDefinitionCache.ContainsKey($RoleName)) { return $script:roleDefinitionCache[$RoleName] }

    $facts = [pscustomobject]@{
        Resolved         = $false
        IsCustom         = $false
        GrantsAllActions = $false
        CanAssignRoles   = $false
        CanWrite         = $false
        ActionSample     = ""
    }

    try {
        $definition = Get-AzRoleDefinition -Name $RoleName -ErrorAction Stop | Select-Object -First 1
        if ($definition) {
            $actions = @($definition.Actions)
            $notActions = @($definition.NotActions)

            $grantsAll = @($actions | Where-Object { $_ -eq "*" }).Count -gt 0
            $assignWrite = @($actions | Where-Object {
                $_ -eq "*" -or $_ -eq "Microsoft.Authorization/*" -or
                $_ -like "Microsoft.Authorization/roleAssignments/write" -or
                $_ -like "Microsoft.Authorization/roleAssignments/*"
            }).Count -gt 0
            # An explicit NotAction on role assignment write takes it back away.
            $assignDenied = @($notActions | Where-Object {
                $_ -eq "Microsoft.Authorization/*" -or $_ -like "Microsoft.Authorization/roleAssignments/write*"
            }).Count -gt 0

            $facts = [pscustomobject]@{
                Resolved         = $true
                IsCustom         = [bool]$definition.IsCustom
                GrantsAllActions = $grantsAll
                CanAssignRoles   = ($assignWrite -and -not $assignDenied)
                # Regex, not -like: in a -like pattern "*" is a wildcard, so
                # "*/*" would match every action that merely contains a slash -
                # including "*/read" - and label a read-only role write-capable.
                CanWrite         = (@($actions | Where-Object {
                                        $_ -eq "*" -or $_ -match '/(write|delete|action)$' -or $_ -match '/\*$'
                                    }).Count -gt 0)
                ActionSample     = ((@($actions | Select-Object -First 6)) -join ", ")
            }
        }
    } catch {
        # Reading a role definition can fail on a custom role scoped to a
        # management group you cannot see. Unresolved is reported as such rather
        # than silently downgraded to Low.
        $facts = [pscustomobject]@{
            Resolved = $false; IsCustom = $false; GrantsAllActions = $false
            CanAssignRoles = $false; CanWrite = $false; ActionSample = ""
        }
    }

    $script:roleDefinitionCache[$RoleName] = $facts
    return $facts
}

function Get-AzureRoleRisk {
    param([string]$RoleName)

    if ($roleRisk.ContainsKey($RoleName)) {
        $entry = $roleRisk[$RoleName]
        return [pscustomobject]@{ Tier = $entry.Tier; Why = $entry.Why; InCatalog = $true; CanAssignRoles = ($escalationRoles -contains $RoleName); IsCustom = $false; Resolved = $true }
    }

    $facts = Get-AzureRoleDefinitionFacts -RoleName $RoleName
    $label = if ($facts.IsCustom) { "Custom role" } else { "Built-in role not in the catalog" }

    if (-not $facts.Resolved) {
        return [pscustomobject]@{
            Tier = "Medium"
            Why  = "$label whose definition could not be read - scored conservatively. Review its Actions manually before trusting this row."
            InCatalog = $false; CanAssignRoles = $false; IsCustom = $false; Resolved = $false
        }
    }

    if ($facts.CanAssignRoles) {
        return [pscustomobject]@{
            Tier = "Critical"
            Why  = "$label that permits Microsoft.Authorization/roleAssignments write - it can grant itself or anyone any role. Actions: $($facts.ActionSample)"
            InCatalog = $false; CanAssignRoles = $true; IsCustom = $facts.IsCustom; Resolved = $true
        }
    }

    if ($facts.GrantsAllActions) {
        return [pscustomobject]@{
            Tier = "Critical"
            Why  = "$label granting Actions '*' - equivalent to Contributor or Owner over its scope. Actions: $($facts.ActionSample)"
            InCatalog = $false; CanAssignRoles = $false; IsCustom = $facts.IsCustom; Resolved = $true
        }
    }

    if ($facts.CanWrite) {
        return [pscustomobject]@{
            Tier = "High"
            Why  = "$label with write or delete actions. Actions: $($facts.ActionSample)"
            InCatalog = $false; CanAssignRoles = $false; IsCustom = $facts.IsCustom; Resolved = $true
        }
    }

    return [pscustomobject]@{
        Tier = "Low"
        Why  = "$label, read-only by its Actions list. Actions: $($facts.ActionSample)"
        InCatalog = $false; CanAssignRoles = $false; IsCustom = $facts.IsCustom; Resolved = $true
    }
}

function Get-ScopeKind {
    param([string]$Scope)
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/') { return "Management group" }
    if ($Scope -match '^/subscriptions/[^/]+$')                              { return "Subscription" }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$')         { return "Resource group" }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/')               { return "Resource" }
    if ($Scope -eq "/")                                                       { return "Root (tenant)" }
    return "Other"
}

function Get-ScopeBreadthRank {
    param([string]$ScopeKind)
    switch ($ScopeKind) {
        "Root (tenant)"    { return 0 }
        "Management group" { return 1 }
        "Subscription"     { return 2 }
        "Resource group"   { return 3 }
        default            { return 4 }
    }
}

# ---------------------------------------------------------------------------
# Collect assignments
# ---------------------------------------------------------------------------
$assignmentRows = @()
$failedSubscriptions = @()
$subIndex = 0

foreach ($subscription in $subscriptions) {
    $subIndex++
    Write-Progress -Activity "Reading Azure role assignments" -Status "$($subscription.Name) ($subIndex of $($subscriptions.Count))" -PercentComplete (100.0 * $subIndex / $subscriptions.Count)

    try {
        # Client-side context switch only - this changes which subscription the
        # local session targets. It does not modify anything in Azure.
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null

        $assignments = @(Get-AzRoleAssignment -ErrorAction Stop |
            Where-Object { $_.ObjectType -eq "ServicePrincipal" })

        foreach ($assignment in $assignments) {
            $scope = [string]$assignment.Scope
            $scopeKind = Get-ScopeKind -Scope $scope
            $isInherited = ($scopeKind -in @("Management group", "Root (tenant)")) -or
                           ($scope -ne "/subscriptions/$($subscription.Id)" -and $scope -notmatch "^/subscriptions/$($subscription.Id)/")

            if (-not $IncludeInherited -and $isInherited) { continue }

            $roleName = [string]$assignment.RoleDefinitionName
            $risk = Get-AzureRoleRisk -RoleName $roleName

            $assignmentRows += [pscustomobject]@{
                RiskTier          = $risk.Tier
                RiskRank          = (Get-RiskRank -Tier $risk.Tier)
                IsEscalation      = ($escalationRoles -contains $roleName) -or [bool]$risk.CanAssignRoles
                Identity          = [string]$assignment.DisplayName
                ObjectId          = [string]$assignment.ObjectId
                ApplicationId     = [string]$assignment.ApplicationId
                Role              = $roleName
                ScopeKind         = $scopeKind
                ScopeBreadthRank  = (Get-ScopeBreadthRank -ScopeKind $scopeKind)
                Scope             = $scope
                Subscription      = [string]$subscription.Name
                SubscriptionId    = [string]$subscription.Id
                Inherited         = $isInherited
                WhyItMatters      = $risk.Why
                InCatalog         = $risk.InCatalog
                IsCustomRole      = [bool]$risk.IsCustom
                DefinitionRead    = [bool]$risk.Resolved
            }
        }
    } catch {
        $message = ($_.Exception.Message -split "`n")[0]

        # Only an access problem is a coverage gap. Anything else - a missing
        # function, a typo, a broken module - is a bug in this script, and
        # recording it as "subscription unreadable" would tell the operator they
        # need Reader when in fact the audit never ran. Fail loudly instead.
        $isAccessProblem = $message -match "authoriz|does not have permission|Forbidden|AuthorizationFailed|403|token|expired|credential|tenant"

        if (-not $isAccessProblem) {
            throw "Reading subscription '$($subscription.Name)' failed for a reason that is NOT an access problem, so it is not a coverage gap - it is a fault in this script or its environment. Fix it rather than trusting a partial report.`nUnderlying error: $message"
        }

        $failedSubscriptions += [pscustomobject]@{
            Subscription = [string]$subscription.Name
            SubscriptionId = [string]$subscription.Id
            Error = $message
        }
        Write-Status "Could not read $($subscription.Name) (access): $message" -Type Warning
    }
}
Write-Progress -Activity "Reading Azure role assignments" -Completed

$assignmentRows = @($assignmentRows | Sort-Object RiskRank, ScopeBreadthRank, Identity)

# ---------------------------------------------------------------------------
# Roll up per identity - one identity with Owner on six subscriptions is one
# problem, not six.
# ---------------------------------------------------------------------------
$identitySummary = @($assignmentRows |
    Group-Object ObjectId |
    ForEach-Object {
        $rows = @($_.Group)
        $worstRank = (@($rows | Measure-Object RiskRank -Minimum).Minimum)
        $broadestRank = (@($rows | Measure-Object ScopeBreadthRank -Minimum).Minimum)
        [pscustomobject]@{
            RiskTier          = switch ($worstRank) { 0 { "Critical" } 1 { "High" } 2 { "Medium" } default { "Low" } }
            RiskRank          = $worstRank
            Identity          = $rows[0].Identity
            ObjectId          = $_.Name
            ApplicationId     = $rows[0].ApplicationId
            CanEscalate       = (@($rows | Where-Object { $_.IsEscalation }).Count -gt 0)
            Roles             = ((@($rows | Select-Object -ExpandProperty Role -Unique)) -join ", ")
            BroadestScope     = (@($rows | Sort-Object ScopeBreadthRank | Select-Object -First 1).ScopeKind)
            Subscriptions     = (@($rows | Select-Object -ExpandProperty Subscription -Unique)).Count
            AssignmentCount   = $rows.Count
            SubscriptionNames = ((@($rows | Select-Object -ExpandProperty Subscription -Unique)) -join "; ")
        }
    } | Sort-Object RiskRank, @{ Expression = "Subscriptions"; Descending = $true }, Identity)

$escalationCapable = @($identitySummary | Where-Object { $_.CanEscalate })
$broadScope        = @($assignmentRows | Where-Object { $_.ScopeBreadthRank -le 2 -and $_.RiskRank -le 1 })
$mgmtGroupScoped   = @($assignmentRows | Where-Object { $_.ScopeKind -in @("Management group", "Root (tenant)") })

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
$findings = @()

if ($escalationCapable.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Azure escalation" `
        -Finding "$($escalationCapable.Count) service principal(s) can grant themselves further Azure access" `
        -Subject (($escalationCapable | Select-Object -First 10 | ForEach-Object { "$($_.Identity) [$($_.Roles)]" }) -join "; ") `
        -Count $escalationCapable.Count `
        -Evidence "Owner, User Access Administrator or RBAC Administrator. Their effective permission set is everything within scope, and unlike a human admin there is no MFA or Conditional Access prompt behind them." `
        -Recommendation "Replace with a narrowly scoped built-in role, or a custom role without Microsoft.Authorization/roleAssignments/write. Owner on a subscription is almost never what an automation account needs."
}

if ($mgmtGroupScoped.Count -gt 0) {
    $findings += New-Finding -Severity Critical -Category "Scope breadth" `
        -Finding "$($mgmtGroupScoped.Count) assignment(s) are at management group or tenant root scope" `
        -Subject (($mgmtGroupScoped | Select-Object -First 10 | ForEach-Object { "$($_.Identity) [$($_.Role)]" }) -join "; ") `
        -Count $mgmtGroupScoped.Count `
        -Evidence "These inherit down to every subscription beneath them, including subscriptions created in future. The blast radius grows on its own." `
        -Recommendation "Move to the narrowest scope that works. A management group assignment should be a deliberate, documented decision."
}

if ($broadScope.Count -gt 0) {
    $findings += New-Finding -Severity High -Category "Scope breadth" `
        -Finding "$($broadScope.Count) high-risk role(s) held at subscription scope or broader" `
        -Subject (($broadScope | Select-Object -First 10 | ForEach-Object { "$($_.Identity) [$($_.Role)] on $($_.Subscription)" }) -join "; ") `
        -Count $broadScope.Count `
        -Evidence "Subscription-wide write access held by a non-human identity." `
        -Recommendation "Scope to the resource group or resource the workload actually touches."
}

$customRoles = @($assignmentRows | Where-Object { $_.IsCustomRole } | Select-Object -ExpandProperty Role -Unique)
if ($customRoles.Count -gt 0) {
    $findings += New-Finding -Severity Medium -Category "Custom roles" `
        -Finding "$($customRoles.Count) custom role definition(s) are assigned to service principals" `
        -Subject (($customRoles | Select-Object -First 15) -join "; ") `
        -Count $customRoles.Count `
        -Evidence "Scored from their actual Actions list, not their name - a custom role's name is not evidence of what it permits." `
        -Recommendation "Custom roles drift. Review their definitions on a schedule, and watch for Microsoft.Authorization/roleAssignments/write in particular."
}

$unresolvedRoles = @($assignmentRows | Where-Object { -not $_.InCatalog -and -not $_.DefinitionRead } | Select-Object -ExpandProperty Role -Unique)
if ($unresolvedRoles.Count -gt 0) {
    $findings += New-Finding -Severity NotChecked -Category "Role definitions" `
        -Finding "$($unresolvedRoles.Count) role definition(s) could not be read and were scored conservatively" `
        -Subject (($unresolvedRoles | Select-Object -First 15) -join "; ") `
        -Count $unresolvedRoles.Count `
        -Evidence "Usually a custom role scoped to a management group this identity cannot see." `
        -Recommendation "Review these definitions manually. Their risk tier here is a placeholder, not an assessment."
}

if ($failedSubscriptions.Count -gt 0) {
    $findings += New-Finding -Severity NotChecked -Category "Coverage" `
        -Finding "$($failedSubscriptions.Count) subscription(s) could not be read" `
        -Subject (($failedSubscriptions | Select-Object -First 10 -ExpandProperty Subscription) -join "; ") `
        -Count $failedSubscriptions.Count `
        -Evidence "Usually missing Reader on that subscription." `
        -Recommendation "This report covers only what your identity can see. Treat unlisted subscriptions as unaudited, not as clean."
}

$findings += New-Finding -Severity NotChecked -Category "Coverage" `
    -Finding "Coverage is bounded by the signed-in identity's own Azure access" `
    -Evidence "$($subscriptions.Count) subscription(s) were visible and audited. A subscription this identity cannot see was not examined and does not appear anywhere in this report." `
    -Recommendation "Run as an identity with Reader at the tenant root management group for full coverage."

if (@($findings | Where-Object { $_.Severity -ne "NotChecked" }).Count -eq 0) {
    $findings += New-Finding -Severity Info -Category "Summary" `
        -Finding "No high-risk Azure role assignments held by service principals" `
        -Count $assignmentRows.Count `
        -Evidence "$($assignmentRows.Count) assignment(s) across $($subscriptions.Count) subscription(s)." `
        -Recommendation "Re-run after infrastructure changes."
}

$findings = @($findings | Sort-Finding)

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
$criticalCount = @($assignmentRows | Where-Object { $_.RiskTier -eq "Critical" }).Count

$statTiles = @(
    @{ Label = "Subscriptions audited"; Value = $subscriptions.Count; Tone = "neutral" }
    @{ Label = "Service principal assignments"; Value = $assignmentRows.Count; Tone = "neutral" }
    @{ Label = "Distinct identities"; Value = $identitySummary.Count; Tone = "neutral" }
    @{ Label = "Can escalate in Azure"; Value = $escalationCapable.Count; Tone = if ($escalationCapable.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Critical assignments"; Value = $criticalCount; Tone = if ($criticalCount -gt 0) { "danger" } else { "good" } }
    @{ Label = "Mgmt group / root scope"; Value = $mgmtGroupScoped.Count; Tone = if ($mgmtGroupScoped.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Subscriptions unreadable"; Value = $failedSubscriptions.Count; Tone = if ($failedSubscriptions.Count -gt 0) { "warn" } else { "good" } }
)

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "..\Reports\Output\ServicePrincipalAzureRoles-$timestamp.html"
}

New-HtmlReport -Title "Service Principal Azure RBAC Assignments" `
    -Subtitle "$($config.TenantDomain) - $($identitySummary.Count) identities across $($subscriptions.Count) subscription(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Findings"                                      = $findings
        "Identities that can escalate their Azure access" = $escalationCapable
        "Assignments at management group or root scope"   = @($mgmtGroupScoped | Select-Object Identity, Role, RiskTier, ScopeKind, Scope, Subscription, WhyItMatters)
        "High-risk roles at subscription scope or broader" = @($broadScope | Select-Object Identity, Role, RiskTier, ScopeKind, Subscription, Inherited, WhyItMatters)
        "All service principal identities, rolled up"     = $identitySummary
        "All assignments"                                 = $assignmentRows
        "Subscriptions that could not be read"            = $failedSubscriptions
    }) `
    -FooterNote "Source: Get-AzSubscription and Get-AzRoleAssignment (read-only Az cmdlets). Azure RBAC is a separate control plane from Entra application permissions - an app clean in IAM/Get-AppRiskInventory.ps1 can still be Owner here. Coverage is limited to subscriptions the signed-in identity can see." `
    -OutputPath $OutputPath `
    -Open:$Open | Out-Null

$outputDir = Split-Path -Parent $OutputPath

if ($ExportCsv) {
    $csvPath = Join-Path $outputDir "ServicePrincipalAzureRoles-$timestamp.csv"
    $assignmentRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Status "CSV written: $csvPath" -Type Success
}

if ($ExportJson) {
    $jsonPath = Join-Path $outputDir "ServicePrincipalAzureRoles-$timestamp.json"
    [pscustomobject]@{
        GeneratedAt          = (Get-Date).ToString("o")
        Tenant               = $config.TenantDomain
        SubscriptionsAudited = @($subscriptions | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Id = $_.Id } })
        SubscriptionsFailed  = $failedSubscriptions
        Findings             = $findings
        Identities           = $identitySummary
        Assignments          = $assignmentRows
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Status "JSON written: $jsonPath" -Type Success
}

if ($PassThru) { return $identitySummary }
