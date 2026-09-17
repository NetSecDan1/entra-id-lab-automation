<#
.SYNOPSIS
    Creates Authentication Context class references and CA policies for step-up
    authentication when apps request elevated assurance.

.DESCRIPTION
    Authentication Contexts let apps and APIs trigger step-up MFA mid-session.
    Instead of requiring phishing-resistant MFA at sign-in time, an app can
    request context "c1" when a user tries to access a sensitive operation —
    and Entra will re-challenge with the required method in real time.

    Contexts created
    ----------------
    c1 — High Sensitivity Operations
         Triggered by: financial systems, HR data, executive reports
         Requires    : Phishing-Resistant MFA (FIDO2 / Windows Hello / Passkey)

    c2 — Admin Operations
         Triggered by: admin portals, PIM activation UI, privileged API calls
         Requires    : Phishing-Resistant MFA + compliant device

    c3 — Confidential Data Access
         Triggered by: DLP-tagged content, legal hold data, M&A documents
         Requires    : Corporate Standard MFA + sign-in frequency 1h

    How to wire an app to an auth context
    --------------------------------------
    In your app code, request the auth context as a claims challenge:
        scope = "openid profile User.Read"
        claims = {"access_token": {"acrs": {"essential": true, "value": "c1"}}}

    Or in app manifest (Azure AD app registration → Token configuration →
    Add optional claim → Access token → acrs)

    The CA policy intercepts the acrs claim and enforces step-up at that moment.

.EXAMPLE
    .\Security\Deploy-AuthContexts.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config   = Get-Config -ConfigPath $ConfigPath
$domain   = $config.TenantDomain
$capState = if ($config.CAP.State) { [string]$config.CAP.State } else { "enabledForReportingButNotEnforced" }

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Authentication Contexts — Step-Up Auth" -Type Header
Write-Host "  Tenant    : $domain"
Write-Host "  CA state  : $capState"
Write-Host ""

# ── Helper: create or update auth context ────────────────────────────────────
function Set-AuthContext {
    param(
        [string]$Id,
        [string]$DisplayName,
        [string]$Description,
        [bool]  $IsAvailable = $true
    )

    $body = @{
        id          = $Id
        displayName = $DisplayName
        description = $Description
        isAvailable = $IsAvailable
    } | ConvertTo-Json

    try {
        $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences/$Id"

        if ($existing -and $existing.id) {
            Invoke-MgGraphRequest -Method PATCH -Body $body -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences/$Id" | Out-Null
            Write-Status "Updated auth context: $Id — $DisplayName" -Type Warning
        } else {
            throw "not found"
        }
    } catch {
        try {
            Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences" | Out-Null
            Write-Status "Created auth context: $Id — $DisplayName" -Type Success
        } catch {
            Write-Status "Failed to create $Id`: $($_.Exception.Message)" -Type Error
        }
    }
}

# ── Resolve custom auth strength IDs ─────────────────────────────────────────
Write-Status "Resolving authentication strength policies" -Type Header

$allStrengths = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies" -ErrorAction SilentlyContinue

$phishResistantId = $allStrengths.value | Where-Object { $_.displayName -eq "Phishing-Resistant MFA" } | Select-Object -ExpandProperty id -First 1
$corporateMfaId   = $allStrengths.value | Where-Object { $_.displayName -eq "Corporate Standard MFA"  } | Select-Object -ExpandProperty id -First 1

# Fall back to built-in phishing-resistant strength if custom not deployed yet
if (-not $phishResistantId) {
    $phishResistantId = $allStrengths.value | Where-Object { $_.displayName -eq "Phishing-resistant MFA" } | Select-Object -ExpandProperty id -First 1
}

Write-Host "  Phishing-Resistant MFA strength : $(if ($phishResistantId) { $phishResistantId } else { 'NOT FOUND — run Deploy-AuthStrengths.ps1' })"
Write-Host "  Corporate Standard MFA strength : $(if ($corporateMfaId)   { $corporateMfaId   } else { 'NOT FOUND — run Deploy-AuthStrengths.ps1' })"

# Resolve break glass exclusion group
$bgGroup = Get-MgGroup -Filter "displayName eq 'CA-BreakGlassAccounts - Exclude'" -ErrorAction SilentlyContinue
$bgExclude = @()
if ($bgGroup) { $bgExclude = @($bgGroup.Id) }

# ── Create authentication contexts ────────────────────────────────────────────
Write-Host ""
Write-Status "Creating authentication context class references" -Type Header

Set-AuthContext -Id "c1" `
    -DisplayName "High Sensitivity Operations" `
    -Description "Financial systems, HR data, payroll, executive reports. Triggers phishing-resistant MFA step-up."

Set-AuthContext -Id "c2" `
    -DisplayName "Admin Operations" `
    -Description "Admin portals, PIM activation UI, privileged API scopes. Requires phishing-resistant MFA + compliant device."

Set-AuthContext -Id "c3" `
    -DisplayName "Confidential Data Access" `
    -Description "DLP-tagged content, legal hold, M&A documents. Triggers standard MFA with hourly re-authentication."

# ── Create CA policies that enforce each context ──────────────────────────────
Write-Host ""
Write-Status "Creating Conditional Access policies for each auth context" -Type Header

function Set-AuthContextCAPolicy {
    param(
        [string]  $Name,
        [string]  $ContextId,
        [string]  $State,
        [string[]]$ExcludeGroups,
        [hashtable]$GrantControls
    )

    $existing = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $Name } | Select-Object -First 1

    $body = @{
        displayName = $Name
        state       = $State
        conditions  = @{
            users        = @{
                includeUsers  = @("All")
                excludeGroups = @($ExcludeGroups) | Where-Object { $_ }
            }
            applications = @{
                includeAuthenticationContextClassReferences = @($ContextId)
            }
            clientAppTypes = @("all")
        }
        grantControls = $GrantControls
    } | ConvertTo-Json -Depth 10

    if ($existing) {
        Invoke-MgGraphRequest -Method PATCH -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($existing.Id)" | Out-Null
        Write-Status "Updated: $Name" -Type Warning
    } else {
        Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" | Out-Null
        Write-Status "Created: $Name" -Type Success
    }
}

# c1 — High Sensitivity → Phishing-Resistant MFA step-up
$c1Grant = if ($phishResistantId) {
    @{ operator = "OR"; authenticationStrength = @{ id = $phishResistantId } }
} else {
    @{ operator = "OR"; builtInControls = @("mfa") }
}

Set-AuthContextCAPolicy `
    -Name       "CA-AuthContext-c1-HighSensitivity-PhishResistantMFA" `
    -ContextId  "c1" `
    -State      $capState `
    -ExcludeGroups $bgExclude `
    -GrantControls $c1Grant

Write-Host "    c1 → Phishing-Resistant MFA (FIDO2 / Windows Hello / Device Passkey)" -ForegroundColor DarkGray

# c2 — Admin Operations → Phishing-Resistant MFA + compliant device
$c2Grant = if ($phishResistantId) {
    @{ operator = "AND"; authenticationStrength = @{ id = $phishResistantId }; builtInControls = @("compliantDevice") }
} else {
    @{ operator = "AND"; builtInControls = @("mfa","compliantDevice") }
}

Set-AuthContextCAPolicy `
    -Name       "CA-AuthContext-c2-AdminOps-PhishResistantMFA-CompliantDevice" `
    -ContextId  "c2" `
    -State      $capState `
    -ExcludeGroups $bgExclude `
    -GrantControls $c2Grant

Write-Host "    c2 → Phishing-Resistant MFA + compliant device" -ForegroundColor DarkGray

# c3 — Confidential Data → Corporate MFA + session controls
$c3Grant = if ($corporateMfaId) {
    @{ operator = "OR"; authenticationStrength = @{ id = $corporateMfaId } }
} else {
    @{ operator = "OR"; builtInControls = @("mfa") }
}

$c3Body = @{
    displayName = "CA-AuthContext-c3-ConfidentialData-MFA-1HourSession"
    state       = $capState
    conditions  = @{
        users        = @{ includeUsers = @("All"); excludeGroups = @($bgExclude) | Where-Object { $_ } }
        applications = @{ includeAuthenticationContextClassReferences = @("c3") }
        clientAppTypes = @("all")
    }
    grantControls = $c3Grant
    sessionControls = @{
        signInFrequency = @{
            value      = 1
            type       = "hours"
            isEnabled  = $true
            frequencyInterval = "timeBased"
        }
    }
} | ConvertTo-Json -Depth 10

$existingC3 = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "CA-AuthContext-c3-ConfidentialData-MFA-1HourSession" } | Select-Object -First 1

if ($existingC3) {
    Invoke-MgGraphRequest -Method PATCH -Body $c3Body -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($existingC3.Id)" | Out-Null
    Write-Status "Updated: CA-AuthContext-c3-ConfidentialData-MFA-1HourSession" -Type Warning
} else {
    Invoke-MgGraphRequest -Method POST -Body $c3Body -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" | Out-Null
    Write-Status "Created: CA-AuthContext-c3-ConfidentialData-MFA-1HourSession" -Type Success
}
Write-Host "    c3 → Corporate MFA + 1-hour sign-in frequency" -ForegroundColor DarkGray

# ── Print all auth contexts ────────────────────────────────────────────────────
Write-Host ""
Write-Status "Authentication contexts in tenant" -Type Header
$allContexts = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences" `
    -ErrorAction SilentlyContinue
foreach ($ctx in $allContexts.value | Sort-Object id) {
    $avail = if ($ctx.isAvailable) { "available" } else { "not available" }
    Write-Host ("  [{0}] {1,-38} : {2}" -f $ctx.id, $ctx.displayName, $avail) -ForegroundColor $(if ($ctx.isAvailable) {"Green"} else {"DarkGray"})
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Authentication Contexts deployment complete" -Type Success
Write-Host ""
Write-Host "  How to trigger step-up from your app:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  // When user accesses financial data, request c1:" -ForegroundColor DarkGray
Write-Host '  claims = {"access_token":{"acrs":{"essential":true,"value":"c1"}}}' -ForegroundColor DarkGray
Write-Host "  // Entra intercepts, enforces phishing-resistant MFA, then continues" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  App registrations using auth contexts:" -ForegroundColor Cyan
Write-Host "    CorpPortal-WebApp → financial dashboard → add acrs:c1 claim request" -ForegroundColor DarkGray
Write-Host "    DataPlatform-ReportingAgent → exec reports → add acrs:c1" -ForegroundColor DarkGray
Write-Host "    Admin portal actions → add acrs:c2 for privilege escalation flows" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
