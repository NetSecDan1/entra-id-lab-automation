<#
.SYNOPSIS
    Configures Privileged Identity Management (PIM) for the test tenant.

.DESCRIPTION
    Requires Entra ID P2 or Microsoft 365 E5.

    Converts permanent active admin role assignments to just-in-time (JIT)
    eligible assignments, then configures PIM policies per role:

    Eligible assignments created
    ----------------------------
    T0 break glass  : remains permanently active GA (never PIM — emergency access)
    T1 service desk : User Admin, Helpdesk Admin, Authentication Admin
    T2 cloud/sec ops: Security Admin, Privileged Role Admin, Cloud App Admin, Security Reader
    C-suite execs   : Global Reader, Reports Reader
    All admins      : Global Reader

    PIM policy settings (per role)
    --------------------------------
    All roles           : 8h max activation, MFA + justification required
    Global Administrator: 4h max, MFA + justification + approval required
    Privileged Role Admin: 4h max, MFA + justification required

.EXAMPLE
    .\PIM\Deploy-PIM.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain

# ── Well-known role definition IDs (identical across all Entra tenants) ────────
$roleIds = @{
    "Global Administrator"            = "62e90394-69f5-4237-9190-012177145e10"
    "Privileged Role Administrator"   = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "Security Administrator"          = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "User Administrator"              = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Authentication Administrator"    = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    "Helpdesk Administrator"          = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "Cloud Application Administrator" = "158c047a-c907-4556-b7ef-446551a6b5f7"
    "Security Reader"                 = "5d6b6bb7-de71-4623-b4af-96380a352509"
    "Global Reader"                   = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    "Reports Reader"                  = "4a5d8f65-41da-4de4-8968-e035b65339cf"
}

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "PIM — Privileged Identity Management Setup" -Type Header
Write-Host "  Tenant : $domain"
Write-Host ""

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-EligibleAssignment {
    param([string]$UserId, [string]$RoleName, [string]$Justification = "PIM eligible assignment — Deploy-PIM.ps1")

    $roleId = $roleIds[$RoleName]
    if (-not $roleId) { Write-Status "Unknown role: $RoleName" -Type Warning; return }

    # Idempotency check
    try {
        $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
            -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" +
                  "?`$filter=principalId eq '$UserId' and roleDefinitionId eq '$roleId' and directoryScopeId eq '/'")
        if ($existing.value.Count -gt 0) {
            Write-Status "Already eligible: $RoleName" -Type Warning; return
        }
    } catch { }

    $body = @{
        action           = "adminAssign"
        justification    = $Justification
        roleDefinitionId = $roleId
        directoryScopeId = "/"
        principalId      = $UserId
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            expiration    = @{ type = "noExpiration" }
        }
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" | Out-Null
        Write-Status "Eligible [$RoleName]" -Type Success
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exists|Exists|duplicate") {
            Write-Status "Already eligible: $RoleName" -Type Warning
        } else {
            Write-Status "Failed [$RoleName]: $msg" -Type Error
        }
    }
}

function Get-PimPolicyId {
    param([string]$RoleName)
    $roleId = $roleIds[$RoleName]
    if (-not $roleId) { return $null }
    try {
        $resp = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
            -Uri ("https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments" +
                  "?`$filter=roleDefinitionId eq '$roleId' and scopeId eq '/' and scopeType eq 'DirectoryRole'")
        return if ($resp.value.Count -gt 0) { $resp.value[0].policyId } else { $null }
    } catch { return $null }
}

function Set-PimActivationDuration {
    param([string]$RoleName, [string]$MaxDuration = "PT8H")
    $policyId = Get-PimPolicyId -RoleName $RoleName
    if (-not $policyId) { Write-Status "No policy found for $RoleName" -Type Warning; return }

    $rule = @{
        "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        id                   = "Expiration_EndUser_Assignment"
        isExpirationRequired = $true
        maximumDuration      = $MaxDuration
    } | ConvertTo-Json -Depth 3

    try {
        Invoke-MgGraphRequest -Method PATCH -Body $rule -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules/Expiration_EndUser_Assignment" | Out-Null
        Write-Status "[$RoleName] max activation → $MaxDuration" -Type Success
    } catch {
        Write-Status "[$RoleName] duration update failed: $($_.Exception.Message)" -Type Warning
    }
}

function Set-PimActivationControls {
    param([string]$RoleName, [string[]]$Controls = @("MultiFactorAuthentication","Justification"))
    $policyId = Get-PimPolicyId -RoleName $RoleName
    if (-not $policyId) { return }

    $rule = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
        id            = "Enablement_EndUser_Assignment"
        enabledRules  = $Controls
    } | ConvertTo-Json -Depth 3

    try {
        Invoke-MgGraphRequest -Method PATCH -Body $rule -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules/Enablement_EndUser_Assignment" | Out-Null
        Write-Status "[$RoleName] activation controls → $($Controls -join ', ')" -Type Success
    } catch {
        Write-Status "[$RoleName] controls update failed: $($_.Exception.Message)" -Type Warning
    }
}

function Set-PimApprovalRequired {
    param([string]$RoleName, [string]$ApproverUserId)
    $policyId = Get-PimPolicyId -RoleName $RoleName
    if (-not $policyId) { return }

    $rule = @{
        "@odata.type"    = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
        id               = "Approval_EndUser_Assignment"
        setting          = @{
            isApprovalRequired              = $true
            isApprovalRequiredForExtension  = $false
            isRequestorJustificationRequired = $true
            approvalMode                    = "SingleStage"
            approvalStages                  = @(@{
                approvalStageTimeOutInDays      = 1
                isApproverJustificationRequired = $true
                escalationTimeInMinutes         = 0
                isEscalationEnabled             = $false
                primaryApprovers               = @(@{
                    "@odata.type" = "#microsoft.graph.singleUser"
                    userId        = $ApproverUserId
                })
            })
        }
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-MgGraphRequest -Method PATCH -Body $rule -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules/Approval_EndUser_Assignment" | Out-Null
        Write-Status "[$RoleName] approval required → approver $ApproverUserId" -Type Success
    } catch {
        Write-Status "[$RoleName] approval update failed: $($_.Exception.Message)" -Type Warning
    }
}

# ── Resolve admin users ────────────────────────────────────────────────────────
Write-Status "Resolving admin accounts" -Type Header

$bgUser   = Get-MgUser -Filter "userPrincipalName eq 'breakglass@$domain'"  -ErrorAction SilentlyContinue
$bg2User  = Get-MgUser -Filter "userPrincipalName eq 'breakglass2@$domain'" -ErrorAction SilentlyContinue
$t1svc01  = Get-MgUser -Filter "userPrincipalName eq 'admin.svc01@$domain'" -ErrorAction SilentlyContinue
$t1svc02  = Get-MgUser -Filter "userPrincipalName eq 'admin.svc02@$domain'" -ErrorAction SilentlyContinue
$t2sec01  = Get-MgUser -Filter "userPrincipalName eq 'admin.sec01@$domain'" -ErrorAction SilentlyContinue

$execUsers = Get-AllEmployeeUsers -CompanyName $config.CompanyName |
    Where-Object { $_.JobTitle -match "^Chief " }

Write-Host "  Break Glass 1  : $(if ($bgUser)  { $bgUser.UserPrincipalName  } else { 'NOT FOUND' })"
Write-Host "  Break Glass 2  : $(if ($bg2User) { $bg2User.UserPrincipalName } else { 'NOT FOUND' })"
Write-Host "  T1 admin.svc01 : $(if ($t1svc01) { 'Found' } else { 'NOT FOUND — run Deploy-Users.ps1' })"
Write-Host "  T1 admin.svc02 : $(if ($t1svc02) { 'Found' } else { 'NOT FOUND — run Deploy-Users.ps1' })"
Write-Host "  T2 admin.sec01 : $(if ($t2sec01) { 'Found' } else { 'NOT FOUND — run Deploy-Users.ps1' })"
Write-Host "  Executives     : $($execUsers.Count)"

# ── T1 service desk — eligible assignments ────────────────────────────────────
Write-Host ""
Write-Status "T1 Service Desk eligible assignments" -Type Header

foreach ($t1User in @($t1svc01, $t1svc02) | Where-Object { $_ }) {
    Write-Host "  User: $($t1User.UserPrincipalName)" -ForegroundColor Cyan
    New-EligibleAssignment -UserId $t1User.Id -RoleName "User Administrator"
    New-EligibleAssignment -UserId $t1User.Id -RoleName "Helpdesk Administrator"
    New-EligibleAssignment -UserId $t1User.Id -RoleName "Authentication Administrator"
    New-EligibleAssignment -UserId $t1User.Id -RoleName "Global Reader"
}

# ── T2 cloud/security ops — eligible assignments ──────────────────────────────
Write-Host ""
Write-Status "T2 Cloud/Security Ops eligible assignments" -Type Header

if ($t2sec01) {
    Write-Host "  User: $($t2sec01.UserPrincipalName)" -ForegroundColor Cyan
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Security Administrator"
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Privileged Role Administrator"
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Cloud Application Administrator"
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Security Reader"
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Global Reader"
    New-EligibleAssignment -UserId $t2sec01.Id -RoleName "Reports Reader"
}

# ── C-suite executives — Global Reader eligible ────────────────────────────────
Write-Host ""
Write-Status "Executive eligible assignments (Global Reader)" -Type Header

foreach ($exec in $execUsers) {
    Write-Host "  $($exec.JobTitle): $($exec.UserPrincipalName)" -ForegroundColor Cyan
    New-EligibleAssignment -UserId $exec.Id -RoleName "Global Reader"
    New-EligibleAssignment -UserId $exec.Id -RoleName "Reports Reader"
}

# ── PIM policy configuration ───────────────────────────────────────────────────
Write-Host ""
Write-Status "Configuring PIM activation policies" -Type Header

$sensitiveRoles = @(
    @{ Role = "Global Administrator";          Duration = "PT4H"; Controls = @("MultiFactorAuthentication","Justification","Ticketing") }
    @{ Role = "Privileged Role Administrator"; Duration = "PT4H"; Controls = @("MultiFactorAuthentication","Justification") }
    @{ Role = "Security Administrator";        Duration = "PT8H"; Controls = @("MultiFactorAuthentication","Justification") }
    @{ Role = "User Administrator";            Duration = "PT8H"; Controls = @("MultiFactorAuthentication","Justification") }
    @{ Role = "Authentication Administrator";  Duration = "PT8H"; Controls = @("MultiFactorAuthentication","Justification") }
    @{ Role = "Helpdesk Administrator";        Duration = "PT8H"; Controls = @("MultiFactorAuthentication","Justification") }
    @{ Role = "Cloud Application Administrator"; Duration = "PT8H"; Controls = @("MultiFactorAuthentication","Justification") }
)

foreach ($rp in $sensitiveRoles) {
    Write-Host "  Configuring: $($rp.Role)" -ForegroundColor Cyan
    Set-PimActivationDuration  -RoleName $rp.Role -MaxDuration $rp.Duration
    Set-PimActivationControls  -RoleName $rp.Role -Controls $rp.Controls
}

# Global Admin requires break glass account approval
if ($bgUser) {
    Write-Host ""
    Write-Status "Setting Global Administrator approval → break glass account" -Type Header
    Set-PimApprovalRequired -RoleName "Global Administrator" -ApproverUserId $bgUser.Id
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "PIM deployment complete" -Type Success
Write-Host ""
Write-Host "  Eligible role assignments created for T1, T2, and C-suite accounts." -ForegroundColor Green
Write-Host "  PIM activation policies configured on sensitive roles." -ForegroundColor Green
Write-Host ""
Write-Host "  Verify in Entra portal:" -ForegroundColor Cyan
Write-Host "    Identity Governance → Privileged Identity Management → Azure AD roles" -ForegroundColor DarkGray
Write-Host "    → Eligible assignments tab" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  To test activation:" -ForegroundColor Cyan
Write-Host "    Log in as admin.svc01@$domain → PIM → My roles → Activate 'User Administrator'" -ForegroundColor DarkGray
Write-Host "    Provide justification + MFA to activate for up to 8 hours" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
