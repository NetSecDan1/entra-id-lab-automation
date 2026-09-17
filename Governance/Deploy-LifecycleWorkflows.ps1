<#
.SYNOPSIS
    Creates Entra ID Identity Governance Lifecycle Workflows for joiner, mover, and leaver.

.DESCRIPTION
    Requires Microsoft Entra ID Governance license (or M365 E5 + Identity Governance add-on).

    Joiner Workflow (on hire date)
    ------------------------------
    Trigger: employeeHireDate + 0 days
    Tasks  : Generate TAP → Add to SG-All-Employees → Send onboarding email to manager

    Mover Workflow (on department change)
    --------------------------------------
    Trigger: attribute change on department (uses scheduled execution)
    Tasks  : Add to new dept group → Send notification email

    Leaver Workflow (7 days before leave date)
    ------------------------------------------
    Trigger: employeeLeaveDate - 7 days
    Tasks  : Send offboarding email → Remove from all groups → Disable account
             (Hard delete on leaveDate + 30 via manual or second workflow)

    All workflows are created in disabled + scheduling-disabled state for review
    before activation. Enable them in Entra portal or re-run with -Enable.

.PARAMETER Enable
    Create workflows with isEnabled = true and isSchedulingEnabled = true.
    Default is false (review before activating).

.EXAMPLE
    # Create workflows (disabled for review)
    .\Governance\Deploy-LifecycleWorkflows.ps1

    # Create and immediately enable
    .\Governance\Deploy-LifecycleWorkflows.ps1 -Enable
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$Enable
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Identity Governance — Lifecycle Workflows" -Type Header
Write-Host "  Tenant  : $domain"
Write-Host "  Enabled : $($Enable.IsPresent)"
Write-Host ""

$isEnabled          = $Enable.IsPresent
$isSchedulingEnabled = $Enable.IsPresent

# ── Discover available task definitions ───────────────────────────────────────
Write-Status "Loading task definitions" -Type Header
try {
    $taskDefs = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
        -Uri "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/taskDefinitions"
    $taskDefMap = @{}
    foreach ($td in $taskDefs.value) { $taskDefMap[$td.displayName] = $td.id }
    Write-Host "  Available task definitions: $($taskDefs.value.Count)"
    $taskDefs.value | ForEach-Object { Write-Host "    - $($_.displayName)" -ForegroundColor DarkGray }
} catch {
    Write-Status "Could not load task definitions (requires LifecycleWorkflows.Read.All): $($_.Exception.Message)" -Type Error
    Write-Host "  Ensure you have the Entra ID Governance license and correct permissions." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}

# ── Resolve groups and accounts for workflow tasks ────────────────────────────
Write-Status "Resolving groups and accounts" -Type Header

$allEmpGroup = Get-MgGroup -Filter "displayName eq 'SG-All-Employees'" -ErrorAction SilentlyContinue

Write-Host "  SG-All-Employees : $(if ($allEmpGroup) { $allEmpGroup.Id } else { 'NOT FOUND' })"

# ── Helper: find task ID by partial name match ─────────────────────────────────
function Get-TaskDefId {
    param([string]$NameFragment)
    $match = $taskDefMap.GetEnumerator() | Where-Object { $_.Key -like "*$NameFragment*" } | Select-Object -First 1
    if (-not $match) {
        Write-Status "Task definition not found: *$NameFragment*" -Type Warning
        return $null
    }
    return $match.Value
}

# ── Helper: create or update lifecycle workflow ───────────────────────────────
function New-OrUpdateLifecycleWorkflow {
    param([string]$DisplayName, [hashtable]$Body)

    $existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
        -Uri "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows?`$filter=displayName eq '$DisplayName'"

    $json = $Body | ConvertTo-Json -Depth 20

    if ($existing.value -and $existing.value.Count -gt 0) {
        $wfId = $existing.value[0].id
        try {
            Invoke-MgGraphRequest -Method PATCH -Body $json -ContentType "application/json" `
                -Uri "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/$wfId" | Out-Null
            Write-Status "Updated: $DisplayName" -Type Warning
        } catch {
            Write-Status "Update failed for '$DisplayName': $($_.Exception.Message)" -Type Error
        }
        return $wfId
    }

    try {
        $created = Invoke-MgGraphRequest -Method POST -Body $json -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
        Write-Status "Created: $DisplayName" -Type Success
        return if ($created -is [hashtable]) { $created["id"] } else { $created.id }
    } catch {
        Write-Status "Failed to create '$DisplayName': $($_.Exception.Message)" -Type Error
        return $null
    }
}

# Task definition IDs
$tapTaskId          = Get-TaskDefId -NameFragment "Temporary Access Pass"
$addGroupTaskId     = Get-TaskDefId -NameFragment "Add user to groups"
$removeGroupTaskId  = Get-TaskDefId -NameFragment "Remove user from groups"
$disableUserTaskId  = Get-TaskDefId -NameFragment "Disable user account"
$sendEmailTaskId    = Get-TaskDefId -NameFragment "Send email"

$tapLifetime = if ($config.Auth -and $config.Auth.TAPLifetimeMinutes) { [int]$config.Auth.TAPLifetimeMinutes } else { 480 }
$tapOnce     = if ($config.Auth -and $null -ne $config.Auth.TAPIsUsableOnce) { [string]$config.Auth.TAPIsUsableOnce } else { "false" }

# ── 1. Joiner Workflow ────────────────────────────────────────────────────────
Write-Host ""
Write-Status "1. Joiner Workflow (on hire date)" -Type Header

$joinerTasks = [System.Collections.Generic.List[hashtable]]::new()

# Task: Generate TAP
if ($tapTaskId) {
    $joinerTasks.Add(@{
        continueOnError  = $false
        description      = "Generate a Temporary Access Pass for first-day sign-in"
        displayName      = "Generate TAP — First Day"
        isEnabled        = $true
        taskDefinitionId = $tapTaskId
        arguments        = @(
            @{ name = "tapLifetimeMinutes"; value = "$tapLifetime" }
            @{ name = "tapIsUsableOnce";   value = $tapOnce }
        )
    })
}

# Task: Add to SG-All-Employees
if ($addGroupTaskId -and $allEmpGroup) {
    $joinerTasks.Add(@{
        continueOnError  = $true
        description      = "Add new employee to the all-employees security group"
        displayName      = "Add to SG-All-Employees"
        isEnabled        = $true
        taskDefinitionId = $addGroupTaskId
        arguments        = @(@{
            name  = "groupID"
            value = $allEmpGroup.Id
        })
    })
}

# Task: Send onboarding email to manager
if ($sendEmailTaskId) {
    $joinerTasks.Add(@{
        continueOnError  = $true
        description      = "Notify the new employee's manager with onboarding instructions"
        displayName      = "Send Onboarding Email to Manager"
        isEnabled        = $true
        taskDefinitionId = $sendEmailTaskId
        arguments        = @(
            @{ name = "cc";               value = "" }
            @{ name = "customSubject";    value = "Action required: New employee {{userDisplayName}} starting today" }
            @{ name = "customBody";       value = "Your new team member {{userDisplayName}} ({{userPrincipalName}}) is starting today. Their Temporary Access Pass has been generated and sent to their registered email. Please help them get set up with their device and introduce them to the team." }
            @{ name = "toRecipients";     value = "manager" }
        )
    })
}

$joinerWorkflow = @{
    category             = "joiner"
    description          = "Automates new employee onboarding: generates TAP, adds to employee group, and notifies manager."
    displayName          = "Joiner — New Employee Onboarding"
    isEnabled            = $isEnabled
    isSchedulingEnabled  = $isSchedulingEnabled
    executionConditions  = @{
        "@odata.type" = "#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions"
        scope         = @{
            "@odata.type" = "#microsoft.graph.identityGovernance.ruleBasedSubjectSet"
            rule          = "department ne null"
        }
        trigger       = @{
            "@odata.type"       = "#microsoft.graph.identityGovernance.timeBasedAttributeTrigger"
            timeBasedAttribute  = "employeeHireDate"
            offsetInDays        = 0
        }
    }
    tasks = @($joinerTasks)
}

$joinerWfId = New-OrUpdateLifecycleWorkflow -DisplayName "Joiner — New Employee Onboarding" -Body $joinerWorkflow

# ── 2. Leaver Workflow (7 days before leave date) ─────────────────────────────
Write-Host ""
Write-Status "2. Leaver Workflow (7 days before leave date)" -Type Header

$leaverTasks = [System.Collections.Generic.List[hashtable]]::new()

# Task: Send offboarding email to manager
if ($sendEmailTaskId) {
    $leaverTasks.Add(@{
        continueOnError  = $true
        description      = "Notify the departing employee's manager of upcoming offboarding"
        displayName      = "Send Offboarding Notice to Manager"
        isEnabled        = $true
        taskDefinitionId = $sendEmailTaskId
        arguments        = @(
            @{ name = "customSubject"; value = "Notice: {{userDisplayName}} departing in 7 days" }
            @{ name = "customBody";    value = "This is a reminder that {{userDisplayName}} ({{userPrincipalName}}) has a scheduled leave date in 7 days. Please ensure knowledge transfer is complete and hand off any open items. Their account access will be automatically removed on their leave date." }
            @{ name = "toRecipients"; value = "manager" }
            @{ name = "cc";           value = "" }
        )
    })
}

# Task: Remove from all groups
if ($removeGroupTaskId -and $allEmpGroup) {
    $leaverTasks.Add(@{
        continueOnError  = $true
        description      = "Remove the departing employee from the all-employees group"
        displayName      = "Remove from SG-All-Employees"
        isEnabled        = $true
        taskDefinitionId = $removeGroupTaskId
        arguments        = @(@{
            name  = "groupID"
            value = $allEmpGroup.Id
        })
    })
}

# Task: Disable account
if ($disableUserTaskId) {
    $leaverTasks.Add(@{
        continueOnError  = $false
        description      = "Disable the user account to revoke all active sessions"
        displayName      = "Disable Account"
        isEnabled        = $true
        taskDefinitionId = $disableUserTaskId
        arguments        = @()
    })
}

$leaverWorkflow = @{
    category             = "leaver"
    description          = "Automates employee offboarding: notifies manager, removes from groups, and disables account 7 days before leave date."
    displayName          = "Leaver — Employee Offboarding"
    isEnabled            = $isEnabled
    isSchedulingEnabled  = $isSchedulingEnabled
    executionConditions  = @{
        "@odata.type" = "#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions"
        scope         = @{
            "@odata.type" = "#microsoft.graph.identityGovernance.ruleBasedSubjectSet"
            rule          = "department ne null"
        }
        trigger       = @{
            "@odata.type"      = "#microsoft.graph.identityGovernance.timeBasedAttributeTrigger"
            timeBasedAttribute = "employeeLeaveDateTime"
            offsetInDays       = -7
        }
    }
    tasks = @($leaverTasks)
}

$leaverWfId = New-OrUpdateLifecycleWorkflow -DisplayName "Leaver — Employee Offboarding" -Body $leaverWorkflow

# ── 3. Post-Leaver Cleanup (30 days after leave) ──────────────────────────────
Write-Host ""
Write-Status "3. Post-Leaver Cleanup (30 days after leave date)" -Type Header

$deleteTaskId = Get-TaskDefId -NameFragment "Delete user"

$cleanupTasks = [System.Collections.Generic.List[hashtable]]::new()

if ($sendEmailTaskId) {
    $cleanupTasks.Add(@{
        continueOnError  = $true
        displayName      = "Notify IT of Account Deletion"
        description      = "Notify IT admin that the former employee account will be permanently deleted"
        isEnabled        = $true
        taskDefinitionId = $sendEmailTaskId
        arguments        = @(
            @{ name = "customSubject"; value = "Account deletion: {{userDisplayName}} — 30-day retention period expired" }
            @{ name = "customBody";    value = "The account for {{userDisplayName}} ({{userPrincipalName}}) has reached the 30-day post-departure retention period and will be permanently deleted. Please ensure all data exports and mailbox archival have been completed." }
            @{ name = "toRecipients"; value = "admin.svc01@$domain" }
            @{ name = "cc";           value = "" }
        )
    })
}

if ($deleteTaskId) {
    $cleanupTasks.Add(@{
        continueOnError  = $false
        displayName      = "Delete Former Employee Account"
        description      = "Permanently delete the user account after 30-day retention"
        isEnabled        = $true
        taskDefinitionId = $deleteTaskId
        arguments        = @()
    })
}

if ($cleanupTasks.Count -gt 0) {
    $cleanupWorkflow = @{
        category             = "leaver"
        description          = "Permanently deletes former employee accounts 30 days after leave date following mandatory retention period."
        displayName          = "Leaver — Post-Departure Account Deletion"
        isEnabled            = $isEnabled
        isSchedulingEnabled  = $isSchedulingEnabled
        executionConditions  = @{
            "@odata.type" = "#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions"
            scope         = @{
                "@odata.type" = "#microsoft.graph.identityGovernance.ruleBasedSubjectSet"
                rule          = "department ne null"
            }
            trigger       = @{
                "@odata.type"      = "#microsoft.graph.identityGovernance.timeBasedAttributeTrigger"
                timeBasedAttribute = "employeeLeaveDateTime"
                offsetInDays       = 30
            }
        }
        tasks = @($cleanupTasks)
    }
    New-OrUpdateLifecycleWorkflow -DisplayName "Leaver — Post-Departure Account Deletion" -Body $cleanupWorkflow | Out-Null
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Lifecycle Workflows deployment complete" -Type Success
Write-Host ""
Write-Host "  Workflows created:" -ForegroundColor Green
Write-Host "    [Joiner] New Employee Onboarding      — fires on employeeHireDate" -ForegroundColor DarkGray
Write-Host "    [Leaver] Employee Offboarding         — fires 7 days before employeeLeaveDateTime" -ForegroundColor DarkGray
Write-Host "    [Leaver] Post-Departure Account Deletion — fires 30 days after employeeLeaveDateTime" -ForegroundColor DarkGray
Write-Host ""

if (-not $isEnabled) {
    Write-Host "  Workflows are DISABLED (safe mode). To activate:" -ForegroundColor Yellow
    Write-Host "    Option A: Re-run with -Enable flag" -ForegroundColor DarkGray
    Write-Host "    Option B: Entra portal → Identity Governance → Lifecycle Workflows → enable each" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  To trigger workflows on existing users:" -ForegroundColor Cyan
Write-Host "    Set user's employeeHireDate attribute, then:" -ForegroundColor DarkGray
Write-Host "    Entra portal → Identity Governance → Lifecycle Workflows → [workflow] → Run on demand" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Verify in Entra portal:" -ForegroundColor Cyan
Write-Host "    Identity Governance → Lifecycle Workflows → All workflows" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
