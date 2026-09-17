<#
.SYNOPSIS
    Orchestrator — provisions a fresh Entra test tenant end-to-end.

.DESCRIPTION
    Edit config/config.json first, then run this script.
    Each module is idempotent: safe to re-run after partial failures.

.PARAMETER ConfigPath
    Path to config.json (default: .\config\config.json)

.PARAMETER Steps
    Comma-separated list of steps to run. Defaults to all.
    Valid values: Users, Groups, NamedLocations, CAPs, Apps, Schema, Auth, AuthStrengths,
                  Directory, Licensing, AdminUnits, PIM, AccessReviews, LifecycleWorkflows,
                  EntitlementManagement

.EXAMPLE
    # Full setup
    .\Setup-TestTenant.ps1

    # Only users and groups
    .\Setup-TestTenant.ps1 -Steps Users,Groups

    # Full governance suite (requires P2 / Entra ID Governance)
    .\Setup-TestTenant.ps1 -Mode Governance

    # Re-run CA with named locations
    .\Setup-TestTenant.ps1 -Steps NamedLocations,CAPs
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\config\config.json",

    [ValidateSet("Full","Foundation","Security","Identity","Applications","Governance")]
    [string]$Mode = "",

    [ValidateSet("Users","FunUsers","Groups","NamedLocations","CAPs","Apps","Schema","Auth","AuthStrengths",
                 "Directory","Licensing","AdminUnits","PIM","AccessReviews","LifecycleWorkflows","EntitlementManagement",
                 "TermsOfUse","PasswordProtection","CrossTenantAccess","AuthContexts")]
    [string[]]$Steps = @(),

    [switch]$ContinueOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. "$PSScriptRoot\Helpers\Common.ps1"

# ── Pre-flight ───────────────────────────────────────────────────────────────
Write-Status "Entra Test Tenant Setup" -Type Header
Write-Status "Config: $ConfigPath" -Type Info

$validation = Test-TenantConfig -ConfigPath $ConfigPath
$config = $validation.Config
$config.DefaultPassword = $validation.ResolvedPassword

if (-not $Mode) {
    $Mode = if ($config.BestPractices.DefaultMode) { [string]$config.BestPractices.DefaultMode } else { "Full" }
}

$Steps = Get-SetupStepsFromMode -Mode $Mode -RequestedSteps $Steps
$stopOnFailure = if ($ContinueOnError) { $false } elseif ($null -ne $config.BestPractices -and $null -ne $config.BestPractices.StopOnFailure) { [bool]$config.BestPractices.StopOnFailure } else { $true }

if (-not $validation.IsValid) {
    Write-Status "Configuration validation failed" -Type Error
    foreach ($issue in $validation.Issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
    exit 1
}

foreach ($warning in $validation.Warnings) {
    Write-Status $warning -Type Warning
}

Write-Status "Execution mode: $Mode" -Type Info
Write-Status "Steps: $($Steps -join ', ')" -Type Info

$recommendations = Get-BestPracticeMessages -Config $config
if (@($recommendations).Count -gt 0) {
    Write-Status "Best-practice review" -Type Header
    foreach ($message in $recommendations) {
        Write-Host "  - $message" -ForegroundColor Yellow
    }
}

$transcriptPath = Start-SetupTranscript -Config $config

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

$startTime = Get-Date

# ── Run steps ────────────────────────────────────────────────────────────────
$scripts = @{
    Users              = "$PSScriptRoot\Users\Deploy-Users.ps1"
    FunUsers           = "$PSScriptRoot\Users\Deploy-FunUsers.ps1"
    Groups             = "$PSScriptRoot\Groups\Deploy-Groups.ps1"
    NamedLocations     = "$PSScriptRoot\NamedLocations\Deploy-NamedLocations.ps1"
    CAPs               = "$PSScriptRoot\CAPs\Deploy-CAPs.ps1"
    Apps               = "$PSScriptRoot\Apps\Deploy-Apps.ps1"
    Schema             = "$PSScriptRoot\Schema\Deploy-SchemaExtensions.ps1"
    Auth               = "$PSScriptRoot\Auth\Deploy-AuthMethods.ps1"
    AuthStrengths      = "$PSScriptRoot\Auth\Deploy-AuthStrengths.ps1"
    Directory          = "$PSScriptRoot\Directory\Deploy-DirectorySettings.ps1"
    Licensing          = "$PSScriptRoot\Licensing\Deploy-Licenses.ps1"
    AdminUnits          = "$PSScriptRoot\AdminUnits\Deploy-AdminUnits.ps1"
    PIM                 = "$PSScriptRoot\PIM\Deploy-PIM.ps1"
    AccessReviews       = "$PSScriptRoot\Governance\Deploy-AccessReviews.ps1"
    LifecycleWorkflows  = "$PSScriptRoot\Governance\Deploy-LifecycleWorkflows.ps1"
    EntitlementManagement = "$PSScriptRoot\Governance\Deploy-EntitlementManagement.ps1"
    TermsOfUse          = "$PSScriptRoot\Security\Deploy-TermsOfUse.ps1"
    PasswordProtection  = "$PSScriptRoot\Security\Deploy-PasswordProtection.ps1"
    CrossTenantAccess   = "$PSScriptRoot\Security\Deploy-CrossTenantAccess.ps1"
    AuthContexts        = "$PSScriptRoot\Security\Deploy-AuthContexts.ps1"
}

$results = @{}
try {
    foreach ($step in $Steps) {
        Write-Host ""
        Write-Status "━━━ Running: $step ━━━" -Type Header
        try {
            & $scripts[$step] -ConfigPath $ConfigPath
            $results[$step] = "OK"
            Write-Status "$step complete." -Type Success
        } catch {
            $results[$step] = "FAILED: $_"
            Write-Status "$step failed: $_" -Type Error

            if ($stopOnFailure) {
                throw
            }
        }
    }
} finally {
    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Status "━━━ Summary (elapsed: $([int]$elapsed.TotalSeconds)s) ━━━" -Type Header
    foreach ($step in $Steps) {
        $status = if ($results.ContainsKey($step)) { $results[$step] } else { "SKIPPED" }
        $color = if ($status -eq "OK") { "Green" } elseif ($status -eq "SKIPPED") { "Yellow" } else { "Red" }
        Write-Host "  $step : $status" -ForegroundColor $color
    }

    if ($transcriptPath) {
        Write-Status "Transcript saved to: $transcriptPath" -Type Info
    }

    Disconnect-MgGraph | Out-Null
    Stop-SetupTranscriptSafe
}

Write-Status "Done." -Type Success
