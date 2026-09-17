<#
.SYNOPSIS
    Deploys a locally-authored Conditional Access baseline (not the remote
    Joey Verlinden import handled by Deploy-CAPs.ps1).

.DESCRIPTION
    Three baselines ship in CAPs/Baselines/*.json:

      Tiered      Custom-authored around this lab's own Tier0/1/2 admin groups,
                  PAW users, VPN users, and Executives group.
      ZeroTrust   Modeled on Microsoft's Zero Trust / Secure Future Initiative
                  Conditional Access guidance.
      SCuBA       Modeled on CISA's M365 Secure Configuration Baseline (SCuBA)
                  for Entra ID, mapped to MS.AAD.3.x control numbers.

    Each policy JSON uses lightweight tokens resolved against the current
    tenant at deploy time — see CAPs/Helpers/CAPolicyEngine.ps1:
      {{Group:ConfigKey}}          -> config.Groups.<ConfigKey> resolved to a group ID
      {{User:ConfigKey}}           -> config.Users.<ConfigKey> resolved to a user ID
      {{NamedLocation:Name}}       -> named location resolved by display name
      {{AuthStrength:Name}}        -> authentication strength policy resolved by display name
      {{Role:Name}} / AllPrivilegedRoles -> built-in directory role template ID(s)
      {{DesiredState}}             -> the policy state from config/-State

    Requires: Deploy-Groups.ps1, Deploy-Users.ps1, Deploy-NamedLocations.ps1,
    and Deploy-AuthStrengths.ps1 to have already run, since every reference
    above is resolved by looking up an existing object — nothing here creates
    groups, users, locations, or auth strengths itself.

.PARAMETER Baseline
    Which baseline to deploy: Tiered, ZeroTrust, or SCuBA. Defaults to
    config.CAPCustomBaseline.Baseline, or "Tiered" if that isn't set.

.EXAMPLE
    .\CAPs\Deploy-CAPs-Custom.ps1 -Baseline ZeroTrust
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [ValidateSet("Tiered", "ZeroTrust", "SCuBA")]
    [string]$Baseline
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\Helpers\CAPolicyEngine.ps1"
$config = Get-Config -ConfigPath $ConfigPath

$customConfig = $config.CAPCustomBaseline
if (-not $Baseline) {
    $Baseline = if ($customConfig -and $customConfig.Baseline) { [string]$customConfig.Baseline } else { "Tiered" }
}
if ($customConfig -and $customConfig.PSObject.Properties.Name -contains "Enabled" -and -not $customConfig.Enabled) {
    Write-Status "Custom Conditional Access baseline deployment is disabled in config (CAPCustomBaseline.Enabled = false)." -Type Warning
    return
}

$desiredState = if ($customConfig -and $customConfig.State) { [string]$customConfig.State } else { [string]$config.CAP.State }

$baselinePath = "$PSScriptRoot\Baselines\$Baseline.json"
if (-not (Test-Path $baselinePath)) {
    throw "Baseline file not found: $baselinePath"
}

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

$baselineDefinition = ConvertTo-CapHashtableDeep (Get-Content $baselinePath -Raw | ConvertFrom-Json -Depth 50)

Write-Host ""
Write-Status "Custom Conditional Access baseline: $($baselineDefinition.name)" -Type Header
Write-Host "  $($baselineDefinition.description)" -ForegroundColor DarkGray
Write-Host "  Policy state target: $desiredState" -ForegroundColor DarkGray
Write-Host "  Policies staged    : $($baselineDefinition.policies.Count)" -ForegroundColor DarkGray
Write-Host ""

$cache = New-CapTokenCache
$results = @()
foreach ($policyDef in $baselineDefinition.policies) {
    $results += New-OrUpdateCapPolicy -PolicyDefinition $policyDef -Config $config -Cache $cache -DesiredState $desiredState
}

$createdCount = @($results | Where-Object { $_.Status -eq "Created" }).Count
$updatedCount = @($results | Where-Object { $_.Status -eq "Updated" }).Count
$skippedCount = @($results | Where-Object { $_.Status -eq "Skipped" }).Count
$failedCount  = @($results | Where-Object { $_.Status -eq "Failed" }).Count

Write-Host ""
Write-Status "$($baselineDefinition.name) baseline deployment complete" -Type Success
Write-Host "  Created: $createdCount   Updated: $updatedCount   Skipped: $skippedCount   Failed: $failedCount" -ForegroundColor Cyan

if ($skippedCount -gt 0) {
    Write-Host ""
    Write-Host "  Skipped policies (license gated):" -ForegroundColor Yellow
    $results | Where-Object { $_.Status -eq "Skipped" } | ForEach-Object { Write-Host "    - $($_.DisplayName)" -ForegroundColor Yellow }
}
if ($failedCount -gt 0) {
    Write-Host ""
    Write-Host "  Failed policies:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "Failed" } | ForEach-Object { Write-Host "    - $($_.DisplayName): $($_.Reason)" -ForegroundColor Red }
}

Disconnect-MgGraph | Out-Null
