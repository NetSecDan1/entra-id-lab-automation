<#
.SYNOPSIS
    Flags app registration and service principal secrets/certificates that
    are already expired or expiring soon — the #1 cause of "it worked
    yesterday" outages in CI/CD and daemon apps.

.DESCRIPTION
    Walks every application registration's passwordCredentials and
    keyCredentials, plus service principals' own credentials (covers
    multi-tenant apps and third-party enterprise apps that carry
    credentials with no local app registration), and reports days-until-expiry
    for each one.

.PARAMETER WarningDays
    Credentials expiring within this many days are flagged "ExpiringSoon".
    Default 30.

.EXAMPLE
    .\IAM\Get-AppCredentialExpiryReport.ps1 -WarningDays 45 -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [int]$WarningDays = 30,
    [switch]$Open
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Reports\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

function Get-CredentialRows {
    param($OwnerDisplayName, $OwnerType, $AppId, [array]$PasswordCredentials, [array]$KeyCredentials, [int]$WarningDays)

    $now = Get-Date
    $rows = @()

    foreach ($cred in @($PasswordCredentials)) {
        $daysLeft = [math]::Floor(($cred.EndDateTime - $now).TotalDays)
        $rows += [pscustomobject]@{
            OwnerType      = $OwnerType
            OwnerName      = $OwnerDisplayName
            AppId          = $AppId
            CredentialType = "Secret"
            CredentialName = if ($cred.DisplayName) { $cred.DisplayName } else { "(unnamed)" }
            EndDateTime    = $cred.EndDateTime
            DaysUntilExpiry= $daysLeft
            Status         = if ($daysLeft -lt 0) { "Expired" } elseif ($daysLeft -le $WarningDays) { "ExpiringSoon" } else { "OK" }
        }
    }

    foreach ($cred in @($KeyCredentials)) {
        $daysLeft = [math]::Floor(($cred.EndDateTime - $now).TotalDays)
        $rows += [pscustomobject]@{
            OwnerType      = $OwnerType
            OwnerName      = $OwnerDisplayName
            AppId          = $AppId
            CredentialType = "Certificate"
            CredentialName = if ($cred.DisplayName) { $cred.DisplayName } else { "(unnamed)" }
            EndDateTime    = $cred.EndDateTime
            DaysUntilExpiry= $daysLeft
            Status         = if ($daysLeft -lt 0) { "Expired" } elseif ($daysLeft -le $WarningDays) { "ExpiringSoon" } else { "OK" }
        }
    }

    return $rows
}

Write-Status "Scanning app registrations" -Type Header
$apps = Get-MgApplication -All -Property "id,displayName,appId,passwordCredentials,keyCredentials" -ErrorAction SilentlyContinue
$appRows = @()
foreach ($app in $apps) {
    $appRows += Get-CredentialRows -OwnerDisplayName $app.DisplayName -OwnerType "Application" -AppId $app.AppId `
        -PasswordCredentials $app.PasswordCredentials -KeyCredentials $app.KeyCredentials -WarningDays $WarningDays
}

Write-Status "Scanning service principals" -Type Header
$sps = Get-MgServicePrincipal -All -Property "id,displayName,appId,passwordCredentials,keyCredentials,servicePrincipalType" -ErrorAction SilentlyContinue
$spRows = @()
foreach ($sp in ($sps | Where-Object { @($_.PasswordCredentials).Count -gt 0 -or @($_.KeyCredentials).Count -gt 0 })) {
    $spRows += Get-CredentialRows -OwnerDisplayName $sp.DisplayName -OwnerType "Service Principal" -AppId $sp.AppId `
        -PasswordCredentials $sp.PasswordCredentials -KeyCredentials $sp.KeyCredentials -WarningDays $WarningDays
}

$allRows = @($appRows) + @($spRows) | Sort-Object DaysUntilExpiry

$expired  = @($allRows | Where-Object { $_.Status -eq "Expired" })
$expiring = @($allRows | Where-Object { $_.Status -eq "ExpiringSoon" })

$statTiles = @(
    @{ Label = "Already expired"; Value = $expired.Count; Tone = if ($expired.Count -gt 0) { "danger" } else { "good" } }
    @{ Label = "Expiring within $WarningDays d"; Value = $expiring.Count; Tone = if ($expiring.Count -gt 0) { "warn" } else { "good" } }
    @{ Label = "Total credentials scanned"; Value = $allRows.Count; Tone = "neutral" }
    @{ Label = "Apps + service principals scanned"; Value = (@($apps).Count + @($sps).Count); Tone = "neutral" }
)

$outputPath = "$PSScriptRoot\..\Reports\Output\AppCredentialExpiry-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "App & Service Principal Credential Expiry" `
    -Subtitle "$($config.TenantDomain) — warning threshold $WarningDays day(s)" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Expired"                  = $expired
        "Expiring soon"            = $expiring
        "All credentials scanned"  = $allRows
    }) `
    -FooterNote "Source: Microsoft Graph /applications and /servicePrincipals passwordCredentials + keyCredentials." `
    -OutputPath $outputPath `
    -Open:$Open

Disconnect-MgGraph | Out-Null
