<#
.SYNOPSIS
    Creates or updates IP-based named locations from config.CAP.TrustedIPRanges.

.DESCRIPTION
    Reads TrustedIPRanges from config.json and creates each as a trusted IP named
    location in Entra ID. Also creates an aggregate "Trusted Office Networks" location
    containing all ranges combined — useful as a CA exclusion condition.

    Named locations are required before CA policies that reference trusted locations
    (e.g. CA301 - Block service accounts from untrusted locations) will work correctly.

    Run this before Deploy-CAPs.ps1.

.EXAMPLE
    .\NamedLocations\Deploy-NamedLocations.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath

$trustedRanges = @($config.CAP.TrustedIPRanges)
if (-not $trustedRanges -or $trustedRanges.Count -eq 0) {
    Write-Status "No TrustedIPRanges defined in config.CAP — nothing to deploy." -Type Warning
    return
}

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Named Locations — IP Trusted Ranges" -Type Header
Write-Host "  Ranges defined in config: $($trustedRanges.Count)"
Write-Host ""

function Set-IpNamedLocation {
    param(
        [string]$DisplayName,
        [bool]  $IsTrusted,
        [array] $CidrAddresses   # strings like "203.0.113.0/25"
    )

    $ipRanges = @($CidrAddresses | ForEach-Object {
        @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            "cidrAddress" = $_
        }
    })

    $body = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        "displayName" = $DisplayName
        "isTrusted"   = $IsTrusted
        "ipRanges"    = $ipRanges
    } | ConvertTo-Json -Depth 6

    $existing = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $DisplayName } |
        Select-Object -First 1

    if ($existing) {
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/$($existing.Id)" `
            -Body $body -ContentType "application/json" | Out-Null
        Write-Status "Updated : $DisplayName" -Type Warning
        return $existing.Id
    }

    $created = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" `
        -Body $body -ContentType "application/json"
    $createdId = if ($created -is [hashtable]) { $created["id"] } else { $created.id }
    Write-Status "Created : $DisplayName" -Type Success
    return $createdId
}

# ── Per-office named locations ─────────────────────────────────────────────────
$allCidrs = [System.Collections.Generic.List[string]]::new()

foreach ($range in $trustedRanges) {
    $name    = [string]$range.Name
    $cidr    = [string]$range.CidrAddress
    $trusted = if ($null -ne $range.IsTrusted) { [bool]$range.IsTrusted } else { $true }

    Set-IpNamedLocation -DisplayName $name -IsTrusted $trusted -CidrAddresses @($cidr) | Out-Null
    Write-Host "    $cidr → $name (trusted: $trusted)" -ForegroundColor DarkGray

    $allCidrs.Add($cidr)
}

# ── Aggregate named location — all office ranges combined ─────────────────────
Write-Host ""
$aggregateName = "Trusted Office Networks"
$aggregateId   = Set-IpNamedLocation -DisplayName $aggregateName -IsTrusted $true -CidrAddresses $allCidrs
Write-Host "    All $($allCidrs.Count) ranges → $aggregateName" -ForegroundColor DarkGray

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Named locations deployed" -Type Success
Write-Host ""

$allLocs = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue
$ipLocs      = @($allLocs | Where-Object { $_."@odata.type" -like "*ip*" -or $_.AdditionalProperties["@odata.type"] -like "*ip*" })
$countryLocs = @($allLocs | Where-Object { $_."@odata.type" -like "*country*" -or $_.AdditionalProperties["@odata.type"] -like "*country*" })

Write-Host "  Total named locations  : $($allLocs.Count)"
Write-Host "  IP-based               : $($ipLocs.Count)"
Write-Host "  Country-based          : $($countryLocs.Count)"
Write-Host ""
Write-Host "  All named locations:" -ForegroundColor Cyan
foreach ($loc in $allLocs | Sort-Object DisplayName) {
    Write-Host "    - $($loc.DisplayName)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Note: CA policies that target 'trusted locations' or 'named locations'" -ForegroundColor Yellow
Write-Host "  will now use these ranges. Run Deploy-CAPs.ps1 after this step." -ForegroundColor Yellow

Disconnect-MgGraph | Out-Null
