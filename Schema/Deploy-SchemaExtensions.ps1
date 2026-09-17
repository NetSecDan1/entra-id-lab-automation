<#
.SYNOPSIS
    Registers the "Tenant Schema Extension" app and its custom directory extension attributes.

.DESCRIPTION
    Custom directory (schema) extensions in Entra ID are always owned by an application
    object. This script:

      1. Creates an app registration + service principal to act as the schema owner
         (default display name: "Tenant Schema Extension").
      2. Adds each attribute defined in config.SchemaExtensions.Attributes as an
         extensionProperty on that app.

    Once created, an attribute is addressable on the target object as:

        extension_<appId-without-dashes>_<attributeName>

    e.g.  extension_a1b2c3d4e5f6_employeeType  on the user object.

    NOTE: extension properties are typed (String, Boolean, Integer, DateTime,
    Binary, LargeInteger) but Entra does NOT enforce an allowed-value list. The
    AllowedValues in config are documentation only and drive the optional
    -AssignSamples pass.

    Idempotent: re-running skips the app and any attribute that already exists.
    Deleting the app deletes every attribute it defines (and unsets them on all
    objects) — so this app is marked with a "do not delete" note.

.PARAMETER AssignSamples
    After creating attributes, assign a random AllowedValue to every enabled
    member user so the attribute has test data. Off by default.

.EXAMPLE
    # Standalone (connect first):
    . .\Helpers\Common.ps1; Connect-TestTenant
    .\Schema\Deploy-SchemaExtensions.ps1

.EXAMPLE
    .\Schema\Deploy-SchemaExtensions.ps1 -AssignSamples
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",
    [switch]$AssignSamples
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath

$schema = $config.SchemaExtensions
if (-not $schema) {
    Write-Status "No SchemaExtensions block in config — nothing to do." -Type Warning
    return
}

$appName = if ($schema.AppName) { [string]$schema.AppName } else { "Tenant Schema Extension" }

# ── 1. Schema owner app registration ─────────────────────────────────────────
Write-Status $appName -Type Header
$app = Get-MgApplication -Filter "displayName eq '$appName'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($app) {
    Write-Status "Exists: $appName ($($app.AppId))" -Type Warning
} else {
    $app = New-MgApplication -BodyParameter @{
        displayName    = $appName
        signInAudience = "AzureADMyOrg"
        notes          = "DO NOT DELETE — owns the tenant's custom directory extension attributes (extension_*). Deleting this app removes those attributes from every object."
        tags           = @("SchemaExtensionOwner")
    }
    Write-Status "Created: $appName ($($app.AppId))" -Type Success
}

# Service principal — not strictly required for directory extensions, created for
# consistency with the other lab apps. The WindowsAzureActiveDirectoryIntegratedApp
# tag is what makes it appear in the portal's default "Enterprise applications" list.
$spTags = @("WindowsAzureActiveDirectoryIntegratedApp", "SchemaExtensionOwner")
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId -Tags $spTags
    Write-Status "Created service principal for $appName" -Type Success
} else {
    $missing = $spTags | Where-Object { $sp.Tags -notcontains $_ }
    if ($missing) {
        Update-MgServicePrincipal -ServicePrincipalId $sp.Id -Tags @($sp.Tags + $missing | Select-Object -Unique)
        Write-Status "Service principal present — added tags: $($missing -join ', ')" -Type Success
    } else {
        Write-Status "Service principal already present" -Type Warning
    }
}

$appIdNoDashes = $app.AppId -replace '-', ''

# ── 2. Extension attributes ─────────────────────────────────────────────────
Write-Status "Extension attributes" -Type Header
$existing  = @(Get-MgApplicationExtensionProperty -ApplicationId $app.Id -All -ErrorAction SilentlyContinue)
$deployed  = [System.Collections.Generic.List[psobject]]::new()

foreach ($attr in @($schema.Attributes)) {
    $short    = [string]$attr.Name
    $dataType = if ($attr.DataType) { [string]$attr.DataType } else { "String" }
    $targets  = @($attr.TargetObjects)
    if (-not $targets -or $targets.Count -eq 0) { $targets = @("User") }

    $fqName = "extension_${appIdNoDashes}_$short"
    $match  = $existing | Where-Object { $_.Name -eq $fqName -or $_.Name -like "extension_*_$short" } | Select-Object -First 1

    if ($match) {
        Write-Status "Attribute exists: $($match.Name)" -Type Warning
        $deployed.Add([PSCustomObject]@{ Short = $short; Name = $match.Name; DataType = $match.DataType; Targets = $match.TargetObjects; AllowedValues = $attr.AllowedValues; Sample = $attr.SampleAssignment })
        continue
    }

    $prop = New-MgApplicationExtensionProperty -ApplicationId $app.Id -BodyParameter @{
        name          = $short
        dataType      = $dataType
        targetObjects = $targets
    }
    Write-Status "Created: $($prop.Name)   [$dataType -> $($targets -join ', ')]" -Type Success
    if ($attr.Description)   { Write-Host "    $($attr.Description)" -ForegroundColor DarkGray }
    if ($attr.AllowedValues) { Write-Host "    Documented values: $(@($attr.AllowedValues) -join ', ')" -ForegroundColor DarkGray }
    $deployed.Add([PSCustomObject]@{ Short = $short; Name = $prop.Name; DataType = $prop.DataType; Targets = $prop.TargetObjects; AllowedValues = $attr.AllowedValues; Sample = $attr.SampleAssignment })
}

# ── 3. Optional: seed sample values ─────────────────────────────────────────
# Humans get a random value from SampleAssignment.HumanValues (fallback: AllowedValues).
# Service accounts (svc-* users, non-human identities) get SampleAssignment.ServiceAccountValue.
if ($AssignSamples) {
    Write-Status "Assigning sample values" -Type Header
    $company     = [string]$config.CompanyName
    $humans      = @(Get-AllEmployeeUsers -CompanyName $company)
    $svcAccounts = @(Get-ServiceAccountUsers -CompanyName $company)
    Write-Status "Targets: $($humans.Count) employees, $($svcAccounts.Count) service accounts" -Type Info

    foreach ($d in $deployed) {
        if ($d.Targets -notcontains "User") { continue }

        $humanVals = @($d.Sample.HumanValues)
        if ($humanVals.Count -eq 0) { $humanVals = @($d.AllowedValues) }
        $svcVal = if ($d.Sample) { [string]$d.Sample.ServiceAccountValue } else { "" }

        $tally = @{}
        if ($humanVals.Count -gt 0) {
            foreach ($u in $humans) {
                $value = Get-Random -InputObject $humanVals
                Update-MgUser -UserId $u.Id -BodyParameter @{ $d.Name = $value }
                $tally[$value] = [int]$tally[$value] + 1
            }
        }
        if ($svcVal) {
            foreach ($u in $svcAccounts) {
                Update-MgUser -UserId $u.Id -BodyParameter @{ $d.Name = $svcVal }
                $tally[$svcVal] = [int]$tally[$svcVal] + 1
            }
        }

        $seen  = @($humanVals + $svcVal | Where-Object { $_ } | Select-Object -Unique)
        $dist  = ($seen | ForEach-Object { "$_=$([int]$tally[$_])" }) -join ' '
        $total = ($tally.Values | Measure-Object -Sum).Sum
        Write-Status "Set $($d.Name) on $total users  ($dist)" -Type Success
    }
}

# ── Summary ────────────────────────────────────────────────────────────────
Write-Status "Schema extension deployment complete" -Type Success
Write-Host ""
Write-Host "  Owner app : $appName"
Write-Host "  App ID    : $($app.AppId)"
Write-Host ""
foreach ($d in $deployed) {
    Write-Host ("  {0,-16} {1}" -f $d.Short, $d.Name)
}
Write-Host ""
Write-Host "  Query example:" -ForegroundColor DarkGray
if ($deployed.Count -gt 0) {
    Write-Host "    Get-MgUser -UserId <upn> -Property `"id,displayName,$($deployed[0].Name)`" | Select-Object -ExpandProperty AdditionalProperties" -ForegroundColor DarkGray
}
