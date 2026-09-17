<#
.SYNOPSIS
    Imports the Joey Verlinden Conditional Access baseline into the tenant.

.DESCRIPTION
    This script pulls the latest baseline JSON templates from:
      https://github.com/j0eyv/ConditionalAccessBaseline

    It creates or updates:
      - Named locations
      - Conditional Access policies

    It rewrites source-tenant group and named-location IDs to IDs from the
    current tenant by matching the baseline migration table objects by
    display name.

    Baseline groups are created by Groups\Deploy-Groups.ps1.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config     = Get-Config -ConfigPath $ConfigPath
$caBaseline = $config.CABaseline
$capConfig  = $config.CAP

if (-not $caBaseline -or -not $caBaseline.Enabled) {
    Write-Status "Conditional Access baseline import is disabled in config." -Type Warning
    return
}

$rawBaseUrl = if ($caBaseline.SourceRepositoryRawBaseUrl) {
    [string]$caBaseline.SourceRepositoryRawBaseUrl
} else {
    "https://raw.githubusercontent.com/j0eyv/ConditionalAccessBaseline/main"
}

$desiredState = if ($caBaseline.PolicyState) { [string]$caBaseline.PolicyState } else { [string]$capConfig.State }
$allowedCountries = @($caBaseline.AllowedCountries)
$allowedCountriesServiceAccounts = @($caBaseline.AllowedCountriesServiceAccounts)

if (@($allowedCountries).Count -eq 0) { $allowedCountries = @("US") }
if (@($allowedCountriesServiceAccounts).Count -eq 0) { $allowedCountriesServiceAccounts = @("US") }

$policyFiles = @(
    "Config/ConditionalAccess/CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist.json",
    "Config/ConditionalAccess/CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication.json",
    "Config/ConditionalAccess/CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows.json",
    "Config/ConditionalAccess/CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-AppEnforcedRestrictions.json",
    "Config/ConditionalAccess/CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions.json",
    "Config/ConditionalAccess/CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json",
    "Config/ConditionalAccess/CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
    "Config/ConditionalAccess/CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation.json",
    "Config/ConditionalAccess/CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA.json",
    "Config/ConditionalAccess/CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser.json",
    "Config/ConditionalAccess/CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices.json",
    "Config/ConditionalAccess/CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA.json",
    "Config/ConditionalAccess/CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms.json",
    "Config/ConditionalAccess/CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ.json",
    "Config/ConditionalAccess/CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
    "Config/ConditionalAccess/CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK.json",
    "Config/ConditionalAccess/CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant.json",
    "Config/ConditionalAccess/CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation.json",
    "Config/ConditionalAccess/CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn.json"
)

if ($caBaseline.IncludeServiceAccountPolicies) {
    $policyFiles += @(
        "Config/ConditionalAccess/CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
        "Config/ConditionalAccess/CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations.json"
    )
}

if ($caBaseline.IncludeGuestPolicies) {
    $policyFiles += @(
        "Config/ConditionalAccess/CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA.json",
        "Config/ConditionalAccess/CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess.json",
        "Config/ConditionalAccess/CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json",
        "Config/ConditionalAccess/CA403-GuestUsers-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser.json",
        "Config/ConditionalAccess/CA404-GuestUsers-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK.json"
    )
}

if ($caBaseline.IncludeAgentPolicies) {
    $policyFiles += @(
        "Config/ConditionalAccess/CA501-Agents-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskAgent.json",
        "Config/ConditionalAccess/CA502-Agents-AttackSurfaceReduction-AllAgentIdentities-AllAgentResources-BLOCK.json",
        "Config/ConditionalAccess/CA503-Agents-BaseProtection-AllAgentUsers-RequireCompliantDevice.json",
        "Config/ConditionalAccess/CA504-Agents-IdentityProtection-AllAgentUsers-AllResources-BlockRiskyAgents.json",
        "Config/ConditionalAccess/CA505-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-RequireCompliantNetWork.json"
    )
}

function Get-RemoteJsonObject {
    param([string]$RelativePath)

    $uri = "{0}/{1}" -f $rawBaseUrl.TrimEnd("/"), $RelativePath.TrimStart("/")
    Write-Status "Downloading: $RelativePath" -Type Info
    $response = Invoke-RestMethod -Uri $uri -Method Get

    if ($response -is [string]) {
        $normalized = $response.TrimStart([char]0xFEFF).Trim()
        if ($normalized.StartsWith("{") -or $normalized.StartsWith("[")) {
            return $normalized | ConvertFrom-Json -Depth 100
        }
    }

    return $response
}

function ConvertTo-HashtableDeep {
    param([Parameter(ValueFromPipeline)]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-HashtableDeep -InputObject $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(ConvertTo-HashtableDeep -InputObject $item)
        }
        return ,$items
    }

    if ($InputObject -is [pscustomobject]) {
        $result = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $result[$prop.Name] = ConvertTo-HashtableDeep -InputObject $prop.Value
        }
        return $result
    }

    return $InputObject
}

function Remove-GraphMetadata {
    param($InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($entry in $InputObject.GetEnumerator()) {
            $key = [string]$entry.Key
            if ($key -match '^@odata' -or $key -match '^#') { continue }
            if ($key -match '@odata\.') { continue }
            if ($key -in @('id','createdDateTime','modifiedDateTime','deletedDateTime','partialEnablementStrategy')) { continue }

            $value = Remove-GraphMetadata -InputObject $entry.Value
            if ($null -ne $value) {
                $result[$key] = $value
            }
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(Remove-GraphMetadata -InputObject $item)
        }
        return ,$items
    }

    return $InputObject
}

function Replace-MappedIds {
    param(
        $InputObject,
        [hashtable]$IdMap
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        if ($IdMap.ContainsKey($InputObject)) {
            return $IdMap[$InputObject]
        }
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($entry in $InputObject.GetEnumerator()) {
            $result[$entry.Key] = Replace-MappedIds -InputObject $entry.Value -IdMap $IdMap
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ,(Replace-MappedIds -InputObject $item -IdMap $IdMap)
        }
        return ,$items
    }

    return $InputObject
}

function Ensure-IntuneEnrollmentServicePrincipal {
    $intuneEnrollmentAppId = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
    $sp = Get-MgServicePrincipal -Filter "appId eq '$intuneEnrollmentAppId'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        New-MgServicePrincipal -AppId $intuneEnrollmentAppId | Out-Null
        Write-Status "Created Microsoft Intune Enrollment service principal." -Type Success
    }
}

function Get-PolicyStateForImport {
    param([string]$DisplayName)

    if ($DisplayName -in @(
        "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation",
        "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation"
    ) -and $desiredState -eq "enabledForReportingButNotEnforced") {
        Write-Status "$DisplayName cannot be report-only. Importing it as disabled." -Type Warning
        return "disabled"
    }

    return $desiredState
}

function New-OrUpdateNamedLocation {
    param(
        [string]$RelativePath,
        [string[]]$OverrideCountries = @()
    )

    $sourceObject = ConvertTo-HashtableDeep (Get-RemoteJsonObject -RelativePath $RelativePath)
    $sourceId = [string]$sourceObject.id
    $body = Remove-GraphMetadata -InputObject $sourceObject

    if ($sourceObject.ContainsKey("@odata.type")) {
        $body["@odata.type"] = $sourceObject["@odata.type"]
    }

    if (@($OverrideCountries).Count -gt 0 -and $body.ContainsKey("countriesAndRegions")) {
        $body["countriesAndRegions"] = @($OverrideCountries)
        $body["includeUnknownCountriesAndRegions"] = $false
    }

    $existing = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $body.displayName } |
        Select-Object -First 1

    $jsonBody = $body | ConvertTo-Json -Depth 20
    if ($existing) {
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$($existing.Id)" `
            -Body $jsonBody `
            -ContentType "application/json" | Out-Null
        Write-Status "Updated named location: $($body.displayName)" -Type Success
        return @{ SourceId = $sourceId; TargetId = $existing.Id }
    }

    $created = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations" `
        -Body $jsonBody `
        -ContentType "application/json"
    $createdId = if ($created -is [hashtable]) { $created["id"] } else { $created.id }
    Write-Status "Created named location: $($body.displayName)" -Type Success
    return @{ SourceId = $sourceId; TargetId = $createdId }
}

function Get-AuthenticationStrengthReference {
    param($GrantControls)

    if (-not $GrantControls.ContainsKey("authenticationStrength")) { return $null }
    $authStrength = $GrantControls["authenticationStrength"]
    if ($null -eq $authStrength) { return $null }

    $authId = $authStrength["id"]
    if ([string]::IsNullOrWhiteSpace($authId)) { return $null }

    return @{ id = $authId }
}

function Build-PolicyBody {
    param(
        [hashtable]$SourcePolicy,
        [hashtable]$IdMap
    )

    $displayName = [string]$SourcePolicy.displayName
    $conditions = Replace-MappedIds -InputObject (Remove-GraphMetadata -InputObject $SourcePolicy.conditions) -IdMap $IdMap

    if ($null -ne $conditions -and $conditions.ContainsKey("users")) {
        $users = $conditions["users"]
        $includeUsers = @($users["includeUsers"])
        $hasAlternativeUserTarget = (
            @($users["includeGroups"]).Count -gt 0 -or
            @($users["includeRoles"]).Count -gt 0
        )

        # Current Graph create validation expects the explicit None sentinel
        # when roles/groups/guest targeting is used without direct users.
        if (@($includeUsers).Count -eq 0 -and $hasAlternativeUserTarget) {
            $users["includeUsers"] = @("None")
        }
    }

    $body = @{
        displayName = $displayName
        state       = Get-PolicyStateForImport -DisplayName $displayName
        conditions  = $conditions
    }

    $rawAuthStrengthId = $null
    if ($SourcePolicy.grantControls -and $SourcePolicy.grantControls["authenticationStrength"]) {
        $rawAuthStrengthId = [string]$SourcePolicy.grantControls["authenticationStrength"]["id"]
    }
    $grantControls = Replace-MappedIds -InputObject (Remove-GraphMetadata -InputObject $SourcePolicy.grantControls) -IdMap $IdMap
    if ($null -ne $grantControls) {
        if (-not [string]::IsNullOrWhiteSpace($rawAuthStrengthId)) {
            $grantControls["authenticationStrength"] = @{ id = $rawAuthStrengthId }
        } elseif ($grantControls.ContainsKey("authenticationStrength")) {
            $grantControls.Remove("authenticationStrength")
        }
        $body["grantControls"] = $grantControls
    }

    $sessionControls = Replace-MappedIds -InputObject (Remove-GraphMetadata -InputObject $SourcePolicy.sessionControls) -IdMap $IdMap
    if ($null -ne $sessionControls) {
        $body["sessionControls"] = $sessionControls
    }

    return $body
}

function New-OrUpdatePolicy {
    param(
        [string]$RelativePath,
        [hashtable]$IdMap
    )

    $sourceObject = ConvertTo-HashtableDeep (Get-RemoteJsonObject -RelativePath $RelativePath)
    $existing = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $sourceObject.displayName } |
        Select-Object -First 1
    $body = Build-PolicyBody -SourcePolicy $sourceObject -IdMap $IdMap

    $jsonBody = $body | ConvertTo-Json -Depth 50

    try {
        if ($existing) {
            Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($existing.Id)" `
                -Body $jsonBody `
                -ContentType "application/json" | Out-Null
            Write-Status "Updated policy: $($body.displayName)" -Type Success
            return [pscustomobject]@{
                DisplayName = $body.displayName
                Status      = "Updated"
                Reason      = $null
            }
        }

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" `
            -Body $jsonBody `
            -ContentType "application/json" | Out-Null
        Write-Status "Created policy: $($body.displayName)" -Type Success
        return [pscustomobject]@{
            DisplayName = $body.displayName
            Status      = "Created"
            Reason      = $null
        }
    } catch {
        $errMsg = $_.ToString()
        if ($errMsg -match '1039') {
            Write-Status "Skipped (P2 license required): $($body.displayName)" -Type Warning
            return [pscustomobject]@{
                DisplayName = $body.displayName
                Status      = "Skipped"
                Reason      = "P2 license required"
            }
        } else {
            throw
        }
    }
}

Write-Status "Conditional Access baseline import" -Type Header
Write-Status "Source: $rawBaseUrl" -Type Info
Write-Status "Policy state target: $desiredState" -Type Info

Ensure-IntuneEnrollmentServicePrincipal

$migrationTable = ConvertTo-HashtableDeep (Get-RemoteJsonObject -RelativePath "Config/MigrationTable.json")
$idMap = @{}

Write-Status "Resolving baseline group IDs" -Type Header
$migrationObjects = if ($migrationTable -is [hashtable]) { $migrationTable["Objects"] } else { $migrationTable.Objects }
foreach ($obj in @($migrationObjects)) {
    if ($obj.Type -ne "Group") { continue }

    $group = Get-MgGroup -Filter "displayName eq '$($obj.DisplayName)'" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $group) {
        Write-Status "Baseline group missing: $($obj.DisplayName). Run Deploy-Groups.ps1 first." -Type Error
        throw "Missing baseline group: $($obj.DisplayName)"
    }

    $idMap[[string]$obj.Id] = [string]$group.Id
}

Write-Status "Creating named locations" -Type Header
$namedLocations = @(
    @{ Path = "Config/NamedLocations/ALLOWED COUNTRIES.json"; Countries = $allowedCountries },
    @{ Path = "Config/NamedLocations/ALLOWED COUNTRIES - SERVICE ACCOUNTS.json"; Countries = $allowedCountriesServiceAccounts }
)

if ($caBaseline.IncludeAgentPolicies) {
    $namedLocations += @{ Path = "Config/NamedLocations/All Compliant Network locations.json"; Countries = @() }
}

foreach ($namedLocation in $namedLocations) {
    $mapping = New-OrUpdateNamedLocation -RelativePath $namedLocation.Path -OverrideCountries $namedLocation.Countries
    $idMap[$mapping.SourceId] = $mapping.TargetId
}

Write-Status "Importing policies" -Type Header
$policyResults = @()
foreach ($policyFile in $policyFiles) {
    $policyResults += New-OrUpdatePolicy -RelativePath $policyFile -IdMap $idMap
}

$createdCount = @($policyResults | Where-Object { $_.Status -eq "Created" }).Count
$updatedCount = @($policyResults | Where-Object { $_.Status -eq "Updated" }).Count
$skippedCount = @($policyResults | Where-Object { $_.Status -eq "Skipped" }).Count
$skippedPolicies = @($policyResults | Where-Object { $_.Status -eq "Skipped" } | Select-Object -ExpandProperty DisplayName)

Write-Status "Conditional Access baseline deployment complete" -Type Success
Write-Host ""
Write-Host "  Source baseline : https://github.com/j0eyv/ConditionalAccessBaseline" -ForegroundColor Cyan
Write-Host "  Policies staged : $($policyFiles.Count)" -ForegroundColor Cyan
Write-Host "  Policies created: $createdCount" -ForegroundColor Cyan
Write-Host "  Policies updated: $updatedCount" -ForegroundColor Cyan
Write-Host "  Policies skipped: $skippedCount" -ForegroundColor Cyan
Write-Host "  Policy state    : $desiredState" -ForegroundColor Cyan
Write-Host "  Allowed countries: $($allowedCountries -join ', ')" -ForegroundColor Cyan
Write-Host "  Service account countries: $($allowedCountriesServiceAccounts -join ', ')" -ForegroundColor Cyan

if ($skippedPolicies.Count -gt 0) {
    Write-Host ""
    Write-Host "  Skipped policies (license gated):" -ForegroundColor Yellow
    foreach ($policyName in $skippedPolicies) {
        Write-Host "    - $policyName" -ForegroundColor Yellow
    }
}
