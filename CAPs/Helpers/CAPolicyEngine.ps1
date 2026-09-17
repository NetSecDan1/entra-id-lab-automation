# CAPs/Helpers/CAPolicyEngine.ps1
#
# Shared engine for deploying locally-authored Conditional Access baselines
# (CAPs/Baselines/*.json). Distinct from Deploy-CAPs.ps1, which imports the
# remote Joey Verlinden baseline — this engine resolves lightweight tokens
# ({{Group:Key}}, {{User:Key}}, {{NamedLocation:Name}}, {{AuthStrength:Name}},
# {{Role:Name}}) against the current tenant instead of a source-tenant
# migration table, since the JSON here has no source tenant to migrate from.

# Built-in directory role template IDs are fixed, universal GUIDs (not tenant-specific) —
# see https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
$script:CapRoleTemplateIds = @{
    "GlobalAdministrator"          = "62e90394-69f5-4237-9190-012177145e10"
    "PrivilegedRoleAdministrator"  = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "SecurityAdministrator"        = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "ConditionalAccessAdministrator" = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    "UserAdministrator"            = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "ApplicationAdministrator"     = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    "CloudApplicationAdministrator"= "158c047a-c907-4556-b7ef-446551a6b5f7"
    "AuthenticationAdministrator"  = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    "HelpdeskAdministrator"        = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "ExchangeAdministrator"        = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    "SharePointAdministrator"      = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    "BillingAdministrator"         = "b0f54661-2d74-4c50-afa3-1ec803f12efe"
}

# All-privileged-roles set used for "any admin role" policy scoping.
$script:CapAllPrivilegedRoleKeys = @(
    "GlobalAdministrator","PrivilegedRoleAdministrator","SecurityAdministrator",
    "ConditionalAccessAdministrator","UserAdministrator","ApplicationAdministrator",
    "CloudApplicationAdministrator","AuthenticationAdministrator","HelpdeskAdministrator",
    "ExchangeAdministrator","SharePointAdministrator","BillingAdministrator"
)

function New-CapTokenCache {
    return @{
        Groups         = @{}
        Users          = @{}
        NamedLocations = $null   # lazy: full list, keyed by DisplayName once loaded
        AuthStrengths  = $null   # lazy: full list, keyed by DisplayName once loaded
    }
}

function Get-CapGroupId {
    param([Parameter(Mandatory)][string]$ConfigKey, [Parameter(Mandatory)]$Config, [Parameter(Mandatory)][hashtable]$Cache)

    if ($Cache.Groups.ContainsKey($ConfigKey)) { return $Cache.Groups[$ConfigKey] }

    $displayName = [string]$Config.Groups.$ConfigKey
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        throw "CA baseline references Groups.$ConfigKey, which is not defined in config.json."
    }

    $group = Get-MgGroup -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $group) {
        throw "CA baseline references group '$displayName' (Groups.$ConfigKey), which does not exist yet. Run Deploy-Groups.ps1 first."
    }

    $Cache.Groups[$ConfigKey] = $group.Id
    return $group.Id
}

function Get-CapUserId {
    param([Parameter(Mandatory)][string]$ConfigKey, [Parameter(Mandatory)]$Config, [Parameter(Mandatory)][hashtable]$Cache)

    if ($Cache.Users.ContainsKey($ConfigKey)) { return $Cache.Users[$ConfigKey] }

    $upnPrefix = [string]$Config.Users.$ConfigKey
    if ([string]::IsNullOrWhiteSpace($upnPrefix)) {
        # Optional references (e.g. BreakGlassUpn2) may legitimately be unset.
        $Cache.Users[$ConfigKey] = $null
        return $null
    }

    $upn = "$upnPrefix@$($Config.TenantDomain)"
    $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
    if (-not $user) {
        throw "CA baseline references user '$upn' (Users.$ConfigKey), which does not exist yet. Run Deploy-Users.ps1 first."
    }

    $Cache.Users[$ConfigKey] = $user.Id
    return $user.Id
}

function Get-CapNamedLocationId {
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][hashtable]$Cache)

    if ($null -eq $Cache.NamedLocations) {
        $Cache.NamedLocations = @{}
        foreach ($loc in Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue) {
            $Cache.NamedLocations[$loc.DisplayName] = $loc.Id
        }
    }

    if (-not $Cache.NamedLocations.ContainsKey($DisplayName)) {
        throw "CA baseline references named location '$DisplayName', which does not exist yet. Run Deploy-NamedLocations.ps1 first."
    }
    return $Cache.NamedLocations[$DisplayName]
}

function Get-CapAuthStrengthId {
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][hashtable]$Cache)

    if ($null -eq $Cache.AuthStrengths) {
        $Cache.AuthStrengths = @{}
        $all = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies"
        foreach ($s in $all.value) { $Cache.AuthStrengths[$s.displayName] = $s.id }
    }

    if (-not $Cache.AuthStrengths.ContainsKey($DisplayName)) {
        throw "CA baseline references authentication strength '$DisplayName', which does not exist yet. Run Deploy-AuthStrengths.ps1 first."
    }
    return $Cache.AuthStrengths[$DisplayName]
}

function Get-CapRoleTemplateId {
    param([Parameter(Mandatory)][string]$RoleKey)

    if ($RoleKey -eq "AllPrivilegedRoles") {
        return @($script:CapAllPrivilegedRoleKeys | ForEach-Object { $script:CapRoleTemplateIds[$_] })
    }
    if (-not $script:CapRoleTemplateIds.ContainsKey($RoleKey)) {
        throw "Unknown role token '{{Role:$RoleKey}}'. Known roles: $($script:CapRoleTemplateIds.Keys -join ', '), AllPrivilegedRoles."
    }
    return $script:CapRoleTemplateIds[$RoleKey]
}

function Resolve-CapValue {
    param($Value, [Parameter(Mandatory)]$Config, [Parameter(Mandatory)][hashtable]$Cache, [Parameter(Mandatory)][string]$DesiredState)

    if ($Value -isnot [string]) { return $Value }

    if ($Value -eq "{{DesiredState}}") { return $DesiredState }

    if ($Value -match '^\{\{Group:(.+)\}\}$')         { return Get-CapGroupId -ConfigKey $Matches[1] -Config $Config -Cache $Cache }
    if ($Value -match '^\{\{User:(.+)\}\}$')          { return Get-CapUserId -ConfigKey $Matches[1] -Config $Config -Cache $Cache }
    if ($Value -match '^\{\{NamedLocation:(.+)\}\}$') { return Get-CapNamedLocationId -DisplayName $Matches[1] -Cache $Cache }
    if ($Value -match '^\{\{AuthStrength:(.+)\}\}$')  { return Get-CapAuthStrengthId -DisplayName $Matches[1] -Cache $Cache }
    if ($Value -match '^\{\{Role:(.+)\}\}$')          { return Get-CapRoleTemplateId -RoleKey $Matches[1] }

    return $Value
}

function Resolve-CapTokensDeep {
    param($InputObject, [Parameter(Mandatory)]$Config, [Parameter(Mandatory)][hashtable]$Cache, [Parameter(Mandatory)][string]$DesiredState)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        $resolved = Resolve-CapValue -Value $InputObject -Config $Config -Cache $Cache -DesiredState $DesiredState
        return $resolved
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($entry in $InputObject.GetEnumerator()) {
            $result[$entry.Key] = Resolve-CapTokensDeep -InputObject $entry.Value -Config $Config -Cache $Cache -DesiredState $DesiredState
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $InputObject) {
            $resolvedItem = Resolve-CapTokensDeep -InputObject $item -Config $Config -Cache $Cache -DesiredState $DesiredState
            # {{Role:AllPrivilegedRoles}} expands one token into many array entries.
            if ($resolvedItem -is [array]) { $items += $resolvedItem } else { $items += ,$resolvedItem }
        }
        return ,$items
    }

    return $InputObject
}

function ConvertTo-CapHashtableDeep {
    param([Parameter(ValueFromPipeline)]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) { $result[$key] = ConvertTo-CapHashtableDeep -InputObject $InputObject[$key] }
        return $result
    }

    if ($InputObject -is [pscustomobject]) {
        $result = @{}
        foreach ($prop in $InputObject.PSObject.Properties) { $result[$prop.Name] = ConvertTo-CapHashtableDeep -InputObject $prop.Value }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) { $items += ,(ConvertTo-CapHashtableDeep -InputObject $item) }
        return ,$items
    }

    return $InputObject
}

function New-OrUpdateCapPolicy {
    param(
        [Parameter(Mandatory)][hashtable]$PolicyDefinition,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][hashtable]$Cache,
        [Parameter(Mandatory)][string]$DesiredState
    )

    $resolved = Resolve-CapTokensDeep -InputObject $PolicyDefinition -Config $Config -Cache $Cache -DesiredState $DesiredState
    $displayName = [string]$resolved.displayName
    $resolved.Remove("description") # informational only in the JSON, not part of the Graph policy body beyond displayName/conditions/etc.

    $jsonBody = $resolved | ConvertTo-Json -Depth 50
    $existing = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1

    try {
        if ($existing) {
            Invoke-MgGraphRequest -Method PATCH `
                -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($existing.Id)" `
                -Body $jsonBody -ContentType "application/json" | Out-Null
            Write-Status "Updated policy: $displayName" -Type Success
            return [pscustomobject]@{ DisplayName = $displayName; Status = "Updated"; Reason = $null }
        }

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" `
            -Body $jsonBody -ContentType "application/json" | Out-Null
        Write-Status "Created policy: $displayName" -Type Success
        return [pscustomobject]@{ DisplayName = $displayName; Status = "Created"; Reason = $null }
    } catch {
        $errMsg = $_.ToString()
        if ($errMsg -match '1039') {
            Write-Status "Skipped (P2 license required): $displayName" -Type Warning
            return [pscustomobject]@{ DisplayName = $displayName; Status = "Skipped"; Reason = "P2 license required" }
        }
        Write-Status "Failed: $displayName — $errMsg" -Type Error
        return [pscustomobject]@{ DisplayName = $displayName; Status = "Failed"; Reason = $errMsg }
    }
}
