# Helpers/Common.ps1 - Shared functions for Entra test tenant setup scripts

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Header")]
        [string]$Type = "Info"
    )
    $colors  = @{ Info="Cyan"; Success="Green"; Warning="Yellow"; Error="Red"; Header="Magenta" }
    $prefix  = @{ Info="[*]"; Success="[+]"; Warning="[!]"; Error="[-]"; Header="[===]" }
    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Get-Config {
    param([string]$ConfigPath = "$PSScriptRoot\..\config\config.json")
    if (-not (Test-Path $ConfigPath)) { throw "Config not found: $ConfigPath" }
    return Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

function Resolve-SecretValue {
    param(
        [Parameter(Mandatory)]
        [psobject]$Config,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [Parameter(Mandatory)]
        [string]$CurrentValue
    )
    # For a test tenant: use env var override if set, otherwise use config value as-is.
    $envVarName = "ENTRA_LAB_DEFAULT_PASSWORD"
    $envValue = [Environment]::GetEnvironmentVariable($envVarName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        Write-Status "Using $PropertyName from environment variable $envVarName" -Type Info
        return $envValue
    }
    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        throw "$PropertyName is empty. Set it in config.json or export $envVarName."
    }
    return $CurrentValue
}

function Test-StrongPassword {
    param([string]$Password)

    if ([string]::IsNullOrWhiteSpace($Password)) { return $false }
    if ($Password.Length -lt 12) { return $false }

    $checks = @(
        $Password -match "[A-Z]",
        $Password -match "[a-z]",
        $Password -match "\d",
        $Password -match "[^A-Za-z0-9]"
    )

    return -not ($checks -contains $false)
}

function Test-IpCidr {
    param([string]$CidrAddress)
    return $CidrAddress -match '^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$'
}

function Test-TenantConfig {
    param([string]$ConfigPath = "$PSScriptRoot\..\config\config.json")

    $config = Get-Config -ConfigPath $ConfigPath
    $issues = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($config.TenantDomain) -or $config.TenantDomain -eq "YOURTENANT.onmicrosoft.com") {
        $issues.Add("TenantDomain must be set to your real onmicrosoft.com domain.")
    }

    if (-not $config.Users) {
        $issues.Add("Users configuration block is missing.")
    } else {
        if ($config.Users.TestUserCount -lt 1) {
            $issues.Add("Users.TestUserCount must be at least 1.")
        }

        if (-not $config.Users.Departments -or $config.Users.Departments.Count -lt 1) {
            $issues.Add("Users.Departments must include at least one department.")
        }
    }

    $resolvedPassword = $null
    try {
        $resolvedPassword = Resolve-SecretValue -Config $config -PropertyName "DefaultPassword" -CurrentValue ([string]$config.DefaultPassword)
    } catch {
        $issues.Add($_.Exception.Message)
    }

    # Password strength check skipped — test tenant, any non-empty password is accepted.

    if ($config.Auth) {
        if ($config.Auth.TAPLifetimeMinutes -lt 10 -or $config.Auth.TAPLifetimeMinutes -gt 480) {
            $issues.Add("Auth.TAPLifetimeMinutes must be between 10 and 480.")
        }
    }

    $validCapStates = @("enabledForReportingButNotEnforced", "enabled", "disabled")
    if ($config.CAP -and $validCapStates -notcontains [string]$config.CAP.State) {
        $issues.Add("CAP.State must be one of: $($validCapStates -join ', ').")
    }

    if ($config.CAP -and $config.CAP.TrustedIPRanges) {
        foreach ($range in $config.CAP.TrustedIPRanges) {
            if (-not (Test-IpCidr -CidrAddress ([string]$range.CidrAddress))) {
                $issues.Add("CAP trusted IP range '$($range.Name)' has an invalid CIDR address: $($range.CidrAddress)")
            }
            if ([string]$range.CidrAddress -eq "203.0.113.0/24") {
                $warnings.Add("Trusted IP range '$($range.Name)' still uses the documentation-only example network 203.0.113.0/24.")
            }
        }
    }

    return [PSCustomObject]@{
        Config           = $config
        ResolvedPassword = $resolvedPassword
        Issues           = @($issues)
        Warnings         = @($warnings)
        IsValid          = ($issues.Count -eq 0)
    }
}

function Get-SetupStepsFromMode {
    param(
        [string]$Mode = "Full",
        [string[]]$RequestedSteps = @()
    )

    if ($RequestedSteps -and $RequestedSteps.Count -gt 0) {
        return $RequestedSteps
    }

    switch ($Mode) {
        "Foundation"   { return @("Users", "Groups", "Directory") }
        "Security"     { return @("Directory", "Auth", "AuthStrengths", "NamedLocations", "CAPs") }
        "Applications" { return @("Apps", "Schema", "AuthStrengths") }
        "Identity"     { return @("Users", "Groups", "Auth", "AuthStrengths", "Directory") }
        "Governance"   { return @("PIM", "AdminUnits", "AccessReviews", "LifecycleWorkflows", "EntitlementManagement") }
        default        { return @("Users", "Groups", "NamedLocations", "CAPs", "Apps", "Schema", "Auth", "AuthStrengths",
                                  "Directory", "Licensing", "AdminUnits", "PIM", "AccessReviews", "LifecycleWorkflows",
                                  "EntitlementManagement", "TermsOfUse", "PasswordProtection", "CrossTenantAccess", "AuthContexts") }
    }
}

function Get-BestPracticeMessages {
    param([psobject]$Config)

    $messages = [System.Collections.Generic.List[string]]::new()

    $messages.Add("Run initial builds in report-only mode for Conditional Access before switching to enforced mode.")

    if ($Config.Directory -and $Config.Directory.AllowInvitesFrom -eq "everyone") {
        $messages.Add("Guest invitations are open to everyone. Consider adminsAndGuestInviters unless broad B2B testing is intentional.")
    }

    if ($Config.CAP -and $Config.CAP.State -eq "enabled") {
        $messages.Add("Conditional Access is set to enabled. Confirm exclusions and named locations before production-style enforcement.")
    }

    if ($Config.DefaultPassword -eq "P@ssw0rd1234!") {
        $messages.Add("The sample default password is still configured. Use an environment variable or prompt-driven secret before broad user creation.")
    }

    return @($messages)
}

function Start-SetupTranscript {
    param([psobject]$Config)

    $bestPractices = $Config.BestPractices
    $writeTranscript = $true
    if ($null -ne $bestPractices -and $null -ne $bestPractices.WriteTranscriptLogs) {
        $writeTranscript = [bool]$bestPractices.WriteTranscriptLogs
    }

    if (-not $writeTranscript) { return $null }

    $logRoot = Join-Path $PSScriptRoot "..\logs"
    if (-not (Test-Path $logRoot)) {
        New-Item -ItemType Directory -Path $logRoot | Out-Null
    }

    $logPath = Join-Path $logRoot ("tenant-build-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
    Start-Transcript -Path $logPath -Force | Out-Null
    Write-Status "Transcript logging: $logPath" -Type Info
    return $logPath
}

function Stop-SetupTranscriptSafe {
    try {
        Stop-Transcript | Out-Null
    } catch {
        # No active transcript
    }
}

function Ensure-GraphModules {
    param([string[]]$Modules = @("Microsoft.Graph"))
    foreach ($mod in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Status "Installing $mod ..." -Type Warning
            Install-Module $mod -Scope CurrentUser -Force -Repository PSGallery
        }
        # Do NOT bulk-import Microsoft.Graph — PowerShell auto-imports sub-modules on first use.
        # Importing the full bundle upfront loads all 40+ sub-modules and takes minutes.
    }
    Write-Status "Microsoft.Graph $((Get-Module -ListAvailable Microsoft.Graph | Select-Object -First 1).Version) ready" -Type Success
}

function Connect-TestTenant {
    # Use Az CLI token cache — run 'az login --use-device-code --tenant <domain>' once to seed it.
    $tenantDomain = (Get-Config).TenantDomain
    $tokenJson = az account get-access-token --resource https://graph.microsoft.com --tenant $tenantDomain 2>$null
    if ($tokenJson) {
        $token       = ($tokenJson | ConvertFrom-Json).accessToken
        $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
        Connect-MgGraph -AccessToken $secureToken -NoWelcome
        Write-Status "Connected via Az CLI token cache" -Type Success
    } else {
        Write-Status "Az CLI token not found — falling back to device code" -Type Warning
        Write-Status "Run once to seed the cache with your tenant domain using az login --use-device-code --tenant yourtenant.onmicrosoft.com" -Type Info
        $scopes = @(
            "User.ReadWrite.All","Group.ReadWrite.All","GroupMember.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess","Policy.ReadWrite.AuthenticationMethod",
            "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All",
            "Directory.ReadWrite.All","Organization.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory","UserAuthenticationMethod.ReadWrite.All",
            "EntitlementManagement.ReadWrite.All","AuditLog.Read.All",
            "IdentityRiskyUser.Read.All","IdentityRiskEvent.Read.All"
        )
        Connect-MgGraph -Scopes $scopes -NoWelcome -UseDeviceAuthentication
    }
    $ctx = Get-MgContext
    Write-Status "Connected: $($ctx.Account)  |  Tenant: $($ctx.TenantId)" -Type Success
}

# Create resource only if it doesn't already exist (by display name filter)
function Invoke-IdempotentCreate {
    param(
        [string]$ResourceType,   # e.g. "User", "Group"
        [string]$DisplayName,
        [scriptblock]$GetBlock,  # returns existing object or $null
        [scriptblock]$CreateBlock
    )
    $existing = & $GetBlock
    if ($existing) {
        Write-Status "$ResourceType already exists: $DisplayName" -Type Warning
        return $existing
    }
    $result = & $CreateBlock
    Write-Status "Created $ResourceType : $DisplayName" -Type Success
    return $result
}

function Add-GroupMemberSafe {
    param([string]$GroupId, [string]$UserId)
    $existing = Get-MgGroupMember -GroupId $GroupId -All |
        Where-Object { $_.Id -eq $UserId }
    if (-not $existing) {
        New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $UserId
    }
}

function Get-OrCreateDirectoryRole {
    param([string]$RoleName)
    $role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $role) {
        $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName } |
            Select-Object -First 1
        if (-not $template) { throw "Role template not found: $RoleName" }
        # Enable-MgDirectoryRole removed in SDK v2 — use REST directly
        $resp = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
            -Body (@{ roleTemplateId = $template.Id } | ConvertTo-Json) `
            -ContentType "application/json"
        $roleId = if ($resp -is [hashtable]) { $resp["id"] } else { $resp.id }
        Write-Status "Activated role '$RoleName' (id: $roleId)" -Type Info
        $role = [PSCustomObject]@{ Id = $roleId }
    }
    if (-not $role.Id) { throw "Could not resolve role ID for '$RoleName'" }
    return $role
}

function Assign-DirectoryRole {
    param([string]$RoleName, [string]$UserId)
    $role = Get-OrCreateDirectoryRole -RoleName $RoleName
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
    $memberIds = @($members | ForEach-Object { $_.Id })
    if ($memberIds -notcontains $UserId) {
        # New-MgDirectoryRoleMember removed in SDK v2 — use REST directly
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.Id)/members/`$ref" `
            -Body (@{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId" } | ConvertTo-Json) `
            -ContentType "application/json" | Out-Null
        Write-Status "Assigned '$RoleName' to user $UserId" -Type Success
    } else {
        Write-Status "User already has role '$RoleName'" -Type Warning
    }
}

function Get-BreakGlassUser {
    param([string]$Domain, [string]$Prefix)
    return Get-MgUser -Filter "userPrincipalName eq '$Prefix@$Domain'" -ErrorAction SilentlyContinue
}

# Returns all regular employees (excludes break glass, admin, service accounts).
# Used by Deploy-Groups.ps1 and Deploy-Licenses.ps1 to enumerate users by company
# instead of by UPN prefix pattern (compatible with firstname.lastname UPN format).
function Get-AllEmployeeUsers {
    param(
        [Parameter(Mandatory)]
        [string]$CompanyName,
        [string[]]$ExcludeUpnPrefixes = @("breakglass","testadmin","admin.","svc-","testblocked")
    )
    $excluded = $ExcludeUpnPrefixes
    $companyFilter = $CompanyName -replace "'", "''"   # OData: escape single quotes (e.g. "O'Brien's Lab")
    # companyName filtering requires advanced query params (ConsistencyLevel eventual + $count).
    return Get-MgUser -All -ConsistencyLevel eventual -CountVariable employeeCount `
        -Filter "companyName eq '$companyFilter' and accountEnabled eq true" `
        -Property "id,displayName,userPrincipalName,department,accountEnabled,city,jobTitle,mobilePhone" |
        Where-Object {
            $upn = $_.UserPrincipalName.ToLower()
            -not ($excluded | Where-Object { $upn.StartsWith($_.ToLower()) })
        }
}

# Returns the automation/integration service accounts (svc-* UPN prefix) for the company.
# These are user-object service accounts (non-human identities), distinct from app
# registrations / service principals.
function Get-ServiceAccountUsers {
    param(
        [Parameter(Mandatory)]
        [string]$CompanyName,
        [string]$UpnPrefix = "svc-"
    )
    $companyFilter = $CompanyName -replace "'", "''"
    return Get-MgUser -All -ConsistencyLevel eventual -CountVariable svcCount `
        -Filter "companyName eq '$companyFilter' and accountEnabled eq true" `
        -Property "id,displayName,userPrincipalName,jobTitle,accountEnabled" |
        Where-Object { $_.UserPrincipalName.ToLower().StartsWith($UpnPrefix.ToLower()) }
}
