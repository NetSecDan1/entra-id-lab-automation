<#
.SYNOPSIS
    Generates realistic sign-in traffic to populate Entra ID sign-in logs and
    validate Conditional Access policy decisions.

.DESCRIPTION
    Uses the OAuth 2.0 ROPC flow to generate sign-in events with varied user
    agents, platforms, client types, timing, and outcomes. All calls hit the
    real Microsoft identity platform token endpoint so events appear in
    Entra > Monitoring > Sign-in logs with full CA decision details.

    CA policies in report-only mode will show "would have required / blocked"
    results in the Conditional Access column — perfect for baseline validation.

    Platform scenarios
    ------------------
    Windows        IE11, Edge, Chrome, Firefox on Windows 10/11
    MacOS          Safari, Chrome, Firefox on macOS 14 Sonoma
    iOS            Safari, Outlook, Teams, Edge on iPhone/iPad
    Android        Chrome, Outlook, Teams, Samsung Browser on Android 14

    Behaviour scenarios
    -------------------
    Normal         Modern browser sign-ins — mixed platform
    Mobile         iOS and Android Outlook/browser
    LegacyAuth     Old Outlook, EAS, MAPI, Thunderbird, IMAP
                   → CA002 (Block Legacy Auth) flags these
    FailedLogins   Wrong password → failed events and risk signals
    AdminAccess    Admin-tier and C-suite sign-ins → CA100/101/105
    ServiceAccounts svc-* daemon sign-ins → CA300/301
    Automation     PowerShell, Python, curl
    Suspicious     Headless browsers, bots, rapid succession

.PARAMETER Scenarios
    Which scenarios to run. Default = All.
    Platform shortcuts: Windows, MacOS, iOS, Android
    Use AllPlatforms to run all four platform scenarios.

.PARAMETER UserCount
    Max users sampled per scenario per run. Default = 8.

.PARAMETER BulkRuns
    Number of times to repeat the selected scenarios. Default = 1.
    Use with -DelayMs 0 for maximum volume.

.PARAMETER DelayMs
    Milliseconds between individual sign-in calls (sequential mode).
    Default = 1500. Set to 0 for bulk/stress runs.

.PARAMETER Parallel
    Run users within each scenario concurrently (requires PowerShell 7+).
    Falls back to sequential on PS 5.1.

.PARAMETER ThrottleLimit
    Max concurrent threads when -Parallel is set. Default = 8.

.PARAMETER QueryLogsAfter
    After simulation, query Entra sign-in logs and display CA decisions.
    Requires AuditLog.Read.All permission on the connected account.

.PARAMETER SaveResults
    Write a JSON result file to .\logs\simulation-<timestamp>.json

.PARAMETER DryRun
    Print what would be called without making any network requests.

.EXAMPLE
    # Full simulation — all scenarios
    .\Simulation\Invoke-SignInSimulation.ps1 -QueryLogsAfter

    # Bulk iOS + Android test — 5 rounds, parallel, 20 users each
    .\Simulation\Invoke-SignInSimulation.ps1 -Scenarios iOS,Android -BulkRuns 5 -UserCount 20 -Parallel

    # All four platform scenarios in parallel
    .\Simulation\Invoke-SignInSimulation.ps1 -Scenarios AllPlatforms -Parallel -QueryLogsAfter

    # Legacy auth only — confirm CA002 blocks it
    .\Simulation\Invoke-SignInSimulation.ps1 -Scenarios LegacyAuth -QueryLogsAfter

    # Max volume stress run
    .\Simulation\Invoke-SignInSimulation.ps1 -Scenarios AllPlatforms,Normal -BulkRuns 10 -UserCount 30 -DelayMs 0 -Parallel -SaveResults
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json",

    [ValidateSet("All","AllPlatforms",
                 "Windows","MacOS","iOS","Android",
                 "Normal","Mobile","LegacyAuth","FailedLogins",
                 "AdminAccess","ServiceAccounts","Automation","Suspicious")]
    [string[]]$Scenarios = @("All"),

    [int]   $UserCount     = 8,
    [int]   $BulkRuns      = 1,
    [int]   $DelayMs       = 1500,
    [int]   $ThrottleLimit = 8,
    [switch]$Parallel,
    [switch]$QueryLogsAfter,
    [switch]$SaveResults,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config   = Get-Config -ConfigPath $ConfigPath
$domain   = $config.TenantDomain
$tenantId = $domain

$resolvedPassword = Resolve-SecretValue -Config $config -PropertyName "DefaultPassword" `
    -CurrentValue ([string]$config.DefaultPassword)

# ── User-agent library ────────────────────────────────────────────────────────
$UA = @{

    # ── Windows ──────────────────────────────────────────────────────────────
    ChromeWin      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    EdgeWin        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51"
    FirefoxWin     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
    IE11           = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
    EdgeLegacy     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19044"
    OutlookWin365  = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17531; Pro)"
    OneDriveWin    = "Microsoft SkyDriveSync 24.011.0121.0001 ship; Windows NT 10.0 (17763)"
    TeamsWin       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.7.0.21268 Chrome/116.0.5845.228 Electron/28.2.10 Safari/537.36"

    # ── macOS ─────────────────────────────────────────────────────────────────
    SafariMac      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
    ChromeMac      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    FirefoxMac     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0"
    EdgeMac        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51"
    OutlookMac     = "Microsoft Outlook/16.85.3 (24031620) for Mac"
    TeamsMac       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.7.0.21268 Chrome/116.0.5845.228 Electron/28.2.10 Safari/537.36"

    # ── iOS ───────────────────────────────────────────────────────────────────
    SafariIOS      = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
    SafariIPad     = "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
    OutlookIOS     = "Microsoft Outlook/4.2403.0 iOS/17.4.1"
    TeamsIOS       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) TeamsRNApp/1.0.0 Safari/604.1"
    EdgeIOS        = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 EdgiOS/124.0.2478.50 Mobile/15E148 Safari/604.1"
    AuthenticatorIOS = "Microsoft Authenticator/6.8.12 iOS/17.4.1"
    EASiPhone      = "Apple-iPhone14C3/2107.1.0.0.1"

    # ── Android ───────────────────────────────────────────────────────────────
    ChromeAndroid  = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36"
    OutlookAndroid = "Outlook-Android/2.0 com.microsoft.office.outlook/4.2403.0"
    TeamsAndroid   = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36 Teams/1416/1.0.0.2024041807"
    EdgeAndroid    = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36 EdgA/124.0.2478.50"
    SamsungBrowser = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36"
    EASAndroid     = "android-mail/6.5 (samsung SM-S918B; Android 14; en)"
    AuthenticatorAndroid = "Microsoft Authenticator/6.8.12 Android/14"

    # ── Legacy / basic auth ───────────────────────────────────────────────────
    Outlook2013    = "Microsoft Office/15.0 (Windows NT 6.1; Trident/7.0; Microsoft Outlook 15.0.5085; Pro)"
    Outlook2010    = "Microsoft Office/14.0 (Windows NT 6.1; Trident/6.0)"
    Thunderbird    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Thunderbird/102.15.1"
    IMAPClient     = "Mutt/2.2.9 (2022-11-12)"
    BasicAuthOther = "Microsoft Data Access Components"

    # ── Automation / scripting ────────────────────────────────────────────────
    PowerShell     = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.2506"
    PythonRequests = "python-requests/2.31.0"
    Curl           = "curl/8.6.0"
    GoHttp         = "Go-http-client/1.1"

    # ── Suspicious / headless ─────────────────────────────────────────────────
    HeadlessChrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36"
    Wget           = "Wget/1.21.4"
    Scrapy         = "Scrapy/2.11.0 (+https://scrapy.org)"
    CustomBot      = "EntraBot/1.0 (+internal)"
}

# ── Core sign-in function ─────────────────────────────────────────────────────
function Invoke-SignIn {
    param(
        [string]$Upn,
        [string]$Password,
        [string]$ClientId,
        [string]$TenantId,
        [string]$UserAgent,
        [string]$Scope    = "openid profile User.Read offline_access",
        [string]$Category = "Normal",
        [bool]  $DryRun   = $false
    )

    $result = [PSCustomObject]@{
        Timestamp   = (Get-Date -Format "HH:mm:ss")
        Category    = $Category
        Upn         = $Upn
        UserAgent   = $UserAgent.Substring(0, [Math]::Min(60, $UserAgent.Length)) + "..."
        Success     = $false
        Error       = ""
        TokenClaims = $null
    }

    if ($DryRun) {
        $result.Success = $true
        $result.Error   = "[DRY RUN]"
        return $result
    }

    $body = "grant_type=password&client_id=$ClientId" +
            "&username=$([Uri]::EscapeDataString($Upn))" +
            "&password=$([Uri]::EscapeDataString($Password))" +
            "&scope=$([Uri]::EscapeDataString($Scope))"

    $headers = @{
        "User-Agent"      = $UserAgent
        "Accept"          = "application/json"
        "Accept-Language" = "en-US,en;q=0.9"
        "Content-Type"    = "application/x-www-form-urlencoded"
        "x-client-SKU"    = "MSAL.Desktop"
        "x-client-Ver"    = "4.61.3"
        "x-client-OS"     = "10.0.22631"
        "client_info"     = "1"
    }

    # Strip MSAL headers to simulate dumb/legacy clients
    if ($Category -in @("LegacyAuth","Suspicious")) {
        "x-client-SKU","x-client-Ver","x-client-OS","client_info" | ForEach-Object { $headers.Remove($_) }
    }

    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    try {
        $resp           = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body -ErrorAction Stop
        $result.Success = $true

        if ($resp.id_token) {
            $parts = $resp.id_token -split '\.'
            $pad   = 4 - ($parts[1].Length % 4); if ($pad -eq 4) { $pad = 0 }
            $b64   = ($parts[1] -replace '-','+' -replace '_','/') + ('=' * $pad)
            try {
                $result.TokenClaims = [System.Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String($b64)) | ConvertFrom-Json
            } catch { }
        }
    } catch {
        $result.Success = $false
        try {
            $errBody    = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            $result.Error = if ($errBody.error) {
                "$($errBody.error): $($errBody.error_codes -join ',')"
            } else { $_.Exception.Message }
        } catch { $result.Error = $_.Exception.Message }
    }

    return $result
}

# ── Setup ─────────────────────────────────────────────────────────────────────
Write-Status "Sign-in Simulation Engine" -Type Header
Write-Host "  Tenant        : $domain"
Write-Host "  Scenarios     : $($Scenarios -join ', ')"
Write-Host "  Users/scenario: $UserCount"
Write-Host "  Bulk runs     : $BulkRuns"
$parallelSupported = $PSVersionTable.PSVersion.Major -ge 7
if ($Parallel) {
    if ($parallelSupported) {
        Write-Host "  Mode          : PARALLEL (ThrottleLimit=$ThrottleLimit)" -ForegroundColor Cyan
    } else {
        Write-Host "  Mode          : Sequential (PS7+ required for -Parallel, got PS$($PSVersionTable.PSVersion.Major))" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Mode          : Sequential (DelayMs=$DelayMs)"
}
if ($DryRun) { Write-Host "  *** DRY RUN — no actual requests ***" -ForegroundColor Yellow }
Write-Host ""

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

$simStartTime = Get-Date

# ── Resolve simulation app ────────────────────────────────────────────────────
Write-Status "Simulation app (SimLogin-PublicClient)" -Type Header
$simAppName = "SimLogin-PublicClient"
$simApp = Get-MgApplication -Filter "displayName eq '$simAppName'" -ErrorAction SilentlyContinue
if (-not $simApp) {
    Write-Status "SimLogin-PublicClient not found — run '.\Setup-TestTenant.ps1 -Steps Apps' first." -Type Warning
    Write-Host "  Auto-creating for this session..." -ForegroundColor Yellow
    $simApp = New-MgApplication -BodyParameter @{
        displayName            = $simAppName
        signInAudience         = "AzureADMyOrg"
        isFallbackPublicClient = $true
        publicClient           = @{ redirectUris = @("https://login.microsoftonline.com/common/oauth2/nativeclient") }
        requiredResourceAccess = @(@{
            resourceAppId  = "00000003-0000-0000-c000-000000000000"
            resourceAccess = @(
                @{ id = "37f7f235-527c-4136-accd-4a02d197296e"; type = "Scope" }
                @{ id = "14dad69e-099b-42c9-810b-d002981feec1"; type = "Scope" }
                @{ id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; type = "Scope" }
                @{ id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"; type = "Scope" }
            )
        })
    }
    New-MgServicePrincipal -AppId $simApp.AppId | Out-Null
    Write-Status "Created: $simAppName ($($simApp.AppId))" -Type Success
    Write-Host "  Waiting 15s for AAD replication..." -ForegroundColor Yellow
    if (-not $DryRun) { Start-Sleep -Seconds 15 }
} else {
    Write-Status "Ready: $simAppName ($($simApp.AppId))" -Type Success
}
$clientId = $simApp.AppId

# ── Load users ────────────────────────────────────────────────────────────────
Write-Status "Loading tenant users" -Type Header
$allEmployees = Get-AllEmployeeUsers -CompanyName $config.CompanyName |
    Where-Object { $_.UserPrincipalName -notlike "admin.*" }

$regularUsers = @($allEmployees | Where-Object { $_.JobTitle -notmatch "^Chief " })
$execUsers    = @($allEmployees | Where-Object { $_.JobTitle -match "^Chief " })
$svcUsers     = @(Get-MgUser -All -Filter "companyName eq '$($config.CompanyName)'" `
    -Property "id,userPrincipalName,displayName,jobTitle" |
    Where-Object { $_.UserPrincipalName -like "svc-*@*" })
$adminUsers   = @(
    (Get-MgUser -Filter "userPrincipalName eq 'admin.svc01@$domain'" -ErrorAction SilentlyContinue),
    (Get-MgUser -Filter "userPrincipalName eq 'admin.svc02@$domain'" -ErrorAction SilentlyContinue),
    (Get-MgUser -Filter "userPrincipalName eq 'admin.sec01@$domain'" -ErrorAction SilentlyContinue)
) | Where-Object { $_ }

Write-Host "  Regular employees : $($regularUsers.Count)"
Write-Host "  Executives        : $($execUsers.Count)"
Write-Host "  Service accounts  : $($svcUsers.Count)"
Write-Host "  Admin accounts    : $($adminUsers.Count)"
Write-Host ""

# ── Scenario definitions ──────────────────────────────────────────────────────
$scenarioMap = @{

    # Platform scenarios
    Windows = @{
        Description = "Windows 10/11 — Edge, Chrome, Firefox, IE11, Outlook, Teams"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.ChromeWin, $UA.EdgeWin, $UA.FirefoxWin, $UA.IE11,
                        $UA.EdgeLegacy, $UA.OutlookWin365, $UA.TeamsWin)
        Password    = $resolvedPassword
        Category    = "Windows"
    }

    MacOS = @{
        Description = "macOS 14 Sonoma — Safari, Chrome, Firefox, Edge, Outlook, Teams"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.SafariMac, $UA.ChromeMac, $UA.FirefoxMac, $UA.EdgeMac,
                        $UA.OutlookMac, $UA.TeamsMac)
        Password    = $resolvedPassword
        Category    = "MacOS"
    }

    iOS = @{
        Description = "iOS 17 — Safari, Outlook, Teams, Edge, Authenticator on iPhone/iPad"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.SafariIOS, $UA.SafariIPad, $UA.OutlookIOS, $UA.TeamsIOS,
                        $UA.EdgeIOS, $UA.AuthenticatorIOS)
        Password    = $resolvedPassword
        Category    = "iOS"
    }

    Android = @{
        Description = "Android 14 — Chrome, Outlook, Teams, Edge, Samsung Browser, Authenticator"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.ChromeAndroid, $UA.OutlookAndroid, $UA.TeamsAndroid,
                        $UA.EdgeAndroid, $UA.SamsungBrowser, $UA.AuthenticatorAndroid)
        Password    = $resolvedPassword
        Category    = "Android"
    }

    # Behaviour scenarios
    Normal = @{
        Description = "Modern browser sign-ins — mixed platform work day pattern"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.ChromeWin, $UA.EdgeWin, $UA.FirefoxWin, $UA.SafariMac, $UA.ChromeMac)
        Password    = $resolvedPassword
        Category    = "Normal"
    }

    Mobile = @{
        Description = "iOS and Android — Outlook, browser, Teams"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.SafariIOS, $UA.OutlookIOS, $UA.ChromeAndroid,
                        $UA.OutlookAndroid, $UA.TeamsIOS, $UA.TeamsAndroid)
        Password    = $resolvedPassword
        Category    = "Mobile"
    }

    LegacyAuth = @{
        Description = "Legacy auth — Outlook 2010/2013, EAS, Thunderbird, IMAP → CA002 should flag"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.Outlook2013, $UA.Outlook2010, $UA.EASiPhone,
                        $UA.EASAndroid, $UA.Thunderbird, $UA.IMAPClient, $UA.BasicAuthOther)
        Password    = $resolvedPassword
        Category    = "LegacyAuth"
    }

    FailedLogins = @{
        Description = "Failed authentications — wrong password, generates risk events"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.ChromeWin, $UA.FirefoxWin, $UA.SafariMac, $UA.SafariIOS, $UA.ChromeAndroid)
        Password    = "WrongP@ssword!$(Get-Random -Minimum 100 -Maximum 999)"
        Category    = "FailedLogin"
    }

    AdminAccess = @{
        Description = "Admin and executive sign-ins — CA100/101/105 should trigger"
        Users       = {
            $pool = @($adminUsers) + @($execUsers)
            $pool | Get-Random -Count ([Math]::Min($UserCount, $pool.Count))
        }
        Agents      = @($UA.EdgeWin, $UA.ChromeWin, $UA.SafariMac, $UA.ChromeMac)
        Password    = $resolvedPassword
        Category    = "AdminAccess"
    }

    ServiceAccounts = @{
        Description = "Service account ROPC sign-ins — CA300/301 should apply"
        Users       = { $svcUsers | Get-Random -Count ([Math]::Min($UserCount, $svcUsers.Count)) }
        Agents      = @($UA.PowerShell, $UA.PythonRequests, $UA.GoHttp)
        Password    = $resolvedPassword
        Category    = "ServiceAccount"
    }

    Automation = @{
        Description = "Scripting clients — PowerShell, Python, curl"
        Users       = { $regularUsers | Get-Random -Count $UserCount }
        Agents      = @($UA.PowerShell, $UA.PythonRequests, $UA.Curl, $UA.GoHttp)
        Password    = $resolvedPassword
        Category    = "Automation"
    }

    Suspicious = @{
        Description = "Unusual patterns — headless browsers, bots, rapid succession"
        Users       = { $regularUsers | Get-Random -Count ([Math]::Min(5, $UserCount)) }
        Agents      = @($UA.HeadlessChrome, $UA.Wget, $UA.Scrapy, $UA.CustomBot)
        Password    = $resolvedPassword
        Category    = "Suspicious"
    }
}

# ── Resolve scenario list ─────────────────────────────────────────────────────
$platformScenarios   = @("Windows","MacOS","iOS","Android")
$behaviourScenarios  = @("Normal","Mobile","LegacyAuth","FailedLogins","AdminAccess","ServiceAccounts","Automation","Suspicious")

$runScenarios = if ($Scenarios -contains "All") {
    $scenarioMap.Keys
} elseif ($Scenarios -contains "AllPlatforms") {
    $platformScenarios + ($Scenarios | Where-Object { $_ -notin @("All","AllPlatforms") })
} else {
    $Scenarios
}
$runScenarios = @($runScenarios | Select-Object -Unique)

$allResults = [System.Collections.Generic.List[object]]::new()

# ── Run scenarios (with BulkRuns loop) ───────────────────────────────────────
for ($run = 1; $run -le $BulkRuns; $run++) {

    if ($BulkRuns -gt 1) {
        Write-Host ""
        Write-Status "━━━ Run $run / $BulkRuns ━━━" -Type Header
    }

    foreach ($scenarioName in $runScenarios) {
        if (-not $scenarioMap.ContainsKey($scenarioName)) { continue }
        $s = $scenarioMap[$scenarioName]

        Write-Host ""
        Write-Status "[$scenarioName] $($s.Description)" -Type Header

        $targetUsers = @(& $s.Users)
        if (-not $targetUsers -or $targetUsers.Count -eq 0) {
            Write-Status "No users available for $scenarioName — skipping." -Type Warning
            continue
        }

        $agentList = $s.Agents
        $password  = if ($s.Password -is [scriptblock]) { & $s.Password } else { [string]$s.Password }
        $category  = $s.Category

        # ── Parallel execution (PS7+) ─────────────────────────────────────
        if ($Parallel -and $parallelSupported -and -not $DryRun) {

            $parallelResults = $targetUsers | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $user      = $_
                $agent     = ($using:agentList) | Get-Random
                $pw        = $using:password
                $cid       = $using:clientId
                $tid       = $using:tenantId
                $cat       = $using:category
                $scope     = "openid profile User.Read offline_access"

                $body    = "grant_type=password&client_id=$cid" +
                           "&username=$([Uri]::EscapeDataString($user.UserPrincipalName))" +
                           "&password=$([Uri]::EscapeDataString($pw))" +
                           "&scope=$([Uri]::EscapeDataString($scope))"
                $headers = @{
                    "User-Agent"      = $agent
                    "Accept"          = "application/json"
                    "Content-Type"    = "application/x-www-form-urlencoded"
                    "x-client-SKU"    = "MSAL.Desktop"
                    "x-client-Ver"    = "4.61.3"
                    "x-client-OS"     = "10.0.22631"
                    "client_info"     = "1"
                }
                if ($cat -in @("LegacyAuth","Suspicious")) {
                    "x-client-SKU","x-client-Ver","x-client-OS","client_info" | ForEach-Object { $headers.Remove($_) }
                }

                $r = [PSCustomObject]@{
                    Timestamp = (Get-Date -Format "HH:mm:ss")
                    Category  = $cat
                    Upn       = $user.UserPrincipalName
                    UserAgent = $agent.Substring(0, [Math]::Min(60, $agent.Length)) + "..."
                    Success   = $false
                    Error     = ""
                }
                try {
                    Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                        -Method POST -Headers $headers -Body $body -ErrorAction Stop | Out-Null
                    $r.Success = $true
                } catch {
                    try {
                        $eb = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        $r.Error = if ($eb.error) { "$($eb.error): $($eb.error_codes -join ',')" } else { $_.Exception.Message }
                    } catch { $r.Error = $_.Exception.Message }
                }
                $r
            }

            foreach ($r in $parallelResults) {
                $color = if ($r.Success) { "Green" } else { "Red" }
                $icon  = if ($r.Success) { "OK " } else { "ERR" }
                Write-Host ("  [{0}] {1,-42} | {2}" -f $icon, $r.Upn, $r.UserAgent) -ForegroundColor $color
                if (-not $r.Success -and $r.Error) {
                    Write-Host ("       $($r.Error)") -ForegroundColor DarkRed
                }
                $allResults.Add($r)
            }

        # ── Sequential execution ──────────────────────────────────────────
        } else {
            foreach ($user in $targetUsers) {
                $agent = $agentList | Get-Random

                if ($DryRun) {
                    Write-Host ("  [DRY] {0,-42} | {1}..." -f $user.UserPrincipalName, $agent.Substring(0,50))
                }

                $r = Invoke-SignIn -Upn $user.UserPrincipalName -Password $password `
                    -ClientId $clientId -TenantId $tenantId -UserAgent $agent `
                    -Category $category -DryRun:$DryRun

                $color = if ($r.Success) { "Green" } else { "Red" }
                $icon  = if ($r.Success) { "OK " } else { "ERR" }
                Write-Host ("  [{0}] {1,-42} | {2}" -f $icon, $r.Upn, $r.UserAgent) -ForegroundColor $color
                if (-not $r.Success -and $r.Error) {
                    Write-Host ("       $($r.Error)") -ForegroundColor DarkRed
                }
                $allResults.Add($r)

                $delayOverride = if ($scenarioName -eq "Suspicious") { 200 } else { $DelayMs }
                if ($delayOverride -gt 0 -and -not $DryRun) { Start-Sleep -Milliseconds $delayOverride }
            }
        }

        Write-Host ("  [{0}] {1} attempts fired" -f $scenarioName, $targetUsers.Count) -ForegroundColor DarkGray
    }
}

# ── Query sign-in logs ────────────────────────────────────────────────────────
if ($QueryLogsAfter -and -not $DryRun) {
    Write-Host ""
    Write-Status "Querying sign-in logs (since simulation start)" -Type Header
    Write-Host "  Waiting 60s for log propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 60

    try {
        $cutoff  = $simStartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signIns = Get-MgAuditLogSignIn `
            -Filter "createdDateTime ge $cutoff and appId eq '$clientId'" `
            -Top 200 -ErrorAction Stop

        Write-Host ""
        Write-Host ("  {0,-42} {1,-10} {2,-14} {3,-20} {4}" -f "UPN","Status","CA Result","Platform","Client App") -ForegroundColor Cyan
        Write-Host ("  " + ("-" * 115)) -ForegroundColor DarkGray

        foreach ($si in $signIns | Sort-Object CreatedDateTime) {
            $caStatus   = if ($si.ConditionalAccessStatus) { $si.ConditionalAccessStatus } else { "notApplied" }
            $caColor    = switch ($caStatus) {
                "success"    { "Green"   }
                "failure"    { "Red"     }
                "notApplied" { "DarkGray"}
                default      { "Yellow"  }
            }
            $ok    = $si.Status.ErrorCode -eq 0
            $icon  = if ($ok) { "OK " } else { "ERR" }
            $color = if ($ok) { "Green" } else { "Red" }
            $os    = if ($si.DeviceDetail.OperatingSystem) { $si.DeviceDetail.OperatingSystem } else { "-" }

            Write-Host ("  [{0}] {1,-40} {2,-10}" -f $icon, $si.UserPrincipalName, $caStatus) `
                -ForegroundColor $color -NoNewline
            Write-Host (" {0,-20} {1}" -f $os, $si.ClientAppUsed) -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host "  Total sign-in events : $($signIns.Count)" -ForegroundColor Cyan

        # CA decision breakdown
        $caGroups = $signIns | Group-Object ConditionalAccessStatus | Sort-Object Name
        foreach ($g in $caGroups) {
            Write-Host ("  CA [{0,-14}] : {1}" -f $g.Name, $g.Count) -ForegroundColor $(
                if ($g.Name -eq "success") { "Green" } elseif ($g.Name -eq "failure") { "Red" } else { "DarkGray" })
        }

        Write-Host ""
        Write-Host "  Full details: Entra portal > Monitoring > Sign-in logs" -ForegroundColor DarkGray
        Write-Host "  Filter by: App = 'SimLogin-PublicClient'" -ForegroundColor DarkGray
    } catch {
        Write-Status "Could not query sign-in logs (needs AuditLog.Read.All): $_" -Type Warning
    }
}

# ── Save results ──────────────────────────────────────────────────────────────
if ($SaveResults -and -not $DryRun) {
    $logRoot = Join-Path $PSScriptRoot "..\logs"
    if (-not (Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot | Out-Null }
    $logPath = Join-Path $logRoot ("simulation-{0:yyyyMMdd-HHmmss}.json" -f $simStartTime)
    $allResults | Select-Object Timestamp, Category, Upn, UserAgent, Success, Error |
        ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath -Encoding UTF8
    Write-Status "Results saved: $logPath" -Type Success
}

# ── Summary ───────────────────────────────────────────────────────────────────
$elapsed   = [int]((Get-Date) - $simStartTime).TotalSeconds
$succeeded = @($allResults | Where-Object { $_.Success }).Count
$failed    = @($allResults | Where-Object { -not $_.Success }).Count

Write-Host ""
Write-Status "━━━ Simulation Summary (${elapsed}s | $BulkRuns run(s)) ━━━" -Type Header
Write-Host ("  Total attempts : {0}"   -f $allResults.Count)
Write-Host ("  Succeeded      : {0}"   -f $succeeded) -ForegroundColor Green
Write-Host ("  Failed/blocked : {0}"   -f $failed)   -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host ""

$byCategory = $allResults | Group-Object Category | Sort-Object Name
foreach ($grp in $byCategory) {
    $ok  = @($grp.Group | Where-Object { $_.Success }).Count
    $err = @($grp.Group | Where-Object { -not $_.Success }).Count
    $bar = "#" * [Math]::Min(40, $ok)
    Write-Host ("  {0,-16} : {1,3} ok  {2,3} failed  {3}" -f $grp.Name, $ok, $err, $bar)
}

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Entra portal → Monitoring → Sign-in logs" -ForegroundColor DarkGray
Write-Host "    2. Filter by App = 'SimLogin-PublicClient'" -ForegroundColor DarkGray
Write-Host "    3. Click any event → Conditional Access tab → see per-policy decisions" -ForegroundColor DarkGray
Write-Host "    4. LegacyAuth events: CA002 should show 'Report-only: Block'" -ForegroundColor DarkGray
Write-Host "    5. AdminAccess events: CA100/101/105 should show MFA required" -ForegroundColor DarkGray
Write-Host "    6. iOS/Android/Windows events: check device compliance policies" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  To enforce and re-run:" -ForegroundColor Cyan
Write-Host '    Set config.CABaseline.PolicyState = "enabled", run Deploy-CAPs.ps1' -ForegroundColor DarkGray
Write-Host "    Then re-run — LegacyAuth returns AADSTS53003, untrusted locations blocked" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
