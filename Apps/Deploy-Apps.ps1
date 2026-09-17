<#
.SYNOPSIS
    Registers enterprise app registrations and service principals.

.DESCRIPTION
    Creates (all idempotent):
      CorpPortal-WebApp           — confidential client (Auth Code + PKCE, OIDC)
      CorpPortal-MobileApp        — public SPA client (PKCE only, no secret)
      CorpOps-AutomationService   — client credentials daemon (app-only)
      ITSM-Connector              — daemon for IT Service Management integration
      CRM-DataBridge              — daemon for CRM identity sync
      HRIS-Integration            — daemon for HRIS provisioning
      DataPlatform-ReportingAgent — daemon for analytics/BI data access
      SimLogin-PublicClient       — public client for sign-in simulation (ROPC flow)

    For daemon apps: admin consent for User.Read.All is granted automatically.
    Client secrets are printed once — store them immediately.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$apps   = $config.Apps

# ── Well-known permission GUIDs (MS Graph) ────────────────────────────────────
$graphAppId         = "00000003-0000-0000-c000-000000000000"
$scopeOpenId        = "37f7f235-527c-4136-accd-4a02d197296e"
$scopeProfile       = "14dad69e-099b-42c9-810b-d002981feec1"
$scopeOfflineAccess = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
$scopeUserRead      = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"   # User.Read (delegated)
$roleUserReadAll    = "df021288-bdef-4463-88db-98f22de89214"   # User.Read.All (app)
$roleGroupReadAll   = "5b567255-7703-4780-807c-7be8301ae99b"   # Group.Read.All (app)
$roleDirectoryReadAll = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All (app)
$roleAuditLogReadAll  = "b0afded3-3588-46d8-8b3d-9842eff778da" # AuditLog.Read.All (app)

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-OrGetApp {
    param([string]$DisplayName)
    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) { Write-Status "Exists: $DisplayName" -Type Warning; return $existing }
    return $null
}

function Ensure-ServicePrincipal {
    param([string]$AppId)
    $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $AppId
        Write-Status "Created SP for appId $AppId" -Type Success
    }
    return $sp
}

function Grant-AppRoleConsent {
    param([string]$SpId, [string]$ResourceSpId, [string]$AppRoleId, [string]$AppName)
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpId -ErrorAction SilentlyContinue |
        Where-Object { $_.AppRoleId -eq $AppRoleId -and $_.ResourceId -eq $ResourceSpId }
    if ($existing) { Write-Status "Consent already granted: $AppName" -Type Warning; return }
    try {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpId `
            -PrincipalId $SpId -ResourceId $ResourceSpId -AppRoleId $AppRoleId | Out-Null
        Write-Status "Admin consent granted: $AppName" -Type Success
    } catch {
        Write-Status "Consent grant failed (needs AppRoleAssignment.ReadWrite.All scope): $_" -Type Warning
    }
}

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction SilentlyContinue

# ── 1. Corporate Portal — Web App (confidential client) ───────────────────────
Write-Status "CorpPortal-WebApp" -Type Header
$webApp = New-OrGetApp -DisplayName $apps.WebApp.Name
if (-not $webApp) {
    $webApp = New-MgApplication -BodyParameter @{
        displayName    = $apps.WebApp.Name
        signInAudience = "AzureADMyOrg"
        web = @{
            redirectUris          = $apps.WebApp.RedirectUris
            implicitGrantSettings = @{ enableAccessTokenIssuance = $false; enableIdTokenIssuance = $false }
        }
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $scopeOpenId;        type = "Scope" }
                @{ id = $scopeProfile;       type = "Scope" }
                @{ id = $scopeOfflineAccess; type = "Scope" }
                @{ id = $scopeUserRead;      type = "Scope" }
            )
        })
    }
    Write-Status "Created: $($apps.WebApp.Name) ($($webApp.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $webApp.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [CorpPortal-WebApp] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
Ensure-ServicePrincipal -AppId $webApp.AppId | Out-Null

# ── 2. Corporate Portal — Mobile/SPA (public PKCE client) ────────────────────
Write-Status "CorpPortal-MobileApp" -Type Header
$spa = New-OrGetApp -DisplayName $apps.SPA.Name
if (-not $spa) {
    $spa = New-MgApplication -BodyParameter @{
        displayName    = $apps.SPA.Name
        signInAudience = "AzureADMyOrg"
        spa            = @{ redirectUris = $apps.SPA.RedirectUris }
        publicClient   = @{ redirectUris = @("https://login.microsoftonline.com/common/oauth2/nativeclient") }
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $scopeOpenId;   type = "Scope" }
                @{ id = $scopeProfile;  type = "Scope" }
                @{ id = $scopeUserRead; type = "Scope" }
            )
        })
    }
    Write-Status "Created: $($apps.SPA.Name) ($($spa.AppId))" -Type Success
    Write-Host "  [CorpPortal-MobileApp] No client secret — public client (PKCE only)" -ForegroundColor Cyan
}
Ensure-ServicePrincipal -AppId $spa.AppId | Out-Null

# ── 3. Automation Service — daemon (client credentials) ───────────────────────
Write-Status "CorpOps-AutomationService" -Type Header
$daemon = New-OrGetApp -DisplayName $apps.Daemon.Name
if (-not $daemon) {
    $daemon = New-MgApplication -BodyParameter @{
        displayName    = $apps.Daemon.Name
        signInAudience = "AzureADMyOrg"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $roleUserReadAll;      type = "Role" }
                @{ id = $roleGroupReadAll;     type = "Role" }
                @{ id = $roleDirectoryReadAll; type = "Role" }
            )
        })
    }
    Write-Status "Created: $($apps.Daemon.Name) ($($daemon.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $daemon.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [CorpOps-AutomationService] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
$daemonSp = Ensure-ServicePrincipal -AppId $daemon.AppId
if ($graphSp -and $daemonSp) {
    Grant-AppRoleConsent -SpId $daemonSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleUserReadAll      -AppName "CorpOps User.Read.All"
    Grant-AppRoleConsent -SpId $daemonSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleGroupReadAll     -AppName "CorpOps Group.Read.All"
    Grant-AppRoleConsent -SpId $daemonSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleDirectoryReadAll -AppName "CorpOps Directory.Read.All"
}

# ── 4. ITSM Connector (ServiceNow-style integration) ─────────────────────────
Write-Status "ITSM-Connector" -Type Header
$itsm = New-OrGetApp -DisplayName "ITSM-Connector"
if (-not $itsm) {
    $itsm = New-MgApplication -BodyParameter @{
        displayName    = "ITSM-Connector"
        signInAudience = "AzureADMyOrg"
        notes          = "ServiceNow-style ITSM integration — reads users/groups for ticket assignment"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $roleUserReadAll;  type = "Role" }
                @{ id = $roleGroupReadAll; type = "Role" }
            )
        })
    }
    Write-Status "Created: ITSM-Connector ($($itsm.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $itsm.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [ITSM-Connector] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
$itsmSp = Ensure-ServicePrincipal -AppId $itsm.AppId
if ($graphSp -and $itsmSp) {
    Grant-AppRoleConsent -SpId $itsmSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleUserReadAll  -AppName "ITSM User.Read.All"
    Grant-AppRoleConsent -SpId $itsmSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleGroupReadAll -AppName "ITSM Group.Read.All"
}

# ── 5. CRM Data Bridge (Salesforce-style sync) ────────────────────────────────
Write-Status "CRM-DataBridge" -Type Header
$crm = New-OrGetApp -DisplayName "CRM-DataBridge"
if (-not $crm) {
    $crm = New-MgApplication -BodyParameter @{
        displayName    = "CRM-DataBridge"
        signInAudience = "AzureADMyOrg"
        notes          = "Salesforce-style CRM integration — syncs identity data to CRM records"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(@{ id = $roleUserReadAll; type = "Role" })
        })
    }
    Write-Status "Created: CRM-DataBridge ($($crm.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $crm.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [CRM-DataBridge] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
$crmSp = Ensure-ServicePrincipal -AppId $crm.AppId
if ($graphSp -and $crmSp) {
    Grant-AppRoleConsent -SpId $crmSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleUserReadAll -AppName "CRM User.Read.All"
}

# ── 6. HRIS Integration (Workday-style provisioning) ─────────────────────────
Write-Status "HRIS-Integration" -Type Header
$hris = New-OrGetApp -DisplayName "HRIS-Integration"
if (-not $hris) {
    $hris = New-MgApplication -BodyParameter @{
        displayName    = "HRIS-Integration"
        signInAudience = "AzureADMyOrg"
        notes          = "Workday-style HRIS — inbound provisioning source, reads/writes user lifecycle"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $roleUserReadAll;      type = "Role" }
                @{ id = $roleDirectoryReadAll; type = "Role" }
            )
        })
    }
    Write-Status "Created: HRIS-Integration ($($hris.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $hris.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [HRIS-Integration] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
$hrisSp = Ensure-ServicePrincipal -AppId $hris.AppId
if ($graphSp -and $hrisSp) {
    Grant-AppRoleConsent -SpId $hrisSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleUserReadAll      -AppName "HRIS User.Read.All"
    Grant-AppRoleConsent -SpId $hrisSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleDirectoryReadAll -AppName "HRIS Directory.Read.All"
}

# ── 7. Data Platform Reporting Agent ─────────────────────────────────────────
Write-Status "DataPlatform-ReportingAgent" -Type Header
$reporting = New-OrGetApp -DisplayName "DataPlatform-ReportingAgent"
if (-not $reporting) {
    $reporting = New-MgApplication -BodyParameter @{
        displayName    = "DataPlatform-ReportingAgent"
        signInAudience = "AzureADMyOrg"
        notes          = "BI/analytics reporting agent — reads audit logs and directory data for dashboards"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $roleAuditLogReadAll;  type = "Role" }
                @{ id = $roleDirectoryReadAll; type = "Role" }
            )
        })
    }
    Write-Status "Created: DataPlatform-ReportingAgent ($($reporting.AppId))" -Type Success
    $secret = Add-MgApplicationPassword -ApplicationId $reporting.Id `
        -PasswordCredential @{ displayName = "DefaultSecret"; endDateTime = (Get-Date).AddYears(1) }
    Write-Host "  [DataPlatform-ReportingAgent] Client Secret : $($secret.SecretText)" -ForegroundColor Cyan
}
$reportingSp = Ensure-ServicePrincipal -AppId $reporting.AppId
if ($graphSp -and $reportingSp) {
    Grant-AppRoleConsent -SpId $reportingSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleAuditLogReadAll  -AppName "Reporting AuditLog.Read.All"
    Grant-AppRoleConsent -SpId $reportingSp.Id -ResourceSpId $graphSp.Id -AppRoleId $roleDirectoryReadAll -AppName "Reporting Directory.Read.All"
}

# ── 8. SimLogin-PublicClient (ROPC sign-in simulation) ───────────────────────
Write-Status "SimLogin-PublicClient" -Type Header
$simApp = New-OrGetApp -DisplayName "SimLogin-PublicClient"
if (-not $simApp) {
    $simApp = New-MgApplication -BodyParameter @{
        displayName            = "SimLogin-PublicClient"
        signInAudience         = "AzureADMyOrg"
        isFallbackPublicClient = $true
        publicClient           = @{
            redirectUris = @("https://login.microsoftonline.com/common/oauth2/nativeclient")
        }
        notes                  = "Public client for Invoke-SignInSimulation.ps1 — ROPC flow, generates sign-in log traffic for CA testing"
        requiredResourceAccess = @(@{
            resourceAppId  = $graphAppId
            resourceAccess = @(
                @{ id = $scopeOpenId;        type = "Scope" }
                @{ id = $scopeProfile;       type = "Scope" }
                @{ id = $scopeUserRead;      type = "Scope" }
                @{ id = $scopeOfflineAccess; type = "Scope" }
            )
        })
    }
    Write-Status "Created: SimLogin-PublicClient ($($simApp.AppId))" -Type Success
    Write-Host "  [SimLogin-PublicClient] Public client — no secret required" -ForegroundColor Cyan
    Write-Host "  Use with: .\Simulation\Invoke-SignInSimulation.ps1" -ForegroundColor DarkGray
}
Ensure-ServicePrincipal -AppId $simApp.AppId | Out-Null

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Status "App deployment complete" -Type Success
Write-Host ""
Write-Host "  CorpPortal-WebApp              : $($webApp.AppId)"
Write-Host "  CorpPortal-MobileApp           : $($spa.AppId)"
Write-Host "  CorpOps-AutomationService      : $($daemon.AppId)"
Write-Host "  ITSM-Connector                 : $($itsm.AppId)"
Write-Host "  CRM-DataBridge                 : $($crm.AppId)"
Write-Host "  HRIS-Integration               : $($hris.AppId)"
Write-Host "  DataPlatform-ReportingAgent    : $($reporting.AppId)"
Write-Host "  SimLogin-PublicClient          : $($simApp.AppId)"
Write-Host ""
Write-Host "  Admin consent auto-granted for all daemon apps." -ForegroundColor Green
Write-Host "  Store all client secrets now — they cannot be retrieved again." -ForegroundColor Yellow
