# Reports/Helpers/KqlQuery.ps1 — Log Analytics query helper for the Reports/KQL/*.ps1 scripts.
# Needs Az.Accounts + Az.OperationalInsights. Provision the workspace with
# IaC/terraform (see its README) or point -WorkspaceId at one you already have.

function Ensure-AzModules {
    param([string[]]$Modules = @("Az.Accounts", "Az.OperationalInsights"))

    foreach ($module in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "[*] Installing $module (CurrentUser scope)..." -ForegroundColor Cyan
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module -Name $module -ErrorAction Stop
    }
}

function Connect-LabAzure {
    param([string]$TenantId)

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context) {
        Write-Host "[+] Already connected to Azure as $($context.Account.Id) (tenant $($context.Tenant.Id))" -ForegroundColor Green
        return $context
    }

    $connectParams = @{}
    if ($TenantId) { $connectParams["TenantId"] = $TenantId }
    Connect-AzAccount @connectParams | Out-Null
    return Get-AzContext
}

function Invoke-LabKqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$Query,
        [timespan]$Timespan = (New-TimeSpan -Days 7)
    )

    Write-Host "[*] Running KQL query against workspace $WorkspaceId ..." -ForegroundColor Cyan
    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -Timespan $Timespan

    if (-not $result -or -not $result.Results) {
        Write-Host "[!] Query returned no rows." -ForegroundColor Yellow
        return @()
    }

    Write-Host "[+] $($result.Results.Count) row(s) returned." -ForegroundColor Green
    return $result.Results
}
