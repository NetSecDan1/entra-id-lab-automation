# Reports/Helpers/KqlQuery.ps1 - Log Analytics query helper for the Reports/KQL/*.ps1 scripts.
#
# Needs Az.Accounts + Az.OperationalInsights. Provision the workspace with
# IaC/terraform (see its README) or point -WorkspaceId at one you already have.
#
# Everything here is READ-ONLY: it authenticates, runs KQL, and returns rows.
# Nothing in this file changes a workspace, a tenant, or a resource.

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

<#
.SYNOPSIS
    Resolves the Log Analytics workspace ID from an explicit value or config.json.

.DESCRIPTION
    Every KQL report needs the same three lines of "was it passed, else read it
    from config, else fail with something actionable". This is those three lines
    in one place. Read-only.

.PARAMETER WorkspaceId
    Explicit workspace (customer) ID. Wins over config when supplied.

.PARAMETER Config
    Parsed config object (from Get-Config). Reads Reporting.LogAnalyticsWorkspaceId.

.EXAMPLE
    $wsId = Resolve-LabWorkspaceId -WorkspaceId $WorkspaceId -Config $config
#>
function Resolve-LabWorkspaceId {
    [CmdletBinding()]
    param(
        [string]$WorkspaceId,
        [psobject]$Config
    )

    if (-not [string]::IsNullOrWhiteSpace($WorkspaceId)) { return $WorkspaceId }

    if ($Config -and $Config.PSObject.Properties.Name -contains "Reporting" -and $Config.Reporting) {
        $fromConfig = [string]$Config.Reporting.LogAnalyticsWorkspaceId
        if (-not [string]::IsNullOrWhiteSpace($fromConfig)) { return $fromConfig }
    }

    throw @"
No Log Analytics workspace ID available.

Fix it one of two ways:
  1. Pass it directly:   -WorkspaceId <guid>
  2. Set it once:        config/config.json -> Reporting.LogAnalyticsWorkspaceId

Don't have a workspace yet? IaC/terraform provisions one plus the tenant-level
Entra ID diagnostic export that fills it. See IaC/terraform/README.md.
"@
}

<#
.SYNOPSIS
    Runs a KQL query against a Log Analytics workspace, with retry and row caps.

.DESCRIPTION
    Read-only wrapper over Invoke-AzOperationalInsightsQuery that adds the three
    things the bare cmdlet leaves to the caller:

      - Retry with exponential backoff on throttling (429) and transient 5xx.
        Log Analytics throttles per-workspace, and an un-retried 429 silently
        looks the same as "no results" once the exception is swallowed.
      - A row cap with an explicit warning, so a query that matched far more
        than expected is loud about it instead of quietly producing a 400 MB
        HTML file.
      - Real error surfacing. A KQL syntax error or a missing table now throws
        with the query name and the service's own message attached.

.PARAMETER WorkspaceId
    Log Analytics workspace (customer) ID.

.PARAMETER Query
    The KQL text to run.

.PARAMETER Timespan
    Query timespan. Note this is applied IN ADDITION to any `ago()` filter inside
    the query itself - the narrower of the two wins. Default 7 days.

.PARAMETER MaxRows
    Warn (and truncate) above this many rows. Default 50000. Set 0 for no cap.

.PARAMETER MaxRetries
    Attempts on a throttled or transient failure. Default 4.

.PARAMETER QueryName
    Friendly name used in log lines and error messages.

.EXAMPLE
    $rows = Invoke-LabKqlQuery -WorkspaceId $wsId -Query $kql -Timespan (New-TimeSpan -Days 14)
#>
function Invoke-LabKqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$Query,
        [timespan]$Timespan = (New-TimeSpan -Days 7),
        [int]$MaxRows = 50000,
        [int]$MaxRetries = 4,
        [string]$QueryName = "query"
    )

    $attempt = 0
    $delaySeconds = 2
    $result = $null

    while ($true) {
        $attempt++
        try {
            Write-Host "[*] Running $QueryName against workspace $WorkspaceId (attempt $attempt)..." -ForegroundColor Cyan
            $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -Timespan $Timespan -ErrorAction Stop
            break
        } catch {
            $message = $_.Exception.Message
            $isTransient = $message -match "429|throttl|too many requests|503|504|timed? out|temporarily unavailable"

            if ($isTransient -and $attempt -le $MaxRetries) {
                Write-Host "[!] Transient failure on $QueryName ($message). Retrying in ${delaySeconds}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delaySeconds
                $delaySeconds = $delaySeconds * 2
                continue
            }

            throw "KQL query '$QueryName' failed after $attempt attempt(s) against workspace $WorkspaceId.`nService said: $message`n`nCommon causes: the table isn't in this workspace (run the Log-IngestionHealth query first), the query has a syntax error, or the signed-in identity lacks Log Analytics Reader on the workspace."
        }
    }

    if (-not $result -or -not $result.Results) {
        Write-Host "[!] $QueryName returned no rows." -ForegroundColor Yellow
        return @()
    }

    $rows = @($result.Results)

    if ($MaxRows -gt 0 -and $rows.Count -gt $MaxRows) {
        Write-Host "[!] $QueryName returned $($rows.Count) rows - truncating to $MaxRows. Narrow the time window or add a filter for the full picture." -ForegroundColor Yellow
        $rows = $rows[0..($MaxRows - 1)]
    }

    Write-Host "[+] ${QueryName}: $($rows.Count) row(s) returned." -ForegroundColor Green
    return $rows
}
