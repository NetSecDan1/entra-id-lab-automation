<#
.SYNOPSIS
    Proves the reporting scripts cannot write to a tenant, a workspace, or Azure.

.DESCRIPTION
    Run this before pointing any report at a tenant you care about, and hand the
    output to whoever has to approve it. It is a static and behavioural check of
    the read-only claim rather than a restatement of it.

    Checks performed:

      1. No mutating Graph verb appears in any report or helper
         (New-Mg, Set-Mg, Remove-Mg, Update-Mg, or Invoke-MgGraphRequest with a
         method other than GET).
      2. No mutating Az verb appears (New-Az, Set-Az, Remove-Az, Update-Az),
         with Set-AzContext explicitly allowed because it changes only the local
         session's subscription, not anything in Azure.
      3. No *.ReadWrite.* Graph scope is requested anywhere outside the
         deployment scripts, which legitimately need write access.
      4. Invoke-GraphPagedRequest exposes no parameter that could change the
         HTTP method - GET is structural, not a default.
      5. No KQL control command (.create/.set/.append/.drop/...) appears in the
         query library.
      6. The call-log assertion actually fails when a non-GET is recorded, so
         the safety net is not itself inert.

    This script reads files and runs in-memory assertions. It connects to
    nothing and needs no credentials.

.PARAMETER Quiet
    Only emit the summary line and the exit status.

.EXAMPLE
    .\Tests\Test-ReadOnlySafety.ps1

.NOTES
    Returns a result object. $result.Passed is $false if any check fails.
#>
[CmdletBinding()]
param([switch]$Quiet)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

. "$repoRoot\Reports\Helpers\GraphReadOnly.ps1"

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Check, [bool]$Passed, [string]$Detail)
    [void]$results.Add([pscustomobject]@{ Check = $Check; Result = if ($Passed) { "PASS" } else { "FAIL" }; Passed = $Passed; Detail = $Detail })
}

# The scripts that must be read-only. Deploy-* and Setup-* are excluded by
# design: they create objects, that is their job.
$readOnlyPaths = @(
    "$repoRoot\IAM",
    "$repoRoot\Reports"
)
$readOnlyFiles = @(Get-ChildItem -Path $readOnlyPaths -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue)

# ---- 1. mutating Graph verbs ------------------------------------------------
$graphMutators = @()
foreach ($file in $readOnlyFiles) {
    $content = Get-Content -Path $file.FullName -Raw
    $stripped = ($content -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    if ($stripped -match '\b(New|Set|Remove|Update)-Mg[A-Za-z]') {
        $graphMutators += "$($file.Name): $($matches[0])"
    }
    if ($stripped -match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)') {
        $graphMutators += "$($file.Name): Invoke-MgGraphRequest $($matches[1])"
    }
}
Add-Result -Check "No mutating Graph cmdlet in IAM/ or Reports/" -Passed ($graphMutators.Count -eq 0) `
    -Detail $(if ($graphMutators.Count -eq 0) { "$($readOnlyFiles.Count) file(s) scanned" } else { $graphMutators -join "; " })

# ---- 2. mutating Az verbs ---------------------------------------------------
# Set-AzContext is allowed: it selects which subscription the local session
# targets and sends no write to Azure.
$azMutators = @()
foreach ($file in $readOnlyFiles) {
    $content = Get-Content -Path $file.FullName -Raw
    $stripped = ($content -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    foreach ($match in [regex]::Matches($stripped, '\b(New|Set|Remove|Update)-Az[A-Za-z]+')) {
        if ($match.Value -eq "Set-AzContext") { continue }
        $azMutators += "$($file.Name): $($match.Value)"
    }
}
Add-Result -Check "No mutating Az cmdlet (Set-AzContext excepted)" -Passed ($azMutators.Count -eq 0) `
    -Detail $(if ($azMutators.Count -eq 0) { "only Set-AzContext found, which is a local session setting" } else { ($azMutators | Sort-Object -Unique) -join "; " })

# ---- 3. no write scopes requested -------------------------------------------
# A permission NAME may legitimately appear in the risk catalog - the catalog
# exists to flag those permissions. What must not appear is a write scope in a
# Connect-MgGraph -Scopes list.
$writeScopeRequests = @()
foreach ($file in $readOnlyFiles) {
    $content = Get-Content -Path $file.FullName -Raw
    if ($content -match 'Connect-MgGraph[^\n]*-Scopes[^\n]*ReadWrite') {
        $writeScopeRequests += $file.Name
    }
}
Add-Result -Check "No *.ReadWrite.* scope requested at connect time" -Passed ($writeScopeRequests.Count -eq 0) `
    -Detail $(if ($writeScopeRequests.Count -eq 0) { "read-only scopes only" } else { $writeScopeRequests -join "; " })

# ---- 4. GET is structural in the paging helper ------------------------------
$pagingCommand = Get-Command Invoke-GraphPagedRequest -ErrorAction SilentlyContinue
$methodParams = @()
if ($pagingCommand) {
    # Exact names, not a substring match: -Verbose contains "Verb" and is a
    # common parameter present on every advanced function.
    $mutableParameterNames = @("Method", "HttpMethod", "Verb", "Body", "Payload", "Content", "RequestBody", "InputObject")
    $methodParams = @($pagingCommand.Parameters.Keys | Where-Object { $mutableParameterNames -contains $_ })
}
Add-Result -Check "Invoke-GraphPagedRequest exposes no method/body parameter" -Passed ($null -ne $pagingCommand -and $methodParams.Count -eq 0) `
    -Detail $(if ($methodParams.Count -eq 0) { "GET is the only verb the function can issue" } else { "found: $($methodParams -join ', ')" })

# ---- 5. no KQL control commands ---------------------------------------------
$kqlFiles = @(Get-ChildItem -Path "$repoRoot\Reports\KQL\Library" -Filter "*.kql" -Recurse -ErrorAction SilentlyContinue)
$kqlMutators = @()
foreach ($file in $kqlFiles) {
    foreach ($line in (Get-Content -Path $file.FullName)) {
        if ($line -match '^\s*\.(create|set|append|drop|alter|ingest|delete|purge|rename)\b') {
            $kqlMutators += "$($file.Name): $($line.Trim())"
        }
    }
}
Add-Result -Check "No KQL control command in the query library" -Passed ($kqlMutators.Count -eq 0) `
    -Detail $(if ($kqlMutators.Count -eq 0) { "$($kqlFiles.Count) query file(s) scanned, all read-only" } else { $kqlMutators -join "; " })

# ---- 6. the safety net is not inert -----------------------------------------
Reset-GraphCallLog
Write-GraphCallLogEntry -Method "GET" -Uri "v1.0/servicePrincipals"
$cleanProof = Test-GraphCallLogIsReadOnly
Write-GraphCallLogEntry -Method "DELETE" -Uri "v1.0/servicePrincipals/x"
$detected = $false
try { Test-GraphCallLogIsReadOnly -ThrowOnViolation | Out-Null } catch { $detected = $true }
Reset-GraphCallLog

Add-Result -Check "Read-only assertion detects a non-GET call" -Passed ($cleanProof.IsReadOnly -and $detected) `
    -Detail $(if ($cleanProof.IsReadOnly -and $detected) { "clean log passes, planted DELETE throws" } else { "the assertion did not behave as expected - the safety net is broken" })

# ---- report -----------------------------------------------------------------
$allResults = @($results)
$failed = @($allResults | Where-Object { -not $_.Passed })

if (-not $Quiet) {
    Write-Host ""
    $allResults | Format-Table -Property @{ N = "Result"; E = { $_.Result }; Width = 6 },
                                         @{ N = "Check"; E = { $_.Check }; Width = 56 },
                                         @{ N = "Detail"; E = { $_.Detail } } |
        Out-String -Width 200 | Write-Host
}

if ($failed.Count -eq 0) {
    Write-Host "[+] READ-ONLY VERIFIED: $($allResults.Count)/$($allResults.Count) checks passed." -ForegroundColor Green
} else {
    Write-Host "[-] READ-ONLY NOT VERIFIED: $($failed.Count) of $($allResults.Count) check(s) failed." -ForegroundColor Red
}

return [pscustomobject]@{
    Passed  = ($failed.Count -eq 0)
    Total   = $allResults.Count
    Failed  = $failed.Count
    Results = $allResults
}
