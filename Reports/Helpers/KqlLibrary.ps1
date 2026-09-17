<#
.SYNOPSIS
    Index, load and parameterize the curated KQL query pack in Reports/KQL/Library.

.DESCRIPTION
    The .kql files in Reports/KQL/Library are the source of truth and are written
    to be pasted straight into Log Analytics, Sentinel, or Defender XDR advanced
    hunting with no preprocessing. This file lets PowerShell work with the same
    files without forking them:

      Get-KqlLibraryIndex    - parse every query's header block into objects
      Get-KqlLibraryQuery    - load one query by name (metadata + text)
      Set-KqlQueryParameter  - override the `let` parameters at the top of a query

    The parameter mechanism is deliberately dumb: each query declares its tunables
    as plain `let name = value;` lines, and Set-KqlQueryParameter rewrites those
    lines in place. That keeps the files valid KQL on their own - nothing here
    invents a templating syntax the portal wouldn't understand.

    Everything in this file is READ-ONLY. It reads text files; it does not
    connect to anything.

.EXAMPLE
    Get-KqlLibraryIndex | Where-Object Severity -eq "critical" | Format-Table Name, Domain

.EXAMPLE
    $q = Get-KqlLibraryQuery -Name "Threat-PasswordSpray"
    $kql = Set-KqlQueryParameter -Query $q.Query -Parameters @{ lookback = "14d"; minTargetedUsers = 10 }
#>

function Get-KqlLibraryRoot {
    param([string]$LibraryPath)

    if ($LibraryPath) { $resolved = $LibraryPath }
    else { $resolved = Join-Path $PSScriptRoot "..\KQL\Library" }

    if (-not (Test-Path $resolved)) {
        throw "KQL library not found at '$resolved'. Expected Reports/KQL/Library relative to Reports/Helpers."
    }
    return (Resolve-Path $resolved).Path
}

<#
.SYNOPSIS
    Parses the `// Key: value` header of every .kql file in the library.

.PARAMETER LibraryPath
    Override the library root. Defaults to Reports/KQL/Library.

.PARAMETER Domain
    Filter to one domain folder (Diagnostics, ThreatHunting, ...). Matches on the
    folder name or the declared Domain, case-insensitively, as a substring.

.PARAMETER Severity
    Filter to one declared severity (info, medium, high, critical).
#>
function Get-KqlLibraryIndex {
    [CmdletBinding()]
    param(
        [string]$LibraryPath,
        [string]$Domain,
        [string]$Severity
    )

    $root = Get-KqlLibraryRoot -LibraryPath $LibraryPath
    $queries = foreach ($file in (Get-ChildItem -Path $root -Filter "*.kql" -Recurse | Sort-Object FullName)) {
        $lines = Get-Content -Path $file.FullName

        $meta = @{}
        $currentKey = $null
        foreach ($line in $lines) {
            if ($line -notmatch '^\s*//') { break }                 # header ends at the first non-comment line
            if ($line -match '^\s*//\s*=+\s*$') { continue }         # rule lines
            if ($line -match '^\s*//\s*([A-Za-z][A-Za-z ]*?):\s*(.*)$') {
                $currentKey = ($matches[1] -replace '\s', '')
                $meta[$currentKey] = $matches[2].Trim()
            } elseif ($currentKey -and $line -match '^\s*//\s{2,}(\S.*)$') {
                $meta[$currentKey] = ($meta[$currentKey] + " " + $matches[1].Trim()).Trim()
            }
        }

        # Tunables are the `let name = value;` lines above the first pipeline stage.
        $parameters = [ordered]@{}
        foreach ($line in $lines) {
            if ($line -match '^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);\s*$') {
                $value = $matches[2].Trim()
                if ($value -notmatch '^(datatable|dynamic|\()' -and $value.Length -le 60) {
                    $parameters[$matches[1]] = $value
                }
            }
        }

        [pscustomobject]@{
            Name        = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            Title       = if ($meta.ContainsKey("Name")) { $meta["Name"] } else { $file.BaseName }
            Domain      = if ($meta.ContainsKey("Domain")) { $meta["Domain"] } else { Split-Path -Leaf $file.DirectoryName }
            Folder      = Split-Path -Leaf $file.DirectoryName
            Severity    = if ($meta.ContainsKey("Severity")) { $meta["Severity"] } else { "info" }
            Tables      = if ($meta.ContainsKey("Tables")) { $meta["Tables"] } else { "" }
            Purpose     = if ($meta.ContainsKey("Purpose")) { $meta["Purpose"] } else { "" }
            Tuning      = if ($meta.ContainsKey("Tuning")) { $meta["Tuning"] } else { "" }
            Caveat      = if ($meta.ContainsKey("Caveat")) { $meta["Caveat"] } else { "" }
            Parameters  = $parameters
            ParameterList = (($parameters.Keys | ForEach-Object { "$_=$($parameters[$_])" }) -join "; ")
            Path        = $file.FullName
        }
    }

    $queries = @($queries)
    if ($Domain)   { $queries = @($queries | Where-Object { $_.Domain -like "*$Domain*" -or $_.Folder -like "*$Domain*" }) }
    if ($Severity) { $queries = @($queries | Where-Object { $_.Severity -eq $Severity }) }
    return $queries
}

<#
.SYNOPSIS
    Loads one library query by file name (with or without the .kql extension).
#>
function Get-KqlLibraryQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$LibraryPath
    )

    $wanted = $Name -replace '\.kql$', ''
    $index = Get-KqlLibraryIndex -LibraryPath $LibraryPath

    $match = @($index | Where-Object { $_.Name -eq $wanted })
    if ($match.Count -eq 0) {
        $match = @($index | Where-Object { $_.Name -like "*$wanted*" })
    }

    if ($match.Count -eq 0) {
        throw "No library query matches '$Name'. Run Invoke-KqlLibraryQuery.ps1 -List to see the $($index.Count) available queries."
    }
    if ($match.Count -gt 1) {
        throw "'$Name' is ambiguous - it matches: $(($match | ForEach-Object { $_.Name }) -join ', '). Use the full name."
    }

    $query = $match[0]
    $text = Get-Content -Path $query.Path -Raw
    return ($query | Select-Object *, @{ Name = "Query"; Expression = { $text }.GetNewClosure() })
}

<#
.SYNOPSIS
    Rewrites `let name = value;` parameter lines in a KQL query.

.DESCRIPTION
    Only rewrites parameters the query already declares - passing an unknown name
    is an error rather than a silent no-op, because a typo'd threshold that quietly
    does nothing is worse than a failed run.

.PARAMETER Query
    The KQL text.

.PARAMETER Parameters
    Hashtable of name -> value. Values are inserted verbatim, so KQL literals like
    "14d", "900.0" or 'dynamic(["a"])' all work. Strings needing quotes must carry
    their own: @{ breakGlassPattern = '"emergency"' }.
#>
function Set-KqlQueryParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [hashtable]$Parameters = @{}
    )

    if ($Parameters.Count -eq 0) { return $Query }

    $result = $Query
    foreach ($key in $Parameters.Keys) {
        $pattern = "(?m)^(\s*let\s+$([regex]::Escape($key))\s*=\s*).+?;\s*$"
        if ($result -notmatch $pattern) {
            throw "Query does not declare a parameter named '$key'. Declared parameters are the `let` lines at the top of the .kql file."
        }
        $replacement = "`${1}$($Parameters[$key]);"
        $result = [regex]::Replace($result, $pattern, $replacement)
    }
    return $result
}

<#
.SYNOPSIS
    Strips the leading `//` documentation header from a query.

.DESCRIPTION
    Useful when embedding a query somewhere the header is noise. The header is
    valid KQL comment syntax, so this is cosmetic - the query runs either way.
#>
function Remove-KqlQueryHeader {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)

    $lines = $Query -split "`r?`n"
    $firstCode = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^\s*//' -and $lines[$i].Trim() -ne "") { $firstCode = $i; break }
    }
    return (($lines[$firstCode..($lines.Count - 1)]) -join "`n")
}
