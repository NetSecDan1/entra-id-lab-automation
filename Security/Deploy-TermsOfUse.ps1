<#
.SYNOPSIS
    Creates a legally-binding Acceptable Use Policy as an Entra Terms of Use
    agreement and enforces acceptance via a Conditional Access policy.

.DESCRIPTION
    Generates a corporate AUP as a PDF, uploads it to Entra ID as a Terms of Use
    agreement, then creates a CA policy requiring every user to accept it before
    accessing any cloud app.

    - Agreement recurs annually (users re-accept every 365 days)
    - Users must view the document before accepting
    - CA policy: All Users → All Cloud Apps → must accept ToU
    - CA policy state follows config.CAP.State (report-only safe by default)

    The agreement PDF is generated inline — no external tools required.

.EXAMPLE
    .\Security\Deploy-TermsOfUse.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config  = Get-Config -ConfigPath $ConfigPath
$domain  = $config.TenantDomain
$company = $config.CompanyName
$capState = if ($config.CAP.State) { [string]$config.CAP.State } else { "enabledForReportingButNotEnforced" }

Ensure-GraphModules -Modules @("Microsoft.Graph")
Connect-TestTenant

Write-Host ""
Write-Status "Terms of Use — Acceptable Use Policy" -Type Header
Write-Host "  Tenant  : $domain"
Write-Host "  Company : $company"
Write-Host ""

# ── PDF generator (pure PowerShell, no external dependencies) ─────────────────
function New-AupPdf {
    param([string]$Company, [string]$Domain)

    $bodyLines = @(
        "ACCEPTABLE USE POLICY (AUP) — Version 1.0",
        "Effective Date: $(Get-Date -Format 'MMMM dd, yyyy')",
        "Organization: $Company ($Domain)",
        "",
        "1. PURPOSE AND SCOPE",
        "This policy governs use of all corporate information systems, devices, applications,",
        "networks, and cloud services provided by $Company. It applies to all employees,",
        "contractors, consultants, and any third party granted access to company systems.",
        "",
        "2. ACCEPTABLE USE",
        "You may use corporate systems for authorized business activities and incidental",
        "personal use that does not interfere with job performance, consume excessive",
        "resources, or violate any provision of this policy.",
        "",
        "You must: protect your credentials and never share passwords or access tokens;",
        "use multi-factor authentication on all corporate accounts; report suspected",
        "security incidents to the security team immediately; comply with data",
        "classification policies when handling sensitive information.",
        "",
        "3. PROHIBITED ACTIVITIES",
        "The following are strictly prohibited: unauthorized access to systems or data;",
        "sharing credentials or circumventing authentication controls; installing",
        "unauthorized software or browser extensions; exfiltrating corporate data to",
        "personal accounts or unapproved storage services; using corporate systems for",
        "illegal activities; attempting to bypass security controls or monitoring;",
        "accessing systems after employment termination.",
        "",
        "4. DATA CLASSIFICATION",
        "You must handle data according to its classification level: Public (no",
        "restrictions), Internal (company personnel only), Confidential (need-to-know",
        "basis, encrypted in transit and at rest), and Restricted (highest sensitivity,",
        "requires explicit authorization and audit trail).",
        "",
        "5. MONITORING AND PRIVACY",
        "Corporate systems are subject to monitoring for security and compliance purposes.",
        "You have no expectation of privacy when using corporate systems or networks.",
        "All sign-in events, data access, and system activity may be logged and",
        "reviewed by authorized security personnel.",
        "",
        "6. INCIDENT REPORTING",
        "Report all security incidents, suspected breaches, phishing attempts, lost",
        "or stolen devices, and unauthorized access immediately. Contact:",
        "security@$Domain or use the internal security incident portal.",
        "",
        "7. CONSEQUENCES OF VIOLATIONS",
        "Violations may result in disciplinary action up to and including termination,",
        "legal action, and civil or criminal penalties. Access privileges will be",
        "suspended pending investigation of any suspected violation.",
        "",
        "By accepting this policy, you confirm that you have read, understood, and",
        "agree to comply with these terms. Your acceptance is logged with timestamp."
    )

    # Build PDF content stream
    $cs = [System.Text.StringBuilder]::new()
    $cs.AppendLine("BT") | Out-Null
    $cs.AppendLine("/F1 13 Tf") | Out-Null
    $cs.AppendLine("50 780 Td") | Out-Null
    $cs.AppendLine("($Company - Acceptable Use Policy) Tj") | Out-Null
    $cs.AppendLine("/F1 8 Tf") | Out-Null
    $cs.AppendLine("0 -18 Td") | Out-Null

    foreach ($line in $bodyLines) {
        # Sanitize: keep printable ASCII only, escape PDF special chars
        $safe = ($line -replace '[^\x20-\x7E]',' ') -replace '\\','\\' -replace '\(','(' -replace '\)',')'
        $cs.AppendLine("($safe) Tj") | Out-Null
        $cs.AppendLine("0 -11 Td") | Out-Null
    }
    $cs.AppendLine("ET") | Out-Null

    $csStr   = $cs.ToString()
    $csBytes = [System.Text.Encoding]::ASCII.GetBytes($csStr)
    $csLen   = $csBytes.Length

    # Build PDF object stream with accurate xref offsets
    $pdf = [System.Collections.Generic.List[byte]]::new()
    $off = @{}

    function A([string]$s) { $pdf.AddRange([System.Text.Encoding]::ASCII.GetBytes($s)) }
    function AB([byte[]]$b) { $pdf.AddRange($b) }

    A "%PDF-1.4`n"

    $off[1] = $pdf.Count
    A "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"

    $off[2] = $pdf.Count
    A "2 0 obj`n<< /Type /Pages /Kids [3 0 R] /Count 1 >>`nendobj`n"

    $off[3] = $pdf.Count
    A "3 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]`n/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>`nendobj`n"

    $off[4] = $pdf.Count
    A "4 0 obj`n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`nendobj`n"

    $off[5] = $pdf.Count
    A "5 0 obj`n<< /Length $csLen >>`nstream`n"
    AB $csBytes
    A "`nendstream`nendobj`n"

    $xrefPos = $pdf.Count
    A "xref`n0 6`n"
    A "0000000000 65535 f `n"
    for ($i = 1; $i -le 5; $i++) {
        A ("{0:D10} 00000 n `n" -f $off[$i])
    }
    A "trailer`n<< /Size 6 /Root 1 0 R >>`nstartxref`n$xrefPos`n%%EOF"

    return [Convert]::ToBase64String($pdf.ToArray())
}

# ── Create or get existing agreement ─────────────────────────────────────────
Write-Status "Generating AUP PDF" -Type Header
$pdfBase64 = New-AupPdf -Company $company -Domain $domain
Write-Host "  PDF generated: $([Math]::Round($pdfBase64.Length / 1024, 1)) KB (base64)" -ForegroundColor DarkGray

Write-Host ""
Write-Status "Creating Terms of Use agreement" -Type Header

$agreementName = "$company - Acceptable Use Policy"
$existing = Invoke-MgGraphRequest -Method GET -ErrorAction SilentlyContinue `
    -Uri "https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements?`$filter=displayName eq '$agreementName'"

if ($existing.value -and $existing.value.Count -gt 0) {
    $agreementId = $existing.value[0].id
    Write-Status "Agreement already exists (id: $agreementId)" -Type Warning
} else {
    $body = @{
        displayName                      = $agreementName
        isViewingBeforeAcceptanceRequired = $true
        isPerDeviceAcceptanceRequired    = $false
        userReacceptRequiredFrequency    = "P365D"
        files                            = @(@{
            fileName = "AUP_v1.pdf"
            language = "en"
            isDefault = $true
            fileData  = @{ data = $pdfBase64 }
        })
    } | ConvertTo-Json -Depth 6

    try {
        $created = Invoke-MgGraphRequest -Method POST -Body $body -ContentType "application/json" `
            -Uri "https://graph.microsoft.com/v1.0/identityGovernance/termsOfUse/agreements"
        $agreementId = if ($created -is [hashtable]) { $created["id"] } else { $created.id }
        Write-Status "Agreement created (id: $agreementId)" -Type Success
    } catch {
        Write-Status "Failed to create agreement: $($_.Exception.Message)" -Type Error
        Disconnect-MgGraph | Out-Null; return
    }
}

# ── Enforce via CA policy ──────────────────────────────────────────────────────
Write-Host ""
Write-Status "Creating CA policy — enforce ToU acceptance" -Type Header

$capName = "CA-ToU-AllUsers-AcceptableUsePolicy"
$existingCap = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq $capName } | Select-Object -First 1

$capBody = @{
    displayName = $capName
    state       = $capState
    conditions  = @{
        users        = @{
            includeUsers  = @("All")
            excludeGroups = @(
                # Exclude break glass group
                (Get-MgGroup -Filter "displayName eq 'CA-BreakGlassAccounts - Exclude'" `
                    -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id -ErrorAction SilentlyContinue)
            ) | Where-Object { $_ }
        }
        applications = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator    = "OR"
        termsOfUse  = @($agreementId)
    }
} | ConvertTo-Json -Depth 10

if ($existingCap) {
    Invoke-MgGraphRequest -Method PATCH -Body $capBody -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($existingCap.Id)" | Out-Null
    Write-Status "Updated CA policy: $capName" -Type Warning
} else {
    Invoke-MgGraphRequest -Method POST -Body $capBody -ContentType "application/json" `
        -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" | Out-Null
    Write-Status "Created CA policy: $capName" -Type Success
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Status "Terms of Use deployment complete" -Type Success
Write-Host ""
Write-Host "  Agreement  : $agreementName" -ForegroundColor Green
Write-Host "  Recurrence : Users must re-accept every 365 days" -ForegroundColor DarkGray
Write-Host "  CA Policy  : $capName ($capState)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Users will see the AUP on their next sign-in." -ForegroundColor Cyan
Write-Host "  Acceptance is logged in: Entra → Identity Governance → Terms of Use" -ForegroundColor DarkGray
Write-Host "    → click the agreement → Acceptance status" -ForegroundColor DarkGray

Disconnect-MgGraph | Out-Null
