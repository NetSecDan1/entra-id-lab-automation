<#
.SYNOPSIS
    Adds a roster of famous movie/TV characters as test users (hackers & office comedies).

.DESCRIPTION
    Purely for fun / demos. Creates (idempotent) ~20 users themed around Silicon Valley,
    Mr. Robot, Hackers, The Matrix, Office Space, Jurassic Park and Tron, each with a
    plausible department + job title so they blend into the existing org.

    - companyName is set to config.CompanyName, so a re-run of Deploy-Groups.ps1 /
      Deploy-Licenses.ps1 will sweep them in like any other employee.
    - Manager hierarchy is wired within each "crew" (e.g. the Initech devs report to
      Bill Lumbergh).
    - If the "Tenant Schema Extension" app + employeeType attribute exist, each
      character also gets a thematically-appropriate employeeType (Nedry the
      contractor = C, Milton = C, Peter Gibbons = P, everyone else = F).

.EXAMPLE
    . .\Helpers\Common.ps1; Connect-TestTenant
    .\Users\Deploy-FunUsers.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain
$company = [string]$config.CompanyName
$usageLocation = if ($config.Users.UsageLocation) { [string]$config.Users.UsageLocation } else { "US" }

$resolvedPassword = Resolve-SecretValue -Config $config -PropertyName "DefaultPassword" -CurrentValue ([string]$config.DefaultPassword)
$passwordProfile  = @{ Password = $resolvedPassword; ForceChangePasswordNextSignIn = $false }

# ── Roster ───────────────────────────────────────────────────────────────────
# Lead = crew lead (their own Manager stays unset); Manager = UPN prefix of the lead.
$roster = @(
    # Pied Piper  (Silicon Valley)
    @{ First="Richard";  Last="Hendricks";      Dept="Software Engineering";     Title="Principal Engineer";        Office="Pied Piper HQ";            City="Palo Alto";      EmpType="F"; Lead=$true }
    @{ First="Dinesh";   Last="Chugtai";        Dept="Software Engineering";     Title="Senior Software Engineer";   Office="Pied Piper HQ";            City="Palo Alto";      EmpType="F"; Manager="richard.hendricks" }
    @{ First="Bertram";  Last="Gilfoyle";       Dept="IT Infrastructure";       Title="Site Reliability Engineer"; Office="Pied Piper HQ";            City="Palo Alto";      EmpType="F"; Manager="richard.hendricks" }
    @{ First="Jared";    Last="Dunn";           Dept="Operations";              Title="Operations Manager";        Office="Pied Piper HQ";            City="Palo Alto";      EmpType="F"; Manager="richard.hendricks" }
    @{ First="Erlich";   Last="Bachman";        Dept="Marketing";               Title="Brand Manager";             Office="The Incubator";           City="Palo Alto";      EmpType="C"; Manager="richard.hendricks" }
    @{ First="Monica";   Last="Hall";           Dept="Product Management";       Title="Director of Product";       Office="Raviga Capital";          City="Menlo Park";     EmpType="F"; Manager="richard.hendricks" }

    # fsociety  (Mr. Robot)
    @{ First="Elliot";   Last="Alderson";       Dept="Cybersecurity";           Title="Security Engineer";         Office="Allsafe - SOC";           City="New York";       EmpType="F"; Lead=$true }
    @{ First="Darlene";  Last="Alderson";       Dept="Cybersecurity";           Title="Penetration Tester";        Office="Coney Island";            City="New York";       EmpType="F"; Manager="elliot.alderson" }
    @{ First="Angela";   Last="Moss";           Dept="Corporate Communications"; Title="Corporate Affairs Analyst"; Office="E Corp - 17th Floor";     City="New York";       EmpType="F"; Manager="elliot.alderson" }
    @{ First="Tyrell";   Last="Wellick";        Dept="Cybersecurity";           Title="Security Architect";        Office="E Corp - Executive";      City="New York";       EmpType="F"; Manager="elliot.alderson" }

    # Hackers (1995)
    @{ First="Dade";     Last="Murphy";         Dept="Cybersecurity";           Title="SOC Analyst";               Office="The Undernet";            City="New York";       EmpType="F"; Manager="elliot.alderson" }
    @{ First="Kate";     Last="Libby";          Dept="Cybersecurity";           Title="Identity Engineer";         Office="The Undernet";            City="New York";       EmpType="F"; Manager="elliot.alderson" }

    # The Matrix
    @{ First="Thomas";   Last="Anderson";       Dept="Software Engineering";     Title="Software Engineer";         Office="MetaCortex";              City="Chicago";        EmpType="F" }
    @{ First="Trinity";  Last="Moss";           Dept="Cybersecurity";           Title="Penetration Tester";        Office="The Nebuchadnezzar";      City="Chicago";        EmpType="F" }

    # Initech  (Office Space)
    @{ First="Bill";     Last="Lumbergh";       Dept="Operations";              Title="Operations Manager";        Office="Initech - Corner Office"; City="Austin";         EmpType="F"; Lead=$true }
    @{ First="Peter";    Last="Gibbons";        Dept="Software Engineering";     Title="Software Engineer";         Office="Initech - Cubicle Farm";  City="Austin";         EmpType="P"; Manager="bill.lumbergh" }
    @{ First="Michael";  Last="Bolton";         Dept="Software Engineering";     Title="Backend Engineer";          Office="Initech - Cubicle Farm";  City="Austin";         EmpType="F"; Manager="bill.lumbergh" }
    @{ First="Samir";    Last="Nagheenanajar";  Dept="Software Engineering";     Title="Full Stack Engineer";       Office="Initech - Cubicle Farm";  City="Austin";         EmpType="F"; Manager="bill.lumbergh" }
    @{ First="Milton";   Last="Waddams";        Dept="Accounting";              Title="Staff Accountant";          Office="Initech - Storage B";     City="Austin";         EmpType="C"; Manager="bill.lumbergh" }

    # Jurassic Park / Cyberdyne / ENCOM
    @{ First="Dennis";   Last="Nedry";          Dept="IT Infrastructure";       Title="Systems Engineer";          Office="Isla Nublar - Control";   City="San Jose";       EmpType="C" }
    @{ First="Miles";    Last="Dyson";          Dept="Research and Development"; Title="Principal Researcher";      Office="Cyberdyne - Special Proj";City="Sunnyvale";      EmpType="F" }
    @{ First="Kevin";    Last="Flynn";          Dept="Software Engineering";     Title="Principal Engineer";        Office="ENCOM Tower";             City="Los Angeles";    EmpType="F" }
    @{ First="Alan";     Last="Bradley";        Dept="Cybersecurity";           Title="Security Architect";        Office="ENCOM Tower";             City="Los Angeles";    EmpType="F" }
)

# ── Resolve employeeType extension attribute (optional) ──────────────────────
$empTypeAttr = $null
$schemaApp = Get-MgApplication -Filter "displayName eq 'Tenant Schema Extension'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($schemaApp) {
    $empTypeAttr = (Get-MgApplicationExtensionProperty -ApplicationId $schemaApp.Id -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*_employeeType" } | Select-Object -First 1).Name
}
if ($empTypeAttr) {
    Write-Status "employeeType attribute: $empTypeAttr" -Type Info
} else {
    Write-Status "Tenant Schema Extension / employeeType not found — skipping employeeType tagging" -Type Warning
}

# ── Create users ─────────────────────────────────────────────────────────────
Write-Status "Fun users (movie & TV characters)" -Type Header
$created = @{}
foreach ($c in $roster) {
    $prefix = "$($c.First.ToLower()).$($c.Last.ToLower())" -replace "[^a-z0-9.]", ""
    $upn    = "$prefix@$domain"

    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status "Exists: $upn" -Type Warning
        $user = $existing
    } else {
        $user = New-MgUser -DisplayName "$($c.First) $($c.Last)" -UserPrincipalName $upn `
            -AccountEnabled -PasswordProfile $passwordProfile -MailNickname $prefix `
            -GivenName $c.First -Surname $c.Last -JobTitle $c.Title -Department $c.Dept `
            -CompanyName $company -UsageLocation $usageLocation -OfficeLocation $c.Office -City $c.City
        Write-Status "Created: $($c.First) $($c.Last)  ($($c.Dept) / $($c.Title))" -Type Success
    }
    $created[$prefix] = @{ User = $user; Spec = $c }

    if ($empTypeAttr) {
        Update-MgUser -UserId $user.Id -BodyParameter @{ $empTypeAttr = $c.EmpType }
    }
}

# ── Wire manager hierarchy ───────────────────────────────────────────────────
Write-Status "Manager hierarchy" -Type Header
foreach ($kv in $created.GetEnumerator()) {
    $mgrPrefix = $kv.Value.Spec.Manager
    if (-not $mgrPrefix) { continue }
    $mgr = $created[$mgrPrefix]
    if (-not $mgr) { Write-Status "Manager '$mgrPrefix' not in roster for $($kv.Key)" -Type Warning; continue }
    try {
        Invoke-MgGraphRequest -Method PUT `
            -Uri "https://graph.microsoft.com/v1.0/users/$($kv.Value.User.Id)/manager/`$ref" `
            -Body (@{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($mgr.User.Id)" } | ConvertTo-Json) `
            -ContentType "application/json" | Out-Null
        Write-Status "$($kv.Value.Spec.First) $($kv.Value.Spec.Last)  ->  $($mgr.Spec.First) $($mgr.Spec.Last)" -Type Success
    } catch {
        Write-Status "Manager set skipped for $($kv.Key): $_" -Type Warning
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Status "Fun users complete — $($created.Count) characters" -Type Success
if ($empTypeAttr) {
    $byType = $roster | Group-Object EmpType | Sort-Object Name
    Write-Host "  employeeType: $(( $byType | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')" -ForegroundColor DarkGray
}
Write-Host "  Re-run Deploy-Groups.ps1 to add them to SG-All-Employees and dynamic groups." -ForegroundColor DarkGray
