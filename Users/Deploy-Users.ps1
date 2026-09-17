<#
.SYNOPSIS
    Creates users in the Entra test tenant simulating a Fortune 100 enterprise.

.DESCRIPTION
    Creates (all idempotent):
      - Break glass accounts x2        (Global Admin, excluded from all CA policies)
      - Legacy test admin               (backward compat)
      - Executive team x8              (CEO, CFO, CTO, CISO, COO, CLO, CMO, CHRO)
      - Admin tier accounts x5         (T1 Service Desk x2, T2 Cloud/Security Ops x3)
      - 150 regular employees          (18 departments, realistic names + profiles)
      - 8 service accounts             (automation and integration workloads)
      - 1 permanently blocked user

    UPN format for employees: firstname.lastname[@N]@tenantdomain
    Manager hierarchy:  IC → Dept Lead → Executive → CEO
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config = Get-Config -ConfigPath $ConfigPath
$domain = $config.TenantDomain
$u      = $config.Users

$resolvedPassword = Resolve-SecretValue -Config $config -PropertyName "DefaultPassword" -CurrentValue ([string]$config.DefaultPassword)
$passwordProfile  = @{ Password = $resolvedPassword; ForceChangePasswordNextSignIn = $false }

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-OrGetUser {
    param([hashtable]$Params)
    $upn      = $Params.UserPrincipalName
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($existing) { Write-Status "Exists: $upn" -Type Warning; return $existing }
    $user = New-MgUser @Params
    Write-Status "Created: $upn" -Type Success
    return $user
}

$upnTracker = @{}
function New-UserUpn {
    param([string]$GivenName, [string]$Surname)
    $base = ("$($GivenName.ToLower()).$($Surname.ToLower())" -replace "[^a-z0-9.]", "")
    if (-not $upnTracker.ContainsKey($base)) { $upnTracker[$base] = 0 }
    $upnTracker[$base]++
    $n = $upnTracker[$base]
    $suffix = if ($n -eq 1) { "" } else { "$n" }
    return "$base$suffix@$domain"
}

function Set-UserManagerSafe {
    param([string]$UserId, [string]$ManagerId)
    try {
        Invoke-MgGraphRequest -Method PUT `
            -Uri "https://graph.microsoft.com/v1.0/users/$UserId/manager/`$ref" `
            -Body (@{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$ManagerId" } | ConvertTo-Json) `
            -ContentType "application/json" | Out-Null
    } catch { <# already set or no permission #> }
}

# ── Profile lookup tables ─────────────────────────────────────────────────────
$givenNames = @(
    "Alex","Jordan","Morgan","Casey","Riley","Taylor","Jamie","Avery","Quinn","Blake",
    "Drew","Hayden","Parker","Reese","Sage","Cameron","Dakota","Emery","Finley","Harley",
    "Logan","Peyton","Rowan","Skylar","Bailey","Charlie","Devon","Ellis","Frankie","Hunter",
    "Jules","Kendall","Lane","Micah","Noel","Phoenix","River","Sam","Terry","Uma",
    "Vale","Wren","Xander","Yael","Zoe","Chris","Dana","Eden","Fynn","Grace"
)
$surnames = @(
    "Anderson","Brown","Chen","Davis","Evans","Fisher","Garcia","Harris","Jackson","Kim",
    "Lee","Martinez","Nelson","OBrien","Park","Quinn","Rodriguez","Singh","Taylor","Ueda",
    "Vargas","Wilson","Xu","Young","Zhang","Adams","Baker","Clark","Diaz","Edwards",
    "Ford","Green","Hall","Ingram","Jones","Kumar","Lewis","Moore","Nguyen","Owen",
    "Patel","Reed","Scott","Thomas","Underwood","Vance","Walker","Yamamoto","Zhen","Cross"
)
$cities = @(
    "New York","New York","New York","New York","San Francisco",
    "Chicago","Austin","Seattle","Boston","Atlanta"
)
$officeLocations = @(
    "HQ Tower - Floor 32","HQ Tower - Floor 28","HQ Tower - Floor 24","HQ Tower - Floor 20",
    "SF Office - Suite 900","Chicago Office - Floor 15",
    "Austin Office","Seattle Office","Boston Office","Atlanta Office"
)
$deptJobTitles = @{
    "IT Infrastructure"        = @("Systems Engineer","Cloud Infrastructure Engineer","Platform Engineer","Network Architect","Site Reliability Engineer")
    "Cybersecurity"            = @("Security Engineer","SOC Analyst","Identity Engineer","Penetration Tester","Security Architect")
    "Software Engineering"     = @("Software Engineer","Senior Software Engineer","Backend Engineer","Full Stack Engineer","Principal Engineer")
    "Product Management"       = @("Product Manager","Senior Product Manager","Group Product Manager","Product Owner","Director of Product")
    "Data and Analytics"       = @("Data Engineer","Data Analyst","Analytics Engineer","BI Developer","Data Scientist")
    "Finance"                  = @("Financial Analyst","Senior Financial Analyst","Finance Manager","Budget Analyst","FP&A Analyst")
    "Accounting"               = @("Staff Accountant","Senior Accountant","Controller","Accounts Payable Specialist","Revenue Accountant")
    "Human Resources"          = @("HR Business Partner","Talent Acquisition Specialist","Compensation Analyst","HRIS Analyst","HR Manager")
    "Legal"                    = @("Associate General Counsel","Legal Counsel","Contract Manager","Regulatory Counsel","Corporate Paralegal")
    "Compliance and Risk"      = @("Compliance Officer","Risk Analyst","GRC Analyst","Privacy Manager","Senior Compliance Manager")
    "Marketing"                = @("Marketing Manager","Content Strategist","Brand Manager","Digital Marketing Specialist","Product Marketing Manager")
    "Sales"                    = @("Account Executive","Senior Account Executive","Sales Engineer","Regional Sales Manager","Business Development Rep")
    "Customer Success"         = @("Customer Success Manager","Technical Account Manager","Solutions Engineer","Onboarding Specialist","CS Operations Analyst")
    "Operations"               = @("Operations Manager","Business Operations Analyst","Program Manager","Process Improvement Specialist","Supply Chain Analyst")
    "Procurement"              = @("Procurement Analyst","Senior Buyer","Vendor Manager","Strategic Sourcing Specialist","Contracts Manager")
    "Internal Audit"           = @("IT Auditor","Senior Auditor","Audit Manager","SOX Compliance Analyst","Internal Controls Specialist")
    "Research and Development" = @("Research Scientist","R&D Engineer","Principal Researcher","Innovation Analyst","Applied Scientist")
    "Corporate Communications" = @("Communications Manager","PR Specialist","Executive Communications Specialist","Employee Comms Manager","Corporate Affairs Analyst")
}

# Dept → exec (used to wire dept leads' manager)
$deptExecUpnMap = @{
    "Finance"                  = "sarah.chen@$domain"
    "IT Infrastructure"        = "marcus.turner@$domain"
    "Cybersecurity"            = "elena.vasquez@$domain"
    "Operations"               = "robert.hayes@$domain"
    "Legal"                    = "diana.park@$domain"
    "Compliance and Risk"      = "diana.park@$domain"
    "Marketing"                = "michael.obrady@$domain"
    "Corporate Communications" = "james.morrison@$domain"
    "Human Resources"          = "jennifer.wu@$domain"
}
$defaultExecUpn = "james.morrison@$domain"  # CEO is fallback manager

# ── Break Glass ───────────────────────────────────────────────────────────────
Write-Status "Break glass accounts" -Type Header
$bgUpn  = "$($u.BreakGlassUpn)@$domain"
$bgUser = New-OrGetUser -Params @{
    DisplayName = "Break Glass Admin"; UserPrincipalName = $bgUpn
    AccountEnabled = $true; PasswordProfile = $passwordProfile
    MailNickname = $u.BreakGlassUpn; JobTitle = "Break Glass"
    Department = "IT Infrastructure"; UsageLocation = $u.UsageLocation
}
Assign-DirectoryRole -RoleName "Global Administrator" -UserId $bgUser.Id

if ($u.BreakGlassUpn2) {
    $bg2Upn  = "$($u.BreakGlassUpn2)@$domain"
    $bg2User = New-OrGetUser -Params @{
        DisplayName = "Break Glass Admin 2"; UserPrincipalName = $bg2Upn
        AccountEnabled = $true; PasswordProfile = $passwordProfile
        MailNickname = $u.BreakGlassUpn2; JobTitle = "Break Glass"
        Department = "IT Infrastructure"; UsageLocation = $u.UsageLocation
    }
    Assign-DirectoryRole -RoleName "Global Administrator" -UserId $bg2User.Id
    Write-Host "  Store BG1 and BG2 passwords separately with independent auth methods." -ForegroundColor Yellow
}

# ── Legacy test admin (backward compat — kept for scripts that reference it) ──
Write-Status "Legacy admin account" -Type Header
$adminUpn  = "$($u.AdminUpn)@$domain"
$adminUser = New-OrGetUser -Params @{
    DisplayName = "Test Admin"; UserPrincipalName = $adminUpn
    AccountEnabled = $true; PasswordProfile = $passwordProfile
    MailNickname = $u.AdminUpn; JobTitle = "IT Administrator"
    Department = "IT Infrastructure"; UsageLocation = $u.UsageLocation
}
Assign-DirectoryRole -RoleName "Helpdesk Administrator" -UserId $adminUser.Id
Assign-DirectoryRole -RoleName "User Administrator"     -UserId $adminUser.Id

# ── Executive Team (C-Suite) ──────────────────────────────────────────────────
Write-Status "Executive team (C-Suite)" -Type Header
$execProfiles = @(
    @{ UPNLocal = "james.morrison";  Name = "James Morrison";   GN = "James";    SN = "Morrison"; Title = "Chief Executive Officer";            Dept = "Corporate Communications" }
    @{ UPNLocal = "sarah.chen";      Name = "Sarah Chen";        GN = "Sarah";    SN = "Chen";     Title = "Chief Financial Officer";             Dept = "Finance" }
    @{ UPNLocal = "marcus.turner";   Name = "Marcus Turner";     GN = "Marcus";   SN = "Turner";   Title = "Chief Technology Officer";            Dept = "IT Infrastructure" }
    @{ UPNLocal = "elena.vasquez";   Name = "Elena Vasquez";     GN = "Elena";    SN = "Vasquez";  Title = "Chief Information Security Officer";   Dept = "Cybersecurity" }
    @{ UPNLocal = "robert.hayes";    Name = "Robert Hayes";      GN = "Robert";   SN = "Hayes";    Title = "Chief Operating Officer";             Dept = "Operations" }
    @{ UPNLocal = "diana.park";      Name = "Diana Park";        GN = "Diana";    SN = "Park";     Title = "Chief Legal Officer";                 Dept = "Legal" }
    @{ UPNLocal = "michael.obrady";  Name = "Michael OBrady";    GN = "Michael";  SN = "OBrady";   Title = "Chief Marketing Officer";             Dept = "Marketing" }
    @{ UPNLocal = "jennifer.wu";     Name = "Jennifer Wu";       GN = "Jennifer"; SN = "Wu";       Title = "Chief Human Resources Officer";       Dept = "Human Resources" }
)

$ceoUser    = $null
$execUserMap = @{}  # UPNLocal → user object

foreach ($ep in $execProfiles) {
    $fullUpn = "$($ep.UPNLocal)@$domain"
    $user = New-OrGetUser -Params @{
        DisplayName = $ep.Name; UserPrincipalName = $fullUpn
        AccountEnabled = $true; PasswordProfile = $passwordProfile
        MailNickname = ($ep.UPNLocal -replace '\.', '')
        GivenName = $ep.GN; Surname = $ep.SN
        JobTitle = $ep.Title; Department = $ep.Dept
        UsageLocation = $u.UsageLocation; City = "New York"
        OfficeLocation = "HQ Tower - Executive Floor"
        CompanyName = $config.CompanyName
    }
    $execUserMap[$ep.UPNLocal] = $user
    if ($ep.Title -eq "Chief Executive Officer") { $ceoUser = $user }
    # Register name so regular user loop won't collide
    $upnTracker[$ep.UPNLocal] = 1
}

# All execs report to CEO
if ($ceoUser) {
    foreach ($execEntry in $execUserMap.GetEnumerator()) {
        if ($execEntry.Value.Id -ne $ceoUser.Id) {
            Set-UserManagerSafe -UserId $execEntry.Value.Id -ManagerId $ceoUser.Id
        }
    }
}

# ── Admin Tier Accounts ────────────────────────────────────────────────────────
Write-Status "Admin tier accounts" -Type Header
$adminTierAccounts = @(
    # Tier 1 — Service Desk / Helpdesk
    @{ Prefix = "admin.svc01";    Name = "Admin - Service Desk 01";    Title = "Service Desk Administrator";       Dept = "IT Infrastructure"; Roles = @("Helpdesk Administrator","User Administrator") }
    @{ Prefix = "admin.svc02";    Name = "Admin - Service Desk 02";    Title = "Service Desk Administrator";       Dept = "IT Infrastructure"; Roles = @("Helpdesk Administrator","User Administrator") }
    # Tier 2 — Cloud / Platform / Security
    @{ Prefix = "admin.cloud01";  Name = "Admin - Cloud Ops 01";       Title = "Cloud Operations Administrator";   Dept = "IT Infrastructure"; Roles = @() }
    @{ Prefix = "admin.azure01";  Name = "Admin - Azure Platform 01";  Title = "Azure Platform Administrator";     Dept = "IT Infrastructure"; Roles = @() }
    @{ Prefix = "admin.sec01";    Name = "Admin - Security Ops 01";    Title = "Security Operations Administrator"; Dept = "Cybersecurity";    Roles = @() }
)

foreach ($acct in $adminTierAccounts) {
    $user = New-OrGetUser -Params @{
        DisplayName = $acct.Name; UserPrincipalName = "$($acct.Prefix)@$domain"
        AccountEnabled = $true; PasswordProfile = $passwordProfile
        MailNickname = ($acct.Prefix -replace '\.', '')
        JobTitle = $acct.Title; Department = $acct.Dept
        UsageLocation = $u.UsageLocation; CompanyName = $config.CompanyName
    }
    foreach ($role in $acct.Roles) { Assign-DirectoryRole -RoleName $role -UserId $user.Id }
}

# ── Regular Employees (150) ───────────────────────────────────────────────────
Write-Status "Creating $($u.TestUserCount) employees" -Type Header
$deptList        = $u.Departments
$deptLeads       = @{}   # dept → first-user object
$createdEmployees = @()

for ($i = 1; $i -le $u.TestUserCount; $i++) {
    $dept      = $deptList[($i - 1) % $deptList.Count]
    $gn        = $givenNames[($i - 1) % $givenNames.Count]
    $sn        = $surnames[($i - 1) % $surnames.Count]
    $upn       = New-UserUpn -GivenName $gn -Surname $sn
    $city      = $cities[($i - 1) % $cities.Count]
    $office    = $officeLocations[($i - 1) % $officeLocations.Count]
    $titleList = if ($deptJobTitles[$dept]) { $deptJobTitles[$dept] } else { @("Analyst") }
    $title     = $titleList[($i - 1) % $titleList.Count]
    $phone     = "+1 555-{0:D3}-{1:D4}" -f (($i * 17 + 100) % 900 + 100), (($i * 137 + 1000) % 9000 + 1000)

    $user = New-OrGetUser -Params @{
        DisplayName = "$gn $sn"; UserPrincipalName = $upn
        AccountEnabled = $true; PasswordProfile = $passwordProfile
        MailNickname = ($upn -replace '@.*$', '')
        GivenName = $gn; Surname = $sn
        JobTitle = $title; Department = $dept
        UsageLocation = $u.UsageLocation; City = $city
        OfficeLocation = $office; MobilePhone = $phone
        CompanyName = $config.CompanyName
    }
    $createdEmployees += $user
    if (-not $deptLeads.ContainsKey($dept)) { $deptLeads[$dept] = $user }
}
Write-Status "$($u.TestUserCount) employees provisioned" -Type Success

# ── Manager Hierarchy ─────────────────────────────────────────────────────────
Write-Status "Setting manager hierarchy" -Type Header

# Dept leads report to their C-suite exec (or CEO as fallback)
foreach ($dept in $deptLeads.Keys) {
    $lead      = $deptLeads[$dept]
    $execUpn   = if ($deptExecUpnMap.ContainsKey($dept)) { $deptExecUpnMap[$dept] } else { $defaultExecUpn }
    $execUser  = Get-MgUser -Filter "userPrincipalName eq '$execUpn'" -ErrorAction SilentlyContinue
    if ($execUser) { Set-UserManagerSafe -UserId $lead.Id -ManagerId $execUser.Id }
}

# Employees report to their dept lead
foreach ($emp in $createdEmployees) {
    $dept = $emp.Department
    $lead = $deptLeads[$dept]
    if ($lead -and $emp.Id -ne $lead.Id) {
        Set-UserManagerSafe -UserId $emp.Id -ManagerId $lead.Id
    }
}
Write-Status "Manager hierarchy wired ($($deptLeads.Count) department leads)" -Type Success

# ── Service Accounts ──────────────────────────────────────────────────────────
Write-Status "Service accounts" -Type Header
$serviceAccounts = @(
    @{ Prefix = "svc-sync01";       Name = "Svc - Directory Sync";         Title = "Directory Synchronization Service" }
    @{ Prefix = "svc-entra01";      Name = "Svc - Entra ID Automation";    Title = "Identity Automation Service"       }
    @{ Prefix = "svc-itsmbridge01"; Name = "Svc - ITSM Integration";       Title = "ITSM Connector Service"            }
    @{ Prefix = "svc-crmbridge01";  Name = "Svc - CRM Data Bridge";        Title = "CRM Integration Service"           }
    @{ Prefix = "svc-hrisbridge01"; Name = "Svc - HRIS Integration";       Title = "HRIS Identity Sync Service"        }
    @{ Prefix = "svc-dataetl01";    Name = "Svc - Data Pipeline";          Title = "ETL Automation Service"            }
    @{ Prefix = "svc-backup01";     Name = "Svc - Backup Operations";      Title = "Backup Automation Service"         }
    @{ Prefix = "svc-monitoring01"; Name = "Svc - Monitoring Platform";    Title = "Monitoring Agent Service"          }
)

$caServiceAccountsGrp = Get-MgGroup -Filter "displayName eq 'CA-ServiceAccounts'" -ErrorAction SilentlyContinue

foreach ($svc in $serviceAccounts) {
    $svcUser = New-OrGetUser -Params @{
        DisplayName = $svc.Name; UserPrincipalName = "$($svc.Prefix)@$domain"
        AccountEnabled = $true; PasswordProfile = $passwordProfile
        MailNickname = $svc.Prefix; JobTitle = $svc.Title
        Department = "IT Operations"; UsageLocation = $u.UsageLocation
        CompanyName = $config.CompanyName
    }
    if ($caServiceAccountsGrp) {
        Add-GroupMemberSafe -GroupId $caServiceAccountsGrp.Id -UserId $svcUser.Id
    }
}
Write-Status "Service accounts provisioned ($($serviceAccounts.Count))" -Type Success

# ── Blocked User ──────────────────────────────────────────────────────────────
Write-Status "Blocked test user" -Type Header
New-OrGetUser -Params @{
    DisplayName = "Blocked Test Account"; UserPrincipalName = "testblocked@$domain"
    AccountEnabled = $false; PasswordProfile = $passwordProfile
    MailNickname = "testblocked"; Department = "IT Infrastructure"
    UsageLocation = $u.UsageLocation
} | Out-Null

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Status "User deployment complete" -Type Success
Write-Host ""
Write-Host "  Break glass    : $bgUpn $(if ($u.BreakGlassUpn2) { '/ ' + $bg2Upn })"
Write-Host "  Admin (legacy) : $adminUpn"
Write-Host "  C-Suite        : $($execProfiles.Count) execs (james.morrison → CEO)"
Write-Host "  Admin tier     : $($adminTierAccounts.Count) accounts (admin.svc*, admin.cloud*, admin.sec*)"
Write-Host "  Employees      : $($u.TestUserCount) across $($deptList.Count) departments"
Write-Host "  Service accts  : $($serviceAccounts.Count) (svc-* prefix, in CA-ServiceAccounts)"
Write-Host "  UPN format     : firstname.lastname[@N]@$domain"
Write-Host "  Password       : suppressed by design"
