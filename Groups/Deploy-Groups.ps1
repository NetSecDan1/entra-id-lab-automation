<#
.SYNOPSIS
    Creates enterprise groups and Conditional Access baseline groups.

.DESCRIPTION
    Creates (all idempotent):
      Business groups:
        SG-All-Employees, SG-Executives, SG-Engineering, SG-Finance,
        SG-Cybersecurity, SG-PAW-Users, SG-VPN-Users
      Admin tier groups:
        SG-Admins-Tier0, SG-Admins-Tier1, SG-Admins-Tier2, SG-Admins-All
      Location groups:
        SG-Location-NewYork, SG-Location-SanFrancisco, SG-Location-Chicago,
        SG-Location-Austin, SG-Location-Remote
      Enterprise app access groups:
        SG-App-ITSM, SG-App-CRM, SG-App-HRIS, SG-App-DataPlatform
      Per-department security groups
      Dynamic group: DYN-Cybersecurity-Department
      M365 collaboration group: M365-Leadership-Team
      CA Baseline groups (required by j0eyv/ConditionalAccessBaseline)
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config\config.json"
)

. "$PSScriptRoot\..\Helpers\Common.ps1"
$config     = Get-Config -ConfigPath $ConfigPath
$domain     = $config.TenantDomain
$u          = $config.Users
$g          = $config.Groups
$caBaseline = $config.CABaseline

# ── CA Baseline group list ─────────────────────────────────────────────────────
$caBaselineGroupNames = @(
    "CA-BreakGlassAccounts - Exclude",
    "APP_Microsoft365_E5",
    "CA-ServiceAccounts",
    "CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist - Exclude",
    "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication - Exclude",
    "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA - Exclude",
    "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows - Exclude",
    "CA005-Global-DataProtection-Office365-iOSenAndroid-ClientApps-Unmanaged-AppEnforcedRestrictions - Exclude",
    "CA006-Global-DataProtection-Office365-AnyPlatform-Browser-Unmanaged-AppEnforceRestrictions - Exclude",
    "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA - Exclude",
    "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency - Exclude",
    "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation - Exclude",
    "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA - Exclude",
    "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser - Exclude",
    "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices - Exclude",
    "CA203-Internals-AppProtection-MicrosoftIntuneEnrollment-AnyPlatform-MFA - Exclude",
    "CA204-Internals-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUnknownPlatforms - Exclude",
    "CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ - Exclude",
    "CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA207-Internals-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK - Exclude",
    "CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant - Exclude",
    "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation - Exclude",
    "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn - Exclude",
    "CA300-ServiceAccounts-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA301-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-BlockUntrustedLocations - Exclude",
    "CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA - Exclude",
    "CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess - Exclude",
    "CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency - Exclude",
    "CA403-Guests-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser - Exclude",
    "CA404-Guests-AttackSurfaceReduction-SelectedApps-AnyPlatform-BLOCK - Exclude",
    "CA501-Agents-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskAgent - Exclude",
    "CA502-Agents-AttackSurfaceReduction-AllAgentIdentities-AllAgentResources-BLOCK - Exclude",
    "CA503-Agents-BaseProtection-AllAgentUsers-RequireCompliantDevice - Exclude",
    "CA504-Agents-IdentityProtection-AllAgentUsers-AllResources-BlockRiskyAgents - Exclude",
    "CA505-Agents-AttackSurfaceReduction-AllAgentUsers-AllResources-RequireCompliantNetWork - Exclude"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
function New-OrGetGroup {
    param(
        [string]$DisplayName,
        [string]$MailNickname,
        [string]$Description,
        [string]$GroupType = "Security",
        [string]$MembershipRule = $null
    )
    $existing = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) { Write-Status "Exists: $DisplayName" -Type Warning; return $existing }

    $params = @{
        DisplayName = $DisplayName; MailNickname = $MailNickname
        Description = $Description; SecurityEnabled = $true
        MailEnabled = $false; GroupTypes = @()
    }
    switch ($GroupType) {
        "M365" {
            $params.MailEnabled = $true; $params.SecurityEnabled = $false
            $params.GroupTypes  = @("Unified")
        }
        "Dynamic" {
            $params.GroupTypes = @("DynamicMembership")
            $params.MembershipRule = $MembershipRule
            $params.MembershipRuleProcessingState = "On"
        }
    }
    $group = New-MgGroup -BodyParameter $params
    Write-Status "Created: $DisplayName" -Type Success
    return $group
}

function Get-UserByUpn {
    param([string]$Upn)
    return Get-MgUser -Filter "userPrincipalName eq '$Upn'" -ErrorAction SilentlyContinue
}

function Get-SafeMailNickname {
    param([string]$DisplayName)
    $nick = $DisplayName.ToLower() `
        -replace '\s+-\s+exclude$', '-excl' `
        -replace '\s+', '-' `
        -replace '[^a-z0-9\-]', ''
    return $nick.Substring(0, [Math]::Min($nick.Length, 64))
}

# ── Resolve key accounts ──────────────────────────────────────────────────────
Write-Status "Resolving user accounts" -Type Header

$bgUser    = Get-UserByUpn "$($u.BreakGlassUpn)@$domain"
$bg2User   = if ($u.BreakGlassUpn2) { Get-UserByUpn "$($u.BreakGlassUpn2)@$domain" } else { $null }
$adminUser = Get-UserByUpn "$($u.AdminUpn)@$domain"

# All employees: companyName match, enabled, exclude system accounts
$systemPrefixes = @("breakglass","testadmin","admin.","svc-","testblocked")
$allEmployees = Get-AllEmployeeUsers -CompanyName $config.CompanyName -ExcludeUpnPrefixes $systemPrefixes

$execUsers    = @($allEmployees | Where-Object { $_.JobTitle -match "^Chief " })
$regularUsers = @($allEmployees | Where-Object { $_.JobTitle -notmatch "^Chief " })

# Admin tier accounts
$t1Users = @(
    (Get-UserByUpn "admin.svc01@$domain"),
    (Get-UserByUpn "admin.svc02@$domain")
) | Where-Object { $_ }
$t2Users = @(
    (Get-UserByUpn "admin.cloud01@$domain"),
    (Get-UserByUpn "admin.azure01@$domain"),
    (Get-UserByUpn "admin.sec01@$domain")
) | Where-Object { $_ }

Write-Status "Found: $($allEmployees.Count) employees, $($execUsers.Count) execs, $($regularUsers.Count) regular" -Type Info

# ── SG-All-Employees ──────────────────────────────────────────────────────────
Write-Status "SG-All-Employees" -Type Header
$grpAll = New-OrGetGroup -DisplayName $g.AllEmployees -MailNickname "sg-all-employees" `
    -Description "All active employees — used as broad include in CA policies"
foreach ($emp in $allEmployees) { Add-GroupMemberSafe -GroupId $grpAll.Id -UserId $emp.Id }
if ($adminUser) { Add-GroupMemberSafe -GroupId $grpAll.Id -UserId $adminUser.Id }
Write-Status "Membership updated: $($g.AllEmployees)" -Type Success

# ── SG-Executives ─────────────────────────────────────────────────────────────
Write-Status "SG-Executives" -Type Header
$grpExec = New-OrGetGroup -DisplayName $g.Executives -MailNickname "sg-executives" `
    -Description "C-Suite and executive leadership — phishing-resistant MFA enforced"
foreach ($exec in $execUsers) { Add-GroupMemberSafe -GroupId $grpExec.Id -UserId $exec.Id }
Write-Status "Membership updated: $($g.Executives)" -Type Success

# ── Admin Tier Groups ─────────────────────────────────────────────────────────
Write-Status "Admin tier groups" -Type Header

$grpT0 = New-OrGetGroup -DisplayName $g.AdminsTier0 -MailNickname "sg-admins-tier0" `
    -Description "Tier 0: Break glass accounts — Global Admin, excluded from all CA policies"
if ($bgUser)  { Add-GroupMemberSafe -GroupId $grpT0.Id -UserId $bgUser.Id }
if ($bg2User) { Add-GroupMemberSafe -GroupId $grpT0.Id -UserId $bg2User.Id }

$grpT1 = New-OrGetGroup -DisplayName $g.AdminsTier1 -MailNickname "sg-admins-tier1" `
    -Description "Tier 1: Service Desk admins — Helpdesk + User Administrator roles"
foreach ($u2 in $t1Users) { Add-GroupMemberSafe -GroupId $grpT1.Id -UserId $u2.Id }

$grpT2 = New-OrGetGroup -DisplayName $g.AdminsTier2 -MailNickname "sg-admins-tier2" `
    -Description "Tier 2: Cloud and Security Operations admins"
foreach ($u2 in $t2Users) { Add-GroupMemberSafe -GroupId $grpT2.Id -UserId $u2.Id }

$grpAdminsAll = New-OrGetGroup -DisplayName $g.AllAdmins -MailNickname "sg-admins-all" `
    -Description "All admin accounts (T0+T1+T2) — used in privileged CA policies"
foreach ($u2 in (@($bgUser,$bg2User,$adminUser) + $t1Users + $t2Users | Where-Object { $_ })) {
    Add-GroupMemberSafe -GroupId $grpAdminsAll.Id -UserId $u2.Id
}
Write-Status "Admin tier groups populated" -Type Success

# ── Department groups ─────────────────────────────────────────────────────────
Write-Status "Department groups" -Type Header
foreach ($dept in $u.Departments) {
    $nick      = ("sg-" + ($dept.ToLower() -replace '[^a-z0-9]', '-') -replace '-+', '-').TrimEnd('-')
    $deptGroup = New-OrGetGroup -DisplayName "SG-$dept" -MailNickname $nick -Description "$dept department employees"
    $deptUsers = @($allEmployees | Where-Object { $_.Department -eq $dept })
    foreach ($u2 in $deptUsers) { Add-GroupMemberSafe -GroupId $deptGroup.Id -UserId $u2.Id }
}
Write-Status "Department groups populated" -Type Success

# ── Focused functional groups ─────────────────────────────────────────────────
Write-Status "Functional groups" -Type Header

# Engineering
$grpEng = New-OrGetGroup -DisplayName $g.Engineering -MailNickname "sg-engineering" `
    -Description "Software Engineering department"
$engUsers = @($allEmployees | Where-Object { $_.Department -eq "Software Engineering" })
foreach ($u2 in $engUsers) { Add-GroupMemberSafe -GroupId $grpEng.Id -UserId $u2.Id }

# Finance (Finance + Accounting)
$grpFin = New-OrGetGroup -DisplayName $g.Finance -MailNickname "sg-finance" `
    -Description "Finance and Accounting — elevated data protection CA policies apply"
$finUsers = @($allEmployees | Where-Object { $_.Department -in @("Finance","Accounting") })
foreach ($u2 in $finUsers) { Add-GroupMemberSafe -GroupId $grpFin.Id -UserId $u2.Id }

# Cybersecurity
$grpSec = New-OrGetGroup -DisplayName $g.Cybersecurity -MailNickname "sg-cybersecurity" `
    -Description "Cybersecurity department — privileged access to security tooling"
$secUsers = @($allEmployees | Where-Object { $_.Department -eq "Cybersecurity" })
foreach ($u2 in $secUsers) { Add-GroupMemberSafe -GroupId $grpSec.Id -UserId $u2.Id }

# PAW Users
$grpPAW = New-OrGetGroup -DisplayName $g.PAWUsers -MailNickname "sg-paw-users" `
    -Description "Privileged Access Workstation users — Tier 0/1/2 admins and security team"
foreach ($u2 in (@($bgUser,$bg2User,$adminUser) + $t1Users + $t2Users + $secUsers | Where-Object { $_ })) {
    Add-GroupMemberSafe -GroupId $grpPAW.Id -UserId $u2.Id
}

# VPN Users
$grpVPN = New-OrGetGroup -DisplayName $g.VPNUsers -MailNickname "sg-vpn-users" `
    -Description "Corporate VPN access — all employees"
foreach ($u2 in $allEmployees) { Add-GroupMemberSafe -GroupId $grpVPN.Id -UserId $u2.Id }

Write-Status "Functional groups populated" -Type Success

# ── Office Location Groups ────────────────────────────────────────────────────
Write-Status "Location groups" -Type Header
$locationGroups = @(
    @{ Name = "SG-Location-NewYork";       Nick = "sg-location-newyork";       Cities = @("New York") }
    @{ Name = "SG-Location-SanFrancisco";  Nick = "sg-location-sanfrancisco";  Cities = @("San Francisco") }
    @{ Name = "SG-Location-Chicago";       Nick = "sg-location-chicago";       Cities = @("Chicago") }
    @{ Name = "SG-Location-Austin";        Nick = "sg-location-austin";        Cities = @("Austin") }
    @{ Name = "SG-Location-Remote";        Nick = "sg-location-remote";        Cities = @("Atlanta","Seattle","Boston","Denver") }
)
foreach ($loc in $locationGroups) {
    $grpLoc = New-OrGetGroup -DisplayName $loc.Name -MailNickname $loc.Nick `
        -Description "Employees based in $($loc.Cities -join '/')"
    $locUsers = @($allEmployees | Where-Object { $loc.Cities -contains $_.City })
    foreach ($u2 in $locUsers) { Add-GroupMemberSafe -GroupId $grpLoc.Id -UserId $u2.Id }
}
Write-Status "Location groups populated" -Type Success

# ── Enterprise App Access Groups ──────────────────────────────────────────────
Write-Status "App access groups" -Type Header
$appGroups = @(
    @{ Name = "SG-App-ITSM";         Nick = "sg-app-itsm";         Desc = "ITSM (ServiceNow-style) — IT + Operations users" }
    @{ Name = "SG-App-CRM";          Nick = "sg-app-crm";          Desc = "CRM (Salesforce-style) — Sales + Customer Success users" }
    @{ Name = "SG-App-HRIS";         Nick = "sg-app-hris";         Desc = "HRIS (Workday-style) — HR department users" }
    @{ Name = "SG-App-DataPlatform"; Nick = "sg-app-dataplatform"; Desc = "Data Platform — Data and Analytics department users" }
    @{ Name = "SG-App-GRC";          Nick = "sg-app-grc";          Desc = "GRC tooling — Compliance and Risk + Internal Audit users" }
)
$appDeptMap = @{
    "SG-App-ITSM"         = @("IT Infrastructure","Cybersecurity","Operations")
    "SG-App-CRM"          = @("Sales","Customer Success","Marketing")
    "SG-App-HRIS"         = @("Human Resources")
    "SG-App-DataPlatform" = @("Data and Analytics","Finance","Internal Audit")
    "SG-App-GRC"          = @("Compliance and Risk","Internal Audit","Legal")
}
foreach ($ag in $appGroups) {
    $grpApp = New-OrGetGroup -DisplayName $ag.Name -MailNickname $ag.Nick -Description $ag.Desc
    $targetDepts = if ($appDeptMap.ContainsKey($ag.Name)) { $appDeptMap[$ag.Name] } else { @() }
    $appUsers = @($allEmployees | Where-Object { $targetDepts -contains $_.Department })
    foreach ($u2 in $appUsers) { Add-GroupMemberSafe -GroupId $grpApp.Id -UserId $u2.Id }
}
Write-Status "App access groups populated" -Type Success

# ── Dynamic Group ─────────────────────────────────────────────────────────────
Write-Status "Dynamic group: $($g.Dynamic)" -Type Header
New-OrGetGroup -DisplayName $g.Dynamic -MailNickname "dyn-cybersecurity-dept" `
    -Description "Dynamic — auto-members when department = Cybersecurity" `
    -GroupType "Dynamic" `
    -MembershipRule '(user.department -eq "Cybersecurity")' | Out-Null

# ── M365 Leadership Group ─────────────────────────────────────────────────────
Write-Status "M365 Leadership Team" -Type Header
$grpM365 = New-OrGetGroup -DisplayName "M365-Leadership-Team" -MailNickname "m365-leadership-team" `
    -Description "Executive leadership Microsoft 365 group — Teams, SharePoint, Planner" `
    -GroupType "M365"
foreach ($exec in $execUsers) { Add-GroupMemberSafe -GroupId $grpM365.Id -UserId $exec.Id }
if ($adminUser) { Add-GroupMemberSafe -GroupId $grpM365.Id -UserId $adminUser.Id }

# ── CA Baseline Groups ────────────────────────────────────────────────────────
if ($caBaseline -and $caBaseline.Enabled) {
    Write-Status "CA Baseline groups ($($caBaselineGroupNames.Count) required)" -Type Header

    foreach ($groupName in $caBaselineGroupNames) {
        $nick  = Get-SafeMailNickname $groupName
        $group = New-OrGetGroup -DisplayName $groupName -MailNickname $nick `
            -Description "CA baseline support group — managed by Deploy-Groups.ps1"

        if ($groupName -eq "CA-BreakGlassAccounts - Exclude") {
            if ($bgUser)  { Add-GroupMemberSafe -GroupId $group.Id -UserId $bgUser.Id }
            if ($bg2User) { Add-GroupMemberSafe -GroupId $group.Id -UserId $bg2User.Id }
        }

        if ($groupName -eq "APP_Microsoft365_E5") {
            if ($adminUser) { Add-GroupMemberSafe -GroupId $group.Id -UserId $adminUser.Id }
            foreach ($u2 in $allEmployees) { Add-GroupMemberSafe -GroupId $group.Id -UserId $u2.Id }
        }
    }
    Write-Status "CA Baseline groups provisioned" -Type Success
}

Write-Status "Group deployment complete" -Type Success
Write-Host ""
Write-Host "  All Employees    : $($allEmployees.Count) members"
Write-Host "  Executives       : $($execUsers.Count)"
Write-Host "  Admin Tier 1/2   : $($t1Users.Count) T1 / $($t2Users.Count) T2 accounts"
Write-Host "  Departments      : $($u.Departments.Count) dept groups"
Write-Host "  Location groups  : $($locationGroups.Count)"
Write-Host "  App access groups: $($appGroups.Count)"
Write-Host "  CA baseline grps : $($caBaselineGroupNames.Count)"
