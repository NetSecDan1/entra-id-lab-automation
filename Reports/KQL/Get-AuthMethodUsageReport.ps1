<#
.SYNOPSIS
    What authentication methods are actually being used at sign-in — and
    how much of that is still a phishable method (SMS, voice call) versus
    phishing-resistant (FIDO2, Windows Hello, certificate).

.DESCRIPTION
    Expands the per-step AuthenticationDetails array on successful sign-ins
    to count usage by method, plus the overall single-factor vs
    multi-factor split (AuthenticationRequirement). Pairs well with
    Auth/Deploy-AuthStrengths.ps1 and the "Phishing-Resistant MFA" /
    "Corporate Standard MFA" strengths it creates — this report tells you
    whether real usage matches what your CA policies are supposed to be
    enforcing.

.EXAMPLE
    .\Reports\KQL\Get-AuthMethodUsageReport.ps1 -WorkspaceId <guid> -Open
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\config.json",
    [string]$WorkspaceId,
    [int]$Days = 7,
    [switch]$Open
)

. "$PSScriptRoot\..\..\Helpers\Common.ps1"
. "$PSScriptRoot\..\Helpers\KqlQuery.ps1"
. "$PSScriptRoot\..\Helpers\HtmlReportFramework.ps1"

$config = Get-Config -ConfigPath $ConfigPath
if (-not $WorkspaceId) {
    $WorkspaceId = if ($config.Reporting -and $config.Reporting.LogAnalyticsWorkspaceId) { [string]$config.Reporting.LogAnalyticsWorkspaceId } else { $null }
}
if (-not $WorkspaceId) {
    throw "No workspace ID provided. Pass -WorkspaceId, or set config.Reporting.LogAnalyticsWorkspaceId. See IaC/terraform to provision one."
}

Ensure-AzModules
Connect-LabAzure | Out-Null

$methodKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ResultType == "0"
| mv-expand AuthDetail = AuthenticationDetails
| extend Method = tostring(AuthDetail.authenticationMethod), Succeeded = tobool(AuthDetail.succeeded)
| where isnotempty(Method) and Succeeded == true
| summarize Uses = count(), DistinctUsers = dcount(UserPrincipalName) by Method
| order by Uses desc
"@

$requirementKql = @"
SigninLogs
| where TimeGenerated > ago($($Days)d)
| where ResultType == "0"
| summarize Count = count() by AuthenticationRequirement
| order by Count desc
"@

$methodRows      = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $methodKql      -Timespan (New-TimeSpan -Days $Days)
$requirementRows = Invoke-LabKqlQuery -WorkspaceId $WorkspaceId -Query $requirementKql -Timespan (New-TimeSpan -Days $Days)

$weakMethods   = @("sms", "voice", "voiceMobile", "voiceAlternateMobile", "voiceOffice")
$strongMethods = @("fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor", "deviceBasedPush")

$weakUses   = ($methodRows | Where-Object { $weakMethods -contains $_.Method } | Measure-Object -Property Uses -Sum).Sum
$strongUses = ($methodRows | Where-Object { $strongMethods -contains $_.Method } | Measure-Object -Property Uses -Sum).Sum
$singleFactor = ($requirementRows | Where-Object { $_.AuthenticationRequirement -eq "singleFactorAuthentication" } | Measure-Object -Property Count -Sum).Sum

$statTiles = @(
    @{ Label = "Phishing-resistant method uses"; Value = [int]($strongUses | ForEach-Object { $_ }); Tone = "good" }
    @{ Label = "Phishable method uses (SMS/voice)"; Value = [int]($weakUses | ForEach-Object { $_ }); Tone = if ($weakUses -gt 0) { "warn" } else { "good" } }
    @{ Label = "Single-factor sign-ins"; Value = [int]($singleFactor | ForEach-Object { $_ }); Tone = if ($singleFactor -gt 0) { "danger" } else { "good" } }
)

$outputPath = "$PSScriptRoot\..\Output\AuthMethodUsage-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
New-HtmlReport -Title "Authentication Method Usage" `
    -Subtitle "$($config.TenantDomain) — last $Days day(s), successful sign-ins only" `
    -StatTiles $statTiles `
    -Rows ([ordered]@{
        "Usage by method" = $methodRows
        "Single-factor vs multi-factor" = $requirementRows
    }) `
    -FooterNote "Source: SigninLogs (Log Analytics), AuthenticationDetails expanded per sign-in step. Weak = SMS/voice; strong = FIDO2/Windows Hello/certificate-based." `
    -OutputPath $outputPath `
    -Open:$Open
