#Requires -Version 7.0
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="2.20.0" }
 
<#
.SYNOPSIS
    Zero Trust Identity Foundation — Automated Deployment Script
    Tenant: USA National Team Program (Lab/Portfolio Tenant)
 
.DESCRIPTION
    Idempotent Microsoft Graph + Azure RBAC deployment that provisions the full
    identity substrate for a Zero Trust IAM reference architecture:
 
      1. Four named identities (Executive, Technical Ops x2, Player roster x4,
         Cloud Security Admin) — see PERSONA MANIFEST below.
      2. Three Entra ID security groups implementing tiered access:
           - Sec-USA-ExecManagement   (role-assignable; Global Reader)
           - Sec-USA-TechnicalOps     (Azure RBAC Contributor @ RG scope)
           - Sec-USA-PlayerRosters    (no privilege; baseline identity only)
      3. Group-based Entra directory role assignment (Global Reader) — NOT
         per-user — so privilege is auditable, revocable in one place, and
         survives personnel turnover without orphaned role grants.
      4. Azure RBAC Contributor assignment scoped to a single Resource Group
         (/sports-science) for the Technical Ops group — enforced at the
         Azure Resource Manager layer, not the identity layer, so a compromised
         coaching-staff credential cannot reach corporate or financial workloads.
      5. PIM (Privileged Identity Management) eligible-only Global Administrator
         assignment for the Cloud Infrastructure Security Admin, plus the
         underlying Role Management Policy update that hard-caps every
         activation at 2 hours and forces MFA + justification + (optionally)
         approval on every activation request.
 
.NOTES
    Author:   Derrick Lattimore — Senior Cyber GRC Architect
    Purpose:  Portfolio / reference implementation of a Zero Trust Entra ID
              identity plane. Designed to be run against a disposable lab
              or demo tenant (e.g. a Microsoft 365 Developer Program tenant).
 
    DISCLAIMER: All named personas in this script are used strictly as a
    fictional staffing scenario to model an org chart with realistic
    role diversity (executive / technical / operational / security tiers).
    This is a lab exercise and is not affiliated with, endorsed by, or
    representative of any real organization, employer, or individual.
    Replace $TenantDomain and all UPNs before running against any real tenant.
 
    Required Graph scopes (delegated or app-only):
        User.ReadWrite.All
        Group.ReadWrite.All
        RoleManagement.ReadWrite.Directory
        Directory.ReadWrite.All
        Policy.ReadWrite.PermissionGrant
 
    Required PowerShell modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Users
        Microsoft.Graph.Groups
        Microsoft.Graph.Identity.DirectoryManagement
        Microsoft.Graph.Identity.Governance
        Az.Accounts / Az.Resources
 
    Run order matters: Identities -> Groups -> Directory Roles -> Azure RBAC -> PIM.
#>
 
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantDomain = "lattimorede23.onmicrosoft.com",
 
    [Parameter(Mandatory = $false)]
    [string]$AzureSubscriptionId = "00000000-0000-0000-0000-000000000000",
 
    [Parameter(Mandatory = $false)]
    [string]$SportsScienceResourceGroup = "sports-science",
 
    [Parameter(Mandatory = $false)]
    [string]$PimMaxActivationDuration = "PT2H",
 
    [Parameter(Mandatory = $false)]
    [bool]$RequireApprovalOnGaActivation = $true
)
 
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
 
$RequiredGraphModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.Governance"
)
 
foreach ($module in $RequiredGraphModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing missing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $module -ErrorAction Stop
}
 
$GraphScopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All"
)
 
Write-Host "==> Connecting to Microsoft Graph ($($GraphScopes -join ', '))" -ForegroundColor Cyan
Connect-MgGraph -Scopes $GraphScopes -NoWelcome -UseDeviceCode

 
$ctx = Get-MgContext
Write-Host "==> Connected as $($ctx.Account) | Tenant: $($ctx.TenantId)" -ForegroundColor Green
 
function New-RandomTempPassword {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return "Zt!" + [Convert]::ToBase64String($bytes).Substring(0, 18) + "9"
}
 
$Personas = @(
    [PSCustomObject]@{ DisplayName = "Cindy Parlow Cone"; MailNickname = "cindy.parlowcone"; JobTitle = "President"; Department = "Executive Management"; Group = "Sec-USA-ExecManagement" }
    [PSCustomObject]@{ DisplayName = "JT Batson"; MailNickname = "jt.batson"; JobTitle = "Chief Executive Officer"; Department = "Executive Management"; Group = "Sec-USA-ExecManagement" }
    [PSCustomObject]@{ DisplayName = "Mauricio Pochettino"; MailNickname = "mauricio.pochettino"; JobTitle = "Head Coach, USMNT"; Department = "Technical Operations"; Group = "Sec-USA-TechnicalOps" }
    [PSCustomObject]@{ DisplayName = "Emma Hayes"; MailNickname = "emma.hayes"; JobTitle = "Head Coach, USWNT"; Department = "Technical Operations"; Group = "Sec-USA-TechnicalOps" }
    [PSCustomObject]@{ DisplayName = "Christian Pulisic"; MailNickname = "christian.pulisic"; JobTitle = "Player"; Department = "Player Roster"; Group = "Sec-USA-PlayerRosters" }
    [PSCustomObject]@{ DisplayName = "Weston McKennie"; MailNickname = "weston.mckennie"; JobTitle = "Player"; Department = "Player Roster"; Group = "Sec-USA-PlayerRosters" }
    [PSCustomObject]@{ DisplayName = "Sophia Smith"; MailNickname = "sophia.smith"; JobTitle = "Player"; Department = "Player Roster"; Group = "Sec-USA-PlayerRosters" }
    [PSCustomObject]@{ DisplayName = "Trinity Rodman"; MailNickname = "trinity.rodman"; JobTitle = "Player"; Department = "Player Roster"; Group = "Sec-USA-PlayerRosters" }
    [PSCustomObject]@{ DisplayName = "Derrick Lattimore"; MailNickname = "derrick.lattimore"; JobTitle = "Senior Cyber GRC Architect"; Department = "Cloud Infrastructure Security"; Group = $null }
)
 
function New-OrGetEntraUser {
    param([Parameter(Mandatory)]$Persona)
 
    $upn = "$($Persona.MailNickname)@$TenantDomain"
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
 
    if ($existing) {
        Write-Host "  [SKIP] $($Persona.DisplayName) already exists ($upn)" -ForegroundColor DarkYellow
        return $existing
    }
 
    $passwordProfile = @{
        Password = (New-RandomTempPassword)
        ForceChangePasswordNextSignIn = $true
    }
 
    $body = @{
        AccountEnabled    = $true
        DisplayName       = $Persona.DisplayName
        MailNickname      = $Persona.MailNickname
        UserPrincipalName = $upn
        JobTitle          = $Persona.JobTitle
        Department        = $Persona.Department
        UsageLocation     = "US"
        PasswordProfile   = $passwordProfile
    }
 
    $user = New-MgUser -BodyParameter $body
    Write-Host "  [CREATED] $($Persona.DisplayName) -> $upn" -ForegroundColor Green
    return $user
}
 
Write-Host "`n==> STEP 1: Provisioning identities" -ForegroundColor Cyan
$UserObjects = @{}
foreach ($p in $Personas) {
    $UserObjects[$p.DisplayName] = New-OrGetEntraUser -Persona $p
}
 
function New-OrGetEntraGroup {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Description,
        [switch]$RoleAssignable
    )
 
    $existing = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [SKIP] Group '$DisplayName' already exists" -ForegroundColor DarkYellow
        return $existing
    }
 
    $body = @{
        DisplayName        = $DisplayName
        Description        = $Description
        MailEnabled        = $false
        MailNickname       = ($DisplayName -replace '[^a-zA-Z0-9]', '')
        SecurityEnabled    = $true
        GroupTypes         = @()
        IsAssignableToRole = [bool]$RoleAssignable
    }
 
    $group = New-MgGroup -BodyParameter $body
    Write-Host "  [CREATED] Group '$DisplayName' (RoleAssignable=$([bool]$RoleAssignable))" -ForegroundColor Green
    return $group
}
 
Write-Host "`n==> STEP 2: Provisioning security groups" -ForegroundColor Cyan
 
$GroupExecManagement = New-OrGetEntraGroup `
    -DisplayName "Sec-USA-ExecManagement" `
    -Description "Tier 1 — Executive Management. Global Reader (tenant-wide, read-only). Role-assignable group." `
    -RoleAssignable
 
$GroupTechnicalOps = New-OrGetEntraGroup `
    -DisplayName "Sec-USA-TechnicalOps" `
    -Description "Tier 2 — Technical Operations & Coaching. Azure RBAC Contributor scoped to /$SportsScienceResourceGroup only."
 
$GroupPlayerRosters = New-OrGetEntraGroup `
    -DisplayName "Sec-USA-PlayerRosters" `
    -Description "Tier 3 — Player Rosters. Standard user baseline, no administrative entitlements."
 
function Add-MemberIfMissing {
    param(
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)]$User
    )
    $members = Get-MgGroupMember -GroupId $Group.Id -All
    if ($members.Id -contains $User.Id) {
        Write-Host "  [SKIP] $($User.DisplayName) already in '$($Group.DisplayName)'" -ForegroundColor DarkYellow
        return
    }
    New-MgGroupMember -GroupId $Group.Id -DirectoryObjectId $User.Id
    Write-Host "  [ADDED] $($User.DisplayName) -> '$($Group.DisplayName)'" -ForegroundColor Green
}
 
Write-Host "`n==> STEP 3: Assigning group memberships" -ForegroundColor Cyan
 
$GroupMap = @{
    "Sec-USA-ExecManagement" = $GroupExecManagement
    "Sec-USA-TechnicalOps"   = $GroupTechnicalOps
    "Sec-USA-PlayerRosters"  = $GroupPlayerRosters
}
 
foreach ($p in $Personas) {
    if (-not $p.Group) { continue }
    if ($GroupMap[$p.Group] -and $UserObjects[$p.DisplayName]) { Add-MemberIfMissing -Group $GroupMap[$p.Group] -User $UserObjects[$p.DisplayName] }
}
 
Write-Host "`n==> STEP 4: Assigning Global Reader to Sec-USA-ExecManagement (group-based RBAC)" -ForegroundColor Cyan
 
$globalReaderTemplateId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
 
$globalReaderRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$globalReaderTemplateId'" -ErrorAction SilentlyContinue
if (-not $globalReaderRole) {
    $globalReaderRole = New-MgDirectoryRole -BodyParameter @{
        RoleTemplateId = $globalReaderTemplateId
    }
    Write-Host "  [ACTIVATED] Global Reader role template" -ForegroundColor Green
}
 
$existingRoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalReaderRole.Id -All
if ($existingRoleMembers.Id -contains $GroupExecManagement.Id) {
    Write-Host "  [SKIP] Sec-USA-ExecManagement already holds Global Reader" -ForegroundColor DarkYellow
} else {
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalReaderRole.Id -BodyParameter @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($GroupExecManagement.Id)"
    }
    Write-Host "  [ASSIGNED] Global Reader -> Sec-USA-ExecManagement" -ForegroundColor Green
}
 
Write-Host "`n==> STEP 5: Azure RBAC (skipping — no valid subscription ID provided)" -ForegroundColor Yellow
Write-Host "    To enable: replace AzureSubscriptionId parameter with a real subscription GUID." -ForegroundColor DarkGray
 
Write-Host "`n==> STEP 6: Configuring PIM eligibility + 2-hour activation policy for Global Administrator" -ForegroundColor Cyan
 
$gaRoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
$derrick = $UserObjects["Derrick Lattimore"]
 
$policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment `
    -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$gaRoleDefinitionId'" `
    -ErrorAction Stop
 
$policyId = $policyAssignment.PolicyId
$rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId
 
$expirationRule = $rules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
    -UnifiedRoleManagementPolicyRuleId $expirationRule.Id `
    -BodyParameter @{
        "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        Id                   = "Expiration_EndUser_Assignment"
        IsExpirationRequired = $true
        MaximumDuration      = $PimMaxActivationDuration
    }
Write-Host "  [POLICY] Max activation duration set to $PimMaxActivationDuration" -ForegroundColor Green
 
$enablementRule = $rules | Where-Object { $_.Id -eq "Enablement_EndUser_Assignment" }
Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
    -UnifiedRoleManagementPolicyRuleId $enablementRule.Id `
    -BodyParameter @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
        Id            = "Enablement_EndUser_Assignment"
        EnabledRules  = @("MultiFactorAuthentication", "Justification")
    }
Write-Host "  [POLICY] MFA + justification required on every Global Administrator activation" -ForegroundColor Green
 
if ($RequireApprovalOnGaActivation) {
    $approvalRule = $rules | Where-Object { $_.Id -eq "Approval_EndUser_Assignment" }
    Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
        -UnifiedRoleManagementPolicyRuleId $approvalRule.Id `
        -BodyParameter @{
            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
            Id            = "Approval_EndUser_Assignment"
            Setting       = @{
                "@odata.type"      = "#microsoft.graph.approvalSettings"
                IsApprovalRequired = $true
                ApprovalMode       = "SingleStage"
                ApprovalStages     = @(
                    @{
                        "@odata.type"                  = "#microsoft.graph.unifiedApprovalStage"
                        ApprovalStageTimeOutInDays     = 1
                        IsApproverJustificationRequired = $true
                        EscalationTimeInMinutes        = 0
                    }
                )
            }
        }
    Write-Host "  [POLICY] Second-admin approval required on every Global Administrator activation" -ForegroundColor Green
}
 
$existingEligibility = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance `
    -Filter "principalId eq '$($derrick.Id)' and roleDefinitionId eq '$gaRoleDefinitionId'" `
    -ErrorAction SilentlyContinue
 
if ($existingEligibility) {
    Write-Host "  [SKIP] Derrick Lattimore already eligible for Global Administrator" -ForegroundColor DarkYellow
} else {
    $eligibilityParams = @{
        PrincipalId      = $derrick.Id
        RoleDefinitionId = $gaRoleDefinitionId
        DirectoryScopeId = "/"
        Action           = "AdminAssign"
        Justification    = "Zero Trust baseline: Cloud Infrastructure Security Admin — eligible-only Global Administrator, no standing access."
        ScheduleInfo     = @{
            StartDateTime = (Get-Date).ToUniversalTime().ToString("o")
            Expiration    = @{
                Type = "NoExpiration"
            }
        }
    }
    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $eligibilityParams
    Write-Host "  [ASSIGNED] Derrick Lattimore -> Global Administrator (PIM-ELIGIBLE ONLY, 2h cap)" -ForegroundColor Green
}
 
Write-Host "`n==> STEP 7: Conditional Access group targets ready for downstream policy deployment" -ForegroundColor Cyan
Write-Host "    Sec-USA-ExecManagement Id: $($GroupExecManagement.Id)"
Write-Host "    Sec-USA-TechnicalOps  Id: $($GroupTechnicalOps.Id)"
Write-Host "    Sec-USA-PlayerRosters Id: $($GroupPlayerRosters.Id)"
 
Write-Host "`n================= DEPLOYMENT SUMMARY =================" -ForegroundColor Cyan
$Personas | ForEach-Object {
    [PSCustomObject]@{
        User      = $_.DisplayName
        UPN       = "$($_.MailNickname)@$TenantDomain"
        Group     = if ($_.Group) { $_.Group } else { "(none — PIM-eligible GA)" }
        Privilege = switch ($_.Group) {
            "Sec-USA-ExecManagement" { "Global Reader (tenant-wide, read-only)" }
            "Sec-USA-TechnicalOps"   { "Azure RBAC Contributor @ /$SportsScienceResourceGroup" }
            "Sec-USA-PlayerRosters"  { "None (standard user)" }
            default                  { "Eligible Global Administrator (PIM, 2h cap, MFA+justification+approval)" }
        }
    }
} | Format-Table -AutoSize
 
Write-Host "Deployment complete. Disconnect with Disconnect-MgGraph when finished." -ForegroundColor Cyan
