# Zero Trust IAM Lab: Microsoft Entra ID

A tiered identity design built in a Microsoft Entra ID lab tenant (`lattimorede23.onmicrosoft.com`). It has four parts:

- A PowerShell deployment script that provisions users, groups, a group-based directory role, and Privileged Identity Management (PIM) settings through Microsoft Graph.
- An implementation guide covering the architecture and the Conditional Access design.
- A NIST SP 800-53 Rev 5 control mapping.
- Portal screenshots of the provisioned tenant.

**Persona note:** the org chart is a fictional staffing scenario modeled on a U.S. Soccer-style organization, using real public figures' names as stand-ins. It is a lab exercise only. It is not affiliated with, endorsed by, or built for U.S. Soccer or any named person.

---

## Implementation status

This table separates what the script does, what the screenshots show, and what exists only as design. It reflects what can be verified from this repository.

| Component | Status | How it is evidenced |
| :-- | :-- | :-- |
| 9 persona accounts | **Implemented by script** (`New-OrGetEntraUser`, Step 1) | [`01_tenant_users.png`](evidence/01_tenant_users.png) shows all 9 personas in the tenant |
| 3 security groups, one role-assignable | **Implemented by script** (Step 2; `IsAssignableToRole` on `Sec-USA-ExecManagement`) | [`02`](evidence/02_group_execmanagement.png), [`03`](evidence/03_group_playerrosters.png), [`04`](evidence/04_group_technicalops.png) show each group and its members |
| Global Reader assigned to `Sec-USA-ExecManagement` | **Implemented by script** (Step 4) | Script only; no screenshot of the role assignment |
| PIM: Global Administrator eligible-only assignment for the admin persona | **Implemented by script** (Step 6, `New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest`) | Script only; no screenshot or run log |
| PIM policy: 2-hour max activation, MFA + justification, approval required | **Implemented by script** (Step 6, three `Update-MgPolicyRoleManagementPolicyRule` calls) | Script only; no screenshot or run log |
| Azure RBAC Contributor for `Sec-USA-TechnicalOps` on the `sports-science` resource group | **Designed. Not performed by the published script.** Step 5 always logs a skip and contains no Az calls. | The author reports applying it to a real subscription; no Activity Log or IAM screenshot is in this repo |
| Conditional Access policies CA-01 to CA-04 | **Designed** in the [Implementation Guide](Implementation_Guide.md). The script creates none; Step 7 prints the group IDs for later CA targeting. | No policy export or screenshot in this repo |
| Access reviews, PIM notifications, Sentinel alert rule, 365-day log retention | **Design only** | Listed as gaps in [Compliance_Mapping.md](Compliance_Mapping.md#explicitly-called-out-gaps-do-not-represent-as-done-in-an-audit) |

The tenant screenshots show two accounts licensed for Microsoft Entra Suite, which includes Entra ID P2. That license supports PIM, Identity Protection risk policies, and Conditional Access. CA-03 (device compliance) additionally requires Intune, and no Intune licensing is shown.

---

## Repository contents

| File | Purpose |
| :-- | :-- |
| [`Deployment_Script.ps1`](Deployment_Script.ps1) | Idempotent Microsoft Graph PowerShell deployment. Re-running it skips objects that already exist. |
| [`Implementation_Guide.md`](Implementation_Guide.md) | Architecture: identity tiers, RBAC isolation design, logic for the four Conditional Access policies, PIM activation workflow, access reviews, threat model |
| [`Compliance_Mapping.md`](Compliance_Mapping.md) | Control-by-control mapping to NIST SP 800-53 Rev 5 (Moderate), with an explicit gaps section |
| [`evidence/`](evidence/) | Microsoft 365 admin center screenshots of the provisioned users and groups |

---

## Architecture at a glance

| Tier | Group | Personas | Grant | Standing privilege |
| :-- | :-- | :-- | :-- | :-- |
| 0: Privileged admin | None; individual PIM eligibility | Derrick Lattimore (persona) | Eligible Global Administrator | None. 2-hour activation with MFA, justification, and approval. |
| 1: Executive | `Sec-USA-ExecManagement` | Cindy Parlow Cone, JT Batson | Global Reader, tenant-wide | Read-only |
| 2: Technical Ops | `Sec-USA-TechnicalOps` | Mauricio Pochettino, Emma Hayes | Azure RBAC Contributor on `sports-science` (designed; see status table) | Bounded to one resource group |
| 3: Standard users | `Sec-USA-PlayerRosters` | Christian Pulisic, Weston McKennie, Sophia Smith, Trinity Rodman | None | None |

The [Implementation Guide](Implementation_Guide.md) explains each design decision. That includes why Tier 0 uses an individual PIM assignment rather than a group, and why Technical Ops isolation is enforced at the resource layer.

---

## Running the deployment script

Run it only against a disposable lab or demo tenant, never a production tenant.

```powershell
# PowerShell 7+. The script installs missing Microsoft.Graph modules on first run.
./Deployment_Script.ps1 `
    -TenantDomain "yourlabtenant.onmicrosoft.com" `
    -PimMaxActivationDuration "PT2H" `
    -RequireApprovalOnGaActivation $true
```

It connects with `Connect-MgGraph -UseDeviceCode`, requesting these scopes:

- `User.ReadWrite.All`
- `Group.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`
- `Directory.ReadWrite.All`

The `-AzureSubscriptionId` and `-SportsScienceResourceGroup` parameters are accepted, but Step 5 (Azure RBAC) does not currently use them.

PIM and the approval policy require Entra ID P2 (or Entra ID Governance) licensing in the tenant. The script does not name approvers. PIM then uses its default approvers, the Privileged Role Administrators and Global Administrators.

---

## Known gaps

These items are not built, and they are called out rather than hidden:

- **Azure RBAC assignment.** It is not performed by the script, and the published repo contains no evidence that it was applied.
- **Conditional Access policies.** Designed, but there is no deployment evidence in the repo.
- **Offboarding and account-disable automation** (AC-2(3)).
- **Sentinel / Log Analytics alert** for anomalous PIM activation. The query logic is designed, not built.
- **365-day log retention.** The target is specified but not provisioned.
- **Tenant administrator accounts.** The tenant's own admin accounts (visible in `01_tenant_users.png`) are outside the tiering model. They should be documented as break-glass or emergency-access accounts and excluded from Conditional Access accordingly.

The full list is in the [Explicitly Called-Out Gaps](Compliance_Mapping.md#explicitly-called-out-gaps-do-not-represent-as-done-in-an-audit) section of the control mapping.

---

**Author:** Derrick Lattimore Jr. · B.S. Information Security, Shawnee State University · Microsoft Certified: Identity and Access Administrator Associate (SC-300)
