# Zero Trust Identity & Access Management — Microsoft Entra ID Reference Build

A production-style Microsoft Entra ID Zero Trust identity architecture, built end-to-end: automated provisioning, Conditional Access design, Privileged Identity Management (PIM), and a NIST SP 800-53 Rev. 5 (Moderate) control mapping.

Designed and documented by **Derrick Lattimore** — Information Security major, Business Administration minor.

---

## What this is

A reference IAM environment modeled on a real-world organizational footprint: executives, technical/operational staff, standard end users, and a single privileged security admin role. It demonstrates the core discipline of Zero Trust identity engineering — least privilege by default, group-based (not user-based) entitlement, control-plane segregation between Entra ID directory roles and Azure RBAC, and fully time-boxed privileged access via PIM.

**Persona roster note:** the org chart (Executive Management, Technical Operations/Coaching, Player Rosters, Cloud Infrastructure Security) uses a U.S. Soccer-style staffing scenario with real public figures' names as a realistic stand-in for a diverse role hierarchy. This is a fictional lab exercise for architecture demonstration — it is not affiliated with, endorsed by, or built on behalf of U.S. Soccer or any named individual.

---

## Repository contents

| File | Purpose |
| :---- | :---- |
| [`Deployment_Script.ps1`](http://./Deployment_Script.ps1) | Idempotent Microsoft Graph \+ Azure PowerShell (Az) automation: provisions all 9 identities, 3 security groups (one role-assignable), group memberships, the Global Reader directory role assignment, the Azure RBAC Contributor grant scoped to `/sports-science`, and the full PIM eligibility \+ 2-hour activation policy for the privileged admin role. |
| [`Implementation_Guide.md`](http://./Implementation_Guide.md) | The architecture itself: identity tiering model, RBAC isolation strategy, the exact logical conditions behind all 4 Conditional Access policies (MFA baseline, geo-fencing, device compliance, risk-based sign-in), the PIM JIT activation workflow, access-review cadence, and a threat-model summary. |
| [`Compliance_Mapping.md`](http://./Compliance_Mapping.md) | A control-by-control matrix mapping every automated step and policy to NIST SP 800-53 Rev. 5 Moderate baseline controls (AC-2, AC-3, AC-6, AC-6(5), AC-17, IA-2, and supporting controls), including an explicit gaps section — no control is claimed as "done" without evidence. |

---

## Architecture at a glance

| Tier | Group | Personas | Grant | Standing Privilege |
| :---- | :---- | :---- | :---- | :---- |
| 1 — Executive | `Sec-USA-ExecManagement` | Cindy Parlow Cone (President), JT Batson (CEO) | Global Reader, tenant-wide | Read-only only |
| 2 — Technical Ops | `Sec-USA-TechnicalOps` | Mauricio Pochettino, Emma Hayes | Azure RBAC Contributor, scoped to `/sports-science` | Bounded to one Resource Group |
| 3 — Standard Users | `Sec-USA-PlayerRosters` | Christian Pulisic, Weston McKennie, Sophia Smith, Trinity Rodman | None | None |
| 0 — Privileged Admin | *(individual PIM eligibility, no group)* | Derrick Lattimore | Eligible Global Administrator | **Zero** — 2-hour JIT activation only, MFA \+ justification \+ second-admin approval required |

Full rationale for every design decision — including why Tier 0 is deliberately excluded from group-based assignment, and why RBAC isolation is enforced at the resource layer rather than the identity layer — is in `Implementation_Guide.md`.

---

## Running the deployment

\# 1\. Install prerequisites (script will also self-check on run)

Install-Module Microsoft.Graph, Az \-Scope CurrentUser \-Force

\# 2\. Run against a disposable lab/demo tenant — never a production tenant

./Deployment\_Script.ps1 \`

    \-TenantDomain "yourlabtenant.onmicrosoft.com" \`

    \-AzureSubscriptionId "\<your-sub-id\>" \`

    \-SportsScienceResourceGroup "sports-science" \`

    \-PimMaxActivationDuration "PT2H" \`

    \-RequireApprovalOnGaActivation $true

The script is fully idempotent — safe to re-run; existing users, groups, memberships, and role assignments are detected and skipped rather than duplicated.

**Required Graph scopes:** `User.ReadWrite.All`, `Group.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All` **Required modules:** `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Identity.Governance`, `Az.Accounts`, `Az.Resources`

---

## Known scope boundaries (Phase 2\)

This build intentionally stops at identity provisioning and access-tiering. Not yet included, and called out explicitly rather than hidden:

- Offboarding / account-disable automation (AC-2(3))  
- A deployed Sentinel/Log Analytics alert rule for anomalous PIM activation (the query logic is designed, not built)  
- Log retention configuration (365-day target specified, not yet provisioned)  
- Tenant-level Smart Lockout / banned-password-list verification

See the **Explicitly Called-Out Gaps** section of `Compliance_Mapping.md` for the full list.

---

## Author

**Derrick Lattimore** Senior Cyber GRC Architect (portfolio role) · Information Security & Business Administration  
