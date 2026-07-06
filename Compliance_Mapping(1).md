# NIST SP 800-53 Rev. 5 (Moderate Baseline) — Control Mapping

### Zero Trust Entra ID Identity & Access Management Deployment

**Scope:** Maps every automated action in `Deployment_Script.ps1` and every policy defined in `Implementation_Guide.md` to the specific NIST SP 800-53 Rev. 5 control(s) it implements, partially implements, or supports as compensating evidence.

**How to read the "Satisfaction" column:**

- **Full** — the technical control alone satisfies the NIST control intent for this environment.  
- **Partial** — the technical control is necessary but not sufficient; a documented organizational process (policy, review cadence, personnel action) is required alongside it. This is called out explicitly rather than glossed over, because an assessor will ask for the missing half regardless of what the automation does.

---

## AC-2 — Account Management

| Sub-control | Implementation | Evidence Source | Satisfaction |
| :---- | :---- | :---- | :---- |
| **AC-2** (base) | `New-OrGetEntraUser` idempotently provisions all 9 personas with defined `JobTitle`, `Department`, `UsageLocation`; account creation is scriptable/repeatable and produces an auditable `AuditLogs` entry per user object created | Entra ID `AuditLogs` (`Add user`) | Partial — automation covers creation; a documented account-management policy (naming standards, sponsor/approval requirement) must exist alongside it |
| **AC-2(1)** Automated System Account Management | `Deployment_Script.ps1` is the single, version-controlled source of truth for account/group/role state — re-running it is idempotent (SKIP branches) rather than duplicative | Script source control history | Full |
| **AC-2(3)** Disable Accounts | Not implemented in this script (out of scope for initial provisioning) | — | **Gap** — requires a companion offboarding script (`Disable-MgUser` / `AccountEnabled = $false`) triggered from HR termination workflow |
| **AC-2(4)** Automated Audit Actions | Every `New-MgUser`, `New-MgGroup`, `New-MgGroupMember`, and role-assignment call generates a corresponding Graph `AuditLogs` entry automatically — no opt-in required | Entra ID `AuditLogs` / `directoryAudits` | Full |
| **AC-2(7)** Privileged User Accounts | Derrick's account is provisioned identically to standard users at creation time; privilege is layered on **exclusively** via the PIM eligibility (Section 7 of script), not via account attributes — privileged and non-privileged account lifecycle are cleanly separable | PIM eligibility schedule (`unifiedRoleEligibilityScheduleRequest`) | Full |
| **AC-2(12)** Account Monitoring for Atypical Usage | CA-04 (Risk-Based Sign-In) plus the PIM activation-frequency alert query described in `Implementation_Guide.md §5.3` | Sentinel/Log Analytics alert rule | Partial — requires the alert rule to be deployed and tuned; script only creates the identity substrate it depends on |

---

## AC-3 — Access Enforcement

| Implementation | Evidence Source | Satisfaction |
| :---- | :---- | :---- |
| Every access decision in this environment is enforced by the platform (Entra ID token issuance \+ Conditional Access \+ Azure RBAC evaluation), not by application-layer logic — access enforcement is centralized and cannot be bypassed by an individual app | Conditional Access `Sign-in logs` (grant/block decision per request) | Full |
| Tier isolation (Section 3, Implementation Guide) means AC-3 is enforced at two independent layers simultaneously: directory role (Graph) and Azure RBAC (ARM) — a failure in one plane does not collapse the other | Azure `Activity Log` (`Microsoft.Authorization/roleAssignments`) \+ Entra `AuditLogs` | Full |

---

## AC-6 — Least Privilege

| Sub-control | Implementation | Evidence Source | Satisfaction |
| :---- | :---- | :---- | :---- |
| **AC-6** (base) | Tier 3 (Players) receive no role or RBAC grant of any kind — the floor of least privilege in this design. Tier 1 is read-only. Tier 2 is scoped to one Resource Group. | Group membership \+ role assignment audit trail | Full |
| **AC-6(1)** Authorize Access to Security Functions | Only Derrick (via PIM activation) can ever hold Global Administrator; no other persona or group in the tenant has a path to a security-relevant role | PIM eligibility scoped to a single named principal | Full |
| **AC-6(2)** Non-Privileged Access for Nonsecurity Functions | Derrick's day-to-day identity carries **no** standing privilege — he operates as a non-privileged account except during an active, time-boxed PIM session | PIM eligibility (not active assignment) on Derrick's principal | Full |
| **AC-6(5)** Privileged Accounts | Global Administrator is restricted to exactly one eligible principal, tenant-wide, with mandatory MFA \+ justification \+ second-admin approval on every activation, and a 2-hour maximum session | Role Management Policy rules: `Expiration_EndUser_Assignment`, `Enablement_EndUser_Assignment`, `Approval_EndUser_Assignment` | Full |
| **AC-6(9)** Log Use of Privileged Functions | Every PIM activation (request → MFA → approval → activation → expiration) is logged to `AuditLogs` and PIM activity logs per `Implementation_Guide.md §5.3` | Entra ID `PIM audit history` | Full |
| **AC-6(10)** Prohibit Non-Privileged Users from Executing Privileged Functions | Enforced structurally: Tiers 1–3 have no path — group-based, not user-based — to any role that could execute privileged directory or resource functions | Group-to-role mapping (Section 5 of `Deployment_Script.ps1`) | Full |

---

## AC-17 — Remote Access

| Sub-control | Implementation | Evidence Source | Satisfaction |
| :---- | :---- | :---- | :---- |
| **AC-17** (base) | All access in this tenant is, by definition, remote/cloud access — every session is mediated by Conditional Access regardless of network origin, satisfying "remote access is monitored and controlled" | CA policy assignment report (`CA-01` through `CA-04`) | Full |
| **AC-17(1)** Monitoring and Control | CA-04 (Risk-Based Sign-In) evaluates every remote session against Identity Protection risk signal in real time | Identity Protection `riskyUsers` / `riskDetections` | Full |
| **AC-17(2)** Protection of Confidentiality/Integrity | CA-01 (MFA baseline) plus CA-03 (device compliance) jointly ensure remote sessions originate only from an authenticated, compliant endpoint | Sign-in logs — `authenticationRequirement`, `deviceDetail.isCompliant` | Full |
| **AC-17(4)** Privileged Commands / Access | Derrick's remote administrative access (Global Administrator) is additionally bounded by geo-fence (CA-02), device compliance (CA-03), MFA (CA-01), and the PIM 2-hour cap — the highest-risk remote access path in the tenant carries the most controls stacked on it | Combined CA \+ PIM audit trail | Full |

---

## IA-2 — Identification and Authentication (Organizational Users)

| Sub-control | Implementation | Evidence Source | Satisfaction |
| :---- | :---- | :---- | :---- |
| **IA-2** (base) | Every persona is provisioned as a uniquely identifiable Entra ID object (`userPrincipalName`, immutable `Id`) — no shared or generic accounts | `Get-MgUser` object inventory | Full |
| **IA-2(1)** MFA to Privileged Accounts | CA-01 mandates MFA tenant-wide; PIM `Enablement_EndUser_Assignment` additionally mandates a **fresh** MFA challenge specifically at Global Administrator activation | CA sign-in log \+ PIM activation record | Full |
| **IA-2(2)** MFA to Non-Privileged Accounts | CA-01 applies identically to Tiers 1–3; there is no MFA exemption for non-privileged personas | CA sign-in log | Full |
| **IA-2(5)** Individual Authentication with Group Authentication | Group membership (`Sec-USA-*`) determines *entitlement*, never *authentication* — each user still authenticates individually; groups are never used as a shared credential | Sign-in logs keyed to individual `userId`, not group `id` | Full |
| **IA-2(8)** Access to Accounts — Replay Resistant | Satisfied by Entra ID's underlying modern-auth token protocols (OAuth2/OIDC), inherited platform capability, not something this script configures directly | Entra ID platform documentation | Full (inherited) |

---

## Supporting Controls (Cross-Referenced, Not Explicitly Requested but Directly Relevant)

| Control | Implementation | Satisfaction |
| :---- | :---- | :---- |
| **AC-4** Information Flow Enforcement | Azure RBAC scope boundary (`/sports-science` only) enforces that Technical Ops data flow cannot cross into corporate/financial resource groups | Full |
| **AC-5** Separation of Duties | PIM approval workflow requires a *second*, distinct Privileged Role Administrator to approve Derrick's own activation — no self-approval path exists | Full |
| **AC-7** Unsuccessful Logon Attempts | Inherited Entra ID Smart Lockout — not configured by this script, verify tenant-level Smart Lockout thresholds separately | Partial — not covered by this script |
| **AU-2 / AU-12** Audit Events / Generation | All Graph write operations (user/group/role/PIM) generate `AuditLogs` entries automatically; this script performs no custom audit suppression | Full |
| **AU-6** Audit Review, Analysis, and Reporting | Sentinel/Log Analytics alert query (Implementation Guide §5.3) for anomalous PIM activation frequency and out-of-geofence activation | Partial — alert rule must be deployed and actively monitored; not a one-time setup |
| **CM-6** Configuration Settings | Role Management Policy (2-hour cap, MFA, justification, approval) is a documented, version-controlled configuration baseline for the Global Administrator role | Full |
| **IA-5** Authenticator Management | Temporary passwords are randomized per-user and forced to change at first sign-in (`ForceChangePasswordNextSignIn = $true`); production deployment should replace this with Temporary Access Pass (TAP) | Partial — script uses interim password flow, notes passwordless upgrade path |
| **PS-4 / PS-5** Personnel Termination/Transfer | Not implemented — see AC-2(3) gap above | **Gap** |
| **SC-7** Boundary Protection | CA-02 geo-fence functions as a logical (identity-layer) boundary control, complementary to but distinct from network-layer SC-7 controls | Partial — identity-layer boundary only, not a substitute for network segmentation |

---

## Explicitly Called-Out Gaps (Do Not Represent as "Done" in an Audit)

1. **AC-2(3) Account Disablement / Offboarding** — this deployment provisions accounts; it does not include a leaver/termination workflow. A companion script triggered from an HR system-of-record event is required before this environment could be represented as fully AC-2 compliant.  
2. **AU-6 Continuous Monitoring** — the alert logic described in the Implementation Guide is a design, not a deployed Sentinel rule. Treat the PIM/CA logging as necessary raw material for AU-6, not as AU-6 itself, until the analytics rule is actually built and tested.  
3. **AC-7 Lockout Thresholds** — this script does not touch tenant-level Smart Lockout or custom banned-password-list configuration; verify separately.  
4. **Retention configuration** — `Implementation_Guide.md §6` specifies a 365-day retention target for audit/sign-in logs; this script does not configure Log Analytics retention or Entra ID diagnostic settings. That is a separate, required deployment step (`Set-AzDiagnosticSetting` against the tenant's diagnostic categories).

Representing these four items as solved would overstate this environment's compliance posture. They are the natural "Phase 2" of this build.  
