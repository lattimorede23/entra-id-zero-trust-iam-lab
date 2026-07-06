# Zero Trust Identity & Access Management — Technical Architecture

### Microsoft Entra ID Reference Implementation

**Author:** Derrick Lattimore, Senior Cyber GRC Architect **Scope:** Entra ID tenant identity plane, Azure RBAC boundary, Conditional Access, and Privileged Identity Management (PIM) **Status:** Reference architecture — lab/portfolio deployment

**Disclaimer:** The persona roster (Executive Management, Technical Operations, Player Rosters) is a fictional staffing scenario used to model an organization with realistic tiering — executive, operational, end-user, and privileged-admin roles. This is a demonstration of IAM architecture patterns and is not affiliated with, or representative of, any real organization.

---

## 1\. Design Principles

This architecture treats identity as the primary security perimeter. Four principles govern every decision below:

**Never trust, always verify.** No user, device, or session is implicitly trusted regardless of network location. Every access request is evaluated against identity signal, device signal, location signal, and risk signal at request time — not once at login.

**Least privilege by default, standing privilege by exception.** Every persona in this tenant holds the minimum entitlement required for their function. The only tier with administrative capability (Tier 0\) holds **zero permanent privilege** — it is entirely time-boxed and activation-gated through PIM.

**Group-based entitlement, not user-based entitlement.** Every role and RBAC assignment in this tenant is granted to a security group, never directly to a user object. This makes access reviewable in one place, makes offboarding a single group-membership removal, and prevents the "orphaned direct assignment" drift that shows up in every access-review finding.

**Segregation of control planes.** Entra ID directory roles (Graph plane) and Azure RBAC roles (ARM plane) are two distinct authorization systems. Global Reader governs what a principal can *read in the directory*. Azure RBAC Contributor governs what a principal can *do to Azure resources*. Conflating the two is a common architectural mistake — this design keeps them intentionally separate so a Technical Ops compromise cannot pivot into directory reconnaissance, and an Exec Management compromise cannot pivot into resource manipulation.

---

## 2\. Identity Tiering Model

| Tier | Group | Personas | Authorization Plane | Grant | Standing Privilege |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **1 — Executive** | `Sec-USA-ExecManagement` | Cindy Parlow Cone (President), JT Batson (CEO) | Entra ID directory role | Global Reader, tenant-wide | Yes — read-only only |
| **2 — Technical Ops** | `Sec-USA-TechnicalOps` | Mauricio Pochettino, Emma Hayes | Azure RBAC | Contributor, scoped to `/sports-science` RG only | Yes — bounded to one RG |
| **3 — Standard Users** | `Sec-USA-PlayerRosters` | Pulisic, McKennie, Smith, Rodman | None | No role, no RBAC | No — baseline identity only |
| **0 — Privileged Admin** | *(none — individual PIM eligibility)* | Derrick Lattimore | Entra ID directory role via PIM | Eligible Global Administrator | **None.** 100% JIT, 2-hour cap |

Tier 0 is intentionally excluded from group-based assignment. Global Administrator is the highest-impact role in the tenant; bundling it into a group (even a role-assignable one) adds an indirection layer that complicates access reviews for the single most sensitive grant in the environment. A named, individual PIM-eligible assignment is more auditable for a role this powerful, and matches Microsoft's own guidance to keep permanent Global Administrator membership at or near zero.

### Why Global Reader is delegated via a role-assignable group, not per-user

`Sec-USA-ExecManagement` is provisioned with `isAssignableToRole = true` at creation (this property is immutable post-creation). Role-assignable groups differ from standard security groups in three ways that matter here:

- They **cannot** have dynamic membership rules — every member is deliberately, manually added, closing the "a misconfigured dynamic rule silently grants Global Reader" attack path.  
- They **cannot** be nested inside other groups — eliminating privilege escalation via nested-group inheritance.  
- They are protected by a stricter management surface — only Privileged Role Administrators / Global Administrators (or delegated Role Assignable Group owners) can alter membership, meaning a compromised Helpdesk Administrator cannot add themselves to the Exec Management group and inherit Global Reader.

---

## 3\. RBAC Isolation Strategy: Technical Operations

The Technical Operations tier (coaching \+ sports science staff) requires operational access to sports-science telemetry infrastructure (wearables data, load-management dashboards, video analysis compute) but has **no legitimate business need** to see payroll systems, sponsorship contracts, or executive reporting.

Isolation is enforced at the **resource** layer, not the identity layer:

Subscription: usa-soccer-prod

├── /sports-science           \<-- Sec-USA-TechnicalOps: Contributor (scoped HERE only)

│     ├── sports-science-storage

│     ├── sports-science-analytics-workspace

│     └── sports-science-compute

├── /corporate-finance         \<-- No assignment. Implicit deny.

├── /executive-reporting       \<-- No assignment. Implicit deny.

└── /identity-core             \<-- No assignment. Implicit deny.

Azure RBAC is deny-by-default: a principal with no role assignment on a scope has **zero** access to it, full stop — there is no "partial visibility" state to misconfigure. Scoping the Contributor grant to a single Resource Group means even a fully compromised coaching-staff credential, used to its maximum granted privilege, cannot enumerate, read, or modify anything outside `/sports-science`. This is the practical enforcement of the Player-data/financial-data separation the org chart implies.

---

## 4\. Conditional Access Policies

All four policies are deployed in **Report-only** mode first, validated against sign-in logs for 7–14 days, then flipped to **On**. Each policy below is expressed in exact logical form (the form used to author the underlying Graph `conditionalAccessPolicy` JSON).

### CA-01: MFA Baseline (all users, all cloud apps)

IF     user IN {All Users}

AND    app IN {All Cloud Apps}

AND    NOT (user IN {Break-Glass Emergency Access Accounts})

THEN   GRANT access

REQUIRE  {Multifactor Authentication}

- **Exclusion is mandatory:** two dedicated break-glass accounts, excluded from every CA policy, credentials stored offline, monitored for any sign-in via a dedicated alert rule.  
- Applies uniformly across Tier 1, 2, and 3 — there is no "trusted internal user" exemption, consistent with never-trust-always-verify.

### CA-02: Geo-Fencing — US / Canada / Mexico Named Location

IF     user IN {All Users}

AND    app IN {All Cloud Apps}

AND    NOT (location IN {Named Location: "CONCACAF-Core" \= US, CA, MX})

AND    NOT (user IN {Break-Glass Emergency Access Accounts})

THEN   BLOCK access

- The Named Location `CONCACAF-Core` is defined as an IP-range-independent **country/region-based** named location (not IP ranges), covering the operational footprint of the program (US, Canada, Mexico) to accommodate cross-border travel for matches, camps, and tournaments within the region.  
- Explicitly a **block**, not a grant-with-control — travel outside the three-country footprint should route through a documented travel-access exception process (temporary named-location addition \+ time-boxed CA policy exclusion for the traveling identity, reviewed and removed post-trip), not a standing bypass.  
- Applied tenant-wide; Tier 3 (players) benefit most directly since their itineraries are the primary legitimate driver of geographic travel in this org.

### CA-03: Device Compliance

IF     user IN {All Users}

AND    app IN {All Cloud Apps}

AND    NOT (user IN {Break-Glass Emergency Access Accounts})

THEN   GRANT access

REQUIRE  {Device marked as Compliant (Intune)}

     OR  {Hybrid Azure AD Joined}

- Compliance is Intune-managed: disk encryption, OS minimum version, and screen-lock timeout are the three baseline compliance checks enforced org-wide.  
- Tier 0 (Derrick) and Tier 2 (Technical Ops) are held to a **stricter** compliance profile at the Intune layer (shorter screen-lock timeout, mandatory endpoint EDR agent) — CA references the same "compliant" signal, but the underlying Intune compliance policy assigned to those groups is stricter than the one assigned to Tier 3\.

### CA-04: Risk-Based Sign-In (Identity Protection)

IF     user IN {All Users}

AND    app IN {All Cloud Apps}

AND    signInRiskLevel IN {Medium, High}

THEN   GRANT access

REQUIRE  {Multifactor Authentication}

AND    IF userRiskLevel IN {High}

       THEN REQUIRE {Secure Password Change}

- Sign-in risk (session-level: impossible travel, anonymized IP, unfamiliar sign-in properties) triggers step-up MFA.  
- User risk (account-level: leaked credentials, confirmed compromise) triggers a forced secure password change **in addition to** MFA — this policy assumes the credential itself may be known to an attacker, not just the session.  
- Requires Entra ID P2 licensing (Identity Protection risk signals are a P2 feature) — flagged explicitly here because it's the one policy in this set with a hard licensing dependency.

### Policy Precedence

All four policies are additive (Conditional Access evaluates every assigned policy and applies the most restrictive combination of controls), except CA-02, which is a hard block and short-circuits the session regardless of what the other three would have granted. Order of evaluation does not matter for correctness here since there's no explicit "policy A excludes policy B" logic — but CA-02 is reviewed first in any troubleshooting scenario since a block always wins.

---

## 5\. PIM: Derrick Lattimore — Eligible Global Administrator

### 5.1 Assignment Model

Derrick holds **zero permanent Global Administrator membership.** His entitlement is a PIM **eligible** assignment (`unifiedRoleEligibilityScheduleRequest`, `directoryScopeId = "/"`) with no expiration on the eligibility itself — eligibility is a durable statement of "this person may request this role," not a grant of access. Access is only granted for the duration of an explicit activation.

### 5.2 Activation Parameters (Role Management Policy — Global Administrator)

| Control | Setting | Rationale |
| :---- | :---- | :---- |
| Maximum activation duration | **2 hours** (`PT2H`, ISO 8601\) | Hard cap enforced by `Expiration_EndUser_Assignment` rule — bounds the blast-radius window of any single activation regardless of task length; long-running work requires re-activation, which re-triggers every control below |
| MFA on activation | **Required** | `Enablement_EndUser_Assignment` includes `MultiFactorAuthentication` — a stolen session token alone cannot activate GA |
| Justification on activation | **Required** | Free-text business justification logged to the audit trail on every activation, non-optional |
| Approval | **Required (second-admin, single-stage)** | `Approval_EndUser_Assignment` — a second Privileged Role Administrator must approve before activation completes; prevents a single compromised or coerced account from unilaterally escalating to GA |
| Approver justification | **Required** | Approver must record a reason for approval, not just click accept |
| Notification | On eligibility assignment, on activation, on approval | Sent to the security operations mailbox and to Derrick, independent of each other, so a silent activation cannot go unnoticed even if one notification channel fails |

### 5.3 Operational Workflow

1. Derrick initiates activation in the Entra ID **My Roles** (PIM) blade, supplies justification.  
2. MFA challenge is presented (satisfies `Enablement_EndUser_Assignment`).  
3. Request enters **Pending Approval**; a designated second Privileged Role Administrator receives an approval request.  
4. On approval, Global Administrator is active for **up to 2 hours**, expiring automatically — no manual deactivation step required, and no standing session survives past the window.  
5. All five events (request, MFA, approval, activation, expiration) are written to `AuditLogs` and `pim_activity` sign-in logs, retained per the retention policy in `Compliance_Mapping.md`.  
6. A scheduled Log Analytics / Sentinel query alerts security operations on: activation outside the CONCACAF-Core geo-fence, activation without a matching approval record, or more than one activation within a rolling 24-hour window (anomalous-frequency signal).

### 5.4 Why Not Time-Bound Eligibility Instead

An alternative design would set the *eligibility* window itself to expire (e.g., quarterly re-certification). This architecture uses indefinite eligibility \+ 2-hour activation caps because the operational risk this design targets is **session duration**, not **entitlement staleness** — entitlement staleness is instead handled by a recurring Access Review (Section 6), which is the correct tool for periodic re-certification and keeps the two concerns (session risk vs. entitlement staleness) decoupled and independently tunable.

---

## 6\. Access Reviews & Continuous Verification

- `Sec-USA-ExecManagement`, `Sec-USA-TechnicalOps`, and the Global Administrator PIM eligibility are all placed under recurring **Access Reviews** (quarterly for Tier 0 eligibility, semi-annual for Tiers 1–2), with the resource owner (or a designated reviewer) required to explicitly re-certify each member.  
- `Sec-USA-PlayerRosters` is reviewed annually given its zero-privilege posture — the review here is primarily a lifecycle/hygiene check (stale accounts, departed players), not a privilege check.  
- Sign-in and audit logs across all four CA policies and the PIM workflow feed a central Log Analytics workspace with a 365-day retention (see `Compliance_Mapping.md` for the control mapping this satisfies).

---

## 7\. Threat Model Summary

| Threat | Mitigating Control |
| :---- | :---- |
| Compromised Player credential used to pivot to sports-science infra | Tier 3 has zero role/RBAC grants — no pivot path exists |
| Compromised Technical Ops credential used to reach financial/exec data | Azure RBAC scoped to a single Resource Group; Entra directory role: none |
| Compromised Executive credential used to modify tenant configuration | Global Reader is read-only by definition — no write capability exists on the grant itself |
| Compromised or coerced Derrick credential used to establish persistent GA access | No standing GA; every activation is time-boxed, MFA-gated, and requires independent second-admin approval |
| Credential-stuffing / impossible-travel sign-in from outside program footprint | CA-02 geo-fence blocks by default; CA-04 adds risk-based step-up on top |
| Legacy/unmanaged device used to authenticate | CA-03 requires Intune compliance or hybrid join before any grant |

