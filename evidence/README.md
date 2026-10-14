# Evidence index

These are original, unedited screenshots from the Microsoft 365 admin center for the lab tenant `lattimorede23.onmicrosoft.com`, captured in July 2026.

| File | Shows | Supports |
| :-- | :-- | :-- |
| [`01_tenant_users.png`](01_tenant_users.png) | Active users: the 9 personas created by the script, plus two tenant administration accounts (`Lattimorede23@…`, `labadmin@…`) licensed for Microsoft Entra Suite | Script Step 1 (user provisioning) |
| [`02_group_execmanagement.png`](02_group_execmanagement.png) | `Sec-USA-ExecManagement`: security group, 2 members (Cindy Parlow Cone, JT Batson) | Script Steps 2–3 (Tier 1 group and membership) |
| [`03_group_playerrosters.png`](03_group_playerrosters.png) | `Sec-USA-PlayerRosters`: security group, 4 members (Christian Pulisic, Sophia Smith, Trinity Rodman, Weston McKennie) | Script Steps 2–3 (Tier 3 group and membership) |
| [`04_group_technicalops.png`](04_group_technicalops.png) | `Sec-USA-TechnicalOps`: security group, 2 members (Emma Hayes, Mauricio Pochettino) | Script Steps 2–3 (Tier 2 group and membership) |

## Not covered by this evidence

The screenshots document identities and group membership only. The repository has no screenshots, exports, or logs for:

- The Global Reader role assignment
- The PIM eligibility and role-management policy
- Azure RBAC
- Conditional Access policies

Useful additions, if the tenant is still available:

- **Entra admin center > Roles and administrators > Global Reader > Assignments**: shows the group assignment.
- **PIM > Microsoft Entra roles > Global Administrator > Eligible assignments**, plus **Role settings**: shows eligibility, the 2-hour cap, MFA, justification, and approval.
- **Conditional Access > Policies**: shows whether CA-01 to CA-04 exist and their state.
