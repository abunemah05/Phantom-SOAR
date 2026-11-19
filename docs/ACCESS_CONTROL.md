# Access control: who may change whose role and permissions

Question from the instructor: *can an admin change the role or permissions of the AI agent (service) accounts, or of
another admin?* Short answer after this change:

* **Another admin: yes, but only with a re-confirmation and a full audit trail.** The acting admin must re-enter their
  own password (and a current MFA code if they use MFA) for every sensitive change to another administrator (role,
  enable / disable, password reset, compromised flag, **delete**) and for every grant of the `Admin` role (promotion
  **or creating an account with the Admin role**). Every accepted or rejected attempt is written to the audit log with
  who, whom, and old -> new. The bootstrap (break-glass) administrator cannot be demoted, disabled or deleted at all.
* **Agent (service) accounts: no.** Their role is fixed to `AI Agent`; an admin can rotate the key, set the key
  expiry / allowed addresses, disable or delete the account, but cannot give it any other role, cannot make it an
  administrator and cannot turn it into a person (or a person into an agent). An agent's key can never call any
  account-management endpoint.
* **Yourself: no.** You cannot change your own role, disable, delete, flag or reset yourself.
* **The platform can never be left without an administrator**, including when two admins act at the same instant.

The policy is one small file, `backend/rbac.py` (pure functions, easy to test). `backend/routers/users.py` loads the
accounts, asks `rbac.decide()`, and enforces the answer. The console shows the same answer: `GET /api/users` returns
`account_actions` per account, so buttons are disabled with the server's own reason.

## 1. Research: what the standards and products say

Pages were opened and read on 2026-11-19. "Rule" is what the page says (paraphrased unless in quotes); the last column
is where this repo applies it. Where a page was only partly readable, that is said.

| Source | Rule used | URL | Applied as |
|---|---|---|---|
| NIST RBAC project (ANSI/INCITS 359-2004, revised 2012) | The standard has two parts: the RBAC reference model (users, roles, permissions, operations, objects) and the system / administrative functional specification. The project page itself does not define separation of duty. | https://csrc.nist.gov/projects/role-based-access-control | Roles are named, finite and assigned by an administrative function (R6) |
| Ferraiolo et al., "Proposed NIST Standard for RBAC" (ACM TISSEC 2001; the proposal, not the final ANSI text) | Static separation of duty "place[s] constraints on the assignments of users to roles"; dynamic SoD constrains roles activated in a session. Components: core, hierarchical, SSD, DSD. | https://www.profsandhu.com/cs6393_s20/FSetal-2001.pdf | The agent role and the admin role are mutually exclusive by assignment (R4): a static separation-of-duty constraint |
| NIST SP 800-53 Rev. 5 AC-2(4) (read in the OSCAL catalog 5.2.0) | "Automatically audit account creation, modification, enabling, disabling, and removal actions." | https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json | Every account change is a `system_logs` row, committed in the same transaction as the change |
| SP 800-53 AC-2(7) Privileged user accounts | Monitor privileged role or attribute assignments; monitor changes to roles or attributes. | same | Granting or removing `Admin`, and any change to an admin, is logged at WARNING |
| SP 800-53 AC-2 (a, d, f) | Define the allowed account types, specify group/role membership and privileges per account, create/enable/modify/disable/remove accounts per policy. | same | Account types: person (4 named roles) and service account (`AI Agent`) |
| SP 800-53 AC-5 Separation of duties | "ensuring that security personnel who administer access control functions do not also administer audit functions"; enforced through account management and access control mechanisms. | same | Agents (who propose actions) can never administer access (R4); admins cannot self-approve their own elevation (R1) |
| SP 800-53 AC-6 Least privilege; AC-6(9) log privileged functions; AC-6(10) non-privileged users cannot run privileged functions | Allow only the access needed; log use of privileged functions; prevent non-privileged users running them. AC-6 also applies least privilege to "system processes". | same | Four roles, deny by default; service accounts narrower than any person; account management is logged |
| SP 800-53 AU-2, AU-3, AU-12 | Define the event types, record what/when/where/source/outcome/identity, generate the records. | same | Audit entry fields: actor, target, action, outcome, code, old -> new, IP (section 4) |
| OWASP ASVS 4.0.3, V4 | 4.1.2 users cannot manipulate user/policy attributes unless authorised; 4.1.3 least privilege; 4.3.1 MFA for administrative interfaces; 4.3.3 step-up or adaptive authentication and/or segregation of duties for high-value applications. | https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x12-V4-Access-Control.md | Step-up for sensitive account changes (R5); mass-assignment whitelist (section 4) |
| OWASP Authorization Cheat Sheet | "deny access by default"; permissions "validated correctly on every request"; never rely on client-side checks; enforce least privilege horizontally and vertically; log authorization failures. The page has no explicit admin / role-change workflow. | https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html | Server checks on every request; UI is advisory; denials are logged |
| OWASP Mass Assignment Cheat Sheet | Use DTOs and explicit allow-lists; a block-list alone is not enough; this does not replace authorisation. | https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html | `UPDATABLE_FIELDS` allow-list; extra fields refused and audited |
| OWASP API Security Top 10 2023, API5 Broken Function Level Authorization | The enforcement mechanism should deny all access by default and require explicit role grants; admin functions inside regular controllers need their own checks. Example attack: an admin-only "invite" endpoint without checks let an attacker create an admin. | https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/ | Every `/users` route depends on `require_admin`; creating an admin is a logged, gated grant |
| OWASP API Security 2023, API3 Broken Object Property Level Authorization | Avoid binding client input to internal objects; allow changes only to the properties that should be client-updatable. | https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/ | `is_service_account`, `username`, hashes, MFA fields cannot be set through update |
| CIS Controls v8, Control 5 (titles read from the CIS Controls Assessment Specification) | 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts; 5.5 Establish and Maintain an Inventory of Service Accounts; 5.1 inventory of accounts. | https://cas.docs.cisecurity.org/en/latest/source/Controls5/ | Service accounts are listed and flagged separately; admin accounts are few and named (5.4 is not enforced, see section 6) |
| CIS Controls v8, Control 6 (titles) | 6.1 Establish an Access Granting Process; 6.2 Access Revoking Process; 6.5 Require MFA for Administrative Access; 6.8 Define and Maintain Role-Based Access Control. Only titles and one-line overviews were readable; the full safeguard text was not. | https://controls-assessment-specification.readthedocs.io/en/latest/control-6/ | Named roles (6.8); MFA re-confirmation for admin changes (6.5); revocation = disable / delete with audit (6.2) |
| Splunk Enterprise `authorize.conf` | Roles inherit capabilities from imported roles. `edit_user`: to change roles you "must hold roles whose combined capabilities either match or exceed" those you edit. Only `admin` holds `edit_roles_grantable` on a new install; `grantableRoles` limits which roles a delegate may hand out. | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/authorize.conf | You cannot grant more than you hold: only an active admin changes roles, and only to the named roles; no custom capability grants |
| Splunk SOAR (on-prem) roles | Default roles (Administrator, Automation, Observer, ...) "can't be edited or deleted"; for a system role you can only add or remove users. `Automation` is "a service account role". Edit permission on Users and Roles lets that user "grant themselves all other privileges". | https://help.splunk.com/en/splunk-soar/soar-on-premises/administer-soar-on-premises/6.4.0/manage-your-splunk-soar-on-premises-users-and-accounts/manage-roles-and-permissions-in-splunk-soar-on-premises | Role definitions are fixed in code; the agent role is a separate, non-administrator role; user management is the most sensitive permission (R1, R4) |
| Cortex XSOAR 6.13 roles | Three assigned roles (Administrator, Analyst, Read-Only). The default administrator "cannot be deleted". Administrators can change user roles, enable/disable other users, and create or update API keys for other users. The page does not say who may edit the Administrator role. | https://cortex-docs.paloaltonetworks.com/xsoar-6-administrator-guide/6.13/onboard-cortex-xsoar/users-and-roles/roles-in-cortex-xsoar | Bootstrap administrator cannot be deleted, disabled or demoted (R2) |
| Microsoft Entra role best practices | Least privilege; fewer than five Global Administrators; two emergency-access ("break glass") accounts; require MFA for administrators; time-limited elevation (PIM). | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices | The bootstrap account is the break-glass account (R2); MFA re-confirmation (R5) |
| Microsoft Entra "who can reset passwords" table | Security Administrator, Security Operator and the SOC identity responder role are "limited to non-administrative user accounts and can't perform actions on privileged accounts"; resetting administrators' passwords is reserved to higher roles. | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions | Acting on a more privileged account is a different, stricter action than acting on an ordinary one (R5) |
| Azure RBAC, delegating role assignment | Owner / User Access Administrator let a delegate assign any role "including themselves" and assign the powerful roles onward; use a role with conditions that limit which roles and principals can be assigned. | https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-overview | No self-assignment (R1); the role set that can be assigned is a fixed allow-list (R6) |
| AWS IAM permissions boundaries | A boundary sets "the maximum permissions an identity-based policy can grant"; effective permissions are the intersection; the delegation example blocks the delegate from editing or removing boundaries so they cannot escalate. | https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html | The agent role is a hard ceiling: nothing an admin does through the API lifts it (R4) |
| Elastic built-in roles | Built-in roles "cannot be updated"; `superuser` "can manage security and create roles with unlimited privileges": "Take extra care when assigning it". | https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/built-in-roles | Granting `Admin` is the sensitive grant (R5, audit at WARNING) |
| Wazuh RBAC "how it works" | Administrators assign roles to users, not individual policies; in white-list mode "the system forbids all actions by default" (recommended for production). The pages read did not say whether default roles are protected from change. | https://documentation.wazuh.com/current/user-manual/api/rbac/how-it-works.html | Deny by default; roles, not ad-hoc permissions |
| GitHub, ownership continuity | Recommends "at least two people within each organization have the owner role" because a single unreachable owner can lock the organisation out; owners cannot change their own role. The page does not describe what happens when removing the last owner. | https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/maintaining-ownership-continuity-for-your-organization | No self role change (R1); last-administrator protection (R3) is stricter than GitHub's documented behaviour |
| GitHub sudo mode | Sensitive actions (including organisation membership and security settings, tokens, webhooks) require re-authentication: password, passkey, security key or TOTP; the session then stays in sudo mode for two hours. | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode | Step-up (R5). Here every sensitive change asks again: there is no "sudo window" |

Not verified (could not be read, so nothing is claimed): the full text of ANSI/INCITS 359-2004; the full text of CIS
Safeguards 5.4 / 6.x; Splunk Enterprise "Aboutusersandroles" and the SOAR "Users" page (the site refused the fetch);
Splunk SOAR claims about the `admin` user restrictions; Wazuh's protection of default users and roles; whether
Entra or Elastic block removing the last administrator. There is no separate OWASP "Access Control Cheat Sheet": the
Authorization Cheat Sheet is the one that covers it. Pages were read through a fetch tool that returns extracts, so
quotations should be re-checked against the live pages before they are cited in a paper.

## 2. What the code allowed before this change

| Question | Before |
|---|---|
| Admin changes another admin's role | Yes, any role, no re-confirmation, one INFO-level audit line, no old value recorded |
| Admin changes **own** role | Yes (if another admin existed) |
| Admin resets own password via the admin API | Yes, with no proof of the old password (bypassed `change-password`) |
| Admin resets / flags another admin | Yes; the temporary password is returned to the caller (account takeover path), no re-confirmation |
| Last administrator | Protected for update and delete by a count-then-write check that was **not race-safe**: two admins demoting each other at once could both succeed |
| Bootstrap administrator | Could not be disabled or deleted, but could be demoted |
| Agent account role | Update with `role` was refused (good); `flag-compromised`, `unlock` and the `compromised_reset_required` update field were accepted for agents (meaningless) |
| Agent key calls `/users/*` | Refused (401/403): no route accepted the key, and `_resolve_user` rejects service accounts |
| Role names | Validated against the known list, but legacy admin aliases ("Sys Admin", "SOC Lead / Admin") could still be assigned to new accounts |
| Update fields | Unknown JSON fields were silently ignored (not bound, but no refusal and no audit) |
| Rejected attempts | Only logged to the process log for non-admin callers; policy refusals were not audited |

## 3. Policy matrix: who may do what to whom

Callers other than an active, human administrator are refused everything: non-admin people get 403 from `require_admin`,
service accounts get 401 / 403 (their key is not a session; a JWT forged for their name is refused by `_resolve_user`;
and `rbac.decide` refuses a service-flagged actor even if its row carried the Admin role).

"Step-up" = the acting admin must send `confirmation` (own password, plus a current TOTP code with MFA). "Audit" = one
`system_logs` row (source `RBAC`).

| Action by an admin on ... | Themselves | Bootstrap admin | Another admin | Last active admin | Non-admin person | Service (agent) account |
|---|---|---|---|---|---|---|
| Change role | Denied (R1) | Denied away from admin (R2) | Allowed with step-up; audit WARNING | Denied (R3) | Allowed; to `Admin` needs step-up (grant); audit | Denied: role fixed, never admin (R4) |
| Disable / enable | Disable denied (R1) | Disable denied (R2) | Allowed with step-up; audit WARNING | Disable denied (R3) | Allowed; audit | Allowed; audit |
| Reset password | Denied; use change-password (R1) | Allowed with step-up | Allowed with step-up; audit WARNING | n/a (see below) | Allowed; audit | Denied: no password (R4) |
| Flag compromised (also the update field) | Denied (R1) | Allowed with step-up | Allowed with step-up; audit WARNING | n/a | Allowed; audit | Denied (R4) |
| Unlock | Allowed | Allowed | Allowed; audit | n/a | Allowed; audit | Denied (R4) |
| Delete | Denied (R1) | Denied (R2): the bootstrap admin cannot be deleted | Allowed with step-up; audit WARNING | Denied (R3) | Allowed; audit | Allowed; audit |
| Rotate key / key policy | Denied: people have no key | Denied | Denied | Denied | Denied | Allowed; audit; **no step-up** (section 6) |
| Create account with role ... | n/a | n/a | `Admin`: allowed with step-up; audit WARNING | n/a | Other named roles: allowed; audit | `AI Agent` / `Service Account` as a person's role: refused (R4, R6) |
| Create a service account | n/a | n/a | n/a | n/a | n/a | Allowed; role forced to `AI Agent`; no role field accepted; **no step-up** (section 6) |
| Make a person an agent or an agent a person | Impossible: `is_service_account` is not an updatable field | | | | | |

"Last active admin" can only be reached by a request when another admin is acting at the same instant, because an acting
admin is itself an active admin. The rule is enforced in two ways: `rbac.decide()` counts the other active admins, and
`users.py` closes the race (section 4).

Rules, as numbered in `backend/rbac.py`:

* **R1** No self-escalation or self-lockout: own role, disable, delete, flag and admin-API password reset are refused.
* **R2** The bootstrap (break-glass) admin is always an active admin: not demoted, disabled or deleted.
* **R3** The last active admin can never be demoted, disabled or deleted.
* **R4** Agent accounts: fixed `AI Agent` role, never an administrator, no password, cannot manage accounts, cannot become people.
* **R5** Sensitive changes to another admin, and every grant of `Admin`, need the acting admin's own password (and TOTP with MFA) and are audited at WARNING.
* **R6** Only named roles can be assigned: `Admin`, `Security Engineer`, `SOC Analyst`, `SOC Auditor (Read-Only)`, plus the legacy
  non-admin aliases already in older databases. `AI Agent`, legacy admin aliases ("Sys Admin", ...) and invented names are refused; canonical roles are stored with their
  canonical spelling.

## 4. Safeguards

* **Step-up.** `POST /users` (when the new role is `Admin`), `PUT /users/{id}`, `POST .../reset-password`,
  `POST .../flag-compromised` and the delete endpoints accept
  `{"confirmation": {"current_password": "...", "mfa_code": "123456"}}`. Missing -> 428 `step_up_required`; wrong ->
  403 `step_up_failed` (nothing changes); five wrong tries per (admin, address), or twenty per admin from any address
  -> 429 with a `Retry-After` equal to the time the lock really has left (at most fifteen minutes; an admin unlock clears it).
  These step-up counters are separate from the sign-in counters: wrong confirmations never slow down or block the
  admin's real logins. A confirmation that is sent is always verified, even when not required. A TOTP code is
  single-use (replays are refused). The target's password is never accepted in its place.
* **Deleting an account.** `DELETE /users/{id}` still accepts the confirmation as a JSON body, but some proxies and
  HTTP clients drop the body of a DELETE (RFC 9110 gives it no defined meaning). `POST /users/{id}/delete` takes the
  same body and does the same thing; the console uses it. Use it when you script the API behind a proxy.
* **Resending the current role is a no-op.** A `PUT` whose `role` equals the stored role on a person (including a legacy name such
  as "Sys Admin") changes nothing and is not re-validated. A service account's role is fixed: any `role` sent for it is refused
  (`service_account_role_fixed`), even its own `AI Agent`.
* **Last-administrator and role re-check, race-safe.** Every privileged account change runs under one in-process lock, with
  `SELECT ... FOR UPDATE` on the person accounts (a real lock on PostgreSQL; SQLite ignores it), and re-reads the acting admin
  and the target inside that lock. If the acting admin lost their rights a moment earlier the request fails with 403
  `admin_rights_revoked`. The test `test_two_admins_demoting_each_other_at_the_same_time_never_leave_zero_admins` runs six rounds of
  two simultaneous demotions; it fails if the lock is removed.
* **Atomic audit.** The change and its audit row are committed together, so there is no change without a record. A refusal
  rolls back and writes a `DENIED:` row at WARNING.
* **Audit entry.** `source=RBAC`, `target=<account>`, `details`: `by` (actor), `changes` ({field: {from, to}}),
  `target_was_admin`, `grants_admin`, `step_up`, `ip`; refusals add `outcome=denied`, `code`, `action`, `attempted`.
* **Mass assignment.** Update accepts only `role`, `is_active`, `compromised_reset_required` (and `confirmation`); create only
  `username`, `role` (and `confirmation`; `mfa_enabled` is accepted and ignored as before); service-account create only
  `username`, `expires_in_days`, `ip_allowlist`. Anything else -> 422 `fields_not_allowed`, nothing applied (even the allowed fields in the same body), audited with the field names.
* **Errors** are `{"detail": {"message": "...", "code": "..."}}` with stable codes: `self_role_change`, `self_disable`, `self_delete`,
  `self_password_reset`, `self_compromised_flag`, `bootstrap_protected`, `last_admin`, `service_account_role_fixed`,
  `service_account_no_password`, `not_a_service_account`, `service_role_not_assignable`, `unknown_role`, `legacy_admin_alias`,
  `role_required`, `fields_not_allowed`, `step_up_required`, `step_up_failed`, `step_up_throttled`, `admin_rights_revoked`, `actor_not_admin`,
  `service_account_cannot_manage`. Policy refusals are 400 (as the existing checks were); the console shows the message.
* **Console.** Disabled buttons show the server's reason, a "Change role" action exists, a one-line lock note explains why an account is protected, and a
  confirmation dialog asks for the admin's own password (and code) before a sensitive change, re-asking if it was wrong.

## 5. Tests

`backend/tests/test_access_control.py`: a table of the policy matrix, the last-admin rule, actors that must be refused, role validation, field
whitelisting, step-up (missing, wrong, target's password, throttle, MFA code and replay), every gated action, grants of `Admin`,
creating an Admin and deleting an admin (including the POST delete route), service accounts (cannot be promoted, converted, given passwords; agent keys, forged tokens and a corrupted
admin-role agent row cannot reach any `/users` route), the audit rows (accepted and denied), the console contract, and the concurrent last-admin race.
Frontend: `frontend/src/lib/accountPolicy.test.ts` and the new error-code cases.

## 6. What is NOT covered

Step-up applies to: changing another administrator (role, enable / disable, password reset, compromised flag), deleting
another administrator, granting the `Admin` role (promotion or creating an account with that role). All of them are also
audit-logged at WARNING.

**Known limitation: service-account creation, API-key rotation and key-policy changes are NOT step-up gated.** They need
an administrator session and are audit-logged (ACTION level), but do not ask for the admin's password again. This was a
deliberate choice: a service account is fixed to the `AI Agent` role, can never be an administrator or manage accounts,
and can only read alert context and submit proposals that a human still approves, so these actions do not grant
administrative power; and gating them would change the contract of many existing callers and tests. Anyone who holds an
admin session can therefore mint or rotate an agent key without re-entering a password. Revisit this if agents are given more
authority.

Not covered:

* **Two-person approval** (a second admin must approve) and **time-limited elevation** (PIM-style just-in-time admin). Step-up plus audit is the chosen safeguard.
* **Notifications.** Changes are audited, but nobody is emailed or messaged when an admin changes another admin.
* **A reset of another admin's MFA.** No endpoint exists, so no admin can do it; recovery is a database operation.
* **Dedicated admin accounts (CIS 5.4).** An admin account can also work cases; nothing forces separate day-to-day and admin accounts.
* **Finer permissions.** Roles are fixed; there are no custom roles, capabilities or per-resource grants. All admins are equal (no "privileged role administrator" tier).
* **Agent least privilege beyond the role.** An agent key can use every agent-API endpoint (read alert context, list actions, submit proposals; humans still approve). Narrower per-agent scopes are not implemented; key expiry and an address allow-list exist.
* **A cap on the number of admins** (Entra suggests fewer than five); there is no warning when there are many.
* **Cross-process locking on SQLite.** The in-process lock protects one worker; with several workers on SQLite the database write lock serialises writes but the
  check-then-write is not atomic across processes. PostgreSQL uses row locks (`FOR UPDATE`) and is the supported production database; this was not exercised against PostgreSQL here.
* **The audit log is in the same database**, so an administrator with database access can alter it (see SECURITY.md).
* **Direct database edits and the first-start bootstrap** bypass this policy by nature.
* **Session revocation on demotion.** A demoted admin's token stops working because the role is re-read on every request; tokens are not separately revoked.
* **Validation errors (422) from FastAPI** for malformed JSON are not audited; only unknown fields on the three account endpoints are.
