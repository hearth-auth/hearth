# UX Lane: Admin & End-User UX Completeness — v2 Audit

**Auditor:** UXDesigner  
**Audit date:** 2026-05-25  
**Branch audited:** `main` (HEAD `ccb4ba3` — "Clustering Gap and Other Updates (#90)")  
**Methodology:** Re-grep from scratch on current `main`. Every claim backed by `file:line` evidence. No issue-tracker citations treated as authoritative. No v1 reports cited as evidence.

---

## Verdict

**production-ready-with-caveats**

The Hearth admin console covers the full CRUD surface for every major entity (users, realms, applications, organizations, groups, roles, sessions, audit log, webhooks, identity providers, migrations). Theme token compliance is strong with one localized violation. The critical gap is that required-action interstitials — while fully implemented at the route, handler, and template level — are **not wired into the web UI login flow**: users with pending `UPDATE_PASSWORD` or `VERIFY_EMAIL` required actions are issued a full session cookie on login and proceed to the dashboard, bypassing the interstitial pages entirely.

---

## Verified Claims

### 1. Admin Users: Full CRUD + Actions

| Surface | Evidence |
|---------|---------|
| List with pagination | `src/protocol/web/mod.rs:974`, handler `admin::admin_users_list` |
| Create form + submit | `src/protocol/web/mod.rs:978-979`, handler `admin::admin_user_create_form` / `admin_user_create_submit` |
| Detail view | `src/protocol/web/mod.rs:982-983`, handler `admin::admin_user_detail` |
| Edit form + submit | `src/protocol/web/mod.rs:986-987` |
| Delete | `src/protocol/web/mod.rs:990-991` |
| Send password reset email | `src/protocol/web/mod.rs:994-995`, template `templates/ui/admin/users/detail.html:70-77` |
| Disable MFA | `src/protocol/web/mod.rs:998-999` |
| Reset MFA recovery codes | `src/protocol/web/mod.rs:1002-1003` |
| Revoke specific user session | `src/protocol/web/mod.rs:1006-1007` |
| Revoke WebAuthn credential | `src/protocol/web/mod.rs:1010-1011` |
| Assign / unassign role | `src/protocol/web/mod.rs:1014-1019` |
| Grant / revoke permission | `src/protocol/web/mod.rs:1022-1027` |
| View / revoke consents | `src/protocol/web/mod.rs:1030-1043` |
| Bulk user actions | `src/protocol/web/mod.rs:1357-1359` |
| CSV user import | `src/protocol/web/mod.rs:1362-1369` |

### 2. Admin Realms: Read-Mostly (config-driven)

| Surface | Evidence |
|---------|---------|
| List | `src/protocol/web/mod.rs:969-970`, handler `admin::admin_realms_list` |
| Detail | `src/protocol/web/mod.rs:1047-1048` |
| Delete archived realm | `src/protocol/web/mod.rs:1051-1052` |
| Admin grants (picker, grant, revoke) | `src/protocol/web/mod.rs:1055-1065` |
| Claims inspector | `src/protocol/web/mod.rs:1067-1069` |

**Note:** No `/admin/realms/new` route — realm creation is only possible via the onboarding wizard. This is intentional (realms are config-reconciled), but operators wanting to add a second realm post-setup have no UI path.

### 3. Admin Applications (OAuth Clients): Full CRUD

| Surface | Evidence |
|---------|---------|
| List | `src/protocol/web/mod.rs:1249-1250` |
| Create | `src/protocol/web/mod.rs:1253-1254` |
| Detail | `src/protocol/web/mod.rs:1257-1258` |
| Edit | `src/protocol/web/mod.rs:1261-1262` |
| Delete | `src/protocol/web/mod.rs:1265-1266` |
| Regenerate client secret | `src/protocol/web/mod.rs:1269-1271` |

### 4. Admin Organizations: Full CRUD + Membership + Invitations

| Surface | Evidence |
|---------|---------|
| List | `src/protocol/web/mod.rs:1115-1116` |
| Create / Edit / Delete / Bulk-delete | `src/protocol/web/mod.rs:1118-1137` |
| Member add / remove / picker | `src/protocol/web/mod.rs:1139-1149` |
| Member role change | `src/protocol/web/mod.rs:1151-1153` |
| Invite / revoke invite / resend invite | `src/protocol/web/mod.rs:1155-1168` |
| Org status toggle | `src/protocol/web/mod.rs:1159-1161` |
| Org member RBAC assign/unassign + permissions | `src/protocol/web/mod.rs:1171-1185` |

### 5. Admin Groups (RBAC): Full CRUD + Membership

| Surface | Evidence |
|---------|---------|
| List | `src/protocol/web/mod.rs:1187-1189` |
| Create / Edit / Delete | `src/protocol/web/mod.rs:1191-1207` |
| Member add / remove / picker | `src/protocol/web/mod.rs:1208-1220` |
| Role assign / unassign | `src/protocol/web/mod.rs:1221-1227` |

### 6. Admin RBAC / Roles: Full CRUD + Debug

| Surface | Evidence |
|---------|---------|
| Role list, create, detail, edit, delete | `src/protocol/web/mod.rs:1090-1108` |
| RBAC debug / token preview | `src/protocol/web/mod.rs:1072-1083` |
| Permissions browser | `src/protocol/web/mod.rs:1085-1088` |
| Scopes browser | `src/protocol/web/mod.rs:1110-1112` |

### 7. Admin Sessions: List + Revoke

| Surface | Evidence |
|---------|---------|
| Realm-scoped session list | `src/protocol/web/mod.rs:1282-1285` |
| Revoke individual session | `src/protocol/web/mod.rs:1286-1289` |

### 8. Admin Audit Log: View + Export + Verify + Prune

| Surface | Evidence |
|---------|---------|
| Audit list viewer | `src/protocol/web/mod.rs:1291-1294` |
| Integrity verify | `src/protocol/web/mod.rs:1295-1298` |
| Export | `src/protocol/web/mod.rs:1299-1302` |
| API: events, config GET/PUT, prune | `src/protocol/web/mod.rs:1303-1315` |

### 9. Required-Action Interstitials: Routes + Handlers + Templates Exist

| Element | Evidence |
|---------|---------|
| `UPDATE_PASSWORD` route (GET + POST) | `src/protocol/web/mod.rs:751-755` |
| `VERIFY_EMAIL` route (GET) | `src/protocol/web/mod.rs:756-759` |
| Resend + success routes | `src/protocol/web/mod.rs:760-767` |
| Handler implementations | `src/protocol/web/handlers.rs:3628` (`ra_update_password_form`), `:3655` (`ra_update_password_submit`), `:3767` (`ra_verify_email_page`), `:3821` (`ra_verify_email_resend`), `:3878` (`ra_verify_email_success`) |
| Templates exist + theme-compliant | `templates/ui/required-actions/update_password.html` (uses `ht-*` tokens), `templates/ui/required-actions/verify_email.html`, `templates/ui/required-actions/verify_email_success.html` |
| Multi-action chain redirect | `src/protocol/web/handlers.rs:3709-3720` — after password update, correctly redirects to verify-email if that action is next |

### 10. Theme Compliance

| Check | Result | Evidence |
|-------|--------|---------|
| No `dark:` prefixes in templates | ✅ Clean | `grep -rn "dark:" templates/` — 0 hits |
| `ht-*` tokens used in RA templates | ✅ Clean | `templates/ui/required-actions/update_password.html:4,9,12,29,41` |
| `ht-*` tokens used in admin templates | ✅ Clean | Sample from `templates/ui/admin/onboarding/wizard.html:15-30` |
| Raw hex violations | ❌ 5 hits | See Gap #2 below |

### 11. End-User Account Surface

| Surface | Evidence |
|---------|---------|
| Account index (password change) | `src/protocol/web/mod.rs:768-772`, `templates/ui/account/index.html` |
| TOTP enroll / disable / recovery codes | `src/protocol/web/mod.rs:773-792` |
| Passkeys register / delete / rename | `src/protocol/web/mod.rs:793-808` |
| Sessions list + revoke | `src/protocol/web/mod.rs:810-820` |
| OAuth consents + revoke-all | `src/protocol/web/mod.rs:822-845` |
| Federation linked-accounts + unlink | `src/protocol/web/mod.rs:847-854` |

---

## Falsified or Unverified v1 Claims

No v1 UX-lane document was found in `docs/audit/v1/` — the `docs/audit/` directory contains only the test-suite audit and the v2 subdirectory. The prior audit conclusions for this lane were embedded in the HEA-720 rollup (issue tracker only, no committed document). Based on typical v1 rollup language ("required-action interstitials implemented and reachable"), the following is now falsified:

### Falsified: "Required-action interstitials are reachable from the login flow"

**v1 claim (inferred from HEA-765 issue status and MEMORY.md "feat(web): required-action UI interstitials"):** The required-action pages (UPDATE_PASSWORD, VERIFY_EMAIL) intercept users at login.

**What current code shows:**

`src/protocol/web/handlers.rs:921-1129` (`login_submit_impl`) authenticates the password, handles MFA, then calls `create_session()` and issues a full session cookie. There is **no call** to `pending_actions()` and no conditional branch that would issue a required-action JWT or redirect to `/ui/required-actions/*`.

The required-action pages exist and are correctly implemented, but they're only reachable by constructing a URL with an `ra_token` parameter manually — they are not triggered by the normal login path.

This is operationally dead code from the web UI's perspective.

---

## New Gaps Discovered

### Gap 1 — CRITICAL: Login flow bypasses required-action check

**Severity:** High  
**File:line:** `src/protocol/web/handlers.rs:1080-1103` (session creation + redirect, no RA check)

The `login_submit_impl` function creates a full session (`create_session`) after password + MFA verification without calling `pending_actions()`. Users with `UPDATE_PASSWORD` or `VERIFY_EMAIL` pending receive a full session cookie and are redirected to `/ui`.

**Fix:** Between MFA gate (line 1078) and `create_session` call (line 1080), add:
```rust
let pending = state.identity.pending_actions(realm.id(), user.id())?;
if !pending.is_empty() {
    let ra_token = state.identity.issue_required_action_token(realm.id(), user.id(), ...)?;
    let first = pending.iter().next().unwrap();
    let path = match first {
        RequiredAction::UpdatePassword => format!("/ui/required-actions/update-password?ra_token={ra_token}"),
        RequiredAction::VerifyEmail => format!("/ui/required-actions/verify-email?ra_token={ra_token}"),
    };
    return Redirect::to(&path).into_response();
}
```

The same fix is needed in `mfa_challenge_submit` (passkey and TOTP paths also bypass the RA check).

### Gap 2 — Raw Hex in Onboarding Wizard (Theme Violation)

**Severity:** Medium  
**Files:** `templates/ui/admin/onboarding/wizard.html:117,126,135,144,153`

Five step-indicator color dots use inline `style="background:#XXXXXX"` rather than Tailwind tokens:

```html
<!-- line 117 --> <span class="h-3 w-3 rounded-full shrink-0" style="background:#e8743b"></span>
<!-- line 126 --> <span class="h-3 w-3 rounded-full shrink-0" style="background:#3b82f6"></span>
<!-- line 135 --> <span class="h-3 w-3 rounded-full shrink-0" style="background:#6d68d8"></span>
<!-- line 144 --> <span class="h-3 w-3 rounded-full shrink-0" style="background:#22a66a"></span>
<!-- line 153 --> <span class="h-3 w-3 rounded-full shrink-0" style="background:#64748b"></span>
```

THEME.md rule: "Never use raw hex outside the config." These should be token-based classes (e.g., `bg-ember-400` for the orange dot, `bg-blue-500` for blue, etc.) or new semantic tokens added to `ui/tailwind.config.js`.

### Gap 3 — No Admin UI to Set Required Actions on Users

**Severity:** Medium  
**Evidence of absence:** `src/protocol/web/admin/users.rs` — 0 hits for `required_action`, `set_required_action`, or `pending_action`. `templates/ui/admin/users/detail.html` has a "Send password reset" button (line 70) which sends an email reset link — this is the `forgot_password` email flow, NOT the `UPDATE_PASSWORD` required-action flow.

Operators cannot force a user to change their password via a required action through the admin UI. The `add_required_action()` / `remove_required_action()` engine methods (`src/identity/mod.rs:1528,1538`) exist but have no HTTP or web UI surface.

### Gap 4 — No Realm Create Route in Admin UI

**Severity:** Low (likely intentional)  
**Evidence:** `src/protocol/web/admin/realms.rs` — 0 hits for `create_realm`. The only realm creation path is the first-run onboarding wizard (`/admin/onboarding/realm`). After onboarding, there is no UI to add new realms.

Realms may be config-reconciled (not ad-hoc), but this leaves operators without a self-service realm creation path outside of the initial setup wizard. An operator who needs to add a realm must edit `hearth.yaml` and restart/reload.

### Gap 5 — Route Table Comment in mod.rs Is Stale

**Severity:** Low (doc-only)  
**File:line:** `src/protocol/web/mod.rs:593-609`

The doc-comment route table still lists `/ui/admin/users`, `/ui/admin/sessions`, and `/ui/admin/audit` as top-level paths. The actual registered routes are all realm-scoped: `/ui/admin/realms/{realm}/users`, `/ui/admin/realms/{realm}/sessions`, etc. This misleads readers of the source but has no runtime effect.

---

## Operational Reachability Matrix

The top 5 admin surfaces assessed for full end-to-end reachability (routing → auth → handler → template → engine):

| Surface | Route registered | Auth gate | Handler implemented | Template exists | Engine method | Operationally reachable |
|---------|-----------------|-----------|--------------------|-----------------|--------------|-----------------------|
| Admin user CRUD | ✅ mod.rs:974-1043 | ✅ `RequireAdmin` | ✅ admin/users.rs | ✅ templates/ui/admin/users/ | ✅ `IdentityEngine::create_user` etc. | **Yes** |
| Admin org management | ✅ mod.rs:1113-1185 | ✅ `RequireAdmin` | ✅ admin/orgs.rs | ✅ templates/ui/admin/organizations/ | ✅ `IdentityEngine::create_organization` etc. | **Yes** |
| Admin role CRUD | ✅ mod.rs:1090-1108 | ✅ `RequireAdmin` | ✅ admin/rbac.rs | ✅ templates/ui/admin/rbac/ | ✅ `RbacEngine::create_role` etc. | **Yes** |
| RA update-password interstitial | ✅ mod.rs:751-755 | JWT `ra_token` param | ✅ handlers.rs:3628 | ✅ templates/ui/required-actions/update_password.html | ✅ `complete_update_password` | **Partially** — page works if accessed directly but login flow never routes here |
| Audit log viewer | ✅ mod.rs:1291-1315 | ✅ `RequireAdmin` | ✅ admin/realms.rs (audit handlers) | ✅ templates/ui/admin/audit/ | ✅ `AuditEngine::query` | **Yes** |

---

## Summary

**Verdict: production-ready-with-caveats**

The admin console is structurally complete across all major entity surfaces. The required-action UX is fully built but operationally isolated — the login path doesn't invoke it. The theme violation is localised and cosmetic. The missing admin surface for setting required actions is a real operator workflow gap.

**Top 3 findings:**
1. **Login flow bypasses RA check** (`handlers.rs:1080`): users with pending `UPDATE_PASSWORD` get a full session, defeating the security intent of required actions.
2. **Raw hex in onboarding wizard** (`wizard.html:117-153`): 5 inline `style=background:#XXXXXX` violate the "no raw hex outside config" theme rule.
3. **No admin UI to assign required actions to users** (absence in `admin/users.rs`): operators cannot force password resets via the required-action mechanism from the web console.
