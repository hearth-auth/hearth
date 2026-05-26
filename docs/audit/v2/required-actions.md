# v2 Audit: Required Actions Real-User Flow (HEA-743 family)

**Auditor**: QA Agent (HEA-777)  
**Date**: 2026-05-25  
**Branch audited**: `feature/gap-updates-for-clustering` @ `7219405`  
**Methodology**: Current code grep + file:line tracing, no reliance on prior reports or issue tracker status.

---

## Verdict

**NOT PRODUCTION READY**

The required-action domain layer (engine, storage, OIDC/OAuth2 intercept) is correctly implemented. However, the primary browser login path (`login_submit_impl`) completely bypasses the required-action system. A user with `UPDATE_PASSWORD` or `VERIFY_EMAIL` pending can log in through the UI and receive a full session cookie with no gate. The interstitial pages exist but are unreachable from the normal login flow. Additionally, the VERIFY_EMAIL resend button sends no email despite a success flash message.

---

## Verified Claims

| Claim | Evidence |
|-------|----------|
| `RequiredAction` enum with `UpdatePassword` / `VerifyEmail` variants | `src/identity/types.rs:57` |
| Storage: `add_required_action` / `remove_required_action` / `pending_actions` | `src/identity/engine.rs:10337–10379` |
| `REQUIRED_ACTION_TOKEN_TYPE = "required_action"` constant | `src/identity/tokens.rs:35` |
| `TokenClaims.required_actions` field (serde default/skip-if-empty) | `src/identity/tokens.rs:194` |
| `issue_required_action_jwt` — short-TTL (900 s), no scopes/permissions | `src/identity/engine.rs:2362` |
| `password_grant_token` checks pending actions → issues RA JWT when non-empty | `src/identity/engine.rs:5025–5038` |
| `exchange_code` checks pending actions → issues RA JWT | `src/identity/engine.rs:4799–4808` |
| `validate_token` rejects RA tokens with `RequiredActionsPending` (→ 403) | `src/identity/engine.rs:4181–4183` |
| `complete_update_password` validates RA JWT, checks stored state, clears action | `src/identity/engine.rs:10428–10489` |
| Admin REST: `POST /admin/users/{id}/required-actions` wired and gated by admin auth | `src/protocol/http.rs:501–502` |
| Admin REST: `DELETE /admin/users/{id}/required-actions/{action}` wired | `src/protocol/http.rs:505–506` |
| UI interstitial routes registered in Axum router | `src/protocol/web/mod.rs:752–768` |
| REST completion routes registered (`/v1/required-actions/*`) | `src/protocol/http.rs:624–634` |
| HTML templates exist for all three interstitial pages | `templates/ui/required-actions/` |
| 41 tests across 5 test files covering interceptor, update-password, verify-email, domain, admin API | `tests/required_action*.rs`, `tests/admin_required_actions.rs` |

---

## Falsified or Unverified v1 Claims

### v1 claim: "Required-action interstitial is reachable after login"

**What current code shows**: `login_submit_impl` (`src/protocol/web/handlers.rs:921–1128`) authenticates the user with `verify_password`, then calls `create_session` directly and issues session cookies. There is **no call to `pending_actions()` or `issue_required_action_jwt()`** in this path. A user with pending required actions receives a full `hearth_ui_session` cookie and is redirected to `/ui` (line 1092–1095).

`create_session` (`src/identity/engine.rs:3725–3784`) also does not check required actions — it only enforces realm status, MFA policy, and user status (Active/PendingVerification/Disabled).

**Conclusion**: The UI login form completely bypasses the required-action gate. The interstitial pages are unreachable from the normal browser login flow.

### v1 claim: "VERIFY_EMAIL resend sends an email"

**What current code shows**: `ra_verify_email_resend` (`src/protocol/web/handlers.rs:3850–3858`) calls `request_email_verification(&realm_id, &user_id)` and matches on `Ok(_)` — the returned composite token is discarded. There is no call to `email_service.send_verification_email()` anywhere in this handler. The flash message "Verification email sent. Check your inbox." is false; no email is dispatched.

Compare to the working registration flow (`handlers.rs:3020–3042`) which correctly constructs a `verify_url` and calls `email_service.send_verification_email()`.

### v1 claim: "Routes `ra_request_email_verification` and `ra_verify_email` are unregistered (HEA-754)"

**What current code shows**: Both routes ARE registered at `src/protocol/http.rs:629–634`. The `#[allow(dead_code)]` attributes and "HEA-754: route not yet registered" comments (lines 4177–4178, 4283–4284) are stale. The handlers compile and are reachable. This is a documentation bug, not a functional gap — but the stale attribute suppresses a useful compiler warning.

---

## New Gaps Discovered

### GAP-1 (Critical): UI login form does not intercept required actions

**File:line**: `src/protocol/web/handlers.rs:1080–1128`

After `verify_password` succeeds (line 1012), the handler calls `create_session` then issues cookies. `pending_actions` is never called. The required-action JWT intercept only fires on OIDC/OAuth2 flows (`password_grant_token`, `exchange_code`, refresh). The UI login form — the primary flow for every browser user — is completely unprotected.

**Fix**: After password verification succeeds but before `create_session`, call `pending_actions`. If non-empty, issue a required-action JWT via `issue_required_action_jwt` and redirect to the appropriate interstitial page with `?ra_token=<jwt>`. The interstitial handlers and cookies-from-RA-JWT machinery (`session_id_from_ra_claims`, `issue_auth_cookies`) already exist at lines 3728–3741.

### GAP-2 (Critical): VERIFY_EMAIL resend handler sends no email

**File:line**: `src/protocol/web/handlers.rs:3850–3858`

`ra_verify_email_resend` calls `request_email_verification` and discards the returned composite token. No email is dispatched. The fix requires: (1) capturing the returned token, (2) constructing a `verify_url` pointing to `GET /v1/required-actions/verify-email?token=<token>`, (3) calling `state.email.send_verification_email(...)`.

### GAP-3 (Critical): Email verification link redeems to JSON, not a browser redirect

**File:line**: `src/protocol/http.rs:4285–4337` (`ra_verify_email`)

`GET /v1/required-actions/verify-email?token=...` returns `application/json` with `{"access_token": ...}`. When a user clicks the link from their email client in a browser, they see raw JSON. They cannot proceed to set session cookies. The success page at `GET /ui/required-actions/verify-email/success` exists but is never linked from the email or from this endpoint.

**Fix**: This endpoint must either: (a) set cookies and redirect to the success page (making it a browser-appropriate URL), or (b) the email must link to a UI handler that calls `redeem_email_verification` and sets cookies (as `ra_update_password_submit` does for update-password). Option (b) is more consistent with the existing pattern.

### GAP-4 (Low): No admin UI for assigning required actions

The admin web panel has no interface for assigning required actions to users. Operators must use `POST /admin/users/{id}/required-actions` directly. The only required-action presence in the admin UI is audit log labels (`src/protocol/web/admin/realms.rs:391–392`).

### GAP-5 (Low): `GET /ui/required-actions/update-password` renders with unsigned JWT

**File:line**: `src/protocol/web/handlers.rs:3632`

`ra_update_password_form` uses only `realm_id_from_ra_token` (which calls `decode_claims_unverified`) to extract the realm ID before rendering. A structurally valid JWT with any signature renders the form. The Playwright test intentionally crafts a forged token (`tests/ui/accessibility/required_actions.spec.ts:50–66`). This is low severity because the POST handler performs full cryptographic validation — the form renders but no action can be taken. However, it allows rendering the form in any realm without credentials.

---

## Operational Reachability Matrix

| Feature | Admin assigns action | Login intercepts | Interstitial reachable | Completion clears | Browser redirect |
|---------|:--------------------:|:----------------:|:----------------------:|:-----------------:|:----------------:|
| UPDATE_PASSWORD via OIDC/OAuth | ✓ | ✓ | ✓ (RA JWT in body) | ✓ | ✓ |
| UPDATE_PASSWORD via UI login | ✓ | ✗ **FAIL** | ✗ **FAIL** | N/A | N/A |
| VERIFY_EMAIL resend email | ✓ | ✗ **FAIL** | ✗ **FAIL** | N/A | N/A |
| VERIFY_EMAIL email link → browser | N/A | N/A | N/A | ✗ **FAIL** (JSON) | ✗ **FAIL** |
| RA token rejected at protected endpoints | N/A | N/A | N/A | ✓ | N/A |

**Key**: ✓ = works end-to-end with file:line evidence; ✗ FAIL = broken, evidence above.

---

## Summary

The HEA-743 feature family is approximately 60% complete. The domain layer (storage, JWT issuance, token validation, completion endpoint) is solid and well-tested. The OIDC/OAuth2 intercept path works correctly. What is missing is the wiring that connects the UI login form, the email dispatch on resend, and the browser-compatible email redemption path. None of these can be reached by a real user clicking through a standard browser login today.

**Action required**: Return to coder (HEA-765 owner / CTO) with GAP-1, GAP-2, and GAP-3 as blocking defects before this branch can be considered production-ready.
