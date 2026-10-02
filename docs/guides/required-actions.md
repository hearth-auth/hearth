# Required Actions — Operator Guide

**Audience:** Operators who need to force users to complete a specific action — verify their email, change their password, or enroll an authentication factor — before they can obtain tokens or use the application.

---

## What required actions are

A **required action** is a user-level gate on authentication and token issuance. You assign one or more pending actions to a user; the next time they authenticate, Hearth intercepts the flow and presents an interstitial page for each action in priority order. Once all actions are completed, the original authentication flow continues normally.

**Enforcement scope:**

| Flow | Enforcement |
|---|---|
| OIDC authorization code (`GET /ui/oauth/authorize`) | Intercepted via browser redirect to the interstitial page |
| Hearth Admin UI browser login (`/ui/login`) | Not enforced — this is a current limitation of the browser login form |

Required actions are stored on the user record in the `required_actions` array and cleared individually when each action is completed. All pending actions must be cleared before a full access token is issued.

---

## Action types

Four action types are supported. Values are SCREAMING_SNAKE_CASE strings in the JSON API.

| Wire value | When to use | Auto-injected? |
|---|---|---|
| `VERIFY_EMAIL` | User must click a verification link sent to their registered email address. | No — assign explicitly. |
| `UPDATE_PASSWORD` | User must set a new password. Use after an admin-initiated credential reset or a forced rotation policy. | No — assign explicitly. |
| `ENROLL_MFA` | User must enroll a second factor: TOTP, or — in a realm with `webauthn_required` — a passkey. | Yes — injected when a client or role requires MFA and the user has no factor, and when the realm sets `webauthn_required` and the user has no passkey (see [Passkey enrolment during login](#passkey-enrolment-during-login)). |
| `ENROLL_EMAIL_OTP` | User must enable email one-time codes as a second factor. | Yes — injected when the realm's `mfa_methods` includes `email_otp` and the user has not enabled it. |

`ENROLL_PHONE_OTP` was removed in Hearth 3.0.0 with SMS one-time codes; the API refuses it as an unknown action. A stored user that still carries it loads with the action dropped.

---

## Execution priority

When a user has multiple pending actions, Hearth presents interstitials in a fixed order. A user cannot skip an earlier action by completing a later one — the priority gate is enforced at every step.

| Priority | Action |
|---|---|
| 1 (first) | `VERIFY_EMAIL` |
| 2 | `UPDATE_PASSWORD` |
| 3 | `ENROLL_MFA` |
| 4 (last) | `ENROLL_EMAIL_OTP` |

---

## Assign required actions to a user

`PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions`

The body takes an `add` list and a `remove` list. Only the listed actions are modified — omitted actions are unchanged. Duplicates in `add` are silently ignored.

**Assign `VERIFY_EMAIL` and `UPDATE_PASSWORD`:**

```bash
curl -X PATCH https://auth.example.com/admin/realms/<realm-id>/users/<user-id>/required-actions \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -H "X-Realm-ID: <realm-id>" \
  -d '{"add": ["VERIFY_EMAIL", "UPDATE_PASSWORD"], "remove": []}'
```

**Remove a single action without touching others:**

```bash
curl -X PATCH https://auth.example.com/admin/realms/<realm-id>/users/<user-id>/required-actions \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -H "X-Realm-ID: <realm-id>" \
  -d '{"add": [], "remove": ["VERIFY_EMAIL"]}'
```

**Response (200 OK):** The updated user object, including the new `required_actions` array.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | `{"error": "invalid input"}` | Unknown or misspelled action string |
| `401` | — | Missing or invalid admin token |
| `404` | `{"error": "not found"}` | User or realm UUID not found |

Every assignment and removal emits an audit event (`RequiredActionAssigned` / `RequiredActionRemoved`) tagged with the admin user ID.

---

## Set realm-level defaults

New users created in a realm automatically inherit a default required-actions list. This is useful for enforcing email verification on all self-registered accounts.

`PATCH /admin/realms/{realm_id}/config`

```bash
curl -X PATCH https://auth.example.com/admin/realms/<realm-id>/config \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -H "X-Realm-ID: <realm-id>" \
  -d '{"default_required_actions": ["VERIFY_EMAIL"]}'
```

This replaces the entire default list. Pass `[]` to clear it. The change affects only users created **after** this call — existing users are not modified.

---

## How the OIDC authorization code flow is intercepted

When a user with pending required actions visits the authorization endpoint:

1. `GET /ui/oauth/authorize?client_id=...&response_type=code&...`
2. Hearth intercepts and issues a `302` redirect to `/required-action/{first_action}` (lowest priority number first).
3. A short-lived required-action cookie (`hearth_ra_session`) is set. This cookie carries the pending actions list and the original OAuth state, so the flow can resume after all actions are completed.
4. The user completes each action via the interstitial page. After each completion, Hearth redirects to the next pending action.
5. Once all actions are cleared, Hearth resumes the original authorization request and issues the authorization code as normal.

**Interstitial page URLs:**

| Action | Interstitial path |
|---|---|
| `VERIFY_EMAIL` | `/required-action/VERIFY_EMAIL` |
| `UPDATE_PASSWORD` | `/required-action/UPDATE_PASSWORD` |
| `ENROLL_MFA` | `/required-action/enroll-mfa` |
| `ENROLL_EMAIL_OTP` | `/required-action/ENROLL_EMAIL_OTP` |

These pages are served by the Hearth browser UI. They require the `hearth_ra_session` cookie to be present; direct requests without the cookie are rejected. Every form on them carries a token bound to that cookie, and a submission without it is refused (`403`).

An enrolment or verification action the user has **already satisfied** when its page is reached — TOTP or a passkey for `ENROLL_MFA`, email OTP for `ENROLL_EMAIL_OTP`, a verified address for `VERIFY_EMAIL` — is recorded as completed (`RequiredActionAutoCleared` audit event), removed from the account, and the login continues.

### Passkey enrolment during login

In a realm with `webauthn_required: true`, a user who has no passkey is not locked out: after the password and any second factor they already hold, `/required-action/enroll-mfa` asks them to register a passkey on the spot.

- The registration requires **user verification** (a PIN, fingerprint or face on the authenticator), whatever the realm's `webauthn_user_verification` setting. A security key that proves presence only is refused, because it could never satisfy the realm.
- The relying-party ID and origin are pinned to Hearth's public origin, exactly as for registration on the account page.
- The registration challenge is single-use and bound to the required-action session that asked for it.
- On success the action is recorded as completed and the login continues. A browser login's session records the passkey as the second factor proved (`ProvedWebAuthn`), which is what `webauthn_required` demands.
- The realm must offer passkeys: if its `mfa_methods` list is set and does not include `webauthn`, the page answers `409` explaining that passkeys must be enabled.


---

## Read pending actions on a user

Call `GET /admin/users/{id}`. There is no separate read endpoint for required actions — they are part of the user record. The `required_actions` field is present when non-empty:

```json
{
  "id": "<uuid>",
  "email": "alice@example.com",
  "display_name": "Alice Example",
  "status": "active",
  "required_actions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
}
```

When `required_actions` is empty or absent, the user has no pending gates.

---

## Keycloak → Hearth mapping

Operators migrating from Keycloak will find this feature conceptually identical. The main differences are in the API shape.

| | Keycloak | Hearth |
|---|---|---|
| **Concept** | Required Actions | Required Actions |
| `UPDATE_PASSWORD` | `UPDATE_PASSWORD` | `UPDATE_PASSWORD` |
| `VERIFY_EMAIL` | `VERIFY_EMAIL` | `VERIFY_EMAIL` |
| MFA enrollment | `CONFIGURE_TOTP` | `ENROLL_MFA` (covers TOTP and WebAuthn) |
| **Admin assignment API** | `PUT /admin/realms/{realm}/users/{id}` — `requiredActions` field replaces the full list | `PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions` — diff model with explicit `add`/`remove` |
| **Realm defaults** | Admin UI → Authentication → Required Actions tab | `PATCH /admin/realms/{realm_id}/config` with `{"default_required_actions": [...]}` — API only, no admin UI |

> **Diff model vs. replace model:** Keycloak's `requiredActions` replaces the entire list in one PUT. Hearth uses an explicit `add`/`remove` diff to prevent race conditions when concurrent admin operations modify the same user. Migration scripts that set `requiredActions` directly should be converted to send only the delta against the current state.
