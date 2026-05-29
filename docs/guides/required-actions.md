# Required Actions — Operator Guide

**Audience:** Operators who need to force users to complete a specific action — verify their email, change their password, or enroll an authentication factor — before they can obtain tokens or use the application.

---

## What required actions are

A **required action** is a user-level gate on authentication and token issuance. You assign one or more pending actions to a user; the next time they authenticate, Hearth intercepts the flow and presents an interstitial page for each action in priority order. Once all actions are completed, the original authentication flow continues normally.

**Enforcement scope:**

| Flow | Enforcement |
|---|---|
| OIDC authorization code (`GET /ui/oauth/authorize`) | Intercepted via browser redirect to the interstitial page |
| Resource owner password credential (`POST /token`, `grant_type=password`) | Blocked with `400 required_actions_pending` |
| Hearth Admin UI browser login (`/ui/login`) | Not enforced — this is a current limitation of the browser login form |

Required actions are stored on the user record in the `required_actions` array and cleared individually when each action is completed. All pending actions must be cleared before a full access token is issued.

---

## Action types

Four action types are supported. Values are SCREAMING_SNAKE_CASE strings in the JSON API.

| Wire value | When to use | Auto-injected? |
|---|---|---|
| `VERIFY_EMAIL` | User must click a verification link sent to their registered email address. | No — assign explicitly. |
| `UPDATE_PASSWORD` | User must set a new password. Use after an admin-initiated credential reset or a forced rotation policy. | No — assign explicitly. |
| `ENROLL_MFA` | User must enroll a TOTP or WebAuthn factor. | Yes — injected by the adaptive-MFA engine when login arrives from an unrecognised device and the user has no enrolled factor. |
| `ENROLL_PHONE_OTP` | User must register and verify a phone number via SMS OTP. | Yes — injected when the realm's `mfa_methods` includes `sms` and the user has no verified phone on record. |

---

## Execution priority

When a user has multiple pending actions, Hearth presents interstitials in a fixed order. A user cannot skip an earlier action by completing a later one — the priority gate is enforced at every step.

| Priority | Action |
|---|---|
| 1 (first) | `VERIFY_EMAIL` |
| 2 | `UPDATE_PASSWORD` |
| 3 | `ENROLL_MFA` |
| 4 (last) | `ENROLL_PHONE_OTP` |

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
| `ENROLL_PHONE_OTP` | `/required-action/ENROLL_PHONE_OTP` |

These pages are served by the Hearth browser UI. They require the `hearth_ra_session` cookie to be present; direct requests without the cookie are rejected.

---

## ROPC error response

For resource owner password credential grants, Hearth returns a `400` error when required actions are pending:

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "required_actions_pending",
  "error_code": "required_actions_pending",
  "actions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
}
```

Your application is responsible for handling this response and redirecting the user to the appropriate completion UI.

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
| SMS enrollment | *(no built-in equivalent)* | `ENROLL_PHONE_OTP` — only injected when `mfa_methods` includes `sms` |
| **Admin assignment API** | `PUT /admin/realms/{realm}/users/{id}` — `requiredActions` field replaces the full list | `PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions` — diff model with explicit `add`/`remove` |
| **Realm defaults** | Admin UI → Authentication → Required Actions tab | `PATCH /admin/realms/{realm_id}/config` with `{"default_required_actions": [...]}` — API only, no admin UI |

> **Diff model vs. replace model:** Keycloak's `requiredActions` replaces the entire list in one PUT. Hearth uses an explicit `add`/`remove` diff to prevent race conditions when concurrent admin operations modify the same user. Migration scripts that set `requiredActions` directly should be converted to send only the delta against the current state.
