## Context

Self-service reset (`request_password_reset`) issues a token, stores `StoredPasswordReset` under `rst:token:{hash}`, and the reset page redeems it with `reset_password_with_token`. The TTL is checked at redemption: the realm's `password_reset_token_ttl` (A-14 caps it at 1 hour), else 30 minutes. A per-address limit (3 in 15 minutes) and a per-user watermark (a newer link supersedes older ones) already apply.

The console's "Send reset email" and bulk "Send invite" call `deliver_password_reset` (`src/protocol/web/admin/users.rs`), which takes `&WebState`. `AppState` carries the same email service, base URL and abuse guards.

## Goals / Non-Goals

**Goals:**
- One admin call that gets any user to a working password, whether or not the user has one.
- An invitation link that survives a weekend.
- One delivery path for the admin API and the console.

**Non-Goals:**
- The onboarding wizard's first-admin email. It has its own flow and copy.
- An invitation flow that creates the user. The caller creates the user first.

## Decisions

### The identity layer picks the kind

A new trait method, `request_password_email(realm_id, user_id)`, returns the kind, the address and the token. It reads the user's stored password credential directly. `has_password_credential` is not used, because it answers `false` for any user in a realm that does not allow password sign-in. Such a realm gets the existing `AuthMethodNotAllowed`, and the REST handler answers `409`, instead of an email that leads nowhere.

Both kinds go through the same issuer as self-service reset: the same limit, the same watermark, the same storage key.

### The stored record carries its purpose

`StoredPasswordReset` gets `purpose: Reset | Setup`, `#[serde(default)]` to `Reset`, so records written before the change still read. Redemption picks the TTL by purpose: `set_password_token_ttl` (default 72 hours, A-14 cap 7 days) for `Setup`, the reset TTL for `Reset`. The reset page reads the purpose without spending the token, to choose its title.

The other choice was a second key prefix and a second redeem path. It doubles the code that enforces single use and supersession, which is where reset bugs come from.

### A protocol helper that does not need `WebState`

`src/protocol/password_email.rs` takes the identity service, the optional email service, the abuse guards and the public base URL. It sends synchronously, because the caller (an operator or an API client) needs to know whether the email left. It applies the A-4 and A-50 outbound caps, which the console path skipped.

### `kind` is a proto enum

`PasswordEmailKind` follows `PROTO.md`: `PASSWORD_EMAIL_KIND_UNSPECIFIED`, `_SETUP`, `_RESET`. The JSON body carries the value name.

## Risks / Trade-offs

- **A 72-hour link is a longer theft window.** It is single-use, a newer link or a password change supersedes it, and an operator chooses to send it. The key lets a realm shorten it.
- **The console now sends a welcome email where it sent a reset email.** The old email told a user with no password to "reset" a password they never had.
