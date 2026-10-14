## Why

An application that provisions users (the first real-world integration moves users off Kratos through the admin API and SCIM) has no API to let a new user choose a password. The console can send a reset email, but only an operator can click it, and its link lives 30 minutes, too short for an invitation. A user created without a password can only use "Forgot password" on their own, if they know to.

## What Changes

- A new admin RPC, `SendPasswordEmail` (`POST /admin/users/{id}/password-email`), emails the user a link to choose a password.
  - A user with no password gets the `welcome` email: "your account is ready, set your password". Its link lives `auth.token.set_password_token_ttl`, a new key with a 72-hour default.
  - A user with a password gets the current password-reset email.
  - The response says which: `kind` is `PASSWORD_EMAIL_KIND_SETUP` or `PASSWORD_EMAIL_KIND_RESET`.
- The same rate limit as self-service reset applies (3 per address per 15 minutes), and the outbound email caps (A-4, A-50) apply.
- The console's "Send reset email" action and the bulk "Send invite" action send the same email, so a user with no password gets the welcome email from them too.
- Hearth ships built-in `welcome` templates. The `welcome` kind's stored templates accept a new `{{set_password_url}}` placeholder.
- The reset page says "Set your password" for a set-password link.
- Every SDK's `AdminClient` gets `sendPasswordEmail(userId)`.

## Capabilities

### New Capabilities

- `password-email`: the admin password email, its two kinds, the set-password link and the `welcome` email.

### Modified Capabilities

- `abuse-prevention`: A-14 caps `set_password_token_ttl` at 7 days unless `allow_unsafe_ttl` is set.
- `sdk-support-contract`: the admin user operations include `sendPasswordEmail(id)`.

## Impact

- `proto/hearth/identity/v1/identity.proto`, the generated OpenAPI document and SDK admin types, and the hand-written `AdminClient` in each SDK.
- `src/identity/`: a set-password token purpose on the stored reset record, a new trait method, the TTL key.
- `src/identity/email/`: the `welcome` sender and templates.
- `src/protocol/`: a shared delivery helper, the admin REST handler, the console actions and the reset page.
- `src/config/types.rs`, `docs/guides/configuration-reference.md`, `hearth.maximal.yaml`.
