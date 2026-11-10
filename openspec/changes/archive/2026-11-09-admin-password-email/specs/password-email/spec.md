## ADDED Requirements

### Requirement: An administrator sends a user a password email
`POST /admin/users/{id}/password-email` (`IdentityAdminService.SendPasswordEmail`) SHALL email the user a single-use link to choose a password. The caller SHALL hold `hearth.users.admin` in the realm that `X-Realm-ID` names, and the sub-admin ceiling of `rbac-admin-api` SHALL apply to the target user. The email depends on the user:

| The user | Email | Link lifetime | Response `kind` |
|---|---|---|---|
| has no password | `welcome`: the account is ready, set a password | `auth.token.set_password_token_ttl` (default 72 hours) | `PASSWORD_EMAIL_KIND_SETUP` |
| has a password | `password_reset` | `auth.token.password_reset_token_ttl` (default 30 minutes) | `PASSWORD_EMAIL_KIND_RESET` |

The link SHALL open the realm's reset page. A newer link, or a password set by any route, SHALL supersede it. The request SHALL count against the self-service reset limit for the user's address (3 requests in 15 minutes), and the outbound email caps (A-4, A-50) SHALL apply. Hearth SHALL answer:

| Case | Status |
|---|---|
| Email sent | `200` with `{"kind": ...}` |
| No such user in the realm | `404` |
| The realm does not allow password sign-in | `409` |
| No email transport is configured | `503` |
| The reset limit or an outbound cap refuses | `429` |
| The email transport refuses the message | `502` |

#### Scenario: A user without a password
- **WHEN** an administrator calls `SendPasswordEmail` for a user created with no password
- **THEN** the response is `200` with `kind` `PASSWORD_EMAIL_KIND_SETUP`
- **AND** the user receives the `welcome` email, whose link still sets a password 24 hours later

#### Scenario: A user with a password
- **WHEN** an administrator calls `SendPasswordEmail` for a user who has a password
- **THEN** the response is `200` with `kind` `PASSWORD_EMAIL_KIND_RESET`, and the user receives the password-reset email

#### Scenario: The rate limit
- **WHEN** an administrator calls `SendPasswordEmail` a fourth time for one user within 15 minutes
- **THEN** the response is `429`

#### Scenario: A sub-admin and a higher-ranked user
- **WHEN** a caller with `hearth.users.admin` sends a password email to a user who holds a higher admin role than the caller
- **THEN** the response is `403`, and no email is sent

### Requirement: The console sends the same password email
The console's "Send reset email" action on a user and its bulk "Send invite" action SHALL send the email that `SendPasswordEmail` sends for that user, with the same limits.

#### Scenario: Inviting a user who has no password
- **WHEN** an operator selects a user with no password and runs the bulk "Send invite" action
- **THEN** the user receives the `welcome` email with a set-password link

### Requirement: The welcome email and the set-password page
Hearth SHALL ship built-in HTML and text templates for the `welcome` email kind. A realm's stored `welcome` template SHALL accept the placeholders `{{user_email}}` and `{{set_password_url}}`. The reset page SHALL title a set-password link "Set your password", and a reset link "Reset your password".

#### Scenario: The page for a set-password link
- **WHEN** a user opens the link from a `welcome` email
- **THEN** the page says "Set your password", and the password the user submits becomes the user's password
