## ADDED Requirements

### Requirement: MFA is required by default
A realm SHALL require MFA when neither the realm nor the global `auth.mfa_required` setting is present.

#### Scenario: Realm with no MFA setting
- **WHEN** a realm is declared with no `auth.mfa_required`, and the global `auth.mfa_required` is absent
- **THEN** a password sign-in to that realm does not complete until the user proves a qualifying second factor

#### Scenario: Dev mode uses the production default
- **WHEN** the server runs with `serve --dev` and the dev realm has no `auth.mfa_required`
- **THEN** the dev realm requires MFA, and the bootstrap admin must enrol a passkey or TOTP before the sign-in completes

#### Scenario: Explicit opt-out is honoured
- **WHEN** a realm sets `auth.mfa_required: false`
- **THEN** a password sign-in to that realm completes without a second factor

### Requirement: One resolver decides the MFA requirement
Every code path that decides whether MFA is required SHALL use one resolver. The resolver SHALL combine realm, organization, client and role requirements with logical OR.

#### Scenario: Every entry point agrees
- **WHEN** a realm requires MFA and a user has proved only a password
- **THEN** the browser login, the authorization endpoint, the token endpoint (all grants that authenticate a user), and step-up each refuse to complete

#### Scenario: CI rejects a direct read
- **WHEN** a change adds a direct read of `mfa_required` outside the resolver
- **THEN** the CI lint fails and names the file and line

### Requirement: Only strong factors satisfy MFA
An MFA requirement SHALL be satisfied only by a WebAuthn credential (passkey or security key), a TOTP code, or a recovery code. Email OTP and magic links SHALL NOT satisfy it.

#### Scenario: Passkey alone satisfies MFA
- **WHEN** a user signs in with a passkey to a realm that requires MFA
- **THEN** the sign-in completes with no further factor

#### Scenario: Email OTP does not satisfy MFA
- **WHEN** a user proves a password and an email OTP in a realm that requires MFA
- **THEN** the sign-in does not complete, and the user is asked for a passkey, TOTP code or recovery code

#### Scenario: Magic link does not satisfy MFA
- **WHEN** a user signs in with a magic link in a realm that requires MFA
- **THEN** the sign-in does not complete until the user proves a qualifying factor

### Requirement: An organization can tighten the MFA requirement
An organization SHALL have an `mfa_required` setting, default `false`. When it is `true`, its members SHALL need MFA even if their realm does not require it. An organization setting SHALL NOT remove a realm requirement.

#### Scenario: Org requires MFA in an optional realm
- **WHEN** a realm sets `auth.mfa_required: false` and an organization in it sets `mfa_required: true`
- **THEN** a member of that organization needs a qualifying factor to sign in, and a non-member does not

#### Scenario: Org cannot loosen the realm
- **WHEN** a realm requires MFA and an organization sets `mfa_required: false`
- **THEN** a member of that organization still needs a qualifying factor

### Requirement: Turning MFA off is loud and audited
When a realm's effective MFA requirement is off, the server SHALL warn at startup, and the admin console SHALL show a warning on that realm. Every change of the effective value SHALL write an audit event.

#### Scenario: Startup warning
- **WHEN** the server starts with a realm whose effective MFA requirement is off
- **THEN** the log contains a `WARN` line that names the realm and says MFA is disabled

#### Scenario: Console warning
- **WHEN** an admin opens that realm in the admin console
- **THEN** the page shows a persistent warning that MFA is disabled for the realm, with the setting that controls it

#### Scenario: Audit on change
- **WHEN** reconcile or an admin action changes a realm's or organization's effective MFA requirement
- **THEN** the audit log records the actor, the realm or organization, and the old and new values
