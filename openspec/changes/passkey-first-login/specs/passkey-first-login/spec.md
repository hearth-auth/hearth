## ADDED Requirements

### Requirement: A passkey prompt follows a sign-in without a passkey
After a sign-in on the hosted pages completes, and after every required action, Hearth SHALL show the passkey prompt page when all of these conditions are true:

- The realm's `passkey_prompt` is not `off`.
- The realm's `allowed_auth_methods` is absent or contains `passkey`.
- The realm does not set `webauthn_required: true`.
- The sign-in did not use a passkey.
- The account has no passkey.
- When `passkey_prompt` is `interval`, the account chose "Not now" no less than `passkey_prompt_interval_days` days ago, or never.

Otherwise Hearth SHALL continue without the prompt. Hearth SHALL issue the authorization code, or follow the `return_to` redirect, only after the user leaves the prompt. A request with `prompt=none` SHALL never show the prompt.

#### Scenario: A password user without a passkey
- **WHEN** a user with no passkey signs in with a password in a realm with `passkey_prompt: every_login`
- **THEN** Hearth shows the passkey prompt page before it redirects to the client with an authorization code

#### Scenario: A passkey sign-in
- **WHEN** a user signs in with a passkey
- **THEN** Hearth shows no passkey prompt

#### Scenario: A user who already has a passkey
- **WHEN** a user who has a passkey signs in with a password
- **THEN** Hearth shows no passkey prompt

#### Scenario: Required actions come first
- **WHEN** a user with no passkey signs in with a password and has a pending `UPDATE_PASSWORD` action
- **THEN** Hearth runs the `UPDATE_PASSWORD` action first
- **AND** Hearth shows the passkey prompt after it

#### Scenario: A realm that does not allow passkeys
- **WHEN** a realm sets `allowed_auth_methods: ["password"]`
- **THEN** its users never see the passkey prompt

#### Scenario: A realm that forces passkeys
- **WHEN** a realm sets `webauthn_required: true`
- **THEN** its users never see the passkey prompt

### Requirement: The realm controls how often the prompt appears
Each realm SHALL have a `passkey_prompt` setting with the values `every_login`, `interval` and `off`. The default SHALL be `every_login`. Each realm SHALL have a `passkey_prompt_interval_days` setting, used only by `interval`, with the default `7`. A value of `passkey_prompt_interval_days` below `1` SHALL be refused, by the admin API with `400` and by `hearth.yaml` at startup. Both settings SHALL be available on the admin API, in the admin console and in `hearth.yaml` realm configuration.

#### Scenario: Every login
- **WHEN** a realm uses `passkey_prompt: every_login` and a user without a passkey chooses "Not now"
- **THEN** that user sees the prompt again at the next password sign-in

#### Scenario: An interval
- **WHEN** a realm uses `passkey_prompt: interval` with `passkey_prompt_interval_days: 7` and a user chooses "Not now"
- **THEN** that user does not see the prompt at sign-ins in the next 7 days, on any device
- **AND** that user sees the prompt at the first password sign-in after 7 days

#### Scenario: Off
- **WHEN** a realm uses `passkey_prompt: off`
- **THEN** no user in that realm sees the prompt

#### Scenario: An invalid interval
- **WHEN** an admin sets `passkey_prompt_interval_days: 0` through the admin API
- **THEN** the response is `400` and the realm keeps its previous value

### Requirement: The prompt offers enrolment and a one-step dismissal
The prompt page SHALL offer "Create a passkey" and "Not now". "Not now" SHALL continue the sign-in with one action. A successful enrolment SHALL continue the sign-in. A failed or cancelled enrolment SHALL return the user to the prompt page, where "Not now" still works. When the browser cannot create a passkey, the page SHALL NOT offer "Create a passkey" and SHALL offer "Continue". "Continue" SHALL NOT count as "Not now".

#### Scenario: The user creates a passkey
- **WHEN** a user on the prompt page chooses "Create a passkey" and completes the browser's passkey ceremony
- **THEN** the account has a new passkey
- **AND** the sign-in continues to the client

#### Scenario: The user dismisses the prompt
- **WHEN** a user on the prompt page chooses "Not now"
- **THEN** the sign-in continues to the client with no further page

#### Scenario: The user cancels the ceremony
- **WHEN** a user cancels the browser's passkey dialog
- **THEN** the prompt page shows again with "Not now" available

#### Scenario: A browser without passkey support
- **WHEN** the prompt page loads in a browser that does not support WebAuthn
- **THEN** the page offers "Continue" and does not offer "Create a passkey"
- **AND** choosing "Continue" does not record a "Not now"

### Requirement: Enrolment from the prompt needs no second step-up proof
When Hearth shows the prompt, it SHALL create an enrolment ticket for that sign-in. The ticket SHALL be random with at least 256 bits, SHALL be bound to the session the sign-in created, SHALL expire 300 seconds after the sign-in, and SHALL be valid for one enrolment. The ticket SHALL appear in the prompt page only. It SHALL NOT be set as a cookie. A passkey registration request that carries a valid ticket for its own session SHALL be accepted without a `password`, `totp_code` or `assertion` step-up proof. A ticket SHALL NOT be accepted as a step-up proof for any other operation, including passkey removal. Every other passkey registration request SHALL keep its current step-up rule.

#### Scenario: Enrolment with the ticket
- **WHEN** the prompt page sends a passkey registration with its ticket, within 300 seconds of the sign-in
- **THEN** the registration is accepted without a password, TOTP code or assertion

#### Scenario: A reused ticket
- **WHEN** a second passkey registration sends a ticket that was already used
- **THEN** the request is refused as a request without a step-up proof

#### Scenario: An expired ticket
- **WHEN** a passkey registration sends a ticket more than 300 seconds after the sign-in
- **THEN** the request is refused as a request without a step-up proof

#### Scenario: A ticket from another session
- **WHEN** a passkey registration sends a valid ticket that is bound to a different session
- **THEN** the request is refused as a request without a step-up proof

#### Scenario: A ticket does not allow removal
- **WHEN** a passkey removal request sends a valid ticket as its only proof
- **THEN** the response is `403 step_up_required` and the passkey stays

### Requirement: Prompt outcomes are counted
Hearth SHALL count each prompt outcome in the counter `hearth_passkey_prompt_total` with the label `outcome` set to `shown`, `enrolled`, `dismissed` or `unsupported`. The counter SHALL carry no user, account or session label.

#### Scenario: A dismissal is counted
- **WHEN** a user sees the prompt and chooses "Not now"
- **THEN** `hearth_passkey_prompt_total{outcome="shown"}` and `hearth_passkey_prompt_total{outcome="dismissed"}` each increase by 1
