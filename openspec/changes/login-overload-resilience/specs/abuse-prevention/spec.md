## MODIFIED Requirements

### Requirement: Abuse guards are opt-in and run before password hashing
The guards listed below, except A-12 and A-53, SHALL be off by default. A-12 SHALL always be on for `POST /ui/device`. A-53 SHALL be on unless `security.device_cookies.enabled` is `false`. A disabled guard SHALL be constructed in its no-op form and SHALL allow every request, so upgrading changes no behaviour until an operator enables a guard. The login-form guards SHALL run before a permit is taken from the Argon2 admission gate, so rejected traffic consumes no hashing capacity. Every refusal by a login-form guard SHALL render the one generic sign-in failure page, so no guard is an account-enumeration oracle. One exception applies: when a CAPTCHA provider is configured, a caller that A-3, A-16 or A-54 challenges SHALL see the login page again with the provider's widget (see A-16). That page SHALL be the same whether or not the submitted address has an account.

| Guard | Where it is consulted |
|-------|-----------------------|
| A-3 distributed-attack detector | login form, before the admission gate; `POST /v1/{realm}/auth/magic-link` |
| A-9 tenant CIDR policy | login form, before the admission gate |
| A-16 CAPTCHA challenge state | login form, before the admission gate; `POST /v1/{realm}/auth/magic-link`; passkey sign-in completion (`POST /webauthn/auth/complete` and the login page's `POST .../login/passkey-complete`) |
| A-53 device cookies | login form, before the admission gate (classifies the attempt as trusted or untrusted); every completed sign-in on the hosted pages (issues the cookie) |
| A-54 challenge under KDF pressure | login form, before the admission gate |
| A-4 outbound volume shield | self-service verification and password-reset sends |
| A-50 cross-realm aggregation cap | self-service verification and password-reset sends |
| A-12 adaptive backoff | `POST /ui/device` approval guard |

#### Scenario: No guard is configured
- **WHEN** `hearth.yaml` enables none of the guards above
- **THEN** login, registration and outbound mail behave exactly as they do without the guards, except that A-53 issues and checks device cookies

#### Scenario: A guard refuses a login
- **WHEN** a login-form guard refuses a sign-in attempt, and no CAPTCHA provider is configured
- **THEN** the response is the same generic sign-in failure page that a wrong password gets
- **AND** no Argon2 work is done for the attempt

#### Scenario: A challenged login sees the widget when a provider is configured
- **WHEN** a CAPTCHA provider is configured and A-3, A-16 or A-54 challenges a login-form attempt
- **THEN** the response is the login page with the provider's widget at `<!-- captcha-widget-slot -->`
- **AND** the page is the same for an address with an account and for one without
- **AND** no Argon2 work is done for the attempt

## ADDED Requirements

### Requirement: A-53 Device cookies
After a sign-in completes on the hosted pages, the server SHALL set a device cookie for the realm and the account. A sign-in is complete when every factor the realm requires has passed. The cookie SHALL be named `__Host-hearth_device_<realm-id>`, where `<realm-id>` is the realm UUID in simple form. It SHALL be `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`. Its `Max-Age` SHALL be `ttl_days` days. Its value SHALL be authenticated with a key that belongs to the realm and that every cluster node can verify. Its value SHALL bind the cookie to the normalized login identifier that the user submitted. The value SHALL NOT contain the identifier, the user id or any other personal data in readable form.

A login-form attempt SHALL be **trusted** when it carries a device cookie for the realm that meets all of these conditions:

- The authentication tag verifies, with a constant-time comparison.
- The cookie is not older than `ttl_days`.
- The cookie is bound to the identifier submitted in this attempt.
- The cookie is not denied on this node.

Every other attempt SHALL be **untrusted**. The check SHALL read no stored record. It SHALL take the same path for an address with an account and for one without.

A trusted attempt SHALL get these treatments:

- The KDF admission gate SHALL admit it before every untrusted attempt (see `credential-hashing`).
- The per-account lockout of `login_per_account` SHALL NOT refuse it.
- A-54 SHALL NOT challenge it.

All other guards SHALL apply to a trusted attempt as to an untrusted one.

A wrong password on a trusted attempt SHALL count as a failure of that device cookie. When one device cookie reaches `max_failures` failures inside `failure_window_secs`, the node SHALL deny that cookie until it expires. A denied cookie SHALL make its attempts untrusted. The deny list SHALL hold at most `deny_list_capacity` entries and SHALL drop the oldest entry first. Each successful sign-in SHALL replace the cookie with a new one.

| Key (`security.device_cookies.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Whether device cookies are issued and checked |
| `ttl_days` | `90` | Lifetime of one device cookie |
| `max_failures` | `5` | Wrong passwords per device cookie before it is denied |
| `failure_window_secs` | `900` | Window for counting those failures |
| `deny_list_capacity` | `100000` | Maximum denied cookies held per node |

#### Scenario: A completed sign-in sets the cookie
- **WHEN** a user completes a sign-in on the hosted login page
- **THEN** the response sets `__Host-hearth_device_<realm-id>` with `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`
- **AND** the cookie value does not contain the user's email address or user id

#### Scenario: A password alone does not set the cookie when MFA is required
- **WHEN** a user whose sign-in requires a second factor submits the correct password and has not yet passed the second factor
- **THEN** no device cookie is set

#### Scenario: A real user signs in while the account is locked by an attacker
- **WHEN** an attacker without a device cookie locks an account by `login_per_account.max_failures` wrong passwords
- **AND** the account's owner then submits the correct password from a browser that holds a valid device cookie for that account
- **THEN** the lockout does not refuse the owner's attempt
- **AND** the owner signs in

#### Scenario: A cookie for another account does not help
- **WHEN** an attempt carries a valid device cookie that is bound to a different identifier than the one submitted
- **THEN** the attempt is untrusted
- **AND** the per-account lockout applies to it

#### Scenario: A forged or expired cookie does not help
- **WHEN** an attempt carries a device cookie whose tag does not verify, or one older than `ttl_days`
- **THEN** the attempt is untrusted

#### Scenario: A stolen cookie is limited
- **WHEN** attempts that carry one device cookie submit `max_failures` wrong passwords inside `failure_window_secs`
- **THEN** later attempts with that cookie are untrusted on that node until the cookie expires

#### Scenario: The cookie is renewed
- **WHEN** a user signs in successfully with a valid device cookie
- **THEN** the response sets a new device cookie whose value differs from the old one

#### Scenario: The guard is turned off
- **WHEN** `security.device_cookies.enabled` is `false`
- **THEN** no device cookie is set
- **AND** every login-form attempt is untrusted

### Requirement: A-54 Challenge under KDF pressure
While the shared KDF admission gate is under pressure (see `credential-hashing`), the server SHALL challenge every untrusted login-form attempt before it takes a permit. The challenge SHALL be answered as the A-16 table says for a configured provider. A trusted attempt (see A-53) SHALL NOT be challenged by this guard. A token that the provider verifies SHALL let that one attempt continue to the admission gate. It SHALL NOT clear the pressure state. When no CAPTCHA provider is configured, this guard SHALL allow every attempt.

Every challenge by this guard SHALL write an `AbuseDetected` audit event with metadata `ip`, `username`, `guard: "a54"` and `surface: "ui"`. At most one event SHALL be written per IP and username in each pressure window.

| Key | Default | Meaning |
|-----|---------|---------|
| `security.captcha.kdf_pressure` | `true` | Whether this guard runs when a CAPTCHA provider is configured |

#### Scenario: A flood with a provider configured
- **WHEN** a CAPTCHA provider is configured and the shared KDF gate is under pressure
- **AND** an untrusted attempt is submitted on the login form without a CAPTCHA token
- **THEN** the response is the login page with the provider's widget at `<!-- captcha-widget-slot -->`
- **AND** no Argon2 work is done for the attempt
- **AND** an `AbuseDetected` audit event with `guard: "a54"` is written

#### Scenario: A solved challenge continues
- **WHEN** the gate is under pressure and an untrusted attempt carries a CAPTCHA token that the provider verifies
- **THEN** the attempt continues to the KDF admission gate

#### Scenario: A trusted attempt is not challenged
- **WHEN** the gate is under pressure and an attempt is trusted by A-53
- **THEN** this guard does not challenge the attempt

#### Scenario: No pressure, no challenge
- **WHEN** the shared KDF gate is not under pressure
- **THEN** this guard does not challenge any attempt

#### Scenario: No provider configured
- **WHEN** no CAPTCHA provider is configured and the gate is under pressure
- **THEN** this guard allows every attempt
- **AND** the admission gate sheds excess attempts as it does without this guard
