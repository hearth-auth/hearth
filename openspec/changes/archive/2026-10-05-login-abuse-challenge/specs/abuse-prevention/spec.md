## MODIFIED Requirements

### Requirement: Abuse guards are opt-in and run before password hashing
The guards listed below, except A-12, SHALL be off by default. A-12 SHALL always be on for `POST /ui/device`. A disabled guard SHALL be constructed in its no-op form and SHALL allow every request, so upgrading changes no behaviour until an operator enables a guard. The login-form guards SHALL run before a permit is taken from the Argon2 admission gate, so rejected traffic consumes no hashing capacity. Every refusal by a login-form guard SHALL render the one generic sign-in failure page, so no guard is an account-enumeration oracle. One exception applies: when a CAPTCHA provider is configured, a caller that A-3 or A-16 challenges SHALL see the login page again with the provider's widget (see A-16). That page SHALL be the same whether or not the submitted address has an account.

| Guard | Where it is consulted |
|-------|-----------------------|
| A-3 distributed-attack detector | login form, before the admission gate; `POST /v1/{realm}/auth/magic-link` |
| A-9 tenant CIDR policy | login form, before the admission gate |
| A-16 CAPTCHA challenge state | login form, before the admission gate; `POST /v1/{realm}/auth/magic-link`; passkey sign-in completion (`POST /webauthn/auth/complete` and the login page's `POST .../login/passkey-complete`) |
| A-4 outbound volume shield | self-service verification and password-reset sends |
| A-50 cross-realm aggregation cap | self-service verification and password-reset sends |
| A-12 adaptive backoff | `POST /ui/device` approval guard |

#### Scenario: No guard is configured
- **WHEN** `hearth.yaml` enables none of the guards above
- **THEN** login, registration and outbound mail behave exactly as they do without the guards

#### Scenario: A guard refuses a login
- **WHEN** a login-form guard refuses a sign-in attempt, and no CAPTCHA provider is configured
- **THEN** the response is the same generic sign-in failure page that a wrong password gets
- **AND** no Argon2 work is done for the attempt

#### Scenario: A challenged login sees the widget when a provider is configured
- **WHEN** a CAPTCHA provider is configured and A-3 or A-16 challenges a login-form attempt
- **THEN** the response is the login page with the provider's widget at `<!-- captcha-widget-slot -->`
- **AND** the page is the same for an address with an account and for one without
- **AND** no Argon2 work is done for the attempt

### Requirement: A-3 Distributed-attack detector
The server SHALL count, in a rolling window, the distinct usernames tried from each source IP and the distinct source IPs that target each username, and SHALL challenge a login attempt when either count exceeds its threshold. Each counting bucket SHALL hold at most `2 × threshold` entries, so memory per key is bounded whatever the attack rate.

| Key (`security.distributed_attack_detector.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the detector runs |
| `window` | `300s` | Rolling window length |
| `username_per_ip_threshold` | `20` | Distinct usernames per IP |
| `ip_per_username_threshold` | `20` | Distinct IPs per username |

A caller that receives a challenge MUST emit an `AbuseDetected` audit event with the IP and the username in its metadata, and MUST answer the client as the challenge-response table in A-16 says. The caller MUST NOT surface the challenge reason to the client. A solved CAPTCHA SHALL let one attempt continue; the detector SHALL keep counting, so its next challenge needs a new token. Setting a threshold to `usize::MAX` SHALL disable that dimension. When its lock is poisoned, the detector SHALL recover the lock and keep counting.

#### Scenario: Password spray from one address
- **WHEN** one source IP tries more than `username_per_ip_threshold` distinct usernames inside the window
- **THEN** the next attempt from that IP is challenged
- **AND** an `AbuseDetected` audit event records the IP and the username

#### Scenario: Distributed credential stuffing
- **WHEN** more than `ip_per_username_threshold` distinct IPs try one username inside the window
- **THEN** the next attempt against that username is challenged

#### Scenario: The reason stays private
- **WHEN** an attempt is challenged
- **THEN** the response does not reveal which dimension fired

#### Scenario: A challenged login is audited and challenged
- **WHEN** the detector challenges a login attempt
- **THEN** an `AbuseDetected` audit event with the IP, the username, `guard: "a3"` and the surface is written
- **AND** the caller gets the challenge response from the A-16 table instead of a bare generic refusal

#### Scenario: A sustained attack does not flood the audit log
- **WHEN** the detector challenges many attempts from one IP against one username inside one window
- **THEN** at most one `AbuseDetected` event is written for that IP, username and guard in that window

#### Scenario: A challenged magic-link request
- **WHEN** the detector challenges a `POST /v1/{realm}/auth/magic-link` request
- **THEN** the request gets the API challenge response, and no link is minted or sent
- **AND** an `AbuseDetected` audit event with `surface: "api"` is written

### Requirement: A-16 CAPTCHA-of-last-resort challenge
The server SHALL count failed authentications per IP and SHALL put an IP into a challenge state for `challenge_ttl_secs` once `challenge_threshold` failures occur inside `window_secs`. A solved CAPTCHA, or expiry of the window, SHALL return the IP to `Allow`.

A challenge by A-3 or A-16 SHALL be answered as follows:

| CAPTCHA provider | Login page (UI) | API sign-in endpoint |
|---|---|---|
| Configured | The login page again, with the provider's widget at `<!-- captcha-widget-slot -->` | `403` with `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"` and no other detail |
| Not configured | The generic sign-in failure page, as for a wrong password | `429` with `error_code: "HEARTH_RATE_LIMITED"` and `Retry-After` |

- Without a provider, `Retry-After` SHALL be the seconds left until the guard's window ends, rounded up, and at least `1`.
- Neither response SHALL say which guard or which dimension fired.
- A UI caller whose IP is in the challenge state SHALL see the widget on the login page it loads.
- A challenged request MAY carry a CAPTCHA token: the provider's form field on the login form, or the optional `captcha_token` body field on a JSON endpoint. A token the provider verifies SHALL let that attempt continue and SHALL clear the IP's challenge state. A token that fails verification SHALL count as a failed attempt and SHALL get the challenge response again.
- Every challenge SHALL write an `AbuseDetected` audit event with metadata `ip`, `username` (when the endpoint has one), `guard` (`a3` or `a16`) and `surface` (`ui` or `api`). At most one event SHALL be written per guard, IP and username per window.
- The guards SHALL run before any credential work: before Argon2, before a passkey assertion is checked, and before a magic-link email is built. A failed passkey assertion SHALL count as a failed attempt. A magic-link request SHALL NOT count as one.

| Key (`security.captcha.*`) | Default | Meaning |
|-----|---------|---------|
| `provider` | none; required | CAPTCHA provider (`turnstile`); a `security.captcha` block without it does not parse |
| `challenge_threshold` | absent | Failures per window before a challenge; required to enable the store |
| `window_secs` | `60` | Window for counting failures |
| `challenge_ttl_secs` | `1800` | How long the challenge state lasts |

When `challenge_threshold` is absent the store SHALL be disabled and every check SHALL return `Allow` (fail-open).

#### Scenario: A hot IP keeps guessing
- **WHEN** an IP reaches `challenge_threshold` failed logins inside `window_secs`
- **THEN** its next API attempt receives `403` with `HEARTH_ABUSE_CHALLENGE_REQUIRED`
- **AND** its next UI attempt is shown the CAPTCHA widget

#### Scenario: The challenge is solved
- **WHEN** the IP solves the CAPTCHA
- **THEN** its state returns to `Allow`

#### Scenario: A challenged caller is told to solve a challenge
- **WHEN** an IP in the challenge state makes an API sign-in attempt, and then loads the UI login page
- **THEN** the API attempt receives `403` with `HEARTH_ABUSE_CHALLENGE_REQUIRED`
- **AND** the login page carries the CAPTCHA widget at `<!-- captcha-widget-slot -->`

#### Scenario: A solved CAPTCHA lets the sign-in continue
- **WHEN** a challenged caller submits the login form, or a JSON sign-in request, with a token the provider verifies
- **THEN** the attempt continues to the credential check
- **AND** the IP's challenge state is cleared

#### Scenario: A wrong CAPTCHA token counts as a failure
- **WHEN** a challenged caller submits a token the provider rejects
- **THEN** the caller gets the challenge response again
- **AND** the attempt counts as a failed attempt for the IP

#### Scenario: Without a provider, the API answers with a timed lockout
- **WHEN** no CAPTCHA provider is configured and the detector challenges an API sign-in request
- **THEN** the response is `429` with `error_code: "HEARTH_RATE_LIMITED"`
- **AND** `Retry-After` is the whole seconds left in the detector's window, at least `1`

#### Scenario: Failed passkey sign-ins count
- **WHEN** an IP reaches `challenge_threshold` failed passkey assertions inside `window_secs`
- **THEN** its next passkey sign-in completion is challenged before the assertion is checked
