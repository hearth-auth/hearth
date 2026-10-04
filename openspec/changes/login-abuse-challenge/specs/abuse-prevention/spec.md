## MODIFIED Requirements

### Requirement: A-3 Distributed-attack detector
The server SHALL count, in a rolling window, the distinct usernames tried from each source IP and the distinct source IPs that target each username, and SHALL challenge a login attempt when either count exceeds its threshold. Each counting bucket SHALL hold at most `2 × threshold` entries, so memory per key is bounded whatever the attack rate.

| Key (`security.distributed_attack_detector.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the detector runs |
| `window` | `300s` | Rolling window length |
| `username_per_ip_threshold` | `20` | Distinct usernames per IP |
| `ip_per_username_threshold` | `20` | Distinct IPs per username |

A caller that receives a challenge MUST emit an `AbuseDetected` audit event with the IP and the username in its metadata, MUST apply the A-16 challenge, and MUST return an error to the client (HTTP `429` or a challenge token). The caller MUST NOT surface the challenge reason to the client. Setting a threshold to `usize::MAX` SHALL disable that dimension. When its lock is poisoned, the detector SHALL recover the lock and keep counting.

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
- **THEN** an `AbuseDetected` audit event with the IP and the username is written
- **AND** the A-16 challenge is applied instead of a bare generic refusal

### Requirement: A-16 CAPTCHA-of-last-resort challenge
The server SHALL count failed authentications per IP and SHALL put an IP into a challenge state for `challenge_ttl_secs` once `challenge_threshold` failures occur inside `window_secs`. An API caller in the challenge state SHALL receive HTTP `403` with `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"`, and that SHALL be the only error code and the only detail returned. A UI caller in the challenge state SHALL receive a login or registration page that carries the configured CAPTCHA widget at the `<!-- captcha-widget-slot -->` marker. A solved CAPTCHA, or expiry of the window, SHALL return the IP to `Allow`.

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
