## Context

Two login guards can decide that a sign-in attempt must be challenged:

- **A-3**, the distributed-attack detector, counts distinct usernames per IP and distinct IPs per username.
- **A-16**, the challenge store, counts failed sign-ins per IP. It runs only when `security.captcha` is set, and that block always names a CAPTCHA provider.

So a challenge can happen with a CAPTCHA provider (A-3 or A-16) or without one (A-3 only, when `security.captcha` is absent).

This change makes a challenge do something the caller can act on, writes it to the audit log, and gives the API one rule for its status code.

**Precedent.** Auth0 answers suspicious-IP throttling with `429` and shows a CAPTCHA when bot detection is on. Keycloak's brute-force detection is a temporary lockout. Hearth follows the same split: a CAPTCHA when one is configured, a timed lockout when not.

## Goals / Non-Goals

**Goals:**
- A challenged attempt writes `AbuseDetected` and gets a response that tells the client what helps.
- The login page shows the CAPTCHA widget to a challenged caller, and a solved CAPTCHA clears the challenge.
- The API sign-in endpoints apply the same guards as the login form.

**Non-Goals:**
- A built-in CAPTCHA (for example a proof-of-work challenge). Hearth stays usable without any third-party service, because without a provider a challenge is a lockout. A built-in provider is a possible follow-up.
- Making a CAPTCHA provider required. That would force a hosted service on self-hosted operators.

## Decisions

### 1. What a challenge does

| CAPTCHA provider | Login page (UI) | API sign-in endpoint |
|---|---|---|
| Configured | The login page again, with the provider's widget at `<!-- captcha-widget-slot -->` | `403` with `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"` and no other detail |
| Not configured | The generic sign-in failure page, as for a wrong password | `429` with `error_code: "HEARTH_RATE_LIMITED"` and `Retry-After` |

- The status tells the client what helps. `403` with the challenge code means "solve a CAPTCHA". `429` means "wait".
- Without a provider, the lockout lasts until the A-3 window ends. `Retry-After` is the seconds left in that window, rounded up, at least `1`.
- Neither response says which guard or which dimension fired.
- The generic page and the widget page do not reveal whether the username exists.

### 2. Solving the challenge

- A challenged request may carry a CAPTCHA token. On the login form it is the provider's own form field. On a JSON endpoint it is an optional `captcha_token` body field.
- A token that the provider verifies lets that attempt continue, and clears the IP's A-16 state (`IpChallengeStore::clear`).
- A token that fails verification counts as a failed attempt and gets the challenge response again.
- A-3 keeps counting after a solved CAPTCHA. Its next challenge needs a new token. This bounds a spray to one CAPTCHA per attempt.

### 3. Where the guards run

| Endpoint | A-3 detector | A-16 store | Failure recorded |
|---|:-:|:-:|:-:|
| `POST /ui/login` (password form) | yes | yes | yes (today) |
| `POST /v1/{realm}/auth/magic-link` | yes | yes | no; a request is not a failed sign-in |
| `POST /webauthn/auth/complete` | no | yes | yes, on a failed assertion |
| `POST .../login/passkey-complete` | no | yes | yes, on a failed assertion |

- A-3 needs a username. Passkey sign-in is usually usernameless, so only the per-IP store applies there.
- The guards run before any credential work: before Argon2, before the assertion check, and before the magic-link email is built.
- The magic-link request answers the same `202` body for a known and an unknown address. A challenge is decided before that lookup, so it adds no account-existence oracle.

### 4. Audit

- Every challenge writes `AbuseDetected` with metadata `ip`, `username` (when the endpoint has one), `guard` (`a3` or `a16`) and `surface` (`ui`, `api`).
- To keep an attack from flooding the audit log, at most one event is written per `(guard, ip, username)` per window. A bounded in-process map holds the last write time; it is evicted like the detector's buckets.

### 5. Spec reconciliation

- A-3 no longer says "`429` or a challenge token". It points to the table in §1.
- The rule "a guard refusal shows the generic page" gains one exception: with a provider configured, a challenged caller sees the login page with the widget.
- `HEARTH_ABUSE_CHALLENGE_REQUIRED` is added to `src/protocol/error_codes.rs` and the error-code reference.

## Risks / Trade-offs

- **Lockout without a provider can lock out a real user** who shares an IP with an attacker, until the window ends. This is the same trade-off Keycloak's temporary lockout makes. Operators who need better can configure a provider.
- **The per-node audit limiter** writes up to one event per node in a cluster for the same key.
