## Why

A flood of password logins can deny sign-in to every real user. Each password login costs about 44 ms of CPU, almost all of it Argon2id. On a 2 vCPU `c-2` node, about 45 login requests per second fill the KDF admission gate (live run `20261008-020550`, journey `login-fast`). One laptop can send that rate. Per-IP limits do not stop a botnet, and the per-account lockout lets an attacker lock a real user out. The live run also shows that past saturation the served login rate falls from 40/s to 32–36/s: work outside the gate takes CPU from the hashes.

The goal is not a higher peak login rate. At OWASP-minimum Argon2id, the peak is set by the hash. The goal is that real users keep a way to sign in while an attacker floods the password form, and that a flood does not degrade the rest of the server.

## What Changes

- **Device cookies (new guard A-53).** After a successful sign-in, Hearth issues a signed device cookie bound to the realm and the account (OWASP "Slow Down Online Guessing Attacks with Device Cookies"). A later password attempt for the same account from that browser is a *trusted* attempt:
  - It is admitted to the KDF gate before every untrusted attempt.
  - The per-account lockout does not refuse it. Wrong passwords count against that device cookie instead.
  - The guard is on by default.
- **Challenge under KDF pressure (new guard A-54).** While the shared KDF gate sheds work, an untrusted login-form attempt is challenged with the configured CAPTCHA before it reaches the gate. Trusted attempts are not challenged. Without a CAPTCHA provider the guard does nothing.
- **The KDF admission gate becomes normative.** The existing gate (`security.password.kdf.*`) is specified for the first time, with these changes:
  - The gate admits trusted attempts before untrusted ones.
  - A permit covers the Argon2id operation only. Today the UI login holds its permit through the MFA gate, session issuance and audit writes.
  - `hearth_kdf_compute_seconds` measures the Argon2id operation only.
  - Passkey sign-in never takes a permit.
- **Password hashing yields CPU.** Argon2id work runs at a lower CPU priority than request handling. A login flood then cannot starve refresh, introspection or userinfo.
- **New load budgets.** Login goodput past saturation, and the latency of other requests during a login flood, get budgets graded by the live load-test journeys.
- **Internal efficiency work** with no spec change: one reused 19 MiB Argon2 block buffer per permit, a release-profile override for the `argon2` crate, and a 4 vCPU (`c-4`) live run that tests whether login capacity scales per vCPU.

No breaking change. Hearth has no deployed users, so the new default-on cookie needs no migration.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `abuse-prevention`: adds guards A-53 (device cookies) and A-54 (challenge under KDF pressure); the opt-in rule gains A-53 as a default-on exception, and the guard table lists both new guards.
- `credential-hashing`: adds requirements for the KDF admission gate (bounded permits, shedding, trusted-first admission, a permit that covers the hash only, the compute metric), for passkey sign-in outside the gate, and for the lower CPU priority of hashing work.
- `performance-budgets`: adds a login-goodput budget past saturation and a budget for non-login requests during a login flood.

## Impact

- **Code:** `src/identity/kdf_gate.rs` (two admission classes, buffer pool, CPU priority), `src/identity/credentials.rs` (hash into a pooled buffer), `src/protocol/web/handlers.rs` (`login_prepare` / `login_finish` split so the permit covers the verify only; device-cookie issue and check), `src/abuse/` (A-53 and A-54), `src/config/` (new keys under `security.device_cookies` and `security.captcha.kdf_pressure`).
- **Cookies:** one new cookie, `__Host-hearth_device`, per realm and account, on the hosted login pages.
- **Config:** new keys; `docs/guides/configuration-reference.md` and `CHANGELOG.md` entries.
- **Metrics:** `hearth_kdf_compute_seconds` changes meaning (hash only); new `hearth_kdf_trusted_admitted_total` and `hearth_kdf_pressure` series.
- **Tests:** `tests/abuse_a53_*.rs` and `tests/abuse_a54_*.rs` (required by `scripts/check-abuse-coverage.sh`); gate unit tests; live load-test journeys for the new budgets.
- **Cargo.toml:** `[profile.release.package.argon2]` override. A crate for thread priority may be needed (see design).
