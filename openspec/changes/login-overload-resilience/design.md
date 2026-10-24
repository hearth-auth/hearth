## Context

Password login runs Argon2id at OWASP-minimum parameters (`m=19456 KiB, t=2, p=1`). The KDF admission gate (`src/identity/kdf_gate.rs`) bounds concurrent hashes to the core count and sheds a request with `503` after `max_queue_wait_ms` (250 ms). A separate admin pool protects `/ui/admin/login`. No normative spec describes the gate today; only `docs/guides/configuration-reference.md` does.

Live run `20261008-020550`, journey `login-fast`, on a DigitalOcean `c-2` (2 vCPU, Xeon Platinum 8168):

| Offered/s | Served/s | Errors | p50 ms | p99 ms | CPU (of 200%) | Time inside the permit |
|---|---|---|---|---|---|---|
| 10 | 10.0 | 0% | 53.7 | 73.1 | 45% | 44 ms |
| 40 | 40.0 | 0% | 78.9 | 130.2 | 176% | 44–51 ms |
| 50 | 36.4 | 27% | 301.8 | 342.5 | 181% | 56 ms |
| 80 | 34.5 | 57% | 258.9 | 343.5 | 183% | 58–62 ms |

Facts that shape the design:

- The CPU cost of a full login journey (about 44 ms) is close to the time inside the permit. Thus the permit time is mostly hash CPU, not I/O wait. Narrowing the permit gives a small gain only.
- Past saturation, the served rate falls by about 15%, and the time inside the permit grows to about 60 ms. Work outside the gate competes with the hashes for CPU.
- A random-email attempt costs a full dummy hash (enumeration resistance), so per-account lockout never triggers for it.
- Per-IP limits (A-2, `login_per_ip`) count IPv6 per `/64`, but a botnet stays under any per-IP limit.
- The per-account lockout (`login_per_account`) lets an attacker lock a real user out.
- Passkey sign-in does not take a KDF permit today. Nothing guarantees that.

Rejected earlier, and out of scope here: a client-side hash (OPAQUE or "server relief"), because no major identity provider uses one; and a lower Argon2id cost.

## Goals / Non-Goals

**Goals:**

- A real user who signed in before from the same browser can sign in during a password-form flood.
- A login flood does not push refresh, introspection or userinfo out of their budgets.
- Login goodput past saturation stays near the saturated rate.
- The KDF gate's behaviour is specified and tested.
- The permit covers only Argon2id work, and the compute metric measures only that work.

**Non-Goals:**

- A higher peak password-login rate. The hash sets it.
- A cluster-wide deny list for device cookies. Attempt trackers are per node (`cluster-consistency`).
- Passkey enrolment prompts. The `passkey-first-login` change covers them.
- Challenges on registration or forgot-password under KDF pressure. Registration is rare and already has P-1.

## Decisions

### D1. Device cookies follow the OWASP design, bound to the submitted identifier

After a sign-in completes (after MFA, when MFA applies), Hearth sets `__Host-hearth_device_<realm-id>` (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`). One cookie exists per realm, because one host serves many realms.

The value is `base64url(version || nonce[16] || issued_at || account_tag[16] || mac[32])`:

- `account_tag = HMAC-SHA256(k_realm, "acct" || normalized login identifier)[..16]`. The identifier is the normalized email the user typed. No PII is readable in the cookie.
- `mac = HMAC-SHA256(k_realm, everything before it)`.
- `k_realm` is derived with HKDF-SHA256 from realm key material that every cluster node holds, with the info label `hearth device cookie v1`. See open question 1.

An attempt is **trusted** when all of these are true: the MAC verifies (constant-time compare), the version is known, `issued_at` is inside `ttl_days`, the realm matches, the `account_tag` matches the submitted identifier, and the nonce is not on the node's deny list.

The check needs no storage read and no user lookup. Thus it runs before the gate at almost no cost, and it is the same for known and unknown addresses.

Each successful sign-in renews the cookie (new nonce, new `issued_at`). Wrong passwords on a trusted attempt count against the nonce. At `max_failures` inside `failure_window_secs`, the nonce goes on the deny list until it expires. The deny list is bounded (LRU, `deny_list_capacity`).

*Alternatives considered:*

- A tag over the user id. This needs a user lookup before the gate. An email change then keeps the cookie valid, but the gain is small: after an email change, one ordinary sign-in renews the cookie.
- A server-side device table. It needs storage writes and replication. The stateless MAC is enough, and only the deny list is state.
- An IP allowlist. It fails for mobile users and for shared addresses.

### D2. Two-class admission inside the shared gate

The shared gate gets two waiter queues: trusted and untrusted. When a permit frees, the next trusted waiter gets it first. An untrusted waiter gets a permit only when no trusted waiter is queued.

- An untrusted waiter is shed after `max_queue_wait_ms` (default `250`), as today.
- A trusted waiter is shed after `trusted_max_queue_wait_ms` (default `2500`). It prefers queueing to shedding, as the admin pool does.
- The admin pool does not change.

The gate is off the hot path. A short `std::sync::Mutex` around the two queues and the free-permit count is acceptable. The mutex is never held across an `.await`. A waiter awaits a `tokio::sync::oneshot`.

*Alternatives considered:*

- Reserved permits for trusted attempts. Reserved permits sit idle when no trusted attempt waits, which lowers the normal peak. Priority admission wastes no capacity.
- A separate gate per class. The two gates would not share capacity.

### D3. The permit covers the Argon2id work only

`login_finish` splits into two parts:

1. **The gated part:** the credential verify and, when needed, the re-hash (`credential-hashing`: stale and legacy hashes are re-hashed on the next successful login). Both are Argon2id work.
2. **The ungated part:** the MFA gate, the required-action gate, session issuance and audit writes. This part runs after the permit is released.

The same rule applies to the other gated callers: password reset, change password, registration, step-up, federation linking and client-secret verification. Client-secret verification already follows the rule. REST `create_user` no longer takes a permit: its request carries no password, so it hashes nothing (#439), and it has its own admission limit (#446).

`hearth_kdf_compute_seconds` then measures Argon2id work only.

The expected gain is small, about 10% or less, because the gated part is already mostly hash CPU. The main value is a correct metric and a correct gate.

### D4. A dedicated KDF worker pool with one reused buffer per worker

The shared gate runs its work on a dedicated pool of `max_in_flight` OS threads, not on Tokio's blocking pool. The admin pool gets `admin_max_in_flight` threads. A permit is a free worker.

Each worker owns one Argon2 block buffer, sized for the default parameters (19 MiB), allocated once at start. A hash uses `Argon2::hash_password_into_with_memory` with that buffer. A verify parses the PHC string, computes the raw output into the buffer, and compares it in constant time.

A realm with a raised cost (`password_memory_cost`) may need a larger buffer. The worker then grows its buffer to that size and keeps it. The pool's memory bound becomes `workers × largest configured memory cost`. This bound is fixed, and startup logs it.

This removes a 19 MiB allocation, its page faults and its zeroing from each hash. It also removes one source of the glibc arena retention found in round 2. The `M_ARENA_MAX` fix stays.

*Alternatives considered:*

- Thread-local buffers on the blocking pool. The blocking pool has up to 512 threads, so the memory bound would be about 9.7 GiB.
- A buffer checked out with each permit, still on the blocking pool. It works, but D5 needs dedicated threads anyway.

### D5. KDF workers run at a lower CPU priority

On Linux, each KDF worker thread sets its own nice value to `security.password.kdf.nice` (default `5`) at start. Linux nice applies to each thread. Under the CFS scheduler, nice `5` gives a weight of 335 against 1024 for nice `0`. Thus a busy Tokio worker gets about 3 times the CPU share of a busy KDF worker. When Tokio workers are idle, the KDF workers use the whole CPU, so the peak login rate does not change at low load.

`0` disables the change. On other platforms the setting does nothing, and startup logs that.

Setting the nice value needs a system call. The identity layer must not contain `unsafe`. Thus the call goes through a small dependency (`thread-priority`, MIT/Apache-2.0) or through a safe wrapper in a layer that allows `unsafe`. See open question 2.

*Alternatives considered:*

- Fewer permits than cores. This halves the peak on a 2 vCPU node, even when there is no flood.
- `SCHED_IDLE`. Under steady request load, hashing could stop completely, and all logins would fail.

### D6. The gate publishes a pressure signal

The shared gate is **under pressure** while it shed at least one untrusted waiter in the last `pressure_window_secs` (default `10`). The gate exposes the state as a cheap atomic read and as the gauge `hearth_kdf_pressure` (`0` or `1`).

A-54 reads this state before the gate. Under pressure, an untrusted login-form attempt gets the A-16 challenge response when a CAPTCHA provider is configured. A solved CAPTCHA lets that one attempt continue. Without a provider, A-54 does nothing, and the gate sheds as before.

### D7. Goodput past saturation: profile first, then choose the mechanism

The spec sets a budget (served rate at 2× the sustained rate ≥ 90% of the sustained rate). The mechanism is chosen after a CPU profile of the overload phase in a live run. The round-2 tooling already captures `perf` and `offcputime`. Candidate mechanisms, in the order they will be tested:

1. D5 alone. Lower-priority hashing may let the request work finish without stretching the hashes.
2. Under pressure, an untrusted attempt that finds the untrusted queue at least `max_in_flight` long is shed at once, without the 250 ms wait.
3. Under pressure, the shed response is a fixed page body, not a rendered template.

### D8. Budgets come from the live load-test journeys

The new budgets in `performance-budgets` are graded by the live journeys (`loadtest/live/`, branch `perf/live-stress-test`). That tooling is not on `main`. A task lands it first. Like every other budget, the new budgets are advisory.

## Risks / Trade-offs

- [A stolen device cookie gives priority and avoids the account lockout for one account] → The attacker still needs the password. The cookie is `HttpOnly`, `Secure` and `__Host-`. Each nonce allows only `max_failures` wrong passwords before it is denied.
- [A device cookie on a shared computer] → It helps the next person only for the same account, and only with that account's password. Sign-out does not remove it, because it carries no session. An operator can turn the guard off.
- [A device cookie is a persistent identifier] → It is first-party, it is used only for sign-in security, and it holds no readable personal data. Privacy documentation must describe it.
- [Untrusted attempts starve under constant trusted load] → Trusted volume is real-user volume. Each trusted nonce is limited by `max_failures`. The pressure gauge and the shed counters show the condition.
- [The per-node deny list allows `max_failures` per nonce on each node] → This matches the per-node attempt trackers in `cluster-consistency`. A cluster of N nodes allows N × `max_failures` at most.
- [The meaning of `hearth_kdf_compute_seconds` changes] → It is recorded in `CHANGELOG.md` under Changed. Hearth has no deployed dashboards.
- [Nice has less effect when other processes on the host also use CPU] → The budgets are measured on a dedicated node. The setting is documented as a priority between Hearth's own threads.
- [Thread-priority dependency] → It must pass `cargo-audit` and the license check, or the wrapper goes in a layer that permits `unsafe`.

## Migration Plan

Hearth has no deployed users. The change ships in one release:

1. A-53 defaults to on, and the first successful sign-in after the upgrade sets the cookie.
2. A-54 is on only when a CAPTCHA provider is configured.
3. To roll back, set `security.device_cookies.enabled: false` and `security.password.kdf.nice: 0`. A cookie that is no longer checked has no effect.

## Open Questions

1. **The root of `k_realm`.** Which existing realm key material does every cluster node hold, and does it rotate? If the signing keys rotate, the HKDF input must be a stable secret, or a rotation must accept the previous key for `ttl_days`.
2. **The thread-priority call.** Use the `thread-priority` crate, or a `libc::setpriority` wrapper in a layer that permits `unsafe`?
3. **Default `ttl_days`.** The draft uses `90`. A longer value helps users who sign in rarely. A shorter value limits the value of a stolen cookie.
4. **Should A-54 also cover the JSON sign-in endpoints?** The draft covers the login form only, because the KDF flood that matters targets the hosted form.
