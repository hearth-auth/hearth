## 1. Baseline and tooling

- [ ] 1.1 Land the live load-test tooling (`loadtest/live/`, branch `perf/live-stress-test`) on `main`. Test first: `loadtest/live/test_analyze.py` covers the goodput and concurrent-journey grading that the new budgets need (served rate at 2× sustained; p99 of a side journey during a flood), and fails before the grading code exists.
- [ ] 1.2 Add a `login-flood` live scenario: the `login` journey at 2× its sustained rate, with `refresh`, `introspect` and `userinfo` at half their sustained rates on the same node. Test first: a `test_analyze.py` case grades a recorded flood run against both new `performance-budgets` requirements.
- [ ] 1.3 Record a baseline `login-flood` run on a `c-2` with a `dd`-checked fast disk, with `perf` and `offcputime` profiles of the overload phase. No code change; the run's `report.md` is the evidence for D7.

## 2. Gate: permit scope and metric (D3)

- [ ] 2.1 Test first: a `kdf_gate` integration test proves that the shared gate counts the permit as free before a password sign-in writes its session (`credential-hashing` "Session issuance runs after the permit is released").
- [ ] 2.2 Split `login_finish` in `src/protocol/web/handlers.rs` so that the gated closure runs only the verify and the re-hash; run MFA, required actions, session issuance and audit after the permit is released.
- [ ] 2.3 Apply the same split to every other gated caller that does non-Argon2id work under the permit (password reset, change password, registration, step-up, federation linking; REST `create_user` takes no permit since #439). Test first: one test per caller asserting the permit is free during its storage write.
- [ ] 2.4 Test first: `hearth_kdf_compute_seconds` excludes session issuance time (a test with a storage layer that sleeps on write). Then make the histogram time only the gated closure.

## 3. Gate: two-class admission (D2)

- [ ] 3.1 Test first: unit tests in `src/identity/kdf_gate.rs` for "A real user gets ahead of a flood" and "A trusted attempt waits longer before it is shed", including that an untrusted waiter is never admitted while a trusted waiter is queued.
- [ ] 3.2 Replace the shared gate's FIFO semaphore with two waiter queues and a free-permit count behind a short `std::sync::Mutex` (never held across `.await`); waiters await a `oneshot`.
- [ ] 3.3 Add `trusted_max_queue_wait_ms` to `security.password.kdf`. Test first: config tests that the default is `2500` and that `0` is refused at startup.
- [ ] 3.4 Add the `hearth_kdf_trusted_admitted_total` counter. Test first: a metrics test that a trusted admission increments it.

## 4. Gate: pressure signal (D6)

- [ ] 4.1 Test first: unit tests for "A shed starts the pressure window" and "Pressure ends", with an injected clock.
- [ ] 4.2 Implement the pressure state as an atomic timestamp of the last untrusted shed, the `pressure_window_secs` key and the `hearth_kdf_pressure` gauge.

## 5. Gate: dedicated workers, buffer reuse, CPU priority (D4, D5)

- [ ] 5.1 Test first: a `credentials.rs` test that a verify through a reused buffer gives the same result as `PasswordVerifier` for correct, wrong and legacy-parameter hashes, and that the comparison is constant-time (uses `subtle` or `ring`, no `==` on secrets).
- [ ] 5.2 Implement hash and verify into a caller-supplied block buffer with `Argon2::hash_password_into_with_memory`, including growth for a realm with a raised `password_memory_cost`.
- [ ] 5.3 Test first: a gate test that the shared gate runs work on exactly `max_in_flight` dedicated threads and the admin gate on `admin_max_in_flight`, and that no Argon2id work runs on Tokio's blocking pool.
- [ ] 5.4 Move gate execution to the dedicated worker pools; each worker owns one buffer allocated at start. Log the pool memory bound at startup.
- [ ] 5.5 Resolve design open question 2 (thread-priority crate or `unsafe` wrapper outside the identity layer); record the decision in `design.md`. If a crate is added, justify it and run `cargo-audit` and the license check.
- [ ] 5.6 Test first: a Linux-only test that a worker thread's nice value is the request threads' value plus `nice`, and equal when `nice` is `0`; a config test that `20` is refused. Then implement the priority change and the non-Linux startup log.
- [ ] 5.7 Add `[profile.release.package.argon2]` with `overflow-checks = false` and `codegen-units = 1` to `Cargo.toml`. Test: an A/B of the `argon2` bench, 5 alternating runs, recorded in the PR (no behaviour change, so no unit test).

## 6. Passkeys outside the gate

- [ ] 6.1 Test first: an integration test that fills every shared permit, makes the gate shed, and then completes a passkey sign-in successfully (`credential-hashing` "Passkeys work during a password flood"). The test must fail if any passkey path takes a permit. Fix any path it finds.

## 7. A-53 device cookies

- [ ] 7.1 Resolve design open questions 1 (root of `k_realm`) and 3 (`ttl_days`); record both in `design.md`.
- [ ] 7.2 Test first: unit tests for the cookie codec: a round trip; a wrong tag, a wrong realm, a wrong identifier and an expired cookie are each untrusted; the value contains no email and no user id; tag comparison is constant-time.
- [ ] 7.3 Implement the codec, key derivation and `security.device_cookies.*` config. Test first: config defaults and refusal of `ttl_days: 0` and `max_failures: 0`.
- [ ] 7.4 Create `tests/abuse_a53_device_cookies.rs` with the `abuse-prevention` A-53 scenarios: cookie set on a completed sign-in only (not after the password alone when MFA is required); the account owner signs in through an attacker's lockout; a cookie for another account does not help; forged and expired cookies do not help; a stolen cookie is denied after `max_failures`; renewal changes the value; `enabled: false` sets nothing. All fail before 7.5–7.7.
- [ ] 7.5 Issue the cookie on every completed sign-in on the hosted pages (password, passkey, magic link, federation) and renew it on each sign-in.
- [ ] 7.6 Classify login-form attempts as trusted or untrusted in `login_prepare`, before the gate, and pass the class to the gate.
- [ ] 7.7 Exempt trusted attempts from the `login_per_account` lockout; count their wrong passwords per cookie; add the bounded per-node deny list.
- [ ] 7.8 Add the A-53 row to the guard table in the docs and the `__Host-hearth_device_<realm-id>` cookie to the privacy and security-hardening guides.

## 8. A-54 challenge under KDF pressure

- [ ] 8.1 Create `tests/abuse_a54_kdf_pressure.rs` with the `abuse-prevention` A-54 scenarios: challenge under pressure with a provider; a verified token continues; a trusted attempt is not challenged; no challenge without pressure; no effect without a provider; one `AbuseDetected` per IP and username per window. All fail before 8.2.
- [ ] 8.2 Consult the pressure state in `login_prepare` for untrusted attempts and answer with the A-16 challenge response; add `security.captcha.kdf_pressure`.
- [ ] 8.3 Resolve design open question 4 (JSON sign-in endpoints) and record it in `design.md`.

## 9. Goodput past saturation (D7)

- [ ] 9.1 Rerun the `login-flood` scenario on `c-2` after sections 2–5. If the goodput budget passes, record the result and skip 9.2.
- [ ] 9.2 If it fails, read the overload profile from 1.3 and the new run, then add the next mechanism from D7 (immediate shed of an untrusted attempt that finds a full queue under pressure; then a fixed shed page body). Test first for each mechanism: a gate unit test for the immediate shed; a handler test that the shed response renders no template. Rerun after each one.

## 10. Measurement and documentation

- [ ] 10.1 Run `login`, `refresh`, `mix` and `login-flood` on `c-2` and on `c-4` with the same build and a `dd`-checked disk. Record logins per second per vCPU on both sizes and both new budgets in the run reports.
- [ ] 10.2 Update `docs/guides/configuration-reference.md` (`security.password.kdf` new keys, `security.device_cookies`, `security.captcha.kdf_pressure`, the changed meaning of `hearth_kdf_compute_seconds`, the new metrics).
- [ ] 10.3 Add `CHANGELOG.md` entries under `[Unreleased]`: Added (device cookies, KDF pressure challenge, new config keys and metrics), Changed (`hearth_kdf_compute_seconds` measures the hash only; Argon2id runs on dedicated lower-priority threads), Security (account-owner sign-in survives an attacker's lockout).
- [ ] 10.4 Run `make check`, `make test-detached`, `make ui-test-smoke` and `make ui-test-accessibility` against `make dev`.
