# HEA-1970 — Saturation rig dry-run #5: does the HEA-2015 CSRF fix actually unblock login?

**Date:** 2026-07-31 · **Host:** dev laptop, generator co-resident — **not** a capacity host
**Commit:** `c65bb36d` + HEA-2015's (then-uncommitted) `examples/http_saturation.rs` change
**Purpose:** Run the harness HEA-2015 repaired, rather than believe its "done".
Grades are INADMISSIBLE by design (co-resident, loopback, `load average ≈ 4`). Knees are null.
This is a proof-of-2xx, not a measurement.

---

## Verdict in one line

**The CSRF fix works. The login plane still grades RED — for a different and final reason:
a successful UI login is `303 See Other`, and the harness counts every non-2xx as an error.**

---

## Results

| Plane | Offered | Completed | non\_2xx | rate\_limited | transport | p50 | Verdict |
|---|---|---|---|---|---|---|---|
| issuance | 200 rps | 2000 | 0 | 0 | 0 | 0.55 ms | **GREEN** ✓ (unchanged from #4) |
| login | 50 rps | 500 | 500 (100%) | 0 | 0 | **20.2 ms** | **amber** — all 500 are `303`, see below |
| blended | 200 rps | 2000 | 36 (1.8%) | 0 | 0 | 0.37 ms | **amber** — 1.8% ≈ the 2% login slice |

Artifacts: `artifacts/hea1970-dryrun5-{issuance,login,blended}.json`

Regime identical to dry-run #4 (§3B limiter config, `--allow-loopback --hold 10 --warmup 2`),
non-`--dev` server, same data_dir/KEK/issuer across the phase-3A→3B switch. `POST /dev/seed-token`
returns 404 in phase 3B — production mode confirmed.

Host at run start: `load average: 4.49` · `MemAvailable 23.2 GB`. At run end: `3.33` · `23.2 GB`.

---

## HEA-2015 is confirmed working

Dry-run #4's login plane returned **422 at p50 0.39 ms** — the CSRF check rejected the request
*before* Argon2id. Dry-run #5 returns **p50 20.2 ms**. Twenty milliseconds is the KDF. The
request now reaches the credential path, which is the entire point of the login/KDF plane.

The `hearth_ui_csrf` cookie is confirmed present on `GET /ui/realms/dev-realm/login` in
production mode, and a single prefetched token is accepted for every user (the pre-login CSRF
token is not session-bound, so one prefetch for the whole corpus is valid).

---

## The remaining defect — success is a 303, the harness demands a 2xx

`examples/http_saturation.rs:1290`:

```rust
if !(200..300).contains(&code) {
    st.non_2xx += 1;
```

A successful browser login does not return 200. Verified by hand against the phase-3B server
with the exact request the harness builds:

```
HTTP/1.1 303 See Other
location: /ui
set-cookie: hearth_ui_session=18147bff-…; HttpOnly; Path=/ui; SameSite=Lax
```

A session cookie was minted — the login **succeeded**. Three independent confirmations that
this is uniform and not a mixed failure mode:

1. 20 distinct seeded users, same prefetched CSRF, replicating the harness request: **20/20 → 303**.
2. Login plane `error_rate` is exactly `1.0` with `transport_errors: 0` and `rate_limited: 0` —
   every request completed and every one was classified an error.
3. Blended `non_2xx` is 36/2000 = **1.8%**, matching the 2% login slice of the 90/8/2 mix to
   within rounding. The read and issuance slices contribute zero.

So the login plane is **functionally green and gradeable-RED**: the server is correct, the
scorer is wrong. Booking the rig in this state would spend droplet-hours to produce an artifact
reporting `error_rate: 1.0` on the KDF plane and a false ~2% error floor on the blended plane —
the mix we intend to publish as the operator-facing sizing number.

---

## Required fix (one classifier, plus the tests that pin it)

Treat `303` as success **for the login op only**, and only when `location` is the post-login
redirect target. Do not blanket-accept 3xx: a 302 to `/ui/realms/{name}/login` is a *failed*
login rendered as a redirect, and blanket-accepting 3xx would score it green. Anything the
login op returns that is neither 2xx nor an accepted 303 stays in `non_2xx`.

The scorer must also keep counting 4xx/5xx for read and issuance exactly as it does today.

Filed as a child of HEA-1970.

---

## Reproduction

```bash
export HEARTH_KEK=$(openssl rand -hex 32)
export HEARTH_SMS_OTP_HMAC_KEY=$(openssl rand -hex 32)

# Phase 3A — seed
hearth serve --dev -c hearth-smoke.yaml --bind 127.0.0.1:8420 &
HEARTH_LOADTEST_LOGIN_PASSWORD='L0adT3st!KnownPassword' \
  hearth-loadtest seed --target-host http://127.0.0.1:8420 --seed-out seed-handle.json \
  --realms 1 --users-per-realm 100 --sessions-frac 1.0
kill -TERM %1

# Phase 3B — production mode, same file
hearth serve -c hearth-smoke.yaml --bind 127.0.0.1:8420 &

# Planes (JSON goes to stdout — there is no --out flag)
http_saturation --target http://127.0.0.1:8420 --seed-handle seed-handle.json \
  --plane login --login-password 'L0adT3st!KnownPassword' \
  --rungs 50 --hold 10 --warmup 2 --conns 8 --allow-loopback > dryrun5-login.json
```
