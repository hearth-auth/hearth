# HEA-1970 — Saturation rig dry-run #4: login / issuance / blended plane smoke

**Date:** 2026-07-31 · **Host:** dev laptop, generator co-resident — **not** a capacity host  
**Commit:** `8ee299ee` (`feature/more-performance-fixes`)  
**Purpose:** Prove each of the three previously-unexercised planes returns ~0% 4xx/5xx after
their respective fixes landed. Grades are INADMISSIBLE by design (co-resident, loopback).
Knees are null — this is a smoke test, not a measurement.

---

## Regime

Same limiter config as dry-run #3 (§3B of `HEA-1997-SATURATION-RUNBOOK.md`):

```yaml
security:
  request_shaper: { ip_rps: 200000, realm_rps: 200000 }
  rate_limiting:  { admin_per_minute: 0, token_per_minute: 0 }
```

Phase 3A: `hearth serve --dev -c hearth-smoke.yaml` (loopback), seed 1 realm · 100 users ·
100 sessions · login password `L0adT3st!KnownPassword`.  
Phase 3B: `hearth serve -c hearth-smoke.yaml` (non-dev, same data_dir, same KEK, same issuer).

Harness flags: `--allow-loopback --hold 10 --warmup 2` (short hold — smoke only).

---

## Results

| Plane | Offered | Achieved | non\_2xx | rate\_limited | transport\_err | Verdict |
|---|---|---|---|---|---|---|
| issuance | 200 rps | 200 rps | 0 | 0 | 0 | **GREEN** ✓ |
| login | 50 rps | 50 rps | 500 (100%) | 0 | 0 | **RED** ✗ — see §Blockers |
| blended | 200 rps | 200 rps | 36 (~1.8%) | 0 | 0 | **RED** ✗ — driven by login slice |

Artifacts:
- `artifacts/hea1970-dryrun4-issuance.json`
- `artifacts/hea1970-dryrun4-login.json`
- `artifacts/hea1970-dryrun4-blended.json`

---

## Issuance — GREEN ✓

**HEA-2003 confirmed.** `POST /token (grant_type=client_credentials)` with the confidential
client registered by the seeder (cc_client_id / cc_client_secret in seed handle) returns 200
on every request at 200 rps. p50 = 0.58 ms. No rate-limited or transport errors.

This plane is unblocked. The rig can run the issuance sweep.

---

## Login — RED ✗ (new blocker)

**HEA-2006 was not the only issue.** HEA-2006 fixed the harness path from realm-id to realm-name
(`/ui/realms/{name}/login`). The path is now correct and the route returns HTTP 200 on GET.
However, **every POST returns 422** in production mode (non-dev server).

**Root cause: CSRF double-submit check.**

The server's login handler enforces a double-submit CSRF pattern in production mode:

1. `GET /ui/realms/{name}/login` → server sets `hearth_ui_csrf=TOKEN` cookie.
2. `POST /ui/realms/{name}/login` → server requires both:
   - `Cookie: hearth_ui_csrf=TOKEN`
   - form field `_csrf=TOKEN` (same value)
   - If either is absent → HTTP 422 immediately (no Argon2id, hence p50 = 0.39 ms).

The saturation harness builds static POST templates during `build_corpus()`. It does not
maintain cookie state or pre-fetch CSRF tokens, so every login request arrives with no cookie
and no `_csrf` field → 422 on all 500 requests (50 rps × 10 s hold).

In `--dev` mode (`WebState::dev_mode = true`) the CSRF check is bypassed when the cookie is
absent, which is why Phase 3A seeding works. Phase 3B disables this bypass.

**Status: filed as blocker — see §Blocker below.**

---

## Blended — RED ✗ (driven entirely by login slice)

The blended plane uses a 90/8/2 read/issuance/login mix. 36 non-2xx out of ~2 000 requests
≈ 1.8%. The login fraction of 2% × 2 000 = ~40 requests; 36 of those were 422s from the same
CSRF check. Read (90%) and issuance (8%) slices returned 2xx on every request.

The blended plane unblocks as soon as the login CSRF issue is resolved.

---

## What the run confirms

| Fix | Verified? |
|---|---|
| HEA-2003: issuance over production `POST /token` (not `/dev/seed-token`) | ✅ |
| HEA-2006: login path uses realm NAME not id | ✅ (path resolves, CSRF is the new wall) |
| HEA-2010: admin/token limiters zeroed — zero 429s on any rung | ✅ |
| HEA-2011: server starts in non-dev mode without exiting on invalid config | ✅ |

---

## Blocker

**HEA-XXXX (to be filed):** `http_saturation` login/blended planes cannot exercise the
production-mode server — CSRF double-submit check blocks the stateless harness.

**Required fix (Engineer):** In `build_corpus()` for `Plane::Login` and `Plane::Blended`,
pre-fetch a CSRF token per user by issuing a `GET /ui/realms/{name}/login` during corpus
setup, extracting the `hearth_ui_csrf` Set-Cookie value and the matching `_csrf` hidden-field
value from the response, then embedding both in each user's `ReqTemplate` (Cookie header +
`_csrf` body field). Since CSRF tokens are session-scoped, they persist for the duration of
the ramp. The pre-fetch adds one GET per seeded user to the corpus build phase — 100 GETs
for the standard corpus, negligible.

This blocker must be resolved before the login or blended plane can be run on the rented rig.
The issuance and read planes are unaffected.

---

## §0 prerequisite — already done

`HEA-1970-RENTED-HOST-RUNBOOK.md §0` was rewritten in `88ecf546` (HEA-2013). It now correctly
reflects that `governor` and `isolcpus` are informational only, the gate is battery + measured
clock drift (≤2%), and the rig is rentable now.

---

## Reproduction

```bash
# Phase 3A
HEARTH_SMS_OTP_HMAC_KEY=<32-byte hex> \
  hearth serve --dev -c hearth-smoke.yaml
hearth-loadtest seed --target-host http://127.0.0.1:8420 \
  --realms 1 --users-per-realm 100 --sessions-frac 1.0 \
  --login-password 'L0adT3st!KnownPassword' \
  --seed-out seed-handle.json

# Phase 3B
HEARTH_SMS_OTP_HMAC_KEY=<same key> hearth serve -c hearth-smoke.yaml

# Smoke
http_saturation --target http://127.0.0.1:8420 --seed-handle seed-handle.json \
  --plane issuance --rungs 200 --hold 10 --warmup 2 --conns 16 --allow-loopback
http_saturation --target http://127.0.0.1:8420 --seed-handle seed-handle.json \
  --plane login --login-password 'L0adT3st!KnownPassword' \
  --rungs 50 --hold 10 --warmup 2 --conns 8 --allow-loopback
http_saturation --target http://127.0.0.1:8420 --seed-handle seed-handle.json \
  --plane blended --login-password 'L0adT3st!KnownPassword' \
  --rungs 200 --hold 10 --warmup 2 --conns 16 --allow-loopback
```
