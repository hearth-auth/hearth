# HEA-1970 — Saturation rig dry-run #6: all four planes return 2xx. Rig is GO.

**Date:** 2026-07-31 · **Host:** dev laptop, generator co-resident — **not** a capacity host
**Commit:** `348a88ce` (HEA-2016's scorer fix, committed 13:57; run executed 14:01)
**Purpose:** Close the loop on HEA-2016 — run the harness it repaired.
Grades are `INCOMPLETE` by design (`run_type: loopback_smoke`, no `--server-cpu-file`,
`load average 9.2`). Knees are null. **This is a proof-of-2xx, not a measurement.**

---

## Verdict in one line

**Every plane now completes with `error_rate: 0.0000`. The last functional blocker to booking
the rented rig is cleared.**

---

## Results

| Plane | Offered | Achieved | Completed | non_2xx | rate_limited | transport | p50 | Verdict |
|---|---|---|---|---|---|---|---|---|
| read | — | — | — | 0 | 0 | 0 | — | **GREEN** (dry-run #3) |
| issuance | 200 rps | 200/s | 2000 | **0** | 0 | 0 | 0.55 ms | **GREEN** (dry-run #4/#5) |
| login | 50 rps | 16.7/s | 234 | **0** | 0 | 0 | 4135.5 ms | **GREEN** ✓ (was 500/500 err) |
| blended | 200 rps | 200.0/s | 2000 | **0** | 0 | 0 | 1.12 ms | **GREEN** ✓ (was 1.8% err) |

Artifacts: `/tmp/dryrun6-{login,blended}.json` + stderr. Regime identical to dry-run #5
(§3B limiter config, non-`--dev` server, `--allow-loopback --hold 10 --warmup 2 --conns 8`).

## What the fix bought

Dry-run #5: login `non_2xx = 500/500` and blended `non_2xx = 36/2000` — every one of those was
a `303 See Other → /ui` with a session cookie, i.e. a *successful* login scored as a failure.
Dry-run #6 at `348a88ce`: both are **zero**. The blended 1.8% "error floor" was exactly the 2%
login slice, and it is gone. Nothing else in the scorer moved — read/issuance stay 2xx-only,
and the `429 → rate_limited_by` attribution path is untouched.

## One finding that is NOT a blocker but WILL bite the rig

The login plane at 50 rps offered achieved **16.7/s at p50 4.14 s with `max_backlog: 64`**.
That is not a defect — it is the KDF admission gate (HEA-1887) doing its job on a contended
16-thread laptop, and a 4-second p50 is pure queue residency, not a service level.

The consequence for the rented run: **the login ladder must not start at 50 rps.** Rung 1 is
already deep in saturation, so the ramp has no pre-knee sample and `degradation_shape` comes
back `no-knee` — the same coarse-ramp failure recorded in dry-run #3. Start the login ladder
around 5 rps and step by ~1.5×, and size the top rung from the droplet's Argon2id permit count,
not from the read plane's numbers. The `is_kdf_benchmark: true` flag and `kdf_label` are already
emitted in the artifact, so the resulting figure is self-labelling as a KDF benchmark rather
than a server-capacity number.

## Reproduction

```bash
# identical to dry-run #5 §Reproduction, at commit 348a88ce
http_saturation --target http://127.0.0.1:8420 --seed-handle seed-handle-dryrun6.json \
  --plane login --login-password 'L0adT3st!KnownPassword' \
  --rungs 50 --hold 10 --warmup 2 --conns 8 --allow-loopback > dryrun6-login.json
```
