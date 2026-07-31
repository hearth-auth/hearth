# HEA-1970 — Saturation rig dry-run #3, post-HEA-2010 (loopback, ungradable by design)

**Date:** 2026-07-31 · **Host:** dev laptop, generator co-resident — **not** a capacity host
**Commit:** `54af5210` (`feature/more-performance-fixes`)
**Question:** dry-run #2 could not saturate — every `read` rung was 65–67 % HTTP 429 and
`knee: null`. HEA-2010 made the admin/token caps configurable. **Does it saturate now?**

**Answer: yes.** First knee this rig has ever produced. `429 = 0` on every rung of every
ramp. The limiter blocker is closed; what remains is a host-class blocker, not a rig one.

---

## Regime

Faithful reproduction of runbook phase 3B's *limiter* regime on one box: seed with
`--dev` on loopback, `SIGTERM`, restart **without** `--dev` (so
`load_test_unthrottled` is refused — logged, verified) against the same
`data_dir` + KEK + issuer. Post-restart `/introspect` smoke → `active: true`.

```yaml
security:
  request_shaper: { ip_rps: 200000, realm_rps: 200000 }
  rate_limiting:  { admin_per_minute: 0, token_per_minute: 0 }   # HEA-2010
```

Corpus: 1 realm, 1 000 users / tokens / sessions. Harness:
`examples/http_saturation --plane read --hold 15 --warmup 3 --conns 512 --allow-loopback`.

## Result — the limiter is gone

| Ramp | 429s | Errors | non-2xx |
|---|---|---|---|
| `1000,2000,4000,8000,16000,32000` | **0** | 0 | 0 |
| `4000,8000,16000,32000` | **0** | 0 | 0 |
| `10000,11000,12000,13000,14000,16000` | **0** | 0 | 0 |

`rate_limited_by_total: {}` — the HEA-2010 attribution map is empty, which is now a
positive statement (untagged sheds land in `unattributed`, so an empty map means no
shed at all). Dry-run #2's 65–67 % is at 0 %.

## Result — the server saturates, and the rig finds the knee

Fine ramp, with a 1 Hz host-CPU sampler wired to `--server-cpu-file`
(`artifacts/hea1970-dryrun3-read-knee.json`):

| Offered | Achieved | p50 | p99 | host CPU | Grade |
|---|---|---|---|---|---|
| 10 000 | 9 992 | 0.76 ms | 27.7 ms | 61.5 % | INADMISSIBLE (`server_cpu_pinned`) |
| 11 000 | 10 993 | 0.90 ms | 26.8 ms | 72.4 % | INADMISSIBLE (`server_cpu_pinned`) |
| 12 000 | 11 990 | 1.41 ms | 67.3 ms | 80.7 % | INADMISSIBLE (`server_cpu_pinned`) |
| 13 000 | 12 990 | 23.1 ms | 109.9 ms | 88.9 % | INADMISSIBLE (`server_cpu_pinned`) |
| **14 000** | **13 331** | 328.9 ms | 403.0 ms | 90.5 % | **ADMISSIBLE ← knee** |
| 16 000 | 13 247 | 341.7 ms | 426.0 ms | 85.7 % | INADMISSIBLE (`server_cpu_pinned`) |

`knee_index: 4` · `knee_throughput: 13 331 /s` · `degradation_shape: "graceful"` —
throughput holds (−0.6 %) past the knee instead of collapsing, with zero errors.

## What this is NOT

- **Not a capacity figure.** The generator shares the 16 threads with the server, so
  the 90.5 % that satisfied `server_cpu_pinned` is host-total including the generator.
  A two-host rig will move this number in an unknown direction.
- **The knee's latency is not a service level.** `max_backlog` hits its 4 096 ceiling at
  the knee rung, so 328 ms p50 is queue residency. The *usable* rate on this box —
  sub-ms p50 — is nearer 11 000/s. Report both or neither.
- **Coarse ramps still report `no-knee`.** The `1000…32000` ramp missed it entirely:
  every rung that kept up was under 90 % CPU, and the one that pinned CPU had already
  fallen behind. Knee detection needs rungs spaced finely around the pin point, and
  the harness correctly declines to guess. Ramp granularity is now the operator's job.
- Without `--server-cpu-file` every rung grades `INCOMPLETE` and the knee is `null` by
  construction. That is the gate working, not a failure.

## Reproduction

`docs/perf/artifacts/hea1970-dryrun3-read-{nocpu,coarse,knee}.json`; commands per
`HEA-1997-SATURATION-RUNBOOK.md` §3–§4 with `--target http://127.0.0.1:8422
--allow-loopback`.

## Incidental confirmation

HEA-2011's fix fired for real: production-mode start failed on a missing
`HEARTH_SMS_OTP_HMAC_KEY` and **printed the reason** rather than exiting 1 in silence.
Pre-2011 that was a blind `exit 1` mid-runbook, after the corpus was already seeded.
