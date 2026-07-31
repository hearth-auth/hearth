# HEA-1970 — Rented-host measurement runbook

**Purpose.** Produce the one set of numbers we are allowed to publish against
competitors: the **HTTP plane**, measured on a host that passes the quiescence
gate in `examples/support/hostenv.rs`, with the host evidence captured in the
artifact.

**Cost envelope.** One droplet, a few hours, single-digit dollars. Destroy it
when the artifacts are copied back.

---

## 0. Host-class gate — satisfied (landed in `480e9829`)

> **Branch provenance.** `480e9829` is on `feature/more-performance-fixes` (this
> runbook's branch) and is **not yet merged to `main`**. `main` still carries the
> old attribute-reading gate, under which every droplet run would be stamped
> `publishable: false`. §4 says to pin `<SHA-under-test>` — that SHA must be a
> descendant of `480e9829`, or this section does not apply to your checkout.

`HostProfile::non_server_class_reasons()` (`examples/support/hostenv.rs:235`)
raises a host-class objection on **two conditions only**:

| check | on a DigitalOcean CPU-Optimized droplet |
|---|---|
| `has_battery` | ✅ structurally passes — a cloud instance has no battery |
| `clock_probe.max_drift_pct > MAX_CLOCK_DRIFT_PCT` (2%) | ⏱️ **measured at run time** — expected to pass on a *dedicated* vCPU, but not verified by us on any droplet yet |

Neither objection is a pre-rental blocker, so **you can rent the rig now** —
this section no longer says otherwise.

⚠️ The drift check is a *measurement, not a property of the plan you bought*.
Do not assume it passes. On a **shared/burstable** droplet it is expected to
fail; on a dedicated vCPU it should clear, but the only thing that settles it
is running the probe. The probe lives in the harness binary, so it cannot run
until after §4 Build — §5 opens with a cheap one-sample gate check for exactly
this reason. Run that before the 5-run sweep. If the box fails, destroy it and
re-provision rather than sweeping on it.

> `governor` and `isolated_cpus` are recorded in the artifact as **informational
> fields** — they are not gate inputs. A missing or unset value does not fail the
> check. Setting `governor=performance` via GRUB is still good practice on a
> rented host (reduces DVFS variance between runs), but it is not required for a
> publishable result.

---

## 1. Provision

- **Provider/plan:** DigitalOcean **CPU-Optimized (Dedicated vCPU)** — *not*
  Basic/shared. On shared vCPU the hypervisor steals cycles invisibly to
  `loadavg`, which is strictly worse than our contended laptop.
- **Size:** 16 vCPU / 32 GB. (8 vCPU works if we drop the `T=32` sweep point.
  Memory headroom is ample either way — a 1.2 M-user corpus peaked at 1,899 MiB
  RSS in HEA-1989.)
- **Image:** Ubuntu 24.04 LTS, NVMe SSD.
- **Access:** SSH key only. No other workload on the box, ever.

## 2. Prepare (≈10 min)

```bash
ssh root@$DROPLET
apt-get update && apt-get install -y build-essential pkg-config libssl-dev \
    protobuf-compiler git curl jq python3 linux-tools-common sysstat
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

# Quiesce: stop everything that can wake up mid-sweep.
systemctl stop unattended-upgrades snapd.service snapd.socket || true
systemctl disable --now snapd.service snapd.socket unattended-upgrades || true
```

## 3. Prove the host is quiet BEFORE building

```bash
uptime                      # want load1 < 0.2
grep MemAvailable /proc/meminfo
vmstat 1 5                  # want st (steal) column == 0 on every line
nproc
```

Record this output verbatim — it is the evidence half of AC #1.

## 4. Build

```bash
git clone <repo> hearth && cd hearth
git checkout <SHA-under-test>          # pin it; record it
export PROTOC=$(command -v protoc)
cargo build --release --example http_delta
```

> Build on the box, then **let it idle 2 minutes** before measuring — a build
> leaves the page cache and the thermal/turbo state hot.

## 5. Measure the HTTP plane (the AC)

`http_delta` runs its own generator and server in one process, so this needs
only the single droplet. Five independent invocations, distinct `--out` paths —
the default path **overwrites its own artifact**.

**First, one cheap gate check.** The host-class gate (§0) is evaluated at run
time, not inferred from the droplet plan, so settle it before spending the full
sweep:

```bash
mkdir -p /root/artifacts
./target/release/examples/http_delta --samples 1 \
  --out /root/artifacts/gate-precheck.json
jq '{publishable,
     host_class: .quiescence.verdict.host_class_objections,
     contention: .quiescence.verdict.contention_objections,
     drift_pct:  .quiescence.host.clock_probe.max_drift_pct,
     clock_ok:   .quiescence.host.clock_probe.stable}' \
  /root/artifacts/gate-precheck.json
```

`publishable: true` ⇒ proceed. `false` ⇒ read the reasons: clock drift >2% or
steal time means this box cannot produce a citable figure. Destroy it and
re-provision (a different droplet of the same plan often lands on a quieter
host); do **not** reach for `--allow-contended-host`.

Then the sweep proper:

```bash
for i in 1 2 3 4 5; do
  ./target/release/examples/http_delta --samples 3 \
    --out /root/artifacts/c11-http-delta-run$i.json
  sleep 30
done
```

- Do **not** pass `--allow-contended-host`. If the gate objects, fix the host —
  a run stamped `publishable: false` is worthless for HEA-1968.
- Compare **medians across the 5 runs** and report the spread. A figure without
  a spread is not publishable (HEA-1974 AC3); >25% spread gets an explanation or
  gets withdrawn.
- Re-check `uptime` and `vmstat 1 5` immediately after the last run.

## 6. Measure the end-to-end plane (optional, second-order)

```bash
MODE=steady USERS=500  RUN_TIME=60s make loadtest
MODE=steady USERS=1000 RUN_TIME=60s make loadtest
```

**Read these with the co-residency caveat.** The Goose generator shares the
droplet with the server; `security.load_test_unthrottled` is refused on any
non-loopback bind, so a second generator host cannot be wired in without a code
change. On a 16 vCPU droplet expect the same shape as HEA-1989 §3: the read
journeys pass, and the ceiling reported at 1,000 users is the *rig*, not Hearth.

## 7. Land the evidence

```bash
scp root@$DROPLET:/root/artifacts/*.json docs/perf/artifacts/
```

Then, in a normal PR:

1. Commit the artifacts plus the `uptime` / `vmstat` / `hostenv` evidence.
2. Resolve `docs/perf/PUBLISHED_FIGURES.md` §4.1 row by row — each HTTP figure
   is either **confirmed** (2.1a value inside the new spread) or **re-based** to
   the new median, with the SHA and artifact path cited.
3. Recompute every derived multiplier in
   `HEA-1867-COMPETITIVE-COMPARISON.md` from the new envelope.
4. Tell HEA-1968 exactly which rows it may quote.

## 8. Destroy the droplet.

---

## Appendix — what a "quiesced host" is, operationally

| signal | threshold | why |
|---|---|---|
| `load1` before/after | < 0.2 on an idle box | catches foreign work |
| `vmstat` `st` | 0 | catches hypervisor steal (invisible to loadavg) |
| fixed-work probe | ±2% across the sweep | catches clock movement without `cpufreq` |
| generator headroom | ≥ 2.0× (`MIN_GENERATOR_HEADROOM`) | catches generator-bound rows |

The first three are host truth; the fourth is per-row admissibility. HEA-1967
failed because only the fourth existed.
