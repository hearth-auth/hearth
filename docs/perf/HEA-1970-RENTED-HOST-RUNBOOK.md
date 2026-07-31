# HEA-1970 — Rented-host measurement runbook

**Purpose.** Produce the one set of numbers we are allowed to publish against
competitors: the **HTTP plane**, measured on a host that passes the quiescence
gate in `examples/support/hostenv.rs`, with the host evidence captured in the
artifact.

**Cost envelope.** One droplet, a few hours, single-digit dollars. Destroy it
when the artifacts are copied back.

---

## 0. Prerequisite — do NOT rent before this lands

`HostProfile::non_server_class_reasons()` (`examples/support/hostenv.rs:127-152`)
currently raises a **hard** host-class objection when:

| check | on a DigitalOcean CPU-Optimized droplet |
|---|---|
| `has_battery` | ✅ passes (no battery) |
| `governor == "performance"` | ❌ **fails** — KVM guests do not expose `cpufreq` at all, so `governor` is `None` → `"clock stability unverifiable"` |
| `isolated_cpus` non-empty | ❌ **fails** — `isolcpus=` is unset on a stock cloud image |

Two hard objections ⇒ `publishable: false` on every run ⇒ the rental produces
nothing citable. Land the gate change first (tracked separately):

- replace the `governor` *attribute* read with a **measured fixed-work probe**
  (interleaved through the sweep; flat to ±2% ⇒ the clock did not move),
- replace `isolcpus` with **measured steal time** (`/proc/stat` field 8 delta)
  plus the existing foreign-process census,
- keep `governor` / `isolcpus` in the artifact as *informational* fields.

Rationale: measure the property, don't read the attribute that implies it.
`governor=performance` never guaranteed a fixed clock on bare metal either
(turbo decay, RAPL, thermal throttling all move it) — it was a provenance
string, not a measurement.

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

```bash
mkdir -p /root/artifacts
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
