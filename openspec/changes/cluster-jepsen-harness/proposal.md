## Why

Cluster mode is experimental and incomplete. `docs/dev/CONSISTENCY.md` (PR #400) now says what a
client of a cluster may rely on. Nothing tests those promises under real faults: the cluster
tests run in one process and never cut a network link or `kill -9` a node. Unit tests do not
prove consensus code correct. Jepsen is the proven tool for this. Two changes already exclude
this work and leave it to a separate change: `scope-trim-trusted-core` (design.md:25) and
`trusted-core-confidence` (design.md:31). This is that change.

The harness comes before the cluster work, not after it. Each open item (G1–G9) is then a
test that fails today and passes when the item lands. Without the harness, nobody can tell
whether a G-item fix works.

## What Changes

- **A Jepsen harness** under `jepsen/`. It runs real Jepsen (Clojure) in Docker: one control
  container and five node containers. Each node runs a production-mode `hearth serve` (real
  fsync, real KEK, peer mTLS, no `--dev`). Faults: network partitions, `kill -9`, restart,
  and peer-link delay.
- **A test for each row of CONSISTENCY.md §9** that Docker can run. A test of an
  **Implemented** promise MUST pass. A test of a **Not yet implemented** promise is an expected
  failure (xfail) tied to its G-id. When it starts to pass, the run says so, and the test
  becomes a required pass in the same PR that closes the G-item.
- **`make jepsen`** to run one test or all of them on a workstation, and a **nightly CI
  workflow**. The harness is not a per-PR gate.
- **The consistency promises move into OpenSpec.** A new capability `cluster-consistency`
  holds the promises that are **Implemented** today (W1–W5, R1, R5, V1, V3, C1, C2, C4).
  `docs/dev/CONSISTENCY.md` stays as the contributor doc: evidence, status, G-items and the
  test mapping, with a link to the spec. Each later change that closes a G-item adds its
  promise to `cluster-consistency` through a delta spec.
- **Out of scope:** fixing any G-item; clock-skew tests (Docker shares one kernel clock, so
  they need VMs); membership-change tests (no membership changes exist, G5).

This change adds tests and tooling only. It is allowed under the `trusted-core-confidence`
feature freeze. The follow-up changes that close the G-items are listed in `design.md`.

## Capabilities

### New Capabilities

- `cluster-consistency`: what a client of a multi-node cluster may rely on for writes, reads,
  revocations and clocks. Only the promises that hold today.
- `cluster-fault-testing`: the Jepsen harness contract. Production-mode nodes, the fault
  types, the pass/xfail rule tied to G-ids, how a run reports results, and when it runs.

### Modified Capabilities

None.

## Impact

- New: `jepsen/` (Clojure project, Docker Compose file, node image, certificate and config
  generator), `make jepsen` targets, `.github/workflows/jepsen.yml` (nightly).
- Changed: `docs/dev/CONSISTENCY.md` (no longer normative; links to the spec and the harness),
  `docs/dev/TESTING.md` (the Jepsen layer exists), `CLAUDE.md` (the two new capabilities),
  `docs/guides/clustering.md` and `hearth.example.yaml` only where a run proves a statement
  wrong.
- Dependencies: Jepsen and its Clojure libraries (Eclipse Public License 1.0), a JDK and
  Leiningen in the control container. None of them is linked into the `hearth` binary or
  shipped. The owner accepted EPL-1.0 for this test-only use on 2026-10-06 (design Open
  Question 1). No Jepsen source is copied into this repo.
- No change to the server's behaviour, wire format or config. No `CHANGELOG.md` entry.
