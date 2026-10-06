## Context

Cluster mode replicates all application storage with `openraft` 0.9 (`src/cluster/`). It is
experimental, and the startup warning says so. `docs/dev/CONSISTENCY.md` lists the target
promises (W, R, V, C), which of them hold today, the open items G1–G9, and one Jepsen test per
promise (§9).

Current state that shapes this design:

- The cluster tests (`tests/cluster_*.rs`) run several nodes inside one process. They never cut
  a network link, never `kill -9` a process, and never restart one from disk.
- Reads are local, with no read barrier. A partitioned follower or a deposed leader serves
  stale reads with no time limit (G1). Hearth does **not** promise linearizable reads, so a
  linearizability check on reads fails by design. That failure is not a bug and not an xfail.
- Membership is static (G5). A "`kill -9` during a membership change" test cannot exist yet.
- `--dev` storage does not fsync, and `/admin/bootstrap` exists only with `--dev` and the
  `dev-endpoints` feature. The harness must run production mode, so it cannot use either.
- A cold cluster with empty data directories has no operator account. The first-boot setup
  URL (`/ui/setup?token=…`) and `hearth admin token` are the documented ways to get one
  (`docs/guides/clustering.md` § System-realm tokens). Neither has been scripted against a
  cluster.
- The host builds on NixOS. A binary built there does not run on a Debian container.
- `trusted-core-confidence` freezes server features until it is archived. Tests and tooling
  are allowed.

## Goals / Non-Goals

**Goals:**

- Run real Jepsen against a 5-node, production-mode Hearth cluster in Docker, on a
  workstation and nightly in CI.
- One test for each CONSISTENCY.md §9 row that Docker can run. Each test is a required pass or
  an xfail tied to one G-id.
- Make each G-item measurable: its test fails today and passes when the item lands.
- Move the promises that hold today into the OpenSpec capability `cluster-consistency`.

**Non-Goals:**

- Fixing any G-item. Each G-group is its own later change (decision 10).
- Clock-skew tests (C1 under skew). Docker containers share the host kernel's clock. They need
  VMs; a later change can add a VM backend.
- Membership-change tests. They wait for G5.
- A per-PR gate. A Jepsen run takes too long and a single pass proves little.
- Testing node-local state (CONSISTENCY.md §7). Lockout counts and rate limits are per node by
  design.

## Decisions

### 1. Real Jepsen in Docker, not a home-grown harness

The owner chose this on 2026-10-02. Jepsen's checkers (Knossos, Elle, the set checker) are
proven. Its nemeses and history format are what other databases are measured with. A Rust
harness would need its own checkers, and a checker bug hides a database bug.

Alternatives: a Rust harness built on `turmoil` or the `hearth-simulation` crate. Those stay
useful for deterministic, in-process fault tests. They do not replace Jepsen.

### 2. Topology: one control container, five node containers

The layout follows Jepsen's own `docker/` setup, with our own pinned Compose file under
`jepsen/docker/`:

- **control**: JDK 21, Leiningen, the Jepsen project, SSH keys. It drives the nodes over SSH.
- **n1–n5**: Debian bookworm, `sshd`, `iptables`, `iproute2` (for `tc`). They run
  `privileged: true`, because the partition and delay nemeses change `iptables` and `tc`.

Five nodes, not three: a majority/minority split then has a two-node minority, and the
cluster survives two dead nodes. Both cases occur in the §9 tests.

### 3. The binary is built in a Debian builder image

A `rust:<MSRV>-bookworm` builder stage runs `cargo build --release` **without**
`dev-endpoints`. The result links against the same glibc as the node image. The cargo
registry and target directory are cached in Docker volumes on a workstation and with
`actions/cache` in CI. The Jepsen `db` setup step uploads the binary to each node.

Alternative: a static `musl` build. That changes the allocator and the TLS stack under test,
so the harness would not test the shipped binary.

Found in task 2.2: a binary built with `dev-endpoints` but run without `--dev` serves no dev
route (`src/protocol/http.rs` merges them only when both hold), and every string a dev build
holds also appears in a production build. So no probe can tell the builds apart. The harness
checks the binary's origin instead: the build target (`make jepsen-binary`, the root
`Dockerfile`, `--no-default-features`) writes `hearth.sha256` beside the binary, and a run
refuses a binary without a matching file before it touches any node.

### 4. Every node runs production mode

Jepsen's `db` setup writes one `hearth.yaml` per node from a template. Per run, the control
node generates:

- one key-encryption key and one `HEARTH_MASTER_KEY`, the same on every node;
- a CA, plus a peer mTLS leaf and an HTTPS leaf for each node, each with
  `subjectAltName=DNS:nX` (rustls ignores the CN);
- `storage.data_dir` on the node's own disk, with the default production sync mode.

No `--dev`. `hearth config validate` runs on each file before start, and a failure stops the
run.

### 5. First operator token: a seeded store, proven by a spike first

A cold cluster has no operator account, and the harness needs a system-realm token to create
realms and users. The recommended path follows the documented rebuild procedure:

1. Start `n1` alone in single-node mode with the cluster's keys.
2. Finish the first-boot setup flow over HTTP (`/ui/setup?token=…` from the log).
3. Stop `n1`. Run `hearth admin token --ttl 1h` on that data directory. It has no `raft.db`
   yet, so the command accepts it.
4. Copy the data directory to `n2`–`n5`. Start all five with the `cluster:` section.

Each test run starts from a fresh store and mints a fresh token, so the 1-hour ceiling of
`--ttl` covers one run. All later setup (realms, users, clients) goes through the admin API
and so through Raft.

Alternative: sign in to the console of a running node and mint at `/ui/admin/api-tokens`. That
needs a scripted password and TOTP form flow on every run.

Task 1 is a spike that proves this path before any workload is written. If no path works
without a server change, the spike stops and reports. A cluster that cannot get its first
operator without `--dev` is itself a cluster gap, and it goes to the owner.

### 6. Client results map to Jepsen's `:ok`, `:fail` and `:info`

This mapping is what makes W3 testable.

| Hearth answer | Write | Read |
|---|---|---|
| `2xx` | `:ok` | `:ok` |
| `503` `HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN` | `:info` (maybe applied) | n/a |
| `503` `HEARTH_CLUSTER_UNAVAILABLE` | `:fail` (not applied) | `:fail` |
| Timeout or connection error | `:info` | `:fail` |
| Any other error | `:fail`, with the code kept in the history | `:fail` |

A `:fail` write that is later seen applied breaks W3, and the checker reports it.

### 7. Workloads

One Clojure namespace per workload under `jepsen/src/jepsen/hearth/`. Every workload uses the
HTTPS admin and OAuth APIs. None reads the store directly.

- **set (W1, W2):** add unique items that the API can list (users with unique emails, or
  members of one group). After the faults stop and the cluster heals, read the full list on
  every node. Checker: Jepsen's `set-full`. An acknowledged add missing at the end fails the
  test.
- **register (W1, W2, W3):** write one mutable user field per key. Reads during the run are
  recorded but not checked for linearizability, because Hearth does not promise it. After the
  heal, each node reads every key once. Checker: Knossos over the writes plus the final reads,
  and all nodes agree.
- **single-use (W4):** many clients redeem one single-use artifact on different nodes. The
  spike picks an artifact that a script can mint through the API (Open Question 3). Checker:
  at most one `:ok` per artifact.
- **counter (W5):** only if the API exposes a counter it can read back (Open Question 3).
  Otherwise W5 stays covered by unit tests, and the test map says so.
- **same-node read (R1):** each client is pinned to one node, writes, then reads on that node.
  Checker: the read shows the write.
- **revocation (V1):** create a session, revoke it on one node, then validate it on every node
  in a loop. Checker: every node in contact rejects it within the V1 bound (Open Question 5, resolved).
- **xfail workloads:** W7 (concurrent audited changes on two nodes; the audit chain verifies),
  R2 (reads during a partition; no stale read after `read_lag_threshold_ms`), R3/R4 (reads on a
  node during a forced snapshot install), V2 (validation on an isolated node never accepts),
  and node replacement (wipe one node, restart it with the same ID; the W1 checker).

### 8. Nemeses

Jepsen's combined nemesis package with these faults: majority/minority partitions, a
partition that isolates the current leader, `kill -9` of a random minority, restart, and
`tc netem` delay on the peer port. Each test lists the faults it uses, from CONSISTENCY.md §9.
After the last fault, a final phase heals everything and waits until every node reports the
same `last_applied_index` in `GET /admin/cluster/status`. Only then run the final reads.

### 9. Pass, xfail and xpass

`jepsen/expectations.edn` maps each test to `:pass` or `{:xfail "G1"}`. A small runner reads
Jepsen's `results.edn` for each test:

| Expected | Jepsen result | Run result |
|---|---|---|
| `:pass` | valid | pass |
| `:pass` | invalid or unknown | **fail** |
| xfail | invalid | pass (reported as "xfail G-n") |
| xfail | valid | pass, with a warning: "xpass G-n" |

An xfail test whose checker returns `:unknown` is a fail: the test could not decide, so it
proves nothing (task 3.1). A test with no entry in `expectations.edn` is a fail too.

An xpass does not fail the run. A fault test can pass by luck while the bug is still there.
The PR that closes a G-item changes its entry to `:pass`. That PR's review is where the
promotion is checked.

The xfail tests also prove the harness works. Each one must fail today. An xfail test that
passes on the first run means its checker or its nemesis is broken. Task 4 checks this before
the harness is trusted.

### 10. The spec move and the follow-up changes

`cluster-consistency` holds only the promises marked **Implemented** today. An OpenSpec spec
is the contract, so it must not hold a promise the code breaks. Each follow-up change adds its
promise through a delta spec and flips its test to `:pass`:

| Follow-up change | G-items | Promise it adds | When |
|---|---|---|---|
| `cluster-local-state-and-clock` | G3, G6, G8 | node-local rows stay out of snapshots; shutdown steps down; C3 | during the freeze |
| `cluster-read-fencing` | G1, G2 | R2, R3, R4, V2 | during the freeze |
| `cluster-audit-chain` | G4 | W7 | during the freeze |
| `cluster-write-idempotency` | G7 | W6 | after `trusted-core-confidence` is archived |
| `cluster-membership` | G5, G9 | membership changes; safe node replacement | after `trusted-core-confidence` is archived |

`docs/dev/CONSISTENCY.md` stays as the contributor doc: evidence with file:line, status, the
G-items and the test map. Its header changes from "Normative" to a pointer to the spec.

### 11. When it runs

- `make jepsen` builds the images and the binary, then runs every test. `make jepsen
  TEST=set` runs one. Each test runs 300 s of faults by default (`TIME_LIMIT=`).
- `.github/workflows/jepsen.yml` runs nightly and on manual dispatch, with a test filter. It
  uploads Jepsen's `store/` (histories, node logs, checker output) as an artifact for 14 days.
  A failed required test fails the workflow. The workflow is not a required check.

## Risks / Trade-offs

- [A Jepsen pass is not proof] → Faults are random. Nightly runs and a 300 s fault window
  raise the odds of a hit. Only a failure is conclusive, and every failure keeps its history.
- [Harness bugs look like Hearth bugs] → The xfail tests must fail today (decision 9). Each
  checker gets a unit test on a hand-written history before it runs against Hearth.
- [Clojure is new in this repo] → Keep it small: one namespace per workload, a shared client,
  and `jepsen/README.md`. The workloads call only public HTTP APIs, so they survive Rust
  refactors.
- [Six containers and a JVM may not fit a standard GitHub runner] → Measure on the first CI
  run. If it does not fit, use a larger runner or three nodes in CI and five on a
  workstation (Open Question 6).
- [A release build in Docker is slow] → Cache the registry and target directory. The nightly
  build is a cost of the job, not of any PR.
- [`privileged` containers] → Only on the developer's machine or an ephemeral CI runner, never
  on shared hosts. `jepsen/README.md` says so.
- [The seeded-store setup is itself a cluster path that may break] → If it breaks, every test
  fails at setup, and the run reports a setup error, not a consistency failure.

## Migration Plan

None. The change adds tests and tooling. It changes no server behaviour, config or data. To
roll back, delete `jepsen/` and the workflow.

## Open Questions

1. **License.** Resolved 2026-10-06 (owner): accepted. Jepsen and its Clojure libraries are
   EPL-1.0. They are test-only, fetched from Clojars at run time, and never linked into or
   shipped with `hearth`. Our `jepsen/` code uses Jepsen but contains none of its source. Rule:
   do not copy Jepsen's own files (for example its `docker/` scripts) into this repo; write our
   own.
2. **First operator token.** Owner rule (2026-10-06): any path is fine if it does not weaken
   security. So the harness MUST NOT add a test-only shortcut, flag or endpoint to the
   production binary, and MUST NOT use `--dev` or `dev-endpoints`. If the seeded-store path
   (decision 5) fails, the fallback is the console login and token mint, scripted as a real
   operator would do it. Task 0.2 answers whether the first-boot setup flow runs on a node that
   later joins a cluster.

   **Spike result (task 0.2, 2026-10-06).** Scripts:
   `jepsen/scripts/{gen-material.sh,seed-store.sh,spike-cold-cluster.sh}`. Decision 5 works
   as written: the first-boot setup and email verification on a single-node seed store,
   `hearth admin token` into it, then three nodes started from copies of it. The first run
   found five server bugs. The owner chose to fix them on this branch, each test-first:
   - `serve` never gave the HTTP layer its cluster engine (`AppState::with_cluster` had no
     caller), so every `/admin/cluster/*` route answered `503 not in cluster mode` on a running
     cluster. Decision 8 and the leader-isolating nemesis need `/admin/cluster/status`.
     Test: `tests/cluster_serve_admin_status.rs`.
   - With that fixed, `POST /admin/cluster/bootstrap` on a formed cluster answered `500`, not
     `409`: it matched openraft's error text. It now matches the typed error.
   - `hearth admin token` signed with the default issuer `https://hearth.local` and audience
     `hearth`, not the configured ones. Production config refuses a `.local` issuer, so no
     production server accepted its tokens. Test: `tests/cli_admin_token.rs`.
   - The host allowlist read only the `Host` header, so a node with native TLS refused every
     HTTP/2 request with `400 host not allowed`. It now checks `:authority` too.
   - Each follower warned `clock skew with leader exceeds 1 s` (`skew_ms=2234`) on one shared
     clock: the check took a late entry's age as the offset (C4). The delta spec now states the
     estimate (in-flight entries, smallest age over 30 s).
   - Also found: the console's login `Origin` check expects the issuer's origin, so a script
     sends no `Origin` (an absent header is same-site by design). And on an empty data directory
     a node opens HTTP only after a leader exists, so there `POST /admin/cluster/bootstrap` is
     out of reach; `docs/guides/clustering.md` claimed it was an escape hatch and is corrected.
   - Task 2.2 found a sixth: with `cluster.peer_address` set to a host name (`n1:7443`), the
     peer server failed to parse it inside a spawned task. It logged one `ERROR`, and the node
     went on serving with `/readyz` at `200`, outside any cluster. The owner chose to fix it on
     this branch too. `config validate` now refuses a `peer_address` that is not an IP address
     and port, and `serve` binds the peer port before it continues, so a bind failure exits.
     Tests: `tests/cli_config.rs`, `tests/cli.rs` (`serve_exits_when_the_peer_server_cannot_bind`).
     The harness still gives each node a fixed IP (decision 2), because the bound address must
     be the node's own IP.
3. **W4 and W5 targets.** Answered 2026-10-06 (task 0.3, from the code):
   - **W4: a presented refresh token**, with the authorization code as the second choice.
     ARCHITECTURE.md §16.3 lists both as claimed with one `put_if_absent` in the state
     machine's apply. One hosted sign-in (the console driver in `jepsen/scripts/` signs in the
     same way) gives a refresh token. Clients on several nodes then redeem the same token at
     `POST /oauth/token`. The one `:ok` answer carries the next refresh token, which is the next
     artifact, so a test needs one sign-in, not one per operation. When no redemption of a token
     is `:ok`, the workload signs in again. The test realm sets
     `realms.<name>.auth.mfa_required: false`, so a script signs in with a password alone (or
     the workload enrols TOTP, as the console driver does). Task 4.3 proves this path at run
     time.
   - **W5: no readable counter.** The only `IncrementU64` counter is the control epoch
     (`src/identity/engine/control.rs:499`, `src/identity/engine/mod.rs:5439`). No API returns
     its value, and `/metrics` exports only `hearth_control_epoch_bump_failures_total` and
     `hearth_control_epoch_bumps_owed`. Every election also bumps it, so a final count could not
     separate test bumps from election bumps. W5 stays covered by the unit tests in
     `src/cluster/state_machine.rs`; task 4.4 records this in CONSISTENCY.md §9.
4. **Freeze.** Resolved 2026-10-06 (owner): G1, G2, G3, G4, G6 and G8 are defect fixes and may
   start during the `trusted-core-confidence` freeze. G5 (membership changes) and G7 (a new
   client request ID) are features and wait until that change is archived. G9 needs G5, so it
   waits too. Decision 10 groups the follow-up changes on this line.
5. **V1 bound.** Resolved 2026-10-06 (owner): the checker uses 400 ms + 2 × the injected
   one-way peer delay + 1 s slack, and records the bound in each result.
6. **CI capacity.** Resolved 2026-10-06 (owner): measure it. Task 6.2 runs the full suite on a
   standard GitHub runner and records time and memory. If it does not fit, the measurement
   decides between a larger runner and three nodes in CI.
