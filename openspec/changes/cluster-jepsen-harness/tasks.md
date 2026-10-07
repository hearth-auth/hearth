## 0. Decisions and spike (before any harness code)

- [x] 0.1 Owner decision on Open Question 1 (EPL-1.0 for a test-only tool). Record it in `design.md`
- [x] 0.2 Spike: script the first operator token for a cold cluster without `--dev` (design decision 5). Proof: a shell script that starts 3 production-mode nodes on the host and ends with `GET /admin/cluster/status` answering `200` to a system-realm token on every node. The path MUST NOT use `--dev`, `dev-endpoints` or any test-only shortcut in the binary (design Open Question 2). If no path works without a server change, stop and report to the owner
- [x] 0.3 Spike: answer Open Question 3. Name one single-use artifact a script can mint and redeem through the API, and say whether any replicated counter is readable through the API. Record the answers in `design.md`
- [x] 0.4 Owner decision on Open Question 4 (are the G-item follow-ups allowed under the freeze). Record it in `design.md`

## 1. Containers and binary

- [x] 1.1 `jepsen/docker/`: Compose file, node image (Debian bookworm, `sshd`, `iptables`, `iproute2`), control image (JDK 21, Leiningen). Proof: `make jepsen-up` starts 6 containers, and `ssh n1 true` from control exits 0 on all 5 nodes
- [x] 1.2 Builder stage: `cargo build --release` without `dev-endpoints`, cached registry and target. Proof: the binary runs `hearth --version` inside a node container
- [x] 1.3 Per-run material: KEK, `HEARTH_MASTER_KEY`, CA, peer and HTTPS leaves with `DNS:nX` SANs, one `hearth.yaml` per node. Proof: `hearth config validate` exits 0 on all 5 files, and `openssl x509 -noout -text` shows the SAN on each leaf

## 2. Jepsen project skeleton

- [x] 2.1 `jepsen/project.clj` with pinned Jepsen version; `jepsen/README.md` (how to run, `privileged` warning, how to read `store/`)
- [x] 2.2 `db` namespace: install binary, write config, seed the store (task 0.2 path), start, stop, `kill -9`, wipe, collect logs. A run refuses a binary that serves `/admin/bootstrap` (spec "The harness is pointed at a dev binary"). Proof: a no-op test with no workload and no faults sets up and tears down 5 nodes, and its `store/` holds 5 node logs
- [x] 2.3 Shared HTTP client with the outcome mapping (design decision 6). Test first: unit tests in `jepsen/test/` feed canned answers (`200`, both `503` codes, timeout, `400`) and assert `:ok` / `:info` / `:fail` for write and read
- [x] 2.4 Heal-and-converge final phase (spec "Final reads follow a heal"). Test first: a unit test with stubbed status answers where one node lags past the timeout, asserting an invalid result naming that node
- [x] 2.5 Nemesis package: majority/minority partition, isolate leader, `kill -9` minority, restart, peer-link delay. Proof: a no-workload test per fault; the node logs show the expected leader change or peer errors

## 3. Expectations and result runner

- [x] 3.1 `jepsen/expectations.edn` and the runner that classifies pass / fail / xfail / xpass (spec "Results are classified…"). Test first: unit tests on four canned `results.edn` files, one per row of the table, plus the exit code of the run
- [x] 3.2 `make jepsen` and `make jepsen TEST=<name>`, with `TIME_LIMIT` (default 300 s). Proof: `make jepsen TEST=noop` exits 0

## 4. Workloads with required passes

Each checker first gets a unit test on a hand-written history with a planted violation (spec "The checkers are proven before they are trusted").

- [x] 4.1 set (W1, W2): unique adds, final list on every node, `set-full` checker. Planted violation: an `:ok` add missing from the final read
- [x] 4.2 register (W1, W2, W3): one mutable user field per key, final read on every node after heal, Knossos on writes plus final reads, all nodes agree. Planted violations: a final value no linearization allows; a `:fail` write visible at the end
- [x] 4.3 single-use (W4): the artifact from task 0.3, redeemed on many nodes. Planted violation: two `:ok` redemptions of one artifact
- [x] 4.4 counter (W5), only if task 0.3 found a readable counter. Otherwise record in `docs/dev/CONSISTENCY.md` §9 that W5 is covered by unit tests only
- [x] 4.5 same-node read (R1): clients pinned to one node, write then read. Planted violation: a read on the writing node that misses the write
- [x] 4.6 revocation (V1): revoke on one node, validate on all nodes in a loop, bound from Open Question 5. Planted violation: a node that accepts the session after the bound
- [x] 4.7 Run 4.1–4.6 with their §9 faults. Every result is valid. A failure here is a real bug: file it with the history, do not mark the test `xfail`

## 5. Expected-failure workloads

- [ ] 5.1 W7 (`xfail G4`): concurrent audited admin changes on two nodes, then verify the audit chain end to end
- [x] 5.2 R2 (`xfail G1`): reads on every node while one node or the leader is isolated; no stale read after `read_lag_threshold_ms`
- [ ] 5.3 R3/R4 (`xfail G2`): reads in a loop on one node while it installs a snapshot (stop it, write past the snapshot threshold, restart)
- [x] 5.4 V2 (`xfail G1`): validate a revoked session on an isolated node; it never accepts
- [ ] 5.5 Node replacement (`xfail G9`): wipe one node's data directory, restart it with the same ID, W1 set checker
- [ ] 5.6 First full run: every task 5 test reports xfail. An xpass here is a harness defect: find it and fix it before task 6 (spec "The checkers are proven before they are trusted")

## 6. CI

- [ ] 6.1 `.github/workflows/jepsen.yml`: nightly and `workflow_dispatch` with a test filter, artifact retention 14 days, not in any required-check list. Proof: one manual dispatch run, green, with the artifact attached
- [ ] 6.2 Measure runner time and memory on that run; answer Open Question 6 in `design.md`

## 7. Docs and spec move

- [ ] 7.1 `docs/dev/CONSISTENCY.md`: header no longer says "Normative"; it links to `openspec/specs/cluster-consistency/spec.md` and `jepsen/README.md`; §9 gets the real test names and the reasons for untested promises (C1 skew, membership, W5 if task 4.4 skipped it)
- [ ] 7.2 `docs/dev/TESTING.md`: replace "not implemented" for partition simulation (line 96) and the line 721 entry with the Jepsen layer and `make jepsen`
- [ ] 7.3 `CLAUDE.md`: add `cluster-consistency` and `cluster-fault-testing` to the capability table
- [ ] 7.4 `hearth.example.yaml` cluster warning block: it still says followers never invalidate caches (C-5) and that a node is replaced by editing YAML (C-6). Align it with `docs/guides/clustering.md` and link `docs/dev/CONSISTENCY.md`
- [ ] 7.5 Any statement in `docs/guides/clustering.md` that a run proved wrong: fix it, citing the run
- [ ] 7.6 `openspec validate cluster-jepsen-harness --strict` passes

## 8. Follow-up changes (propose only, after task 5.6)

- [ ] 8.1 Propose `cluster-local-state-and-clock` (G3, G6, G8), `cluster-read-fencing` (G1, G2) and `cluster-audit-chain` (G4), each naming the tests it flips to `pass` (design decision 10)
- [ ] 8.2 After `trusted-core-confidence` is archived: propose `cluster-write-idempotency` (G7) and `cluster-membership` (G5, G9)
