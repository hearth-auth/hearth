# Cluster mode: GA readiness

Tasks 23.1 (re-run of P21) and 23.16 (§8.3 — stand up three nodes and enumerate
every cache the state machine bypasses).

`reports/follower-bypass-enumeration-2026-09-21.md` is the analytical half. It
reasoned with **two identity engines over one storage engine**. That shape
proves engine logic and nothing about replication: one storage handle makes
every write instantly visible to both engines, so it cannot distinguish "the
control epoch propagated" from "there was nothing to propagate". This is the
empirical half — three real nodes, three storage engines, three Raft nodes over
real mTLS gRPC sockets — plus the two things P21's critic asked for that the
analytical pass did not do: a test-by-test "can this actually fail" probe, and a
cold walkthrough of the operator documentation.

---

## Verdict

**Multi-node cluster mode is not GA-ready, and the gap is larger than
"experimental". Following `docs/guides/clustering.md` exactly, a three-node
cluster cannot be started at all.** All three nodes exit fatally ~0.6 s after
binding their Raft listeners, before the documented bootstrap step can be
reached. See **G-1**.

The verdict rests on three things, in this order:

1. **G-1** — a real three-node walkthrough, transcript below, reproduced as an
   automated test. This alone is disqualifying.
2. **B-5** — a fifth authoritative cache the analytical pass missed, confirmed
   on real followers and fixed in this pass with a mutation proof.
3. **T-1** — the only test in the repository that mentions network partitions
   passes with the partition injection entirely removed. There is **no**
   split-brain test.

The single-node verdict is unaffected: `serve` with no `cluster:` section takes
none of these paths. Everything below is cluster-mode-only.

---

## What was actually stood up

`tests/cluster_three_node_control_coherence.rs`. Three `EmbeddedStorageEngine`s
in three separate data dirs, each under its own `ClusterEngine::build_clustered`
with its own leaf certificate from a throwaway CA, each serving openraft over
real mTLS gRPC on a loopback socket, each with its own `EmbeddedRbacEngine` and
`EmbeddedIdentityEngine` over a `ClusterStorageAdapter` — the same composition
`main.rs` performs, including the `ReplicatedWriteObserver` wiring. Mutations
run on the elected leader; **every assertion is made on both followers**, so a
mechanism that works for node 2 but not node 3 has nowhere to hide.

One fixture detail cost a debugging cycle and is worth recording, because
getting it wrong makes a coherence assertion measure nothing. Convergence must
be waited for against `last_log_index`, not `last_applied`: a client write
returns on majority commit while the state machine applies asynchronously, so a
target taken from `max(last_applied)` can be behind the write that was just
acknowledged, and every node then satisfies it immediately while the follower's
storage is still stale. With that bug in place the realm-suspend probe "passed"
for the wrong reason.

---

## Findings

### G-1 — the documented bootstrap sequence cannot start a node

`docs/guides/clustering.md` § Bootstrap Sequence:

> 1. Start all nodes: `hearth serve -c hearth-N.yaml`
> 2. Wait until all nodes are listening …
> 3. Call the bootstrap endpoint on **one** designated bootstrap node

No node survives to step 3.

`serve` builds `EmbeddedIdentityEngine` over the `ClusterStorageAdapter`
(`src/main.rs:1391`), and the constructor's first act is
`load_or_persist_global_signing_key` (`src/identity/engine/mod.rs:2099`), which
**writes** on a cold data dir. In cluster mode that write is a Raft proposal.
Before bootstrap there is no leader, so it returns `NotLeader`, the `?`
propagates, and start-up is fatal.

Observed on all three nodes of a real run (transcript in the walkthrough
section):

```text
ERROR hearth: error: storage error: storage I/O error:
              raft: not the leader; redirect to unknown
```

**Failure scenario.** An operator provisions three hosts, generates the PKI,
writes the three YAML files, starts all three, and has nothing to bootstrap:
every process is already dead. There is no message naming the cause; the error
says "not the leader" about a node that is trying to become one. The
`clustering.md` caveats (C-5, C-6, H-3) all describe behaviour of a *running*
cluster and so read as understatement.

A fix is not contained — it needs either lazy global-key creation, or
auto-initialisation from `cluster.peers` on a cold cluster, or deferring the
identity engine until a leader exists. **Reported, not fixed.** Pinned by
`identity_engine_construction_fails_on_an_unbootstrapped_cluster_node`, whose
failure message tells whoever fixes it to re-run the walkthrough.

### B-5 — the RBAC decision cache is never invalidated by replication (FIXED)

`ShardedResolutionCache` (`src/rbac/resolution_cache.rs`) gates every cached
permission resolution on a per-realm generation counter, bumped by
`EmbeddedRbacEngine::invalidate_realm` — which only the node that *served* the
mutation runs. On any other node a role unassignment, permission revoke or group
removal arrives as a plain replicated `rba:` storage write that touches no
generation, so a warm entry keeps serving the pre-revocation permission set
until coarse shard eviction happens to drop it.

The control epoch does not cover this. `sync_control_epoch` reloads the identity
engine's caches and never touches RBAC, and no RBAC mutation bumps the epoch.

**Failure scenario.** An operator revokes an administrator's role on the leader.
`src/protocol/web/admin/mod.rs:187` is the `/ui/admin` authorization gate and it
resolves through exactly this cache — on an ordinary GET, which a follower is
free to serve and which a read-spreading load balancer will send there. The
revoked administrator keeps admin on every follower, bounded only by cache
eviction, with no restart and no further write to end it.

This is the same class as B-1..B-4 but a different mechanism: not "a miss means
allow", but "a hit means stale". It was missed because the enumeration was
scoped to the identity engine's own fields.

**Fixed.** `RbacEngine` gains `on_replicated_row` / `on_replicated_snapshot`.
The identity engine — which is the node's single `ReplicatedWriteObserver` —
forwards every applied put and delete to the RBAC engine, which bumps that
realm's generation when the key carries the `rba:` prefix and drops every entry
on a snapshot install. One prefix compare per applied row; no new transport.

Proven by `an_rbac_grant_revoked_on_the_leader_stops_resolving_on_both_followers`
(red before, green after). **Mutation proof:** `sha256` of
`src/identity/engine/mod.rs` recorded, the three-line forward in
`on_replicated_delete` deleted, the binary re-run — *exactly* that test went red
("node 2 still resolves a permission the leader revoked") while the control-epoch
test stayed green — file restored, `sha256sum -c` OK.

### B-6 — the audit chain head is cached per node across leadership changes

`EmbeddedAuditEngine::chain_locks` (`src/audit/engine.rs:171`) is
`Mutex<HashMap<RealmId, Arc<Mutex<Option<ChainHead>>>>>`. The append path
(`:608`) prefers the cached head and only loads the persisted one when the cache
is `None`, so once a node has appended for a realm it never re-reads the head.

**Failure scenario.** Node A is leader and appends audit events for realm R;
its cached head reaches seq N. Leadership moves to node B, which appends up to
seq N+50 (B's cache started `None`, so it loaded correctly). Leadership moves
back to A. A's cached head is still at seq N, so it chains the next event from a
50-events-stale `prev_hash` and re-uses sequence numbers that are already
taken — the keyed-HMAC chain forks, and `audit verify` on realm R fails or
silently loses entries depending on which write lands last.

Leader flapping is not exotic: the documented graceful-shutdown procedure is a
`transfer-leadership` call, and §"Quorum and Failure Tolerance" expects nodes to
come and go.

**Not fixed and not mutation-proven.** The contained fix is to drop the cached
head whenever the node is not the leader, but "am I the leader" is a cluster-layer
fact and the audit engine is above it; wiring it needs the same observer
plumbing B-5 now has, and the repro needs an audit-specific failover harness.
**Labelled unproven** — the mechanism is read off the code, not demonstrated.

### T-1 — the only partition test passes with partitions removed

`simulation/src/tests/cluster_failover.rs::simulation_partition_and_convergence`
is the sole test in the repository that injects a network partition. It
partitions the leader from **one** follower, so the leader keeps quorum, then
writes five more entries, heals, and asserts convergence.

**Probe.** `InMemoryPeer::is_partitioned` was rewritten to return `false`
unconditionally — the partition injection removed entirely, `partition()` and
`heal()` reduced to bookkeeping nobody reads. The test still passes
(`1 test run: 1 passed`). It cannot fail from the property it names.

It is also not a split-brain test even on its own terms. There is **no** test
anywhere that isolates a leader into a *minority* and asserts it cannot commit,
and none that asserts two nodes never both believe they are leader for the same
term. **Split-brain test count: 0.**

### D-1 — the guide's example config does not start

Following `docs/guides/clustering.md` § Configuration verbatim, all three nodes
refuse to start:

```text
✗ Configuration invalid — 2 error(s):
  security.key_encryption_key: production mode requires a key-encryption key …
  server.tls_cert_path: production mode requires HTTPS …
```

The example YAML carries `oidc`, `storage` and `cluster` and nothing else. The
two mandatory production settings are documented in
`docs/specs/CONFIGURATION.md` § Mandatory in Production, but the clustering
guide neither sets them nor links to that section, and it is the page an
operator follows for this task.

### D-2 — a third mandatory secret is not in the mandatory list, and is found only after the validator passes

With D-1 fixed, all three nodes still die — one layer later, past config
validation:

```text
ERROR hearth: error: cryptographic operation failed: HEARTH_MASTER_KEY is not set
              and auto-generation is disabled in production mode
```

`HEARTH_MASTER_KEY` is a hard production requirement. It is listed in
`CONFIGURATION.md`'s environment-variable table (line 44) but **not** in the
"Mandatory in Production" table (lines 31–32) that the startup validator
mirrors. So the validator reports exactly two errors for a configuration that
has three, and the operator pays a second round trip.

Cluster-specific and worse: `HEARTH_MASTER_KEY` and the KEK wrap data that
*replicates*. They must be **identical on every node**. The string `HEARTH`
does not occur in `clustering.md` at all. Three nodes provisioned independently
— the obvious reading of "each node gets its own `hearth.yaml`" — produce three
different master keys and a cluster whose nodes cannot decrypt one another's
replicated rows.

### D-3 — the guide's first certificate recipe produces a certificate rustls rejects

`clustering.md` § Generating Certificates gives an `openssl x509 -req` command
with no `-extfile`, then a second "for a test environment with IP-based SANs"
variant. Verified: the first command's output has **no** `subjectAltName`
extension. rustls has required SAN since it dropped CN fallback, so the
unqualified recipe — the one presented as the default — yields peers that
cannot complete the mTLS handshake. The SAN variant is not optional and the
guide presents it as a special case.

### D-4 — the guide's example config collides with itself on one host

The per-node YAML sets `cluster.peer_address` per node but no `server.port`, so
all three nodes inherit port 8420. The guide's addresses are distinct hosts, but
the whole section is headed "Development and Evaluation Only" and an evaluator
runs three nodes on one box. Mentioning `server.port` alongside
`cluster.peer_address` costs one line.

### D-5 — `tests/cluster_smoke.rs` does not exist

`tests/cluster_grpc_loopback.rs`'s module doc says it "complements
`tests/cluster_smoke.rs`, which exercises the same surface area through the
in-process `MemRouter`". There is no such file and no `MemRouter` in the tree.
A reader looking for the in-process cluster coverage the comment promises finds
nothing.

### D-6 — the startup warning's C-5 clause is now stale in one direction and still true in another

`src/main.rs:1115` warns that "followers serve stale RBAC and session state
after a revocation (C-5)". As of task 24.6 the *session* half is closed (proved
below), and as of this pass the *RBAC* half is closed too. The same sentence
appears in `clustering.md` §C-5 and in its Backups note. Left as-is
deliberately: G-1 means the warning's overall conclusion — do not run this in
production — is if anything understated, and rewriting the clause to say
"cache coherence is fixed" while the cluster cannot boot would be worse than
leaving it.

---

## What IS genuinely covered

Everything in this table was demonstrated on three real nodes in this pass,
unless the Evidence column says otherwise.

| Property | Evidence | Can it fail? |
|---|---|---|
| Realm suspend on the leader binds on **both** followers | `a_control_asserted_on_the_leader_binds_on_both_followers`, asserting exactly `RealmSuspended` | Yes — the assertion is deliberately `RealmSuspended` and not "some error". Suspension also revokes the realm's sessions, so a follower that never reloaded `realm_status_cache` still rejects the token, with `InvalidToken` from the missing session. Accepting that would have made the assertion a re-run of the session check. |
| Session revocation on the leader binds on **both** followers | same test | Yes — the follower validated that exact token moments earlier, which warmed its `session_cache` with a live entry; `lookup_session` returns a cached live session without consulting storage, so the only route to a rejection is the epoch having dropped the cache. |
| Revoked-JTI blocklist reaches a follower without a restart | `ReplicatedWriteObserver::on_replicated_put` projection (task 24.6); not separately re-proved here | Covered by the existing two-engine test only. |
| DPoP key blocklist reaches a follower | reloaded by the same `sync_control_epoch` line as realm status, which *is* proved on three nodes | By construction, not separately. |
| RBAC revocation binds on **both** followers | `an_rbac_grant_revoked_on_the_leader_stops_resolving_on_both_followers` | Yes — mutation-proved (above). |
| 10 writes on the leader appear on all 3 nodes over real mTLS gRPC | `three_node_grpc_loopback_replicates_ten_writes` | Yes. |
| A killed leader is replaced within 10 s and post-election writes survive | `simulation_leader_kill_and_election` | **Yes — probed.** Removing the `shutdown()` + `unregister()` makes it fail with "AC-2 FAIL: no new leader elected within 10 s". |
| Rolling restart with zero read errors | `simulation_rolling_restart_zero_errors` | Not probed. |
| A new follower catches up via snapshot | `simulation_snapshot_catchup_new_follower` | Not probed. |
| Committed writes survive sequential leadership changes | `simulation_committed_writes_survive_sequential_leadership_changes` | Not probed. |
| Writes survive a leader kill mid-sequence | `simulation_leader_kill_mid_write_sequence` | Not probed. |
| WAL replay after a crash in a cluster | `simulation_wal_replay_after_crash` | Not probed. |
| `put_if_absent` has exactly one winner through Raft | `simulation_raft_put_if_absent_exactly_one_winner`, `…_durable_guard` | Not probed. |
| Network partition tolerance | `simulation_partition_and_convergence` | **No — probed and vacuous (T-1).** |
| Split-brain (minority leader cannot commit; no two leaders in a term) | — | **No test exists.** |

### Failover and split-brain test count

**10 tests** touch failover, crash recovery or partitions:

| # | Test | File | Family |
|---|---|---|---|
| 1 | `simulation_partition_and_convergence` | `simulation/src/tests/cluster_failover.rs` | partition — **vacuous** |
| 2 | `simulation_leader_kill_and_election` | same | failover — **probed, can fail** |
| 3 | `simulation_rolling_restart_zero_errors` | same | restart |
| 4 | `simulation_snapshot_catchup_new_follower` | same | catch-up |
| 5 | `simulation_leader_kill_mid_write_sequence` | `simulation/src/tests/cluster_chaos.rs` | failover |
| 6 | `simulation_wal_replay_after_crash` | same | crash recovery |
| 7 | `simulation_committed_writes_survive_sequential_leadership_changes` | same | failover |
| 8 | `simulation_raft_put_if_absent_exactly_one_winner` | `simulation/src/tests/txn_raft_concurrent.rs` | concurrency |
| 9 | `simulation_raft_put_if_absent_durable_guard` | same | concurrency |
| 10 | `three_node_grpc_loopback_replicates_ten_writes` | `tests/cluster_grpc_loopback.rs` | transport (not failover) |

Of these, **1 exercises partitions and it is vacuous**, **0 exercise
split-brain**, and **2 were mutation-probed** (one can fail, one cannot).
Tests 1–9 all run against an **in-process `RaftNetwork`**, never the gRPC
transport; only test 10 uses real sockets, and it does no failure injection. So
no test in the repository exercises failover *and* the real network layer at the
same time.

---

## Systematic cache enumeration

The sweep that produced this list:

```
grep -rn "ArcSwap<\|SwapCell<\|Mutex<HashMap\|RwLock<HashMap\|DashMap\|LruCache\
\|ShardedArcSwapMap<\|OnceLock<Mutex" src/
```

plus a field-by-field read of `EmbeddedIdentityEngine` (`src/identity/engine/mod.rs:505–862`).

**47 items** of process-local state, not five. The report's "five" counted only
authoritative caches on the token-validation path inside the identity engine,
and it undercounted even those: the true count of caches that are
**authoritative** — where a miss or a stale hit is itself the decision — is
**six**, of which one (`realm_signing_keys`/`realm_retiring_keys`, task 18.7)
was already closed, four were closed by the control epoch, and one (B-5) was
missed entirely. A seventh, B-6, is authoritative for audit-chain integrity
rather than for an access decision.

### Authoritative — a miss or a stale hit *is* the decision

| # | State | Where | Status |
|---|---|---|---|
| 1 | `realm_status_cache` | identity engine | Closed by the control epoch. **Verified on both followers.** |
| 2 | `revoked_jti_cache` | identity engine | Closed by the control epoch **and** the `ReplicatedWriteObserver` projection. |
| 3 | `blocked_dpop_jkt_cache` | identity engine | Closed by the control epoch. |
| 4 | `session_cache` | identity engine | Closed by the control epoch. **Verified on both followers.** |
| 5 | `realm_signing_keys` + `realm_retiring_keys` | identity engine | Closed by `realm_key_epoch` (task 18.7). |
| 6 | **`ShardedResolutionCache`** | `src/rbac/resolution_cache.rs` | **B-5 — was open. Fixed and mutation-proved in this pass.** |
| 7 | **cached `ChainHead`** | `src/audit/engine.rs` | **B-6 — open. Unproven.** |

### Derived from replicated rows — a miss re-derives, it does not decide

`mfa_dek_cache`, `dpop_nonce_cache`, `realm_saml_keys`, `dummy_hashes`,
`hmac_key_cache` (audit), `signing_key` (global), `device_fp`
(`DeviceFingerprintStore` is storage-backed — no in-memory map),
`sv_store` (`SessionVersionStore` is storage-backed), `token_claims_cache` +
`token_claims_cache_gen` (flushed by both epochs). **9 items, safe.**

### Per-node by design — NOT defects

Recorded so a later sweep does not "fix" them into a distributed-coordination
problem.

| Group | Members | Why per-node is right |
|---|---|---|
| In-process advisory locks (**11**) | `session_limit_locks`, `jti_locks`, `token_redemption_locks`, `approval_locks`, `txn_locks`, `code_exchange_locks`, `grant_family_locks`, `otp_redemption_locks`, `realm_ops_lock`, `org_write_lock`, `chain_locks` (the lock, not the head it caches) | They serialise a local read-modify-write. Cross-node atomicity comes from `put_if_absent` through the cluster adapter, not from these. The last three are not in the analytical report's list. |
| Rate limiters in the identity engine (**7**) | `attempt_trackers`, `mfa_attempt_trackers`, `magic_link_rate_trackers`, `password_reset_rate_trackers`, `registration_email_rate_trackers`, `registration_ip_rate_trackers`, `ip_login_rate_trackers` | Per-node counting is a weaker limit, not a bypass. See the N-factor analysis below. |
| Rate limiters and detectors elsewhere (**15**) | `agent_rate_monitor` (identity), `abuse::agent_monitor::windows`, `abuse::backoff::entries`, `abuse::challenge::entries`, `abuse::detector` ×6, `abuse::device_approval::failures`, `abuse::shaper` ×2, `abuse::tarpit::entries`, `protocol::admin_auth::trackers` | Same shape. None appear in the analytical report. |
| Ceremony state (**1**) | `webauthn_challenges` | A registration or authentication ceremony started on one node cannot be finished on another. Fails **closed** (the challenge is simply not found), so it is a usability constraint in cluster mode, not a bypass — but it means WebAuthn requires sticky sessions and nothing says so. Not in the analytical report. |
| Node identity (**2**) | `protocol::tls::certified_key`, `abuse::ip_reputation::spamhaus` filter | A node's own cert, and a feed each node fetches for itself. |
| Config projections (**1**) | `main.rs` `RegistrySwap` (`PermissionRegistry`) | Rebuilt per node from that node's own `hearth.yaml` on SIGHUP. Correct as designed, but it means a permission-registry change is a per-node config rollout, never a replicated one. |
| Below the apply point (**4**) | `block_cache`, `sst_readers`, `memtable`, tiered hot tier | Written by the state machine itself as it applies. |

### Dead code found while sweeping

`DPopJtiCache` and `DPopProcessor` (`src/identity/dpop.rs:475`, `:525`) have
**zero references outside their own file**. Their doc comments describe an
in-memory DPoP replay cache; the live path is
`IdentityEngine::check_and_record_dpop_jti`, which is storage-backed and
therefore already cluster-consistent (four call sites in `src/protocol/http/`).
No defect — but a reader auditing DPoP replay protection for cluster safety
will find the dead in-memory type first and reasonably conclude there is a
bypass. Worth deleting.

### The rate-limit N-factor: is it N, or worse?

The task asked specifically. **In steady state it is exactly N** — each node
keeps its own counter and checks it locally, so a request spread round-robin
across N nodes gets N × the allowed attempts per window. Nothing multiplies
that further: the check and the increment are the same local map, and a
successful login clears only the local entry.

Two caveats that are *not* a bigger factor but are worth recording:

* Six of the seven families persist to storage for rehydration at boot
  (`restore_attempt_trackers_from_wal`). Those writes go through
  `self.storage.put` — a Raft proposal — and are discarded with `let _ =`.
  On a **follower** they therefore fail silently with `NotLeader`. The symmetric
  `clear_attempts` delete fails the same way, so a *successful* login served by
  a follower leaves the durable lockout row in place; the next restart of any
  node rehydrates a lockout for a user who has already authenticated. This is a
  correctness bug in the durability half, not an N-factor change, and in
  practice logins are steered to the leader anyway (they also write a session).
* `registration_ip_rate_trackers` is memory-only by design (task 20.16), so it
  additionally resets on every restart — N × (restarts + 1) over a long window.

---

## Operator-documentation walkthrough

`docs/guides/clustering.md`, followed as a new operator, three nodes on one
host, loopback addresses. Every step that did not work as written is a finding.

| Step | Command as written | Result |
|---|---|---|
| Generate CA | `openssl req -new -x509 -days 3650 -nodes -subj "/CN=hearth-cluster-ca" -keyout ca.key -out ca.crt` | OK |
| Generate leaf CSR | `openssl req -new -nodes -subj "/CN=hearth-node-1" -keyout node1.key -out node1.csr` | OK |
| Sign leaf (first recipe) | `openssl x509 -req -days 3650 -CA ca.crt -CAkey ca.key -CAcreateserial -in node1.csr -out node1.crt` | **D-3** — no `subjectAltName`; rustls will reject it. Used the second (SAN) recipe instead. |
| Write `hearth-N.yaml` from the § Configuration example | — | **D-4** — no `server.port`, so three nodes on one host all take 8420. |
| Start all three nodes | `hearth serve -c hearth-N.yaml` | **D-1** — `✗ Configuration invalid — 2 error(s)`: missing KEK, missing HTTPS. |
| …after adding `security.key_encryption_key` + `trust_forwarded_proto`/`trusted_proxies` | same | **D-2** — `HEARTH_MASTER_KEY is not set and auto-generation is disabled in production mode`. Not in the mandatory-config list the validator mirrors, so it surfaces only on the *next* attempt. |
| …after exporting a shared `HEARTH_MASTER_KEY` | same | Raft listeners bind, `Raft peer gRPC server starting (mTLS)` logs on all three, then **all three exit** with `error: storage error: storage I/O error: raft: not the leader; redirect to unknown` — **G-1**. |
| Bootstrap | `curl -X POST …/admin/cluster/bootstrap` | **Unreachable.** No process is alive. |
| Status / transfer-leadership / backup-from-follower | — | **Unreachable.** |

Seven of the guide's steps were executed; five produced a finding, and the
sequence terminates before the endpoint the guide is mostly about. That
pattern matches `reports/cold-first-run-2026-09-21.md`, which found 17 issues in
a single-node surface that also "looked fine".

The three `/admin/cluster/*` handlers themselves read correctly against the
guide: `bootstrap` returns `{node_id, term, leader_id}` and 409/503 as
documented; `status` returns `role`/`term`/`last_applied_index`/`peers[]` with
`is_healthy` derived from the leader's replication map, exactly as described;
`transfer-leadership` accepts `target_node_id` and reports `exact_target`. Only
the bootstrap *sequence* is broken, not the endpoints — which is why this was
invisible to `tests/cluster_admin_endpoints.rs`, a pure authorization-gate test
that never starts a cluster.

---

## Changes made in this pass

| File | Change |
|---|---|
| `src/rbac/mod.rs` | `RbacEngine::on_replicated_row` / `on_replicated_snapshot`. |
| `src/rbac/engine.rs` | Implemented for `EmbeddedRbacEngine`: bump the realm's generation when the applied key carries the `rba:` prefix. |
| `src/rbac/keys.rs` | `RBAC_KEY_PREFIX`. |
| `src/rbac/resolution_cache.rs` | `invalidate_all` — bump every known generation *and* clear the entry shards, because a realm never resolved has generation 0 and an entry tagged 0 would still match. |
| `src/identity/engine/mod.rs` | The node's single `ReplicatedWriteObserver` forwards every applied put/delete/reset to the RBAC engine. |
| `tests/cluster_three_node_control_coherence.rs` | New. Three real nodes; the B-1/B-4 proof on both followers, the B-5 regression test, and the G-1 characterisation test. |
| `tests/seed_realm_hard_error.rs` | Test double forwards the two new trait methods. |
| `docs/guides/clustering.md` | D-1 to D-5 corrected; G-1 documented in place of the bootstrap sequence that does not work. |

Not fixed: **G-1** (too large — needs a start-up ordering redesign), **B-6**
(needs leadership state in the audit layer plus a failover harness; labelled
unproven), **T-1** (writing a real split-brain test is its own task), the dead
`DPopJtiCache`, and D-6.

### Where the code landed

All eleven files above are in commit **`5a1242dc`**, not in a commit of this
task's own. The index is shared between agents on this branch, and a sibling's
bare `git commit` — run while these files were staged and before the `git
commit` that would have carried this task's message — absorbed every one of
them. The content is byte-for-byte what this pass intended and was verified at
that commit: `cargo clippy -D warnings` clean on the lib and all three touched
test binaries, `cargo fmt --check` clean, and all five tests in those binaries
green. Only the commit message and the `Co-Authored-By` trailer were lost;
history was deliberately not rewritten, because rewriting a sibling's commit
under a live branch is worse than a wrong author line.
