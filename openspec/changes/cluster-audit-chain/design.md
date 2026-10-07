## Context

Each realm has one audit hash chain. Every event's `integrity_hash` is an HMAC-SHA256, under the
realm's key, over the previous event's hash and the event's fields. A signed chain head
(`ChainHead`: `anchor`, `last_hash`, `seq`, `count`, MAC) records where the chain ends.
`verify_integrity` walks the events in key order and checks each link, then checks the head.

How an append works today (`src/audit/engine.rs`, `with_pending_append`):

1. Take the realm's chain lock. This is a `Mutex` in this process only.
2. Read the head from the cache, or load and MAC-check it from storage.
3. Build the event with `prev_hash = head.last_hash`, `seq = head.seq + 1`, `timestamp = now`.
4. Write the event, its two index rows and the new head as one batch, under the lock.

The event key is `audit:evt:` + timestamp + seq + event id. Verification scans in that order.

In cluster mode the batch becomes one Raft `Batch` command (`ClusterStorageAdapter::put_batch`,
reached through the default `enqueue_batch`). The command is unconditional. So two nodes can read
the same head and both commit an event that chains from it. The head written last wins. The
chain is broken on every node. The replicated-write observer (task 26.47) drops a node's cached
head when another node's head row applies, but only between appends, and only if `try_lock`
succeeds. It narrows the window; it cannot close it.

A second, smaller defect has the same effect. Timestamps come from the proposing node's clock.
If node B's clock is behind node A's, B's event can chain after A's event but sort before it.
Verification then sees the links out of order.

Two invariants must hold after this change:

- **Keyed HMAC chain.** The proposer computes every HMAC. The per-realm key never leaves the
  audit engine.
- **`put_batch` atomicity.** A merged append (caller rows + audit rows) commits whole or not at
  all, on every node.

Precedent: `RaftCommand::PutIfAbsent` and `RaftCommand::IncrementU64` decide at apply time and
return a result to the proposer. Raft applies entries one at a time, in log order, on every node.

## Goals / Non-Goals

**Goals:**

- One linear chain per realm when any number of nodes append at once (W7).
- Chain order and key order agree under clock skew between nodes.
- Every path that writes the head uses the same guard: append, merged append, import, both
  prunes.
- Single-node mode keeps its group-commit pipelining (HEA-1948) and its behaviour.

**Non-Goals:**

- Global event order across realms. Each realm has its own chain.
- Closing G8 (records stamped with `leader_timestamp`). This change only keeps chain timestamps
  monotonic.
- Making audit appends idempotent across a lost answer (that is G7, `cluster-write-idempotency`).
- Changing what an event contains, or the HMAC construction.

## Decisions

### 1. A guarded batch decided at apply time

Add `RaftCommand::WriteBatchIf { realm, guard_key, expected, puts, deletes }`. `expected` is
`Option` of the bytes the proposer read at `guard_key`; `None` means "absent". At apply, the
state machine reads `guard_key`. If it equals `expected`, it applies `puts` and `deletes` as one
`write_batch` and answers `success: true`. Otherwise it writes nothing and answers
`success: false`. Every node reaches the same answer, because every node applies the same log in
the same order.

`StorageEngine` gets `write_batch_if(realm, guard_key, expected, puts, deletes) -> Result<bool>`.
`ClusterStorageAdapter` proposes the new command. A follower forwards it to the leader like any
write and answers after its own apply, so the follower's storage already holds the winner.

The single-node default does not check the guard. In single-node mode one process is the only
writer, and the chain lock already serializes it. This keeps the embedded engine's
`enqueue_batch` group commit unchanged.

The audit engine uses `guard_key = chain_head_key()` and `expected = ` the head bytes it built
the event from.

*Alternatives considered:*

- **Append on the leader only.** Followers would forward the audit write. But identity merges
  audit rows with its own rows in one batch, on any node, so whole operations would need
  forwarding. A leader change still lets an old and a new leader race on one head. The guard is
  still needed then. Rejected.
- **Chain at apply time in the state machine.** The proposer would send an unchained event, and
  apply would compute the HMAC. This orders the chain by construction, with no retries. But the
  cluster layer would need the realm HMAC key and the KEK, crypto would run in the apply loop,
  `src/cluster/` would depend on `src/audit/`, and minting a realm's first key at apply is not
  deterministic. Rejected for this change. It stays an option if contention retries cost too
  much.
- **A distributed lock on the head.** More moving parts than one conditional command, and it
  needs a lease to survive a crash. Rejected.

### 2. Bounded retry on a lost race

When `write_batch_if` answers `false`, the audit engine drops its cached head, reloads the head
from local storage, rebuilds the event and the head, and proposes again. Local storage is current
enough: the rejected entry applied after the winning entry, on this node too. After 8 losses in a
row the append fails with a new retryable `AuditError` that maps to `503` and
`HEARTH_CLUSTER_UNAVAILABLE`. Nothing was written. A metric counts conflicts.

The observer's `try_lock` skip (task 26.47) stays. A stale cache now costs one retry, not a fork.

### 3. Merged appends pass rows, not a closure

`AuditEnqueueFn` is an `FnOnce` that enqueues the combined batch itself. A retry cannot call it
twice. The merged-append call changes to take the caller's rows (`Vec<(Vec<u8>, Vec<u8>)>`), and
the audit engine builds the combined batch on each attempt. The caller's rows are plain puts
computed before the call, so proposing them again is safe. The two callers change with it:
session creation in `src/identity/engine/mod.rs` and the webhook decorator in
`src/webhook/mod.rs`. In single-node mode the engine still enqueues and returns the durability
handle, so group commit is unchanged.

### 4. Monotonic chain timestamps

The event timestamp becomes `max(clock.now(), head.last_timestamp)`. `ChainHead` gains
`last_timestamp`, and the head MAC covers it. Equal timestamps sort by `seq`, which strictly
increases along the chain. So key order equals chain order for any clock skew. This also meets
C1: chain safety does not depend on clocks.

There is no installed base, so the head format changes in place. A head without the field is
not read as valid.

### 5. One guard for every head writer

`import_events`, `prune_before` and `prune_oldest` also write the head. Each uses
`write_batch_if` with the head it read. A prune that loses the race reloads and plans again.

## Risks / Trade-offs

- [Contention: every node appending at once makes most proposals lose and retry] → Bounded
  retries, a conflict metric, and a clear `503`. The Jepsen `audit` test runs five nodes at full
  rate and must pass, which measures this.
- [A rejected proposal still costs a Raft round trip and a log entry] → It writes nothing. The
  log is compacted by snapshots as usual.
- [Sign-in latency: session creation appends an audit event] → Retries happen only under
  cross-node contention on one realm. The login path is off the hot path.
- [A node on an older build cannot decode `WriteBatchIf`] → Mixed-version clusters are already
  unsupported; membership changes need a full-cluster restart.
- [A follower behind on apply reloads a head that is still old] → The forwarded write returns
  only after the follower applied that index, and the winner is at an earlier index.
- [The single-node default skips the guard check] → It is correct only while one process writes.
  The trait documentation says so, and every replicated storage overrides it.

## Migration Plan

No data migration: there is no installed base. Deploy is a full-cluster restart on the new build,
as for any cluster upgrade. Rollback is the previous build, also with a full-cluster restart. A
chain written by the new build does not verify under the old build, because the head MAC input
changed.

## Open Questions

- Is 8 the right retry bound? Measure the conflict rate in the Jepsen `audit` test and adjust.
- Should the conflict metric be per realm? A per-realm label risks unbounded cardinality, so the
  default is one counter.
