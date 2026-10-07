## Why

In cluster mode, the audit hash chain forks when two nodes append at the same time (G4 in
`docs/dev/CONSISTENCY.md`). Each node reads the chain head under its own mutex, then writes the
event and the new head as a plain batch. Nothing stops two nodes from chaining from one head.
The Jepsen `audit` test proved it: concurrent admin changes on five nodes left 1233 events that
verify on no node. With one client the chain verifies. A broken chain is indistinguishable from
tampering, so the tamper evidence fails exactly when a cluster is busy.

## What Changes

- A new conditional Raft write: a batch that applies only when one guard key still holds the
  value the proposer read. Raft orders all entries, so exactly one of two racing appends wins.
- The audit engine writes every chain-head change through that guarded batch: live appends,
  merged appends, imports and both retention prunes. A losing append reloads the head and
  retries a bounded number of times.
- The merged-append interface changes: a caller passes its own key-value pairs instead of an
  enqueue closure, so the audit engine can re-propose the whole batch after a conflict.
- An event's timestamp is never earlier than the previous event's timestamp in the chain.
  Events are stored in timestamp order, so a follower with a slow clock no longer reorders the
  chain. The chain head records the last timestamp, under its MAC.
- An append that keeps losing the race is refused with `503` and
  `HEARTH_CLUSTER_UNAVAILABLE`. No partial event is written.
- The Jepsen `audit` test expects `:pass`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cluster-consistency`: adds promise W7, one linear audit chain under concurrent appends on
  different nodes. The capability is added by `cluster-jepsen-harness`; archive this change
  after that one.

## Impact

- `src/cluster/`: one new `RaftCommand` variant, its apply in `state_machine.rs`, and the
  `ClusterStorageAdapter` method that proposes it. A node on an older build cannot decode the
  new variant. Mixed-version clusters are already unsupported.
- `src/storage/mod.rs`: one new `StorageEngine` method with a single-node default.
- `src/audit/`: the append, import and prune paths, the `ChainHead` format and the
  merged-append interface (`AuditEnqueueFn`).
- `src/identity/engine/mod.rs` and `src/webhook/mod.rs`: the two merged-append callers.
- Off the hot path: audit appends happen on writes and sign-ins, never in `validate_token()`.
- No installed base exists, so the chain-head format changes in place with no migration.
- Docs: `docs/dev/CONSISTENCY.md` (W7 status, G4, section 9), `docs/guides/clustering.md`,
  `CHANGELOG.md`.
- `jepsen/expectations.edn`: `audit` becomes `:pass`.
