# Parked OpenSpec changes

A change in this folder is NOT part of the contract. Its delta specs describe work that is
paused, not behaviour Hearth has. The `openspec` CLI does not read this folder.

To resume a change, move it back to `openspec/changes/` with `git mv`. Then re-check its
delta specs against `openspec/specs/` before work starts.

| Change | Why it is parked |
|--------|------------------|
| `cluster-local-state-and-clock` | Cluster mode is experimental; the work is "defects first, one node". No task is started. |
| `cluster-audit-chain` | Same reason. No task is started. |

Resumed changes: `cluster-read-fencing` moved back to `openspec/changes/` on 2026-11-26.
