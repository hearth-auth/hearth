# Parked OpenSpec changes

A change in this folder is NOT part of the contract. Its delta specs describe work that is
paused, not behaviour Hearth has. The `openspec` CLI does not read this folder.

To resume a change, move it back to `openspec/changes/` with `git mv`. Then re-check its
delta specs against `openspec/specs/` before work starts.

| Change | Why it is parked |
|--------|------------------|
| `cluster-read-fencing` | Cluster mode is experimental; the work is "defects first, one node". Tasks 5.1, 5.3–5.6 and 6.1–6.4 have 8 commits on the branch `feature/cluster-read-fencing` (last commit 2026-10-07). That branch is local to the owner's checkout and is not pushed. |
| `cluster-local-state-and-clock` | Same reason. No task is started. |
| `cluster-audit-chain` | Same reason. No task is started. |
