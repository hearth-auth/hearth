#!/usr/bin/env bash
# scripts/check-rbac-storage-writes.sh — CI guard: RBAC-graph mutations must
# invalidate the resolution decision cache.
#
# Tracks: HEA-1781 (follow-up to HEA-1777, the SecurityAuditor re-review of the
# HEA-1770 resolution decision cache).
#
# The RBAC resolution decision cache (src/rbac/engine.rs) memoizes the full
# pre-narrowing permission resolution keyed by (realm, user, org) + a per-realm
# graph version. A stale-served entry is a privilege-escalation bug. The cache is
# invalidated ONLY by `invalidate_realm()`, which bumps the per-realm graph
# version. Every RBAC-graph mutation therefore MUST route through the
# `write_put` / `write_put_batch` / `write_delete` helpers, which perform the raw
# storage write and then bump the version.
#
# HEA-1770 shipped two invalidation-bypass bugs (Critical + Medium, fixed in
# febfe092) with the exact same root cause: a mutation path calling
# `self.storage.put/put_batch/delete` DIRECTLY, bypassing the version bump, so a
# cached resolution stayed live after the underlying grant/membership changed.
#
# FAILS on any occurrence in src/rbac/engine.rs of:
#
#   self.storage.put(...)
#   self.storage.put_batch(...)
#   self.storage.delete(...)
#   self.storage.delete_batch(...)
#
# unless the line carries the inline allow marker:
#
#   // rbac-storage-write-ok
#
# The only legitimately-marked lines are the bodies of the `write_*` helpers
# themselves. Any NEW raw call must be converted to the matching `write_*`
# helper, NOT annotated. (Non-mutating `self.storage.scan/get` reads are not
# matched — they cannot make a cached entry stale.)
#
# Usage: bash scripts/check-rbac-storage-writes.sh
# Exit:  0 if clean, 1 if any un-marked raw write is found.

set -euo pipefail

FILE="src/rbac/engine.rs"

if [[ ! -f "$FILE" ]]; then
    echo "WARN: $FILE not found; check working directory."
    exit 0
fi

violations=0

# Match direct storage-mutation calls on the engine's storage handle.
# `put_batch`/`delete_batch` are matched by the `put(`/`delete(`-prefixed
# alternatives below via the `(_batch)?` optional group.
while IFS= read -r hit; do
    [[ "$hit" == *"rbac-storage-write-ok"* ]] && continue
    echo "FAIL [raw rbac storage write] $FILE:$hit"
    violations=$((violations + 1))
done < <(grep -nE 'self\.storage\.(put|delete)(_batch)?\(' "$FILE" 2>/dev/null || true)

if (( violations > 0 )); then
    echo ""
    echo "rbac-storage-writes: $violations violation(s)."
    echo ""
    echo "Every RBAC-graph mutation in $FILE MUST route through the"
    echo "invalidating write helpers so the resolution decision cache is bumped:"
    echo ""
    echo "  self.write_put(realm_id, key, value)?;      // instead of self.storage.put(...)"
    echo "  self.write_put_batch(realm_id, &entries)?;  // instead of self.storage.put_batch(...)"
    echo "  self.write_delete(realm_id, key)?;          // instead of self.storage.delete(...)"
    echo ""
    echo "A direct self.storage.put/delete call skips invalidate_realm(), leaving a"
    echo "stale cached resolution live after the grant/membership changed — a"
    echo "privilege-escalation bug (see HEA-1770 § febfe092, HEA-1777)."
    echo ""
    echo "The write_* helper bodies are the ONLY exempt lines; they carry the inline"
    echo "marker:  // rbac-storage-write-ok"
    exit 1
fi

echo "OK: all RBAC-graph mutations in $FILE route through invalidating write helpers."
exit 0
