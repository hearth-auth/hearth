#!/usr/bin/env bash
# scratch-retention.sh — Retention policy for /scratch build caches.
#
# Prevents /scratch from silently filling and blocking all agent runs (HEA-2198).
#
# RETENTION POLICY
#   target-hea-*   per-issue cargo builds  →  delete if idle > 7 days
#   target-*       other named target dirs  →  delete if idle > 14 days
#   /scratch/tmp   temp entries             →  delete if idle > 7 days
#   target (shared active)                 →  never deleted; cargo sweep --time 14
#
# USAGE
#   ./scripts/scratch-retention.sh              # live run
#   ./scripts/scratch-retention.sh --dry-run    # preview only, no deletions
#   make scratch-prune                          # live via make
#   make scratch-prune-dry-run                  # dry-run via make
#
# CRON (run as the build user, daily at 03:00)
#   0 3 * * * /home/brad/Code/personal/hearth/scripts/scratch-retention.sh \
#             >> /scratch/cache/retention.log 2>&1
#
# Install cron: crontab -e  then paste the line above.

set -euo pipefail

CACHE_DIR="${SCRATCH_CACHE_DIR:-/scratch/cache}"
TMP_DIR="${SCRATCH_TMP_DIR:-/scratch/tmp}"
ACTIVE_TARGET="${CACHE_DIR}/target"   # shared active target — swept, never deleted

ISSUE_TARGET_MAX_DAYS=7     # target-hea-* per-issue dirs
NAMED_TARGET_MAX_DAYS=14    # other target-* named dirs
TMP_MAX_DAYS=7              # /scratch/tmp entries

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

# Returns 0 (true = idle) if $1 has not had a cargo build within the last $2 days.
# Uses .rustc_info.json as the canonical build-timestamp marker: cargo writes this
# file at the start of every build, making it the most reliable staleness signal.
# Directory mtimes are unreliable (traversals update subdir mtimes without builds).
tree_idle_for() {
  local dir="$1" days="$2"
  local marker="$dir/.rustc_info.json"
  if [[ ! -f "$marker" ]]; then
    return 0  # No cargo build marker found → treat as idle
  fi
  local hit
  hit=$(find "$marker" -mtime "-${days}" -print -quit 2>/dev/null)
  [[ -z "$hit" ]]   # empty = marker is older than $days → idle → return 0
}

remove_dir() {
  local dir="$1"
  local size
  size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "?")
  if "$DRY_RUN"; then
    log "DRY-RUN  would remove: $dir  ($size)"
  else
    log "Removing: $dir  ($size)"
    rm -rf "$dir"
    log "Removed:  $dir"
  fi
}

remove_entry() {
  local entry="$1"
  if "$DRY_RUN"; then
    log "DRY-RUN  would remove: $entry"
  else
    log "Removing: $entry"
    rm -rf "$entry"
  fi
}

# ── Pass 1: per-issue cargo target dirs (target-hea-*) ────────────────────────
log "=== Pass 1: per-issue cargo target dirs (idle > ${ISSUE_TARGET_MAX_DAYS}d) ==="
found=0
while IFS= read -r -d '' dir; do
  if tree_idle_for "$dir" "$ISSUE_TARGET_MAX_DAYS"; then
    found=$((found + 1))
    remove_dir "$dir"
  else
    log "SKIP (active within ${ISSUE_TARGET_MAX_DAYS}d): $dir"
  fi
done < <(find "$CACHE_DIR" -maxdepth 1 -name 'target-hea-*' -type d -print0 2>/dev/null)
log "Pass 1 done: $found candidate(s) processed."

# ── Pass 2: other named target dirs (not the active shared target) ─────────────
log "=== Pass 2: named cargo target dirs (idle > ${NAMED_TARGET_MAX_DAYS}d) ==="
found=0
while IFS= read -r -d '' dir; do
  # Never touch the active shared target or per-issue dirs (handled by pass 1).
  [[ "$dir" == "$ACTIVE_TARGET" ]] && continue
  [[ "$dir" == */target-hea-* ]] && continue
  if tree_idle_for "$dir" "$NAMED_TARGET_MAX_DAYS"; then
    found=$((found + 1))
    remove_dir "$dir"
  else
    log "SKIP (active within ${NAMED_TARGET_MAX_DAYS}d): $dir"
  fi
done < <(find "$CACHE_DIR" -maxdepth 1 -name 'target-*' -type d -print0 2>/dev/null)
log "Pass 2 done: $found candidate(s) processed."

# ── Pass 3: /scratch/tmp entries ──────────────────────────────────────────────
log "=== Pass 3: /scratch/tmp entries (idle > ${TMP_MAX_DAYS}d) ==="
found=0
if [[ -d "$TMP_DIR" ]]; then
  while IFS= read -r -d '' entry; do
    found=$((found + 1))
    remove_entry "$entry"
  done < <(find "$TMP_DIR" -maxdepth 1 -mindepth 1 \
             -mtime "+${TMP_MAX_DAYS}" -print0 2>/dev/null)
fi
log "Pass 3 done: $found entry/entries processed."

# ── Pass 4: cargo sweep on shared active target ────────────────────────────────
log "=== Pass 4: cargo sweep on shared target (--time 14) ==="
if [[ ! -d "$ACTIVE_TARGET" ]]; then
  log "Active target not found at $ACTIVE_TARGET; skipping sweep."
elif command -v cargo-sweep &>/dev/null; then
  if "$DRY_RUN"; then
    log "DRY-RUN  would run: cargo sweep --time 14 $ACTIVE_TARGET"
  else
    cargo-sweep --time 14 "$ACTIVE_TARGET" \
      && log "cargo sweep complete on $ACTIVE_TARGET" \
      || log "WARNING: cargo sweep failed (non-fatal — likely an unfamiliar target layout)"
  fi
else
  log "cargo-sweep not installed; skipping sweep of shared target."
  log "  Install: cargo install cargo-sweep"
  log "  Re-run after install to sweep old artifacts from $ACTIVE_TARGET"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log "=== Retention run complete ==="
df -h /scratch 2>/dev/null | tail -1 || true
