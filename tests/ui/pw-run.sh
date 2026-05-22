#!/usr/bin/env bash
# Cross-platform Playwright runner.
#
# Handles browser setup transparently so callers never need a manual nix-shell
# or apt-get invocation. Pass any `playwright` CLI arguments:
#   bash tests/ui/pw-run.sh test --project=smoke
#   bash tests/ui/pw-run.sh install firefox webkit
#
# Platform logic:
#   NixOS   — re-invokes itself inside nix-shell (sets CHROMIUM_EXECUTABLE_PATH)
#   Debian  — npx playwright install --with-deps chromium
#   other   — npx playwright install chromium (macOS has system libs; bare install works)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── NixOS auto-entry ──────────────────────────────────────────────────────────
# Detect NixOS: nix-shell available, apt-get absent, not already inside a shell.
# Re-exec the entire script inside nix-shell so CHROMIUM_EXECUTABLE_PATH is set
# by shell.nix's shellHook before playwright tries to launch a browser.
if [ -z "${IN_NIX_SHELL:-}" ] \
    && ! command -v apt-get >/dev/null 2>&1 \
    && command -v nix-shell >/dev/null 2>&1; then
    echo "NixOS detected — entering nix-shell for browser deps (transparent, one-time per terminal)..."
    QUOTED_SCRIPT="$(printf '%q' "$SCRIPT_DIR/pw-run.sh")"
    QUOTED_ARGS=""
    for arg in "$@"; do
        QUOTED_ARGS="$QUOTED_ARGS $(printf '%q' "$arg")"
    done
    exec nix-shell "$SCRIPT_DIR/shell.nix" --run "bash $QUOTED_SCRIPT$QUOTED_ARGS"
fi

cd "$SCRIPT_DIR"

# ── Playwright browser install ────────────────────────────────────────────────
# Pre-install chromium only when running tests (not when the caller is already
# issuing an explicit `install` subcommand, which manages browsers itself).
SUBCOMMAND="${1:-}"
if [ "$SUBCOMMAND" != "install" ]; then
    if [ -n "${CHROMIUM_EXECUTABLE_PATH:-}" ]; then
        # nix-shell shellHook set this — nixpkgs chromium is RPATH-patched; skip download.
        :
    elif command -v apt-get >/dev/null 2>&1; then
        npx playwright install --with-deps chromium
    else
        npx playwright install chromium
    fi
fi

# ── Run ───────────────────────────────────────────────────────────────────────
exec npx playwright "$@"
