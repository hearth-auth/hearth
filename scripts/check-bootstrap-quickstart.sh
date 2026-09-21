#!/usr/bin/env bash
# scripts/check-bootstrap-quickstart.sh — the commands Hearth hands a brand-new
# operator must actually run.
#
# Production-readiness task 26.27 (audit reports/cold-first-run-2026-09-21.md,
# finding C-7):
#
#   `POST /admin/bootstrap` returns a `quickstart` block. On a server bound to
#   port 18420 it came back targeting `http://127.0.0.1:8420` — the port was a
#   string literal — and its closing line read
#   "see docs/guides/getting-started.md". That file is `getting-started.mdx`.
#   Low severity, highest possible visibility: it is the first thing a new user
#   copies, and both halves are wrong before they have typed anything.
#
# Three rules, all text over the generator, no Rust build:
#
#   R1  The generator exists. A renamed or deleted function must fail the guard
#       loudly rather than let it pass on zero findings.
#   R2  No URL in the snippet hard-codes a host:port. The address must come
#       from the request (the `Host` header), so an instance on any port hands
#       back commands that run. A bare fallback literal outside the snippet is
#       fine — the rule is about the text handed to the operator.
#   R3  Every repository path the snippet cites exists on disk. `docs/guides/
#       getting-started.md` did not; `.mdx` does.
#
# Usage:  bash scripts/check-bootstrap-quickstart.sh
# Env:    REPO_ROOT  tree to inspect (default: this script's repository)
#         SOURCE     generator source file (default:
#                    $REPO_ROOT/src/protocol/http/admin.rs)

set -uo pipefail

DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$DEFAULT_ROOT}"
SOURCE="${SOURCE:-${REPO_ROOT}/src/protocol/http/admin.rs}"

failures=0
fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}
pass() { echo "ok:   $*"; }

# ── R1 — the generator exists ────────────────────────────────────────────────
if [[ ! -f "$SOURCE" ]]; then
    fail "R1: ${SOURCE} not found; the bootstrap quickstart generator has no home."
    echo ""
    echo "✗ bootstrap quickstart guard: ${failures} rule(s) failed."
    exit 1
fi

# The raw-string body of the quickstart generator: from the function signature
# to the closing `}` in column 0.
snippet="$(
    awk '
        /^fn bootstrap_quickstart\(/ { inside = 1 }
        inside { print }
        inside && /^}/ { exit }
    ' "$SOURCE"
)"

if [[ -z "$snippet" ]]; then
    fail "R1: no \`fn bootstrap_quickstart(\` in ${SOURCE}." \
        $'\n      The generator was renamed, deleted or inlined back into the handler.' \
        $'\n      Point SOURCE at its new home, or this guard passes on nothing (C-7).'
    echo ""
    echo "✗ bootstrap quickstart guard: ${failures} rule(s) failed."
    exit 1
fi
pass "R1: the quickstart generator is where the guard expects it."

# Only the lines of the snippet the operator is handed — i.e. the raw string
# literal — not the Rust around it. The fallback literal lives in the `unwrap_or`
# line, which is Rust, and is deliberately exempt.
handed="$(grep -v 'unwrap_or' <<<"$snippet")"

# ── R2 — no hard-coded host:port in the handed-out commands ──────────────────
hardcoded="$(grep -nE 'https?://[A-Za-z0-9._-]+:[0-9]+' <<<"$handed")"
if [[ -n "$hardcoded" ]]; then
    fail "R2: the quickstart hands the operator a hard-coded host:port (C-7)." \
        $'\n      An instance bound to any other address returns commands that cannot' \
        $'\n      run. Interpolate the request\'s Host header instead:' \
        $'\n'"$(sed 's/^/        /' <<<"$hardcoded")"
elif ! grep -q 'https\?://{host}' <<<"$handed"; then
    fail "R2: no URL in the quickstart interpolates a runtime host." \
        $'\n      The address handed to the operator must be the one they reached.'
else
    pass "R2: the quickstart URL interpolates the request's host."
fi

# ── R3 — every repository path the snippet cites exists ──────────────────────
mapfile -t cited < <(grep -oE '\bdocs/[A-Za-z0-9._/-]+' <<<"$handed" | sed 's/[.,)]$//' | sort -u)
if [[ "${#cited[@]}" -eq 0 ]]; then
    pass "R3: the quickstart cites no repository path."
else
    missing=""
    for path in "${cited[@]}"; do
        [[ -e "${REPO_ROOT}/${path}" ]] || missing="${missing} ${path}"
    done
    if [[ -n "${missing// /}" ]]; then
        fail "R3: the quickstart cites path(s) that do not exist:${missing}" \
            $'\n      C-7 was exactly this: it said docs/guides/getting-started.md; the' \
            $'\n      file is getting-started.mdx.'
    else
        pass "R3: every path the quickstart cites exists (${cited[*]})."
    fi
fi

echo ""
if [[ $failures -gt 0 ]]; then
    echo "✗ bootstrap quickstart guard: ${failures} rule(s) failed — the first commands a new operator copies do not work."
    exit 1
fi
echo "✓ bootstrap quickstart guard: the generated quickstart runs where it is handed out."
exit 0
