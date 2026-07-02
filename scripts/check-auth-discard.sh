#!/usr/bin/env bash
# scripts/check-auth-discard.sh — CI guard: authentication results must never be discarded.
#
# Tracks: HEA-1657 (parent: HEA-1629 deep security audit).
#
# Prevents recurrence of the cross-realm BOLA class where a handler called
# extract_admin_auth() / authenticate_admin() but threw away the Result, silently
# bypassing authentication.
#
# FAILS on any occurrence in the auth-boundary protocol files of:
#
#   1. `let _auth`
#        — explicit underscore-prefixed discard of an auth binding.
#          `let _auth = extract_admin_auth(...)` compiles and silences the
#          unused-variable warning while the AuthResult is silently dropped.
#
#   2. `let _ = extract_admin_auth(...)` / `let _ = authenticate_admin(...)`
#        — unit-discard: the caller explicitly throws away the Result.
#          Rust's `#[must_use]` does NOT warn on the `_ =` pattern; only the
#          grep catches it.
#
#   3. Unbound call: a line containing `extract_admin_auth(` or `authenticate_admin(`
#      where no `let <ident> =` binding captures the return value.
#      (Rust's `#[must_use]` on those functions catches this at compile time via
#      `clippy -D warnings`; this check is belt-and-suspenders.)
#
# Scope:
#   src/protocol/http/admin.rs
#   src/protocol/grpc/*.rs
#
# Suppress a specific line with an inline comment:  // auth-discard-lint-allow
#
# Usage: bash scripts/check-auth-discard.sh
# Exit:  0 if clean, 1 if any violation is found.

set -euo pipefail

SCOPE_FILES="$(git ls-files -- 'src/protocol/http/admin.rs' 'src/protocol/grpc/*.rs' 2>/dev/null)"

if [[ -z "$SCOPE_FILES" ]]; then
    echo "WARN: auth-discard scope matched no tracked files; check working directory."
    exit 0
fi

violations=0

while IFS= read -r file; do
    [[ -f "$file" ]] || continue

    # ── Pattern 1: let _auth ─────────────────────────────────────────────────
    # Any auth binding whose name starts with `_` — Rust silences the
    # unused-variable warning but the value is dropped without being used.
    while IFS= read -r hit; do
        [[ "$hit" == *"auth-discard-lint-allow"* ]] && continue
        echo "FAIL [let _auth] $file:$hit"
        violations=$((violations + 1))
    done < <(grep -n '\blet _auth\b' "$file" 2>/dev/null || true)

    # ── Pattern 2: let _ = <auth-call> ───────────────────────────────────────
    # Explicit unit-discard; bypasses #[must_use] in Rust.
    while IFS= read -r hit; do
        [[ "$hit" == *"auth-discard-lint-allow"* ]] && continue
        echo "FAIL [let _ = auth-call] $file:$hit"
        violations=$((violations + 1))
    done < <(grep -nE 'let _ = (extract_admin_auth|authenticate_admin)\(' "$file" 2>/dev/null || true)

    # ── Pattern 3: unbound call — result not captured ─────────────────────────
    # Match lines containing an auth call, then exclude legitimate uses:
    #   - properly bound:  starts with `let <ident> =` (or `let mut <ident> =`)
    #   - function defs:   `fn extract_admin_auth` / `fn authenticate_admin`
    #   - use imports:     `use super::auth::authenticate_admin;`
    #   - comment lines:   `//`
    while IFS= read -r hit; do
        [[ "$hit" == *"auth-discard-lint-allow"* ]] && continue
        # Extract line body (strip leading "lineno:" prefix)
        body="${hit#*:}"
        body_trim="${body#"${body%%[! ]*}"}"  # ltrim whitespace
        # Skip comment lines
        [[ "$body_trim" == "//"* ]] && continue
        # Skip function definitions
        [[ "$body_trim" =~ ^(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+(extract_admin_auth|authenticate_admin)[[:space:]]*\( ]] && continue
        # Skip use imports
        [[ "$body_trim" =~ ^use[[:space:]] ]] && continue
        # Skip properly-bound assignments: `let <ident> =`, `let mut <ident> =`
        [[ "$body_trim" =~ ^let[[:space:]]+(mut[[:space:]]+)?[a-z_][a-zA-Z0-9_]*[[:space:]]*(:[^=]+)?= ]] && continue
        echo "FAIL [unbound auth-call] $file:$hit"
        violations=$((violations + 1))
    done < <(grep -nE '(extract_admin_auth|authenticate_admin)\(' "$file" 2>/dev/null || true)

done <<< "$SCOPE_FILES"

if (( violations > 0 )); then
    echo ""
    echo "auth-discard: $violations violation(s)."
    echo ""
    echo "Every extract_admin_auth() / authenticate_admin() call MUST capture its"
    echo "result in a named binding, e.g.:"
    echo ""
    echo "  let auth = match extract_admin_auth(&headers, &state) { ... };"
    echo "  let auth = authenticate_admin(req.metadata(), &self.state)?;"
    echo ""
    echo "Discarding the Result silently bypasses authentication and opens cross-realm"
    echo "BOLA vulnerabilities (see HEA-1629 § cross-realm class)."
    echo ""
    echo "To suppress a specific line that is legitimately exempt (e.g. a test helper"
    echo "that intentionally tests the discard path), add an inline comment:"
    echo "  // auth-discard-lint-allow"
    exit 1
fi

echo "OK: no auth-discard violations in protocol handler files."
exit 0
