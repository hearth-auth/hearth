#!/usr/bin/env bash
# scripts/check-mfa-resolver.sh — CI guard: one resolver decides the MFA
# requirement (scope-trim-trusted-core, spec `mfa-policy`).
#
# Every decision "does this sign-in need a second factor?" MUST go through
# `IdentityEngine::effective_mfa_requirement`, which ORs the realm,
# organization, client and role requirements. Before the resolver, eight call
# sites each read `mfa_required` with their own default, and they disagreed:
# a gate that read the realm alone missed a role requirement, and a gate that
# read the client alone missed the realm.
#
# FAILS on any read of a `mfa_required` value under src/ —
#
#   config.mfa_required          (a field read)
#   client.mfa_required()        (a getter call)
#
# — unless the line, or the line directly above it, carries the allow
# marker with a reason (rustfmt moves a trailing comment after `{`, so put
# the marker on its own line above the read):
#
#   // mfa-resolver-ok: <reason>
#
# Exempt without a marker: the code that builds or copies the setting and
# never decides with it — the config loader (src/config/), reconcile, the
# backup importer, and the settings editors (the admin REST API and the admin
# console pages). Writes (`mfa_required:`
# in a struct literal, `x.mfa_required = v`) and `mfa_required_roles` never
# match. A copy of a request field into storage is a read and needs a marker.
#
# Usage: bash scripts/check-mfa-resolver.sh [root]
#        `root` defaults to the repository; the self-test passes a fixture.
# Exit:  0 if clean, 1 if any unmarked read is found.

set -euo pipefail

ROOT="${1:-.}"
SRC="$ROOT/src"

if [[ ! -d "$SRC" ]]; then
    echo "FAIL: $SRC not found; run from the repository root or pass a root."
    exit 1
fi

violations=0

while IFS= read -r hit; do
    file="${hit%%:*}"
    rel="${file#"$ROOT"/}"
    case "$rel" in
        src/config/*|src/backup/import.rs|src/identity/reconcile.rs) continue ;;
        src/protocol/http/admin.rs|src/protocol/http/admin/*|src/protocol/web/admin/*) continue ;;
        src/protocol/generated/*) continue ;;
    esac
    [[ "$hit" == *"mfa-resolver-ok:"* ]] && continue
    lineno="${hit#*:}"; lineno="${lineno%%:*}"
    if (( lineno > 1 )) && sed -n "$((lineno - 1))p" "$file" | grep -q 'mfa-resolver-ok:'; then
        continue
    fi
    # Skip comment-only lines.
    code="${hit#*:*:}"
    [[ "$code" =~ ^[[:space:]]*// ]] && continue
    echo "FAIL [direct mfa_required read] $rel:${hit#*:}"
    violations=$((violations + 1))
done < <(grep -rnE '\.mfa_required(\(\)|[^_(a-zA-Z0-9]|$)' "$SRC" --include='*.rs' 2>/dev/null \
    | grep -vE '\.mfa_required[[:space:]]*=[^=]' || true)

if (( violations > 0 )); then
    echo ""
    echo "mfa-resolver: $violations direct read(s) of mfa_required."
    echo ""
    echo "Decide whether a sign-in needs a second factor with the one resolver:"
    echo ""
    echo "  identity.effective_mfa_requirement(realm_id, user_id, client_id)?"
    echo ""
    echo "For the realm policy alone (startup warnings, audit), use"
    echo "crate::identity::realm_requires_mfa(config). A read that is not a"
    echo "decision (an admin form showing the stored value) carries:"
    echo "  // mfa-resolver-ok: <reason>"
    exit 1
fi

echo "OK: every MFA-requirement decision goes through the resolver."
