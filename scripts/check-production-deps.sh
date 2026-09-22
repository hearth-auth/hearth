#!/usr/bin/env bash
# scripts/check-production-deps.sh — banned crates must not reach the published
# binary, even through a transitive edge.
#
# Audit 2026-08-28 finding §4.8#9 (MEDIUM):
#
#   A third crypto backend and a policy-banned HTTP client are linked into the
#   published binary; deny.toml encodes neither ban.
#
# deny.toml now encodes both. One gap remains that cargo-deny cannot express:
# `reqwest` is a legitimate *dev*-dependency (the integration-test HTTP client),
# so its ban carries `wrappers = ["hearth"]`. That wrapper would also permit a
# production `hearth -> reqwest` edge. This script closes it by asking the
# resolver the only question that matters: is the crate in the NORMAL
# dependency graph of the `hearth` package? `cargo tree -e normal` excludes
# dev- and build-dependencies, so a hit here means the crate ships.
#
# Usage:  bash scripts/check-production-deps.sh
# Env:    PRODUCTION_BANNED  space-separated crate names (default below)
#         CARGO_PKG_UNDER_TEST  package to inspect (default hearth)

set -uo pipefail

PKG="${CARGO_PKG_UNDER_TEST:-hearth}"
# Crates that must never appear in the shipped binary. Kept short and specific:
# deny.toml is the broad policy, this is the transitive-edge backstop.
PRODUCTION_BANNED="${PRODUCTION_BANNED:-reqwest openssl native-tls hyper-tls boring curl isahc}"

command -v cargo >/dev/null || { echo "FAIL: cargo not found."; exit 1; }

failures=0

for crate in $PRODUCTION_BANNED; do
    # `-i` inverts the tree: it prints the paths by which $crate is reached.
    # With no normal-dependency path it prints "nothing to print" on stderr.
    out="$(cargo tree -e normal -i "$crate" -p "$PKG" 2>&1)"
    if printf '%s' "$out" | grep -q "nothing to print"; then
        echo "ok: ${crate} is absent from the production graph of ${PKG}"
        continue
    fi
    if printf '%s' "$out" | grep -qE "^error: package ID specification|did not match any packages"; then
        # The crate is not in the lockfile at all — also absent.
        echo "ok: ${crate} is not in the dependency graph at all"
        continue
    fi
    echo "FAIL: ${crate} reaches the published ${PKG} binary through a normal dependency."
    printf '%s\n' "$out" | sed 's/^/    /'
    echo "      Pin the offending feature out in Cargo.toml (see the"
    echo "      opentelemetry-otlp and tokio-rustls entries for the pattern)."
    failures=$((failures + 1))
done

if [[ "$failures" -ne 0 ]]; then
    echo ""
    echo "${failures} banned crate(s) reach the published binary."
    exit 1
fi

echo "OK: no banned crate reaches the published ${PKG} binary."
exit 0
