#!/usr/bin/env bash
# scripts/tests/check-dockerfile-claims.test.sh — tests for
# scripts/check-dockerfile-claims.sh (audit 2026-08-28 §4.8#15).
#
# The guard is the deliverable, so it needs a test that proves it FAILS on the
# pre-fix Dockerfile — not just that it passes on the fixed one.
#
# The defect: the Dockerfile said the repo declares `rust-version = "1.75"` and
# that the value is aspirational (it declares 1.88.0, and the msrv CI job
# enforces it), and it called the binary "static-ish" (it is dynamically linked
# against glibc, which is why the runtime base is Debian and not scratch).
#
# Usage: bash scripts/tests/check-dockerfile-claims.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-dockerfile-claims.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; failures=$((failures + 1)); }

cat > "${TMP}/Cargo.toml" <<'EOF'
[package]
name = "hearth"
version = "1.6.11"
rust-version = "1.88.0"
license = "Apache-2.0"
EOF

# make_dockerfile <path> <header-comment> [builder-version]
make_dockerfile() {
    local path="$1" header="$2" ver="${3:-1.89}" lic="${4:-Apache-2.0}"
    {
        printf '%s\n' "$header"
        cat <<EOF
FROM rust:${ver}-slim-bookworm@sha256:deadbeef AS builder
RUN cargo build --release

FROM debian:bookworm-slim@sha256:cafebabe AS runtime
LABEL org.opencontainers.image.licenses="${lic}"
USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/hearth"]
CMD ["serve", "-c", "/etc/hearth/hearth.yaml"]
EOF
    } > "$path"
}

# run_case <name> <expected-exit> <dockerfile> [expected-substring]
run_case() {
    local name="$1" want="$2" df="$3" expect="${4:-}" out rc
    out="$(DOCKERFILE="$df" CARGO_TOML="${TMP}/Cargo.toml" bash "$CHECK" 2>&1)"
    rc=$?
    if [[ "$rc" != "$want" ]]; then
        fail "${name}: exit ${rc}, want ${want}"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    if [[ -n "$expect" ]] && ! printf '%s\n' "$out" | grep -qF "$expect"; then
        fail "${name}: output does not mention '${expect}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        return
    fi
    pass "$name"
}

echo "== the corrected header passes =="
make_dockerfile "${TMP}/good" '# Stage 2 ("runtime"): copy the binary onto a minimal debian base and run
# `hearth serve -c /etc/hearth/hearth.yaml` under tini.
# The binary is dynamically linked against glibc.'
run_case "no version claim, no static claim, CMD matches" 0 "${TMP}/good" "OK:"

echo "== the pre-fix header fails (the defects) =="
make_dockerfile "${TMP}/stale-msrv" '# Pinned to 1.89 — the repo`s declared `rust-version = "1.75"` is aspirational.'
run_case "an MSRV claim that drifted from Cargo.toml" \
    1 "${TMP}/stale-msrv" 'Cargo.toml declares "1.88.0"'

make_dockerfile "${TMP}/static" '# Stage 2 ("runtime"): copy the static-ish binary onto a minimal debian base.'
run_case "a static claim about a Debian-based runtime" \
    1 "${TMP}/static" "dynamically linked"

echo "== a builder older than the MSRV is refused =="
make_dockerfile "${TMP}/old-builder" '# Builder.' "1.85"
run_case "rust:1.85 under an MSRV of 1.88.0" \
    1 "${TMP}/old-builder" "older than the declared MSRV"

echo "== a documented run command that is not the real CMD is refused =="
make_dockerfile "${TMP}/wrong-cmd" '# Stage 2 runs `hearth serve --dev`.'
run_case "the header documents a different command" \
    1 "${TMP}/wrong-cmd" "but CMD is"

echo "== quoting the declared MSRV is fine =="
make_dockerfile "${TMP}/right-msrv" '# The MSRV is rust-version = "1.88.0", enforced by the msrv job.'
run_case "an MSRV claim that matches Cargo.toml" 0 "${TMP}/right-msrv" "OK:"

echo "== a scratch runtime may call the binary static =="
cat > "${TMP}/scratch" <<'EOF'
# Stage 2: copy the statically linked binary onto scratch.
FROM rust:1.89-slim-bookworm AS builder
RUN cargo build --release
FROM scratch AS runtime
LABEL org.opencontainers.image.licenses="Apache-2.0"
CMD ["serve", "-c", "/etc/hearth/hearth.yaml"]
EOF
run_case "a scratch-based runtime" 0 "${TMP}/scratch" "OK:"

echo "== THE REGRESSION (§4.12#7): a licence label that is not the project licence =="
make_dockerfile "${TMP}/agpl" '# Builder.' "1.89" "AGPL-3.0-only"
run_case "the audited AGPL-3.0-only label under an Apache-2.0 project" \
    1 "${TMP}/agpl" "labels the image 'AGPL-3.0-only'"

echo "== an image with no licence label at all is refused =="
cat > "${TMP}/nolabel" <<'EOF'
# Builder.
FROM rust:1.89-slim-bookworm AS builder
RUN cargo build --release
FROM debian:bookworm-slim AS runtime
CMD ["serve", "-c", "/etc/hearth/hearth.yaml"]
EOF
run_case "no org.opencontainers.image.licenses label" \
    1 "${TMP}/nolabel" "sets no org.opencontainers.image.licenses label"

echo "== the checked-in Dockerfile passes =="
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    pass "the repository's Dockerfile and Cargo.toml agree"
else
    fail "the checked-in Dockerfile does not pass"
    printf '%s\n' "$out" | sed 's/^/         /'
fi

echo
if [[ "$failures" -eq 0 ]]; then
    echo "check-dockerfile-claims: all checks passed"
    exit 0
fi
echo "check-dockerfile-claims: ${failures} check(s) failed"
exit 1
