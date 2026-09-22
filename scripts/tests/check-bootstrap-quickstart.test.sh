#!/usr/bin/env bash
# scripts/tests/check-bootstrap-quickstart.test.sh — tests for
# scripts/check-bootstrap-quickstart.sh (production-readiness task 26.27).
#
# A guard with no red case is not a guard. Each rule is fed the shape it exists
# to refuse, including HEAD's exact text:
#
#   case 1  the remediated generator passes
#   case 2  R2 — THE DEFECT: `http://127.0.0.1:8420` hard-coded in the snippet
#   case 3  R2 — a runtime host that is not interpolated at all
#   case 4  R2 — the fallback literal in the Rust `unwrap_or` must NOT trip it
#   case 5  R3 — THE DEFECT: the snippet cites getting-started.md (it is .mdx)
#   case 6  R1 — the generator renamed away (guard rot)
#   case 7  the checked-in tree passes
#
# Usage: bash scripts/tests/check-bootstrap-quickstart.test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK="${SCRIPT_DIR}/check-bootstrap-quickstart.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
case_n=0

# run_case <name> <expected-exit> <generator-source> [expected-substring]
run_case() {
    local name="$1" want="$2" src="$3" expect="${4:-}"
    case_n=$((case_n + 1))
    local dir="${TMP}/case-${case_n}"
    mkdir -p "${dir}/src/protocol/http" "${dir}/docs/guides"
    : > "${dir}/docs/guides/getting-started.mdx"
    printf '%s' "$src" > "${dir}/src/protocol/http/admin.rs"

    local out got=0
    out="$(REPO_ROOT="$dir" bash "$CHECK" 2>&1)" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "FAIL: ${name} — expected exit ${want}, got ${got}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    if [[ -n "$expect" && "$out" != *"$expect"* ]]; then
        echo "FAIL: ${name} — output missing expected text: ${expect}"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
        return
    fi
    echo "ok: ${name}"
}

GOOD='fn bootstrap_quickstart(headers: &HeaderMap, access_token: &str, realm_id: &str) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or("127.0.0.1:8420");
    format!(
        r#"# 1. Register an OAuth application
curl -fsS -X POST http://{host}/clients \
  -H "Authorization: Bearer {access_token}" \
  -H "X-Realm-ID: {realm_id}" \
  -H "Content-Type: application/json"

# 2. Full PKCE flow — see docs/guides/getting-started.mdx"#
    )
}
'

# 1 — the remediated generator.
run_case "the remediated generator passes" 0 "$GOOD" \
    "the generated quickstart runs where it is handed out"

# 2 — THE DEFECT AT HEAD (C-7, first half): the port was a literal, so the
#     server on 18420 told the operator to curl 8420.
run_case "R2 rejects a hard-coded host:port in the snippet" 1 \
'fn bootstrap_quickstart(headers: &HeaderMap, access_token: &str, realm_id: &str) -> String {
    format!(
        r#"# 1. Register an OAuth application
curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "Authorization: Bearer {access_token}"

# 2. Full PKCE flow — see docs/guides/getting-started.mdx"#
    )
}
' \
    "hard-coded host:port"

# 3 — a snippet with neither a literal nor an interpolated host is not a pass:
#     the rule is that the address handed out is the one the caller reached.
run_case "R2 rejects a snippet with no interpolated host" 1 \
'fn bootstrap_quickstart(headers: &HeaderMap, access_token: &str, realm_id: &str) -> String {
    format!(
        r#"# 1. Register an OAuth application
curl -fsS -X POST /clients -H "Authorization: Bearer {access_token}"

# 2. Full PKCE flow — see docs/guides/getting-started.mdx"#
    )
}
' \
    "no URL in the quickstart interpolates a runtime host"

# 4 — the guard must NOT cry wolf on the Rust-side fallback literal. A gate
#     that fails on its own correct implementation gets switched off, which is
#     the fail-open this repository has already shipped once.
run_case "R2 ignores the Rust unwrap_or fallback literal" 0 "$GOOD" \
    "interpolates the request's host"

# 5 — THE DEFECT AT HEAD (C-7, second half): the cited guide does not exist.
run_case "R3 rejects a cited path that does not exist" 1 \
'fn bootstrap_quickstart(headers: &HeaderMap, access_token: &str, realm_id: &str) -> String {
    let host = headers.get(HOST).unwrap_or("127.0.0.1:8420");
    format!(
        r#"curl -fsS -X POST http://{host}/clients

# 2. Full PKCE flow — see docs/guides/getting-started.md"#
    )
}
' \
    "cites path(s) that do not exist"

# 6 — guard rot: renaming the generator must fail loudly, not pass on nothing.
run_case "R1 rejects a renamed generator" 1 \
'fn build_the_quickstart(headers: &HeaderMap) -> String {
    format!(r#"curl http://{host}/clients"#)
}
' \
    "no \`fn bootstrap_quickstart(\`"

# 7 — the checked-in tree passes.
out="$(cd "$REPO_ROOT" && bash "$CHECK" 2>&1)"; rc=$?
if [[ "$rc" == "0" ]]; then
    echo "ok: the repository's own quickstart generator passes"
else
    echo "FAIL: the checked-in generator does not pass"
    sed 's/^/    /' <<<"$out"
    failures=$((failures + 1))
fi

echo ""
if [[ "$failures" -ne 0 ]]; then
    echo "${failures} guard self-test failure(s)."
    exit 1
fi
echo "OK: guard self-tests passed."
exit 0
