#!/usr/bin/env bash
# scripts/check-docs-only-filter.sh — the `docs-only` routing output must mean
# "EVERY changed file is documentation", never "ANY changed file is".
#
# GA audit 2026-09-28, finding M19:
#
#   ci.yml computed `docs-only` as a dorny/paths-filter filter with the default
#   `predicate-quantifier: some`. A paths-filter filter is 'true' when ANY
#   changed file matches it, so every PR that also touched a .md file
#   (CHANGELOG.md, CLAUDE.md …) reported docs-only=true and skipped the
#   `security` job (Trivy, osv-scanner, CodeQL). required-summary counts
#   `skipped` as a pass, so PR #358 changed Rust and merged with no scanner run.
#
# The fix computes the inverse question in its own paths-filter step — does ANY
# changed file fall outside the documentation set? — with
# `predicate-quantifier: 'every'` and negated doc patterns, and derives
# docs-only as its negation. This guard fails if that arrangement regresses:
#
#   1. a `docs-only:` filter reappears inside a paths-filter `filters:` block
#      (any-match semantics, the original defect);
#   2. the `docs` step loses `predicate-quantifier: 'every'`, or its `non-docs`
#      filter loses the '**' include or a negated doc pattern;
#   3. the job output stops deriving docs-only from `non-docs == 'false'` (the
#      fail-closed form: an empty output must NOT read as docs-only).
#
# Usage:  bash scripts/check-docs-only-filter.sh
# Env:    CI_WORKFLOW  (default .github/workflows/ci.yml)

set -uo pipefail

CI_WORKFLOW="${CI_WORKFLOW:-.github/workflows/ci.yml}"

[[ -f "$CI_WORKFLOW" ]] || { echo "FAIL: ${CI_WORKFLOW} not found."; exit 1; }

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# The filter job, comments dropped, up to the next top-level job header.
filter_job="$(awk '
    /^  filter:$/                       { inblock = 1; next }
    inblock && /^  [a-z][a-z0-9-]*:$/   { inblock = 0 }
    inblock                             { print }
' "$CI_WORKFLOW" | grep -vE '^[[:space:]]*#')"

if [[ -z "$filter_job" ]]; then
    fail "no 'filter' job in ${CI_WORKFLOW}."
    echo "${failures} failure(s)."
    exit 1
fi

# ── 1. No any-match docs-only filter ──────────────────────────────────────────
if printf '%s\n' "$filter_job" | grep -qE '^[[:space:]]+docs-only:[[:space:]]*$'; then
    fail "a 'docs-only:' paths-filter filter is back. A paths-filter filter is 'true' when ANY changed file matches it, so every PR that also edits a .md file would skip the security job (GA audit M19). Derive docs-only from the 'non-docs' step instead."
fi

# ── 2. The `docs` step: every-quantifier, '**' include, negated doc globs ────
docs_step="$(printf '%s\n' "$filter_job" | awk '
    /^[[:space:]]+id: docs[[:space:]]*$/          { inblock = 1; next }
    inblock && /^      - name:/                   { inblock = 0 }
    inblock                                       { print }
')"

if [[ -z "$docs_step" ]]; then
    fail "no paths-filter step with 'id: docs' in the filter job."
else
    if ! printf '%s\n' "$docs_step" | grep -qE "predicate-quantifier:[[:space:]]*'?every'?[[:space:]]*$"; then
        fail "the 'docs' step does not set predicate-quantifier: 'every'. Without it a negated pattern is OR-ed with '**' and every file matches."
    fi
    if ! printf '%s\n' "$docs_step" | grep -qE '^[[:space:]]+non-docs:[[:space:]]*$'; then
        fail "the 'docs' step has no 'non-docs' filter."
    fi
    for pattern in "'**'" "'!docs/**'" "'!**/*.md'"; do
        if ! printf '%s\n' "$docs_step" | grep -qF -- "- ${pattern}"; then
            fail "the 'non-docs' filter does not list ${pattern}."
        fi
    done
fi

# ── 3. docs-only is the fail-closed negation of non-docs ─────────────────────
output_line="$(printf '%s\n' "$filter_job" | grep -E '^[[:space:]]+docs-only:[[:space:]]*\$\{\{')"
if [[ -z "$output_line" ]]; then
    fail "the filter job exports no 'docs-only' output."
elif ! printf '%s\n' "$output_line" | grep -qF "steps.docs.outputs.non-docs == 'false'"; then
    fail "the 'docs-only' output is not derived as \"steps.docs.outputs.non-docs == 'false'\". Any other form either reintroduces any-match semantics or reads an empty output as documentation-only."
fi

if (( failures > 0 )); then
    echo "${failures} failure(s)."
    exit 1
fi
echo "OK: docs-only is true only when every changed file is documentation."
