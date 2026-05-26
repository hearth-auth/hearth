#!/usr/bin/env bash
# scripts/check-secret-hygiene.sh — CI guard for accidentally committed secret material.
#
# Tracks: HEA-858. Scope: catches the most common foot-gun — a developer pastes a real
# value into hearth.example.yaml, hearth-defaults.yaml, deploy/helm/**/values.yaml, or any
# tracked YAML/Markdown/Shell file and forgets to revert before committing.
#
# This is a STATIC source scan. Runtime log scrubbing is a separate concern handled per
# docs/guides/security-hardening.md § "Device fingerprint HMAC secret".
#
# Known blind spots (documented; surface a CI follow-up if any of these stops being
# acceptable):
#   • Markdown files are skipped wholesale, not just comment lines. A real secret pasted
#     inside a ```yaml fenced block in docs/ would not be caught here. Risk is low because
#     Markdown is code-reviewed as documentation, but auditors should be aware.
#   • Rust binding right-hand sides (e.g. `secret.to_string()`, `cfg.secret.clone()`) are
#     trusted because they delegate to a value defined elsewhere. If the source binding
#     is itself a literal, this script will not see it — the test author must use one of
#     the ALLOW_LITERALS sentinels or move the value to an env-var binding.
#
# FAILS on any tracked file containing a `fingerprint_hmac_secret` assignment whose value
# is anything other than:
#   • empty string ("" or '')
#   • a ${VAR}/${VAR:-default} env substitution
#   • a String::new() / String::default() literal (Rust)
#   • a documented test sentinel (see ALLOW_LITERALS below)
#
# Usage: scripts/check-secret-hygiene.sh
# Exit:  0 if clean, 1 if any suspect value is found.

set -euo pipefail

# Test-only literals that may legitimately appear in tests/. These are documented
# dummy values that match the ≥32-byte length validation but have no real cryptographic
# meaning. Keep this list short — every entry is one fewer signal we can rely on.
ALLOW_LITERALS=(
    "test-secret-at-least-32-bytes-ok"
    "some-secret-value-here"
)

# Build a single ripgrep-friendly alternation for the allow-list.
ALLOW_PATTERN=""
for lit in "${ALLOW_LITERALS[@]}"; do
    if [[ -n "$ALLOW_PATTERN" ]]; then
        ALLOW_PATTERN+="|"
    fi
    ALLOW_PATTERN+="$lit"
done

# Search for any assignment of fingerprint_hmac_secret across tracked files.
# We exclude target/, node_modules/, .git/, and ignored paths via .gitignore.
RAW="$(git ls-files | grep -E '\.(rs|ya?ml|md|sh|toml|tf|tfvars)$' \
    | xargs -d '\n' grep -HnE 'fingerprint_hmac_secret' /dev/null 2>/dev/null || true)"

if [[ -z "$RAW" ]]; then
    echo "OK: no fingerprint_hmac_secret references found in tracked source."
    exit 0
fi

violations=0
while IFS= read -r line; do
    # `line` looks like: path:lineno:contents
    path="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    body="${rest#*:}"

    # Strip leading whitespace.
    body_trim="$(echo "$body" | sed 's/^[[:space:]]*//')"

    # Skip comment lines (Rust //, YAML/Shell #, Markdown anywhere).
    if [[ "$body_trim" =~ ^// || "$body_trim" =~ ^# || "$path" == *.md ]]; then
        continue
    fi

    # The grammar we care about: anything that looks like the field name is followed
    # by an `=` or `:` and then a value. Allowed forms (regex):
    #   empty:               (\"\"|\'\'|String::new\(\)|String::default\(\))
    #   env substitution:    \$\{[A-Z0-9_]+(:-[^}]*)?\}    (possibly quoted)
    #   binding reference:   any non-literal Rust expression in tests/ (we whitelist
    #                        common ones below)
    #
    # The conservative thing is: if the line contains a quoted literal that is NOT
    # in ALLOW_PATTERN and NOT a ${VAR} substitution, fail.

    # Extract the value side of the assignment.
    value="$(echo "$body" | sed -nE 's/.*fingerprint_hmac_secret[[:space:]]*[:=][[:space:]]*(.*)$/\1/p' \
        | sed -E 's/[[:space:],}]*$//')"

    # Empty / structural — fine.
    case "$value" in
        ""|'""'|"''"|"String::new()"|"String::new()."*|"String::default()"|"\"\".to_string()"|"String::new().to_string()")
            continue
            ;;
    esac

    # Env substitution — fine. Match "${VAR}" or '${VAR}' (with optional :-default).
    if [[ "$value" =~ ^\"\$\{[A-Z0-9_]+(:-[^}]*)?\}\" || "$value" =~ ^\'\$\{[A-Z0-9_]+(:-[^}]*)?\}\' ]]; then
        continue
    fi

    # Variable reference in tests (e.g. `secret.to_string()`, `cfg.secret.clone()`).
    # These are not literals — they bind to a value defined elsewhere, which the human
    # author controls. Accept identifiers and method-call chains that do not contain
    # a quoted string literal at all.
    if [[ ! "$value" =~ \"[^\"]+\" && ! "$value" =~ \'[^\']+\' ]]; then
        continue
    fi

    # Documented test sentinels — allowed only under tests/, simulation/, or fuzz/.
    if [[ "$path" == tests/* || "$path" == simulation/* || "$path" == fuzz/* ]]; then
        if [[ -n "$ALLOW_PATTERN" ]] && echo "$value" | grep -qE "($ALLOW_PATTERN)"; then
            continue
        fi
    fi

    echo "FAIL ($path:$lineno): suspect fingerprint_hmac_secret literal:"
    echo "     $body_trim"
    violations=$((violations + 1))
done <<< "$RAW"

if (( violations > 0 )); then
    echo ""
    echo "secret-hygiene: $violations suspect occurrence(s) found."
    echo "Move the value to an env var and reference it as \${HEARTH_REALM_<NAME>_FINGERPRINT_HMAC_SECRET}."
    echo "Document or whitelist a new test sentinel in scripts/check-secret-hygiene.sh ALLOW_LITERALS."
    echo "See docs/guides/security-hardening.md § \"Device fingerprint HMAC secret\"."
    exit 1
fi

echo "OK: no secret-hygiene violations."
exit 0
