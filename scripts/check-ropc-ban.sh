#!/usr/bin/env bash
# Guardrail: the RFC 6749 §4.3 Resource Owner Password Credentials (ROPC)
# "password" grant MUST NOT be reachable in Hearth.
#
# Two independent assertions, because HEA-1862 showed they can drift apart:
#
#   1. CONFIG   — "password" must not appear in VALID_GRANT_TYPES, so operators
#                 cannot declare it under `applications:` / `oauth_clients:`.
#   2. DISPATCH — no `"password" =>` match arm may exist in the HTTP token
#                 handlers. This is the assertion that actually matters: on
#                 `main` at the time HEA-1862 was filed, config was already
#                 clean *while both token endpoints still dispatched ROPC*. A
#                 config-only gate passes on a vulnerable tree.
#
# See HEA-1814 / HEA-1816 / HEA-1862.

set -euo pipefail

CONFIG_FILE="src/config/validate.rs"
DISPATCH_FILES=("src/protocol/http/oauth.rs")
status=0

# ── 1. Config allowlist ──────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "FAIL: expected $CONFIG_FILE to exist (did the config module move?)"
  exit 1
fi

block="$(awk '/^const VALID_GRANT_TYPES/,/^];/' "$CONFIG_FILE")"

# Fail closed: if the constant was renamed or relocated, the grep below would
# trivially "pass" against empty input and report a false ✓.
if [[ -z "$block" ]]; then
  echo "FAIL: VALID_GRANT_TYPES not found in $CONFIG_FILE."
  echo "      The constant was renamed or moved — update scripts/check-ropc-ban.sh"
  echo "      so this gate keeps guarding the real allowlist (HEA-1862)."
  exit 1
fi

if grep -q '"password"' <<<"$block"; then
  echo "SECURITY VIOLATION: 'password' (ROPC) found in VALID_GRANT_TYPES in $CONFIG_FILE"
  echo "  Remove it — use authorization_code+PKCE or client_credentials instead (HEA-1814)."
  status=1
else
  echo "✓ VALID_GRANT_TYPES: ROPC 'password' grant absent"
fi

# ── 2. Runtime dispatch ──────────────────────────────────────────────────────
for f in "${DISPATCH_FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: expected token-dispatch file $f to exist (did the handler move?)"
    echo "      Update DISPATCH_FILES in scripts/check-ropc-ban.sh (HEA-1862)."
    status=1
    continue
  fi
  if grep -nE '^[[:space:]]*"password"[[:space:]]*=>' "$f"; then
    echo "SECURITY VIOLATION: ROPC dispatch arm found in $f (see lines above)"
    echo "  A grant_type=password request would mint a token directly, bypassing"
    echo "  interactive/step-up MFA. Delete the arm (HEA-1816 / HEA-1862)."
    status=1
  else
    echo "✓ $f: no grant_type=password dispatch arm"
  fi
done

exit "$status"
