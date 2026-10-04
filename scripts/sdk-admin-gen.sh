#!/usr/bin/env bash
# sdk-admin-gen.sh — regenerate every SDK's admin client from docs/api/openapi.json.
#
# Usage:
#   scripts/sdk-admin-gen.sh           regenerate all four SDKs
#   scripts/sdk-admin-gen.sh --check   regenerate, then fail if any committed
#                                      generated client differs (CI gate)
#
# Each SDK owns its generator and pinned version in `sdks/<sdk>/gen-admin.sh`,
# which takes the admin subset of the spec as $1 (scripts/admin_openapi.py).
# Generated code is committed; never edit it by hand.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDKS=(typescript go python php)

# The generated directories `--check` compares. Keep in step with each
# gen-admin.sh output path.
GENERATED=(
  sdks/typescript/src/generated/admin
  sdks/go/generated/admin
  sdks/python/src/hearth/generated/admin
  sdks/php/generated/admin
)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 "$REPO_ROOT/scripts/admin_openapi.py" "$tmp/admin-openapi.json"

for sdk in "${SDKS[@]}"; do
  echo "==> sdk-admin-gen: $sdk"
  bash "$REPO_ROOT/sdks/$sdk/gen-admin.sh" "$tmp/admin-openapi.json"
done

if [[ "${1:-}" == "--check" ]]; then
  cd "$REPO_ROOT"
  stale="$(git status --porcelain -- "${GENERATED[@]}")"
  if [[ -n "$stale" ]]; then
    echo "ERROR: a generated SDK admin client is stale. Run 'make sdk-admin-gen' and commit:"
    echo "$stale"
    exit 1
  fi
  echo "✓ generated SDK admin clients are up to date."
fi
