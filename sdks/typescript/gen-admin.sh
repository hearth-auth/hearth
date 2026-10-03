#!/usr/bin/env bash
# gen-admin.sh — generate the TypeScript admin-API types from the admin subset
# of docs/api/openapi.json. Called by scripts/sdk-admin-gen.sh with that subset
# as $1 (see scripts/admin_openapi.py).
#
# Generator: openapi-typescript, pinned to an exact version in package.json's
# devDependencies, so every machine writes the same bytes. The output is
# committed; never edit it by hand. AdminClient (src/admin.ts) wraps it through
# openapi-fetch.

set -euo pipefail

SPEC="${1:?usage: gen-admin.sh <admin-openapi.json>}"
SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SDK_DIR/src/generated/admin/schema.ts"

if [[ ! -x "$SDK_DIR/node_modules/.bin/openapi-typescript" ]]; then
  (cd "$SDK_DIR" && npm ci --silent)
fi

mkdir -p "$(dirname "$OUT")"
(cd "$SDK_DIR" && npx --no-install openapi-typescript "$SPEC" --output "$OUT" >/dev/null)
