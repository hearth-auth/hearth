#!/usr/bin/env bash
# gen-admin.sh — generate the Python SDK's admin client.
#
# Usage: sdks/python/gen-admin.sh ADMIN_OPENAPI.json
# Called by scripts/sdk-admin-gen.sh (make sdk-admin-gen), which writes the
# /admin subset of docs/api/openapi.json. The output is committed under
# src/hearth/generated/admin/ (package `hearth.generated.admin`); never edit it
# by hand. hearth.admin.AdminClient wraps it.

set -euo pipefail

# Pinned: a generator or formatter upgrade changes the output, so it is a
# deliberate edit here. RUFF must match the dev pin in pyproject.toml.
GENERATOR="openapi-python-client==0.29.1"
RUFF="ruff==0.16.9"

spec="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
sdk="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$sdk/src/hearth/generated/admin"

rm -rf "$out"
uvx --quiet "$GENERATOR" generate \
  --path "$spec" \
  --meta none \
  --config "$sdk/gen-admin.config.yaml" \
  --output-path "$out"
# Generated code is excluded from lint; only the formatter runs, so the
# committed output does not depend on whatever ruff is installed.
uvx --quiet "$RUFF" format --quiet --config "$sdk/pyproject.toml" --no-force-exclude "$out"
