#!/usr/bin/env bash
# gen-admin.sh — generate the PHP SDK's admin client (sdks/php/generated/admin).
#
# Usage: sdks/php/gen-admin.sh <admin-openapi.json>
#
# Called by scripts/sdk-admin-gen.sh with the /admin subset of
# docs/api/openapi.json. The generator is jane-php/open-api-3, pinned exactly
# in composer.json require-dev. Never edit the generated code by hand.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <admin-openapi.json>" >&2
  exit 2
fi

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

cd "$SDK_DIR"
if [[ ! -x vendor/bin/jane-openapi ]]; then
  composer install --quiet --no-interaction
fi

# Jane writes files but never deletes them: clear the output so a renamed or
# removed operation leaves no stale class behind.
rm -rf generated/admin
HEARTH_ADMIN_OPENAPI="$SPEC" vendor/bin/jane-openapi generate --config-file=.jane-openapi
