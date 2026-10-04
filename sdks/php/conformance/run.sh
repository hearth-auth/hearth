#!/usr/bin/env bash
# PHP runner for the shared SDK conformance harness (sdks/conformance/README.md).
# Usage: sdks/php/conformance/run.sh <cases.json>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <cases.json>" >&2
  exit 2
fi

cases="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
sdk_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$sdk_dir/vendor/autoload.php" ]]; then
  (cd "$sdk_dir" && composer install --quiet --no-interaction) >&2
fi

exec php "$sdk_dir/conformance/runner.php" "$cases"
