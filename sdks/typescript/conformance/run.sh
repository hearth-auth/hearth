#!/usr/bin/env bash
# TypeScript SDK conformance runner (sdks/conformance/README.md).
# Usage: sdks/typescript/conformance/run.sh <cases.json>
set -euo pipefail

CASES="$(cd "$(dirname "${1:?usage: run.sh <cases.json>}")" && pwd)/$(basename "$1")"
SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "$SDK_DIR/node_modules/.bin/tsx" ]]; then
  (cd "$SDK_DIR" && npm ci --silent) >&2
fi
cd "$SDK_DIR"
exec node_modules/.bin/tsx conformance/runner.ts "$CASES"
