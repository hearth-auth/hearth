#!/usr/bin/env bash
# Python SDK conformance runner (sdks/conformance/README.md).
# Usage: sdks/python/conformance/run.sh <cases.json>
# Needs python3 and uv; installs the SDK from source into uv's project env.
set -euo pipefail

cases="$(cd "$(dirname "${1:?usage: run.sh <cases.json>}")" && pwd)/$(basename "$1")"
sdk="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# uv prints its progress on stderr; stdout carries only the result lines.
exec uv run --quiet --project "$sdk" python "$sdk/conformance/runner.py" "$cases"
