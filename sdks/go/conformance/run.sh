#!/usr/bin/env bash
# Runs the shared SDK conformance cases through the Go SDK
# (contract: sdks/conformance/README.md).
# Usage: sdks/go/conformance/run.sh <cases.json>
set -euo pipefail

cases="$(cd "$(dirname "${1:?usage: run.sh <cases.json>}")" && pwd)/$(basename "$1")"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec go run ./conformance "$cases"
