#!/usr/bin/env bash
# scripts/regen-store-format-fixture.sh — rewrite tests/fixtures/store-format/ (#646).
#
# Run this only when you bump STORE_FORMAT_VERSION in src/storage/format.rs.
# Then describe what operators must do in docs/guides/upgrading.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo run --quiet --example gen_store_format_fixture
ls -l tests/fixtures/store-format
