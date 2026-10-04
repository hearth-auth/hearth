#!/usr/bin/env bash
# gen-admin.sh — generate the Go SDK's admin client from the admin OpenAPI subset.
#
# Usage: sdks/go/gen-admin.sh ADMIN_OPENAPI_JSON
# Called by scripts/sdk-admin-gen.sh (`make sdk-admin-gen`), which writes the
# subset with scripts/admin_openapi.py. Output: sdks/go/generated/admin/admin.gen.go.
#
# The generator is pinned here, run with `go run ...@version`, so it never
# enters the SDK's go.mod and importers do not inherit its dependencies.

set -euo pipefail

OAPI_CODEGEN_VERSION=v2.8.0

spec="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
sdk_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="$sdk_dir/generated/admin"

mkdir -p "$out_dir"
cd "$sdk_dir"
go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -generate types,client \
  -package admin \
  -o "$out_dir/admin.gen.go" \
  "$spec"
gofmt -w "$out_dir/admin.gen.go"
