# HEA-1114 — Abuse-Prevention Plane

Abuse-prevention measures for Hearth, organised into rows that CI enforces via
the §3.41 adversarial test-quality gate (`scripts/check-abuse-coverage.sh`).

Each row MUST have at least one adversarial (negative-scenario) test in
`tests/abuse_*.rs` whose source references the row identifier (e.g. `A-2`).

## A-N Row Table

| ID   | Feature                                          | Layer                      | Phase  |
|------|--------------------------------------------------|----------------------------|--------|
| A-2  | Global request shaper (100 rps/IP, 1000 rps/realm) | `src/abuse/shaper.rs`     | Phase-0 |
| A-15 | gRPC rate-limit interceptor (`Server::layer`)    | `src/protocol/grpc/`       | Phase-0 |
| A-21 | JSON parse-bomb guard (depth >128, array ≥65536 → 413) | `src/abuse/guards.rs` | Phase-0 |
| A-22 | Decompression-bomb cap (4 MiB decoded max)       | `src/abuse/guards.rs`      | Phase-0 |
| A-23 | Pagination hard cap (`cap_page_size`, MAX=1000)  | `src/identity/mod.rs`      | Phase-0 |
| A-39 | HTTP/2 rapid-reset defense (CVE-2023-44487)      | `src/protocol/http.rs`     | Phase-0 |
| A-40 | `Host` allowlist + COOP/COEP/Permissions-Policy + `__Host-` cookies | `src/protocol/web/middleware.rs` | Phase-0 |
| A-47 | `deny_unknown_fields` audit (codebase-wide)      | cross-cutting              | Phase-0 |
| A-52 | Unified `return_to`/federation-redirect allowlist | `src/protocol/web/saml.rs` | Phase-0 |

## CI Enforcement

The `scripts/check-abuse-coverage.sh` script (wired into the `abuse-coverage` CI
job and `make abuse-check`) scans this file for `A-N` identifiers, then verifies
each appears at least once in `tests/abuse_*.rs`. Any uncovered row fails the
build with a clear message.

**Rollback:** set `SKIP_ABUSE_COVERAGE_CHECK=1` as a GitHub Actions secret or
repo-level environment variable. Document the reason and the tracking issue when
activating the escape hatch. The flag is logged visibly in CI output so accidental
bypass is observable.

## Adding New Rows

1. Add the row to this table with a unique `A-N` identifier (increment the
   largest existing N).
2. Land at least one adversarial test in `tests/abuse_*.rs` that references the
   identifier before (or in the same PR as) the plan doc change.
3. CI will fail the PR if step 2 is missing — that is the gate working correctly.
