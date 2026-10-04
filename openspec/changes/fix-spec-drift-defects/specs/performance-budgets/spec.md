## MODIFIED Requirements

### Requirement: RBAC resolution and claim-lookup budgets
`resolve_permissions` runs off the hot path, at token issue. It SHALL meet p50 < 100 μs and p99 < 1 ms for a typical user with 5 roles, 10 groups and 30 permissions. A JWT claim lookup (`hasPermission` on a decoded token, a hash-set `contains`) SHALL meet p99 < 1 μs and a throughput of 10M+ ops/sec/core. Benchmarks, not the hot-path allocation rules, SHALL enforce the `resolve_permissions` budget.

The `rbac_check` bench, run by `make bench-gate`, SHALL exit non-zero when `resolve_permissions` p99 > 1 ms or `hasPermission` p99 > 1 μs. It also exits non-zero when a `hasPermission` call allocates. `make bench-gate` is advisory (see "Benchmark gates are advisory"), and no workflow runs `rbac_check` on a pull request. No gate enforces the `resolve_permissions` p50 or the `hasPermission` throughput target.

#### Scenario: Permission resolution for a typical user
- **WHEN** the bench resolves permissions for a user with 5 roles, 10 groups and 30 permissions
- **THEN** p50 is below 100 μs and p99 is below 1 ms

#### Scenario: Claim lookup on a decoded token
- **WHEN** the bench calls `hasPermission` on a decoded token's permission set
- **THEN** p99 is below 1 μs

#### Scenario: The RBAC gate breaches
- **WHEN** `make bench-gate` measures `resolve_permissions` p99 above 1 ms, or `hasPermission` p99 above 1 μs
- **THEN** the `rbac_check` bench exits non-zero
- **AND** `make bench-gate` fails

#### Scenario: Regression — the gate times Hearth's resolve_permissions
- **WHEN** the `rbac_check` bench runs its `resolve_permissions` gate
- **THEN** it times the RBAC engine's `resolve_permissions` for a user with 5 roles, 10 groups and 30 permissions
- **AND** it does not time a bench-local decode of a forged JWT

### Requirement: Hot-path reads allocate nothing
Hot-path code MUST NOT perform a heap allocation in the steady state: no `Box::new`, `Vec::new`, `String::from`, `format!()`, `to_string()` or any other allocating operation. Pre-allocated buffers and arena allocators are the alternatives. The one exception is the bookkeeping of the epoch collector. A read through `core::EpochCell` pins its thread in the cells' `crossbeam-epoch` collector, and every 128th pin on a thread runs a slice of that collector's pending work. That work SHALL allocate at most once per 1,024 loads on the thread, and only while collector work is pending. Only `EpochCell` writes, and exiting threads that used a cell, produce that work. With neither, a warm load SHALL allocate nothing. The cells SHALL have a collector of their own, so no other code's deferred work, such as `crossbeam-skiplist`'s node frees, runs or allocates in a hot-path read. Hot-path code MUST NOT add any other allocation, amortised or not.

`tests/epoch_cell_hot_path.rs` and the allocation gate of the `validate_token` bench (0 allocations per warm call) enforce this rule. The `session_lookup` bench's allocation gate (0 allocations per call) measures a warm `get_session` on a session with no heap-allocated fields (`SessionContext::default()`); `get_session` copies the session, so a session with an IP address, a user agent or a device label allocates on that path.

#### Scenario: Warm token validation
- **WHEN** `validate_token()` runs with its token claims and session already cached
- **THEN** it performs zero heap allocations per call

#### Scenario: Warm session lookup
- **WHEN** `get_session_arc` reads a session from the warm session cache
- **THEN** it performs zero heap allocations per call

#### Scenario: No writer is running
- **WHEN** no thread writes an `EpochCell`, including after earlier writes left garbage for the collector
- **THEN** a warm load allocates nothing

#### Scenario: A writer is running
- **WHEN** another thread writes `EpochCell`s while this thread performs loads
- **THEN** this thread's loads cost at most one allocation per 1,024 loads

#### Scenario: Work deferred to the default collector
- **WHEN** other code, such as `crossbeam-skiplist`, defers work to `crossbeam-epoch`'s default collector
- **THEN** that work never runs inside an `EpochCell` load, and never costs one an allocation

#### Scenario: Regression — warm user lookup allocates nothing
- **WHEN** `lookup_user()` reads a user by ID, or by email, and the records are in the hot tier
- **THEN** it performs zero heap allocations per call

### Requirement: Load-test journeys are graded against HTTP budgets
`make loadtest` SHALL grade each journey's HTTP p99 against the engine budget of its operation, plus a loopback envelope of 1 ms (1,000 μs). A journey SHALL pass only when its p99 is at or below that HTTP budget and its failure rate is at most 5%.

| Journey | Request | Engine budget | HTTP p99 budget |
|---|---|---|---|
| `validate` | `POST /introspect` | token validation p99, 500 μs | 1,500 μs |
| `session_lookup` | `GET /userinfo` | session lookup p99, 100 μs | 1,100 μs |
| `user_lookup` | `GET /admin/users/{id}` | user lookup p99, 200 μs | 1,200 μs |
| `issuance` | `POST /dev/seed-token` | token issuance p99, 5 ms | 6,000 μs |
| `lookup_hot` | `GET /dev/probe-user` | user lookup p99, 200 μs | 1,200 μs |
| `lookup_cold` | `GET /dev/probe-user` | user lookup cold path, 5 ms | 6,000 μs |

The compound revoke journey (`revoke_mint`, `revoke_precheck`, `revoke`, `revoke_revalidate`) has no budget. A healthy run that breaches a latency budget SHALL exit with code 3. A run with a journey over the 5% failure budget SHALL exit with code 1. `make loadtest-smoke`, the required `loadtest-smoke` CI job, treats latency as advisory: it fails on an erroring journey, and only reports a latency breach. No workflow runs `make loadtest`.

#### Scenario: A journey within its budget
- **WHEN** the `validate` journey records a p99 of 1 ms with no failed requests
- **THEN** the journey passes its 1,500 μs budget

#### Scenario: A fast journey that errors
- **WHEN** every request of a journey fails, even within its latency budget
- **THEN** the journey fails
- **AND** the run exits with code 1, with or without `--latency-advisory`

#### Scenario: A latency breach on a healthy run
- **WHEN** a journey's p99 is above its HTTP budget and its failure rate is at most 5%
- **THEN** `make loadtest` exits with code 3
- **AND** `make loadtest-smoke` reports the breach and exits 0

#### Scenario: Regression — tier-miss lookups carry the user-lookup budget
- **WHEN** the `lookup_hot` journey records a p99 of 2 ms with no failed requests
- **THEN** the journey breaches its 1,200 μs budget
- **AND** the `lookup_cold` journey is graded against 6,000 μs, from the user-lookup cold-path budget
