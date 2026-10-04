# performance-budgets Specification

## Purpose
The latency and throughput budgets of the hot path and the main flows, the conditions they are measured under, and the gate (if any) that enforces each one.
## Requirements
### Requirement: Budgets are single-node percentile targets
Each latency budget in this capability SHALL be a p50 or p99 target for one named operation on a single node. Benches measure the budgets with `criterion`. A "cold path" budget SHALL apply to the first access of a record that is not in the hot tier. A throughput target SHALL be a per-core rate (ops/sec/core), unless the requirement names an aggregate rate at a stated concurrency. A budget that no gate enforces is still a target. Each requirement says which gate, if any, enforces it.

A bench gate is a threshold assertion in the bench binary's `main`, run before `criterion` sampling. It discards a warm-up run, collects its samples, sorts them, and reads p50 as `samples[len / 2]` and p99 as `samples[len * 99 / 100]`. A breach makes the bench binary exit non-zero.

#### Scenario: A gated bench reports against its limit
- **WHEN** a gated bench measures an operation that has a budget in this capability
- **THEN** it takes p50 and p99 from its sorted samples after warm-up
- **AND** it exits non-zero when a percentile is above the gate's limit

#### Scenario: A cold-path figure
- **WHEN** a bench reads a record that has been evicted from the hot tier
- **THEN** the operation's cold-path budget applies to that first access, not its p50 or p99 budget

### Requirement: Benchmark gates are advisory
Bench gates SHALL report a budget breach as a failed job, and they SHALL NOT block a merge: no benchmark result is a required check. The gates run in the places in the table below.

| Where | What runs | Effect of a breach |
|---|---|---|
| `make bench-gate` | `rbac_check`, `session_lookup`, `storage_gate`, `demotion_latency`, `validate_token` | the make target fails |
| Release workflow, validation job, step 7 | `make bench-gate`, with `continue-on-error: true` | recorded as `FAIL` under "Advisory gates" in `validation-summary.txt`; the release is not blocked |
| `bench-regression.yml`, on pull requests into `main` and pushes to `main` | `storage_gate`, `tiered_storage`, `demotion_latency`, `validate_token` | the job fails; `bench-required-summary` fails; neither is a required check |

`bench-regression.yml` runs only when `src/storage/**`, `src/identity/**`, `benches/**`, `Cargo.toml`, `Cargo.lock`, `scripts/check-bench-regression.sh` or its own setup files change. A change to `src/rbac/**` alone does not run it.

The regression threshold for every operation is +20%. No gate enforces it. At release, the release engineer reviews a regression of more than 20% against the recorded baseline. On a pull request, `scripts/check-bench-regression.sh` compares each bench's mean with the cached `main` baseline and emits a warning when a mean grows by more than 10%. It always exits 0.

The `token_validation`, `user_lookup`, `oidc_exchange`, `oauth`, `admin` and `audit` benches assert no threshold. The `agent_credentials` and `point_lookup` benches assert thresholds, but no workflow and no make target runs them. The only load test in CI, `loadtest-smoke`, treats latency as advisory.

#### Scenario: A gate breaches on a pull request
- **WHEN** a pull request changes `src/identity/**` and the `validate_token` gate measures p99 above its limit
- **THEN** the `bench-regression` job fails
- **AND** the pull request can still merge, because the job is not a required check

#### Scenario: A gate breaches at release
- **WHEN** `make bench-gate` fails during release validation
- **THEN** `validation-summary.txt` records the benchmark gate as `FAIL`
- **AND** the release is not blocked by it

#### Scenario: A mean regresses by more than 10%
- **WHEN** a bench's mean on a pull request is more than 10% above the cached `main` baseline
- **THEN** the workflow emits a warning annotation
- **AND** the regression check exits 0

### Requirement: Token validation budget
`validate_token()` (JWT verify plus session lookup) SHALL meet the budgets in the table below. These are the targets.

| Measure | Budget |
|---|---|
| p50 | < 50 μs |
| p99 | < 500 μs |
| Cold path | < 5 ms |
| Throughput | 200K+ ops/sec/core |
| Regression threshold | +20% |

The `validate_token` bench gates only the p99 of a warm validation, and its limit is 1 ms, not 500 μs: the extra headroom absorbs the noise of shared CI runners. It has no p50 gate. No gate enforces the p50, cold-path or throughput targets. The `token_validation` bench measures validation without a threshold. The load test grades its `validate` journey against the 500 μs p99 budget plus its loopback envelope.

#### Scenario: Warm token validation
- **WHEN** a token is validated and its session is in the hot tier
- **THEN** p50 is below 50 μs and p99 is below 500 μs

#### Scenario: The CI gate's limit
- **WHEN** the `validate_token` gate measures a warm p99 of 700 μs
- **THEN** the gate passes, although the p99 target is missed
- **AND** a measured p99 above 1 ms makes the bench exit non-zero

### Requirement: Session lookup budget
Session lookup by ID (`lookup_session()`) SHALL meet p50 < 10 μs and p99 < 100 μs, with a regression threshold of +20%. A hot-tier session lookup in the storage engine SHALL meet the same budget: p50 < 10 μs and p99 < 100 μs. Session lookup has no cold-path budget, because a session is always hot while it is active.

The `storage_gate` bench enforces both budgets at their source values: its `session_lookup_by_id` gate (a warm `get_session`) and its `storage_hot_tier_lookup` gate each require p50 ≤ 10 μs and p99 ≤ 100 μs. The `session_lookup` bench gates the same warm `get_session` call at p99 ≤ 1 ms, for runner headroom. The load test grades its `session_lookup` journey against the 100 μs p99 budget plus its loopback envelope.

#### Scenario: Session lookup by ID
- **WHEN** the `storage_gate` bench looks up an active session by its ID
- **THEN** p50 is at most 10 μs and p99 is at most 100 μs

#### Scenario: Hot-tier session lookup
- **WHEN** the `storage_gate` bench reads a key that is in the storage hot tier
- **THEN** p50 is at most 10 μs and p99 is at most 100 μs

### Requirement: User lookup budget
`lookup_user()` by email or by ID SHALL meet p50 < 20 μs and p99 < 200 μs, and < 5 ms on a cold-path first access, with a regression threshold of +20%.

The `storage_gate` bench enforces p50 ≤ 20 μs and p99 ≤ 200 μs with its `user_lookup_by_id` and `user_lookup_by_email` gates. No gate enforces the cold-path budget. The load test grades its `user_lookup`, `lookup_hot` and `lookup_cold` journeys against this budget plus its loopback envelope.

#### Scenario: User lookup by ID
- **WHEN** the bench looks up a user by ID and the record is in the hot tier
- **THEN** p50 is at most 20 μs and p99 is at most 200 μs

#### Scenario: User lookup by email
- **WHEN** the bench looks up a user through the email index and both records are in the hot tier
- **THEN** p50 is at most 20 μs and p99 is at most 200 μs

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

### Requirement: Token issuance budget
Token issuance through the full OAuth2 flow SHALL meet p50 < 1 ms and p99 < 5 ms, and < 10 ms on a cold-path first access, with a regression threshold of +20%.

No gate enforces this budget. The `token_validation` bench measures issuance without a threshold. The load test's `issuance` journey mints each token with `POST /dev/seed-token`, a dev-only route that creates a session and signs a JWT for a seeded user. It is not the full OAuth2 flow. The load test grades that journey against the 5 ms p99 budget plus its loopback envelope.

#### Scenario: Full-flow token issuance
- **WHEN** a token is issued through the full OAuth2 flow
- **THEN** p50 is below 1 ms and p99 is below 5 ms

### Requirement: OAuth endpoint budgets
The OAuth 2.0 and OIDC operations in the table below SHALL meet their budgets, each with a regression threshold of +20%.

| Operation | p50 | p99 |
|---|---|---|
| Authorization code exchange | < 1 ms | < 5 ms |
| Client credentials token issuance | < 500 μs | < 2 ms |
| Token introspection (`/introspect`) | < 50 μs | < 500 μs |

No gate enforces these budgets. The `oidc_exchange` and `oauth` benches measure them without a threshold, and no workflow runs those benches. `POST /oauth/authorize` (decision mode) has no budget of its own: it is one token validation plus one RBAC resolution, so its cost is comparable to introspection.

#### Scenario: Authorization code exchange
- **WHEN** an authorization code is exchanged for tokens
- **THEN** p50 is below 1 ms and p99 is below 5 ms

#### Scenario: Client credentials issuance
- **WHEN** a token is issued with the `client_credentials` grant
- **THEN** p50 is below 500 μs and p99 is below 2 ms

#### Scenario: Token introspection
- **WHEN** an active token is introspected
- **THEN** p50 is below 50 μs and p99 is below 500 μs

### Requirement: User creation budget
User creation with Argon2id credential hashing SHALL meet p50 < 50 ms and p99 < 100 ms. User creation is a write, so it has no cold-path budget. No gate enforces this budget: the `user_lookup` bench measures user creation without a threshold.

#### Scenario: User creation with Argon2id
- **WHEN** a user is created with a password hashed by Argon2id
- **THEN** p50 is below 50 ms and p99 is below 100 ms

### Requirement: Durable session creation throughput
The durable session creation target SHALL be more than 30,000 sessions/s in aggregate at T=256 concurrent writers, with fsync-before-ack. The target is ungraded: no gate enforces it, and no reproducible measurement of it exists. `docs/perf/PUBLISHED_FIGURES.md` §2.1 retracts the earlier peak figures. Session creation is a write, so it has no cold-path budget.

#### Scenario: Session creation under 256 writers
- **WHEN** 256 concurrent writers create sessions, and each create is acknowledged only after its WAL `fsync`
- **THEN** the target is an aggregate rate above 30,000 sessions/s

### Requirement: Cold-to-hot promotion budget
Promoting a record from the cold tier to the hot tier SHALL take < 5 ms on NVMe storage. No gate run by CI or by a make target enforces it. The `tiered_storage` bench measures promotion without a threshold. The `point_lookup` bench asserts a cold-read p99 ≤ 5 ms, but nothing runs it.

#### Scenario: Promotion of an evicted record
- **WHEN** a read hits a record that is only in the cold tier, on NVMe storage
- **THEN** the record is loaded and promoted to the hot tier in under 5 ms

### Requirement: Admin listing and audit query budgets
The admin user listing and the audit log query SHALL meet the budgets in the table below, each with a regression threshold of +20%.

| Operation | Data set | p50 | p99 |
|---|---|---|---|
| Admin user listing, with pagination | 10K users | < 5 ms | < 50 ms |
| Audit log query, with a time-range filter | 100K entries | < 10 ms | < 100 ms |

No gate enforces these budgets. The `admin` and `audit` benches measure without a threshold, and no workflow runs them. The `audit` bench filters by actor, not by time range.

#### Scenario: Paging through 10K users
- **WHEN** a client pages through a realm of 10K users with the admin user listing
- **THEN** each page has p50 below 5 ms and p99 below 50 ms

#### Scenario: Time-range audit query
- **WHEN** a client queries 100K audit entries with a time-range filter
- **THEN** p50 is below 10 ms and p99 is below 100 ms

### Requirement: Agent API key verification budget
`verify_agent_api_key` runs on every agent-authenticated request. It SHALL meet p99 < 1 ms. The `agent_credentials` bench asserts p99 ≤ 1 ms for a correct key on an agent with one active credential, but no workflow and no make target runs it.

#### Scenario: Verifying a correct agent key
- **WHEN** a correct API key is verified for an agent with one active credential
- **THEN** p99 is below 1 ms

### Requirement: Single-node capacity targets
A single node SHALL meet the capacity targets in the table below. No gate enforces any of them.

| Metric | Target |
|---|---|
| Total managed users | 100M+ |
| Active sessions | 10M+ |
| Role assignments | 100M+ |
| Memory (1M hot users) | < 500 MB |
| Memory (10M hot users) | < 8 GB |
| Binary size | < 50 MB |
| Cold start to serving | < 2 seconds |

#### Scenario: Memory footprint of 1M hot users
- **WHEN** a single node holds 1M users in the hot tier
- **THEN** its memory footprint is below 500 MB

#### Scenario: Cold start
- **WHEN** the server starts
- **THEN** it serves requests in under 2 seconds

### Requirement: The hot path is the hot-tier read path
The hot path SHALL be any code reachable from `validate_token()`, `lookup_session()` (session by ID) or `lookup_user()` (by an indexed field: email or ID) when the data is in the hot tier. For `validate_token()`, the hot path is the session lookup, not signature re-verification. For session lookup, the hot path is `get_session_arc`, which returns the cached session as a shared `Arc`. `get_session` returns an owned copy of that session, and the copy is not on the hot path. Authorization decisions SHALL NOT be on the hot path. The RBAC engine resolves permissions at token issue and embeds them in the JWT. Client-side permission checks read the decoded token with no server round trip. Server-side checks read verified claims in-process. Everything else is off the hot path: user creation, credential hashing, token issuance, RBAC permission resolution, WAL writes, cold-tier promotion, audit materialization, SAML/SCIM handling and admin API operations. Write-path code (WAL append, memtable insert) is not hot path.

#### Scenario: A hot-tier session lookup
- **WHEN** `validate_token()` looks up a session that is in the hot tier
- **THEN** the hot-path rules in this capability apply to every line of code it runs, through `get_session_arc`

#### Scenario: Token issuance
- **WHEN** a token is issued
- **THEN** the hot-path rules do not apply to the issuance code
- **AND** the token issuance budget applies instead

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

### Requirement: Hot-path calls complete synchronously
Hot-path functions MUST NOT `.await` on I/O. They SHALL complete synchronously within the async context that calls them. `validate_token`, `get_session`, `get_session_arc`, `get_user` and `get_user_by_email` are synchronous methods, so they cannot yield.

#### Scenario: An async handler validates a token
- **WHEN** an async HTTP handler calls `validate_token()`
- **THEN** the call returns without yielding to the runtime

### Requirement: Hot-tier reads make no syscalls
Hot-tier reads MUST be served from memory-mapped structures or in-process data. A hot-tier read MUST NOT call `read()`, `pread()` or any other file I/O.

#### Scenario: A hot-tier hit is not timed
- **WHEN** a storage `get` hits the hot tier
- **THEN** no latency observation is recorded for it, and no `hearth_storage_get_duration_seconds` series with `outcome="hot_hit"` exists
- **AND** a read that falls through to an SST is timed, under `outcome="sst_hit"`

### Requirement: Hot-path readers take no locks
Hot-path readers MUST NOT acquire a mutex, an `RwLock` write lock, or any other blocking synchronization primitive. Readers SHALL use epoch-based reclamation (for example `crossbeam-epoch`) or read-copy-update.

#### Scenario: Control-plane locks are held during a validation
- **WHEN** a control writer holds the control-plane lock, and a reload holds the one-reload-at-a-time lock
- **THEN** `validate_token()` on the same node completes without waiting for either lock

### Requirement: Control-cache reloads stay off the validation path
Control-cache reloads SHALL NOT be on the hot path. When the replicated control epoch moves (a control was asserted on another node), the revoked-JTI blocklist, the DPoP blocklist and the realm statuses are rebuilt from storage on a dedicated reloader thread. The validation path SHALL only compare the epoch, with at most one debounced storage read per `EPOCH_SYNC_INTERVAL_MICROS`. When the epoch moved, the validation path SHALL signal the reloader thread with an atomic store and an `unpark`. In cluster mode, the replicated epoch row signals the reloader from the Raft observer. Control writers and the reloader order their cache changes under a lock that covers in-memory work only, and validation MUST NOT take that lock. The result SHALL be bounded staleness on the nodes that did not serve the control, never a blocked validation.

#### Scenario: Validation sees a moved epoch
- **WHEN** another node moved the persisted control epoch, the debounce interval has passed, and a validation runs
- **THEN** the validation completes without taking the control-plane lock
- **AND** it signals the reloader exactly once

#### Scenario: A reload is in flight
- **WHEN** a reload is held part-way through its rebuild
- **THEN** validations on that node still complete

### Requirement: Cold-path reads do not degrade hot-path reads
Cold-path reads MUST NOT degrade hot-path performance. Cold-tier promotion MUST NOT lock or invalidate hot-tier data structures. Cold-tier promotion is not hot path: it MAY allocate, perform I/O and acquire locks. The `demotion_latency` bench, run by `make bench-gate` and by `bench-regression.yml`, measures read p99 before, during and after a hot-tier demotion cycle.

#### Scenario: Reads during a demotion cycle
- **WHEN** writes force hot-tier evictions while reads continue
- **THEN** read p99 before, during and after the evictions stays at or below the `demotion_latency` ceiling of 500 μs
- **AND** reads of re-promoted entries return to the lock-free hot-tier path

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

