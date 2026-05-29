# Completeness Analysis — Hearth
_Generated: 2026-05-06 · Spec source: docs/specs/ + docs/vision/VISION.md · Code rev: a7c028d · Updated: 2026-05-28 · Refreshed against: 574c68e (chore/doc-updates)_

## Summary

- **Phase 0 (Foundation):** 148/148 test scenarios passing. Core engine is solid.
- **Phase 1 (Production Single-Node):** ~99% complete. All P0/P1 gaps closed. Three new Phase 1 features landed since 2026-05-06: Required Actions, Adaptive MFA + SMS OTP, and `access_token_authorization` modes.
- **Phase 2 (Clustering):** Early access. Core Raft implementation exists in `src/cluster/` (~2,900 LOC, openraft-backed). Not yet chaos-tested under production load — single-node recommended for v1.0. See `docs/guides/clustering.md`.

### ~~Top 5 Production Blockers~~ (all resolved)

1. **~~Encryption at rest~~** — ✅ RESOLVED (2026-05-06).

2. **~~Audit logging is not wired~~** — ✅ RESOLVED (2026-05-07). `EmbeddedIdentityEngine` now holds `Arc<dyn AuditEngine>`. 47 mutation methods emit audit events (`src/identity/engine.rs`). Failure policy: `FailOperation` for destructive mutations (delete, credential change, session revoke, consent revoke), `LogOnly` for non-destructive. `AuditContext { actor: Actor, metadata }` type in `src/audit/context.rs`. 3 redundant protocol-layer audit calls removed (consent grant, consent revoke, session self-revoke). Follow-up: metadata-threading for remaining protocol-layer audit sites (4 federation + 1 SAML + registration IP).

3. **No periodic cleanup** — ✅ RESOLVED (2026-05-08). Background `tokio::spawn` task runs `sweep_expired()` on a configurable interval (default 300s). Sweeps expired authorization codes (`oauth:code:`), device codes (`oauth:device:` + `oauth:ucode:`), pending authorization tickets (`oauth:pending_auth:`), and grant families (`oauth:family:`). Grant families carry a new `expires_at` field (extended on rotation, sliding). Best-effort per-entity-type error handling. Summary `AuditAction::Cleanup` audit event emitted per realm per sweep. `IdentityConfig.cleanup` (enabled, interval_secs, max_per_type).

4. **~~Hot tier auto-sizing missing~~** — ✅ RESOLVED (2026-05-08). Capacity now auto-sizes from `/proc/meminfo` `MemAvailable`, cgroup v2 `memory.max`, or cgroup v1 `memory.limit_in_bytes` (with sentinel detection). Reserves margin (`max(20%, 2 GiB)`) and converts bytes to entries via estimated `ESTIMATED_BYTES_PER_HOT_ENTRY = 1024`. `hot_tier_capacity` in YAML is now `Option<usize>` (`None` = auto-size). `hot_tier_max_memory` provides an explicit memory budget override. `StorageConfig::production()` constructor wires the full `[storage]` YAML section — fixing a latent bug where `StorageConfig::dev()` was used even in production mode, ignoring all storage settings.

5. **~~Background compaction~~** — ✅ RESOLVED (2026-05-08). Background `tokio::spawn` task periodically calls `compact_ssts()` at a configurable interval (default 3600s). Merges all SSTs into a single file via `sst::compact_with_fs()` (newest-value-wins, tombstone removal). Writes to `.sst.tmp` + atomic rename for crash safety. Acquires `flush_lock` to serialize with flushes; offloaded to `spawn_blocking` to avoid blocking Tokio workers. Old SST deletion is best-effort after rename — leaked files after crash are harmless orphans cleaned up by the next compaction. Configurable via `[storage.compaction]` YAML section (all fields optional: `enabled`, `interval_secs`, `min_sst_count`).

6. **~~Token size cap enforcement~~** — ✅ RESOLVED (2026-05-09). `validate_claim_payload()` enforces permissions≤100, roles≤50, groups≤50, claim bytes≤8KiB (JSON-serialized roles+groups+permissions) per `ClaimTarget` with per-target limit names. Wired post-`apply_claim_profile` in `issue_tokens_with_context` (access token) and `exchange_authorization_code` (access + ID token). Five integration tests cover permissions cap, roles cap, groups cap, exact-limit success, and byte-cap refusal.

### What IS Working Well

- **Storage**: WAL with fsync, atomic batch writes, memtable with lock-free reads, SST format + compaction logic, clock-based LRU tiering — all passing unit/property/simulation tests.
- **RBAC**: Complete engine with roles, groups, assignments, transitive resolution, cycle detection, scope filtering, seed data, YAML reconciliation.
- **Identity**: User CRUD, Argon2id + multi-algo verification + upgrade-on-login, session management with enumeration resistance, JWT/Ed25519 + JWKS, realm management with cascading delete, full OAuth 2.0 (all grant types), WebAuthn/Passkeys, TOTP/MFA, magic links, organizations, SAML 2.0, federation.
- **Required Actions**: Full-stack implementation — `src/identity/ra_token.rs`, OIDC gate intercepting authorization code flow, UI interstitials (`src/protocol/web/required_action.rs`), ROPC error response, realm-level defaults. ROPC bypass security fix (HEA-905) landed. `docs/guides/required-actions.md` published.
- **Adaptive MFA + SMS OTP**: Adaptive MFA chain with per-device fingerprinting (`src/identity/device_fp.rs`). SMS/phone MFA transport via Twilio and AWS SNS (`HEARTH_SMS_OTP_HMAC_KEY` env var). HMAC secret fingerprinting + rotation runbook (HEA-858). `docs/guides/sms-mfa-deployment.md` published.
- **`access_token_authorization` modes**: New `OAuthClient.access_token_authorization` field controlling token validation mode (opaque vs JWT, introspection endpoint). Documented in `docs/guides/admin-api.md` and `docs/specs/AUTHORIZATION.md`.
- **Clustering (early access)**: Raft consensus via openraft implemented — durable log store (`src/cluster/log_store.rs`), gRPC transport with mTLS (`src/cluster/network.rs`), state machine (`src/cluster/state_machine.rs`), leader routing, HA admin endpoints, 3-node integration test, cluster failover simulation (`simulation/src/tests/cluster_failover.rs`). Not production-validated; `docs/guides/clustering.md` carries an early-access warning.
- **Supply chain**: `cosign` keyless signatures, SLSA L1 provenance, CycloneDX SBOM in `.github/workflows/release.yml`. Binary release verification documented at `docs/guides/verify-release.md`. Note: supply-chain audit (2026-05-25, `docs/audit/v2/supply-chain.md`) flagged this workflow as absent on audited branch — verify on final release branch before v1.0 declaration.
- **Backup / Disaster Recovery**: Signing-key DR restore, PKCS#8/DEK zeroize on transit copies (HEA-750-745). `docs/guides/backup.md` and `docs/guides/disaster-recovery.md` published.
- **Docs site**: Docusaurus site with full guide tree — 25 operator guides, API reference, migration guides (Keycloak + Auth0), audit backlog, blog.
- **Protocol**: OIDC, REST Admin API, comprehensive web UI (~70 templates), SCIM 2.0, gRPC admin services, SAML SP/IdP endpoints.
- **Per-realm auth policies**: `mfa_required` enforced in login flow (`src/identity/engine.rs:3939`); `password_policy` enforced in credential flows (`src/identity/engine.rs:1644`, `3670`, `3857`). Resolves P2 gap #23.
- **Tests**: All 148 Phase 0 scenarios pass. 121 integration test files. 12 simulation tests. 9 benchmarks. 7 fuzz targets.

---

## Critical P0 Gaps (Must Fix Before Production)

| # | Gap | Spec | Evidence |
|---|-----|------|----------|
| 1 | **Encryption at rest** | ARCH §6.3 | ✅ RESOLVED. Envelope encryption (AES-256-GCM) implemented in `src/storage/`. Per-file DEKs wrapped by per-realm KEKs. Host key from `HEARTH_MASTER_KEY` env var or auto-generated. SST and WAL fully encrypted. |
| 2 | **Audit engine not wired** | ARCH §8.5 | ✅ RESOLVED (2026-05-07). `EmbeddedIdentityEngine` holds `Arc<dyn AuditEngine>`. 47 mutation methods emit audit events. |
| 3 | **No periodic cleanup** | — | ✅ RESOLVED (2026-05-08). Background sweep task with configurable interval (default 300s). |
| 4 | **Hot tier auto-sizing** | ARCH §6.2 | ✅ RESOLVED (2026-05-08). Auto-sizing via /proc/meminfo + cgroup v1/v2. Margin: max(20%, 2 GiB). `hot_tier_capacity` is now `Option<usize>`. `StorageConfig::production()` wires the full storage section. |
| 5 | **Background compaction** | — | ✅ RESOLVED (2026-05-08). Background `compact_ssts()` at configurable interval (default 3600s). Atomic rename for crash safety. Offloaded to `spawn_blocking`. |
| 6 | **Token size cap enforcement** | AUTHZ §2.6, §5.4 | ✅ RESOLVED (2026-05-09). `validate_claim_payload()` enforces post-profile caps (permissions≤100, roles≤50, groups≤50, claim bytes≤8KiB). |
| 7 | **`/admin/users/{id}/effective-permissions` REST endpoint** | AUTHZ §8.2 | ✅ RESOLVED (2026-05-09). `GET /admin/users/{id}/effective-permissions` with optional `org_id` and `scope` query params. Six integration tests. |
| 8 | **Dynamic Client Registration (RFC 7591)** | AGENT_AUTH §2.7 | ✅ RESOLVED (2026-05-09). `POST /register` endpoint, per-realm `DcrPolicy`, server-generated client secret, `registration_endpoint` in OIDC discovery. Eight integration tests. |
| 9 | **Resolve-time cycle detection** | AUTHZ §3 | ✅ RESOLVED (2026-05-10). `expand_role` DFS path-tracking. True cycles return `CycleDetected`. Diamonds preserved. |

---

## Important P1 Gaps

| # | Gap | Detail |
|---|-----|--------|
| 10 | **Audience-scoped scope resolution** | ✅ RESOLVED (2026-05-11). `resolve_with_scopes` accepts `resource: Option<&Uri>`. Permission scopes resolve against resource scope bundles. `resource_indicators_supported` in OIDC discovery. |
| 11 | **User.attributes on create/import requests** | ✅ RESOLVED (2026-05-10). `attributes` field added to `CreateUserRequest`, `ImportUserRequest`, proto, and engine wiring. |
| 12 | **ArcSwap registry hot-swap not wired** | ✅ RESOLVED. SIGHUP handler at `main.rs:988` calls `run_config_reconciliation()` with registry param; `PermissionRegistry` atomically swapped at line 1345. |
| 13 | **Missing OIDC default claim mappings** | ✅ RESOLVED (2026-05-10). Added 7 mappings: `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`, `phone_number`, `address`. |
| 14 | **Config structure: flat vs nested `rbac:`** | ✅ RESOLVED (2026-05-10). Flat structure confirmed; spec updated in AUTHORIZATION.md §9.5. |
| 15 | **No YAML-declared groups** | ✅ RESOLVED (2026-05-11). `GroupYamlConfig`, `groups` field on `RealmYamlConfig`, `reconcile_groups` on `RbacEngine`. Example in `hearth.example.yaml`. |
| 16 | **`list_groups`/`list_role_members` cursor unused** | ✅ RESOLVED (2026-05-10). Cursor now used for scan offsets; `next_cursor` set from boundary entry. |
| 17 | **`list_roles` cursor derivation flawed** | ✅ RESOLVED (2026-05-10). Cursor derived from boundary entry's key, not `items.last()`. |
| 18 | **RESERVED_PREFIX: `system.` vs `hearth.`** | ✅ RESOLVED (2026-05-10). Constant updated to `"hearth."`. Tests updated. |
| 19 | **No standalone WebAuthn REST API** | ✅ RESOLVED (2026-05-11). 6 REST endpoints: register begin/complete, auth begin/complete, list, delete. |
| 20 | **Only 2 of 8 SDKs exist** | ✅ PARTIALLY RESOLVED (2026-05-11). Python and Rust SDKs added. Java, PHP, C#, Ruby, Elixir remain. |
| 21 | **Only 2 of 6 migration tools exist** | Keycloak and Auth0 implemented. Clerk, Cognito, Firebase Auth, Okta missing. |
| 22 | **No shadow mode** | Required for zero-downtime migration per VISION.md §5.5. Not implemented. |

---

## P2 Gaps (Polish)

| # | Gap | Detail |
|---|-----|--------|
| 23 | **Per-realm auth policies not enforced** | ✅ RESOLVED (2026-05-28). `mfa_required` enforced in login/token-issuance flows (`engine.rs:3935–3939`). `password_policy` enforced in credential creation/update flows (`engine.rs:1644`, `3670`, `3857`, `7164`). Rate limits, allowed auth methods, and token TTL overrides from `RealmConfig` are populated but per-method rate-limit enforcement is still best-effort. |
| 24 | ~~**No Prometheus `/metrics` endpoint**~~ | ✅ RESOLVED (prior). `/metrics` endpoint wired in `src/protocol/http.rs`; hot-path counters/histograms increment in production code paths. Gated by `metrics.enabled` (default `true`). |
| 25 | **No OpenTelemetry distributed tracing** | ARCH §14.3. No tracing integration exists. |
| 26 | **No Helm chart or systemd service file** | VISION §10 Phase 2. |
| 27 | **No comprehensive README** | THINGS_WE_NEED.md. |
| 28 | **No example sites** | THINGS_WE_NEED.md requires SPAs for every SDK. |
| 29 | **No comprehensive SDK READMEs** | THINGS_WE_NEED.md. |
| 30 | **UI audit P1 items unresolved** | P1-6 (silent realm redirect), P1-9 (admin-user route conflated), P1-10 (pagination unverified), P1-3 (invite form structure). |
| 31 | **UI audit P2 items unresolved** | Breadcrumb self-link, pagination breadcrumb, reset confirmation, syntax highlighting, RBAC autocomplete. |
| 32 | **Roles UI redesign not implemented** | ROLES_UI_REDESIGN.md — inline add member, dropdown-on-change, confirm-remove, resolver links. |
| 33 | **TEST_SCENARIOS.md RBAC checkboxes stale** | Phase 0 Authorization Engine (lines 258-291) and Phase 1 RBAC Authorization Full (lines 599-624) still show `[ ]` despite 15+ passing test files. |
| 34 | **TESTING.md §8 benchmark list outdated** | Missing `oidc_exchange`, `oauth`, `tiered_storage`, `admin`, `audit`; `permission_check` renamed to `rbac_check`; `token_issuance` merged into `token_validation`. |
| 35 | **Embedded mode support contradiction** | VISION.md §6.2 describes embedded mode as supported. ARCHITECTURE.md Appendix says "not supported — FFI tax unjustified". |
| 36 | ~~**`email_verified` claim not computed**~~ | ✅ RESOLVED (prior). `User` struct has a dedicated `email_verified: bool` field (`src/identity/types.rs:142`) with getter and setter. Not computed — stored explicitly. |
| 37 | **Supply-chain audit gaps** | `docs/audit/v2/supply-chain.md` (2026-05-25) found: no `cargo deny` in CI, no binary hardening profile (`RELRO`, `PIE`, stack canaries), deprecated `serde_yaml` dependency. Release workflow (`release.yml`) exists on current branch but was absent on the audited branch — confirm presence on final release branch before v1.0 declaration. |
| 38 | **Clustering not production-validated** | Raft implementation is complete and wired (~2,900 LOC). No chaos testing under production load. `docs/guides/clustering.md` carries an explicit "early access" warning. Required before removing the single-node recommendation from the getting-started guide. |
| 39 | **Rate-limit enforcement incomplete** | `RealmConfig.rate_limits` is populated from YAML but per-method token-bucket enforcement in login/token endpoints is partial. mfa_required and password_policy are fully enforced; rate limits per auth method are not. |
| 40 | **RFC 7592 client management endpoint deferred** | DCR gap deferred at resolution time: initial access token gating, RFC 7592 management endpoint (`GET/PUT /register/{client_id}`), software statements, slug↔ClientId index. |

---

## Clustering: Implementation Status (Phase 2)

Raft clustering is implemented but not production-validated. The `src/cluster/` directory contains ~2,900 lines of real openraft-backed code:

- ✅ Durable log store (`src/cluster/log_store.rs`) with append, read, compact
- ✅ gRPC transport with mTLS (`src/cluster/network.rs`)
- ✅ State machine (`src/cluster/state_machine.rs`) with apply + snapshot
- ✅ Leader routing — writes forwarded to leader via `client_write`
- ✅ Raft admin endpoints: join, leave, status (`src/cluster/engine.rs`)
- ✅ System-realm auth gate on Raft admin RPCs (HEA-799)
- ✅ 3-node integration test and cluster failover simulation (`simulation/src/tests/cluster_failover.rs`)
- ⚠️ No chaos testing under production load
- ⚠️ Online membership changes and snapshot-based recovery not fully validated
- ⚠️ Multi-region replication not implemented

The system defaults to single-node mode when `cluster:` is absent from `hearth.yaml`. There is zero overhead in single-node mode.

---

## Spec/Code Divergences

| # | Issue | Spec Says | Code Does | Recommendation |
|---|-------|-----------|-----------|----------------|
| D1 | RBAC config nesting | `realms.<id>.rbac.{permissions,roles,scopes,groups}` | Flat fields on `RealmConfig` | ✅ RESOLVED (2026-05-10): Spec updated to flat structure. |
| D2 | Reserved prefix | `hearth.*` | `system.` constant in `types.rs:21` | ✅ RESOLVED (2026-05-10): Code aligned to `"hearth."`. |
| D3 | Embedded mode support | VISION.md says supported; ARCHITECTURE.md appendix says not supported | Not implemented | Remove embedded-mode from VISION.md or update ARCHITECTURE.md |
| D4 | `email_verified` claim | Spec shows it as supported | ✅ RESOLVED: `User.email_verified` is a stored `bool` field (`types.rs:142`), not computed from `UserStatus`. Spec updated. |

---

## Resolution Todo List

### P0 — Must fix before production deploy

- [x] **[P0][L]** Implement encryption at rest: envelope encryption (AES-256-GCM), DEK/KEK, SST header encryption fields, WAL per-segment encryption, per-realm keys — resolves gaps #1 · _depends on: none_
- [x] **[P0][M]** Wire `AuditEngine` into `EmbeddedIdentityEngine` — hold `Arc<dyn AuditEngine>`, call `audit.append()` for every security-critical mutation — resolves gaps #2 · ✅ DONE (2026-05-07)
- [x] **[P0][S]** Add periodic cleanup background task: sweep expired authorization codes, device codes, grant families, pending authorization tickets — resolves gaps #3 · ✅ DONE (2026-05-08)
- [x] **[P0][M]** Implement hot tier auto-sizing: read `/proc/meminfo` or cgroup `memory.limit_in_bytes`, reserve margin (20% or 2GB), allocate remainder; respect `storage.hot_tier_max_memory` override — resolves gaps #4 · ✅ DONE (2026-05-08)
- [x] **[P0][M]** Add background compaction loop to `EmbeddedStorageEngine` — resolves gaps #5 · ✅ DONE (2026-05-08)
- [x] **[P0][S]** Implement `validate_claim_payload()` — resolves gaps #6
- [x] **[P0][S]** Add `GET /admin/users/{id}/effective-permissions` REST endpoint — resolves gaps #7 · ✅ DONE (2026-05-09)
- [x] **[P0][M]** Implement Dynamic Client Registration (RFC 7591) `POST /register` endpoint — resolves gaps #8 · ✅ DONE (2026-05-09)

### P1 — Should fix

- [x] **[P1][M]** Add `resource: Option<Uri>` parameter to `resolve_with_scopes()` — resolves gaps #10 · ✅ DONE (2026-05-11)
- [x] **[P1][S]** Add `attributes` field to `CreateUserRequest` and `ImportUserRequest` — resolves gaps #11 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Wire `ArcSwap` hot-swap for `PermissionRegistry` in `main.rs` on SIGHUP — resolves gaps #12 · ✅ VERIFIED (2026-05-10)
- [x] **[P1][S]** Add missing OIDC default claim mappings — resolves gaps #13 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Fix `list_groups` and `list_role_members` cursor usage — resolves gaps #16 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Fix `list_roles` cursor derivation — resolves gaps #17 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Align `RESERVED_PREFIX` to `"hearth."` — resolves gaps #18 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Decide: nest RBAC config or update spec to flat structure — resolves gaps #14, D1 · ✅ DONE (2026-05-10)
- [x] **[P1][S]** Add YAML-declared groups — resolves gaps #15 · ✅ DONE (2026-05-11)
- [x] **[P1][M]** Add standalone REST WebAuthn/Passkey endpoints — resolves gaps #19 · ✅ DONE (2026-05-11)
- [x] **[P1][M]** Add Python SDK — resolves gaps #20 (partial) · ✅ DONE (2026-05-11)
- [x] **[P1][M]** Add Rust SDK — resolves gaps #20 (partial) · ✅ DONE (2026-05-11)
- [x] **[P1][S]** Add resolve-time cycle detection for role DAGs — resolves gaps #9 · ✅ DONE (2026-05-10)
- [x] **[P1][M]** Enforce per-realm auth policies: `mfa_required` + `password_policy` — resolves gaps #23 · ✅ DONE (2026-05-28)

### P2 — Polish

- [ ] **[P2][M]** Add OpenTelemetry-compatible distributed tracing — resolves gaps #25 · _depends on: none_
- [ ] **[P2][S]** Create systemd service file and Helm chart — resolves gaps #26 · _depends on: none_
- [ ] **[P2][S]** Write comprehensive README — resolves gaps #27 · _depends on: none_
- [ ] **[P2][M]** Create example sites — resolves gaps #28 · _depends on: SDKs_
- [ ] **[P2][S]** Write comprehensive README for each SDK — resolves gaps #29 · _depends on: none_
- [ ] **[P2][M]** Fix remaining UI audit items (P1-6, P1-9, P1-10, P2 items) — resolves gaps #30, #31 · _depends on: none_
- [ ] **[P2][M]** Implement Roles UI redesign — resolves gaps #32 · _depends on: P0 gap #7_
- [ ] **[P2][S]** Update TEST_SCENARIOS.md RBAC checkboxes — resolves gaps #33 · _depends on: none_
- [ ] **[P2][S]** Update TESTING.md §8 benchmark file list — resolves gaps #34 · _depends on: none_
- [ ] **[P2][S]** Resolve embedded-mode support contradiction — resolves gaps #35, D3 · _depends on: none_
- [ ] **[P2][M]** Implement per-method rate-limit enforcement in login/token endpoints — resolves gap #39 · _depends on: none_
- [ ] **[P2][M]** Implement RFC 7592 client management endpoint (`GET/PUT /register/{client_id}`) — resolves gap #40 · _depends on: DCR #8_
- [ ] **[P2][M]** Fix supply-chain audit gaps: `cargo deny` in CI, binary hardening profile, replace deprecated `serde_yaml` — resolves gap #37 · _depends on: none_
- [ ] **[P2][L]** Chaos-test and production-validate Raft clustering — resolves gap #38 · _depends on: none_

### Future Phases (tracked, not started)

- [ ] **[P3][L]** Complete clustering: online membership changes, multi-region replication, snapshot-based recovery validation (Phase 2 per VISION.md)
- [ ] **[P3][L]** Implement agent authentication (Phase A-D per AGENT_AUTH.md): `AgentId` newtype, agent CRUD, credentials, DPoP, token exchange, OBO, consent, AATs, CAEP
- [ ] **[P3][M]** Add remaining SDKs: Java/Kotlin, PHP, C#/.NET, Ruby, Elixir
- [ ] **[P3][M]** Add remaining migration tools: Clerk, Cognito, Firebase Auth, Okta
- [ ] **[P3][L]** Implement shadow mode for zero-downtime migration
- [ ] **[P3][M]** S3-compatible object storage for cold data and audit logs
- [ ] **[P3][M]** Multi-region replication with configurable consistency

---

## Recommended Execution Order

1. **Supply-chain hardening** (S, <1 week) — `cargo deny` in CI, binary hardening, replace `serde_yaml`
2. **Clustering production validation** (L, 3-5 weeks) — chaos testing 3-node under production load
3. **P2 polish** (variable) — rate-limit enforcement, RFC 7592, UI audit items, SDK READMEs
4. **Phase 3 (agent auth, additional SDKs/migrations)** — next greenfield scope; needs scoping and estimation
