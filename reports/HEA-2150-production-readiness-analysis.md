# Hearth — Production Readiness Analysis (HEA-2150)

**Commit audited:** `af4edb59` (main, clean tree) · **Date:** 2026-08-12
**Method:** 9 parallel verification sweeps against source. Documentation treated as untrusted per the brief; every headline finding below was re-verified independently against the code.

---

## Bottom line

**Hearth is a genuinely substantial, well-tested engineering artifact that is NOT ready to be released as a production identity database.**

The codebase is large (~225k lines of Rust across 277 files), the test suite is real and fully green (4,685 tests, 0 failures, 88s), CI is honestly green at job level, and the feature surface is broader than most self-hosted competitors at this age (4 months, 485 commits). This is not vaporware.

But the audit found **six defects that each independently cause data loss, silent authorization corruption, or a security control failure in production** — and the public-facing claims contain several statements that are trivially falsifiable by any evaluator who opens the source or runs `ldd`.

The correct disposition is: **do not launch as GA. Fix the six criticals, correct the marketing claims, reposition clustering as experimental, and ship a single-node 1.x.**

---

## 1. Release blockers — CRITICAL

These are ranked by blast radius. Items marked ✅ were re-verified personally, not just reported by an agent.

### C-1 ✅ Backup restore silently destroys all authorization state
`src/backup/export.rs` writes **12** archive members: `realm, users, credentials, clients, roles, permissions, groups, assignments, scopes, organizations, signing_key, audit`.
`src/backup/import.rs` reads **5**: `realm, credentials, users, clients, signing_key`.

`roles, permissions, groups, assignments, scopes, organizations, audit` are **exported and never restored**. `ImportReport` (`import.rs:82-91`) has no field for them, so there is **no warning and no error** — the restore reports success. Disaster recovery of an identity *and authorization* database silently wipes every role, permission, group membership, and role assignment.

It is untested because `tests/backup.rs:260-262` constructs `roles`/`groups`/`org_groups` as **empty vectors** — the round-trip test cannot fail.
`docs/guides/backup.md:18-27` advertises those files and promises "Full restore."

### C-2 ✅ SIGTERM is unhandled — no graceful shutdown under any orchestrator
Repo-wide, the only Unix signal handled is `SignalKind::hangup()` (SIGHUP, for TLS cert reload, `main.rs:2699,3179`). The sole shutdown trigger is `tokio::signal::ctrl_c()` — SIGINT — at `main.rs:2722,3208`.

`docker stop`, `kubectl delete pod`, and `systemctl stop` all send **SIGTERM**, whose default disposition kills the process instantly. The graceful-drain plumbing is correctly wired (`serve.rs:46,189`, gRPC `server.rs:325`) and simply never fires. **Every rolling update is a hard kill** with no connection draining. Acked writes survive (WAL fsyncs before ack); in-flight requests do not.

### C-3 Host key written without fsync → unrecoverable total data loss
`key_registry.rs:435-452` — `write_host_key_private` never calls `sync_all()` and never dir-fsyncs. `rewrite_keys_file` (`:528-535`) syncs the temp file but omits the post-rename directory fsync. Power loss shortly after first boot loses the host key, rendering **every KEK in `hearth.keys` permanently undecryptable** — i.e. the entire encrypted dataset.

### C-4 Crash during compaction can resurrect deleted keys
There is **no compaction manifest**; the SST set is derived from `read_dir` (`engine.rs:764-775`). A crash between rename and unlink leaves an orphan older SST behind a tombstone-free output. The code admits it: *"closing that window durably needs a compaction manifest (HEA-1857)"* (`engine.rs:1075-1077`).

For an identity database this **un-deletes revoked users, sessions and credentials**. It is structurally untestable today: `FaultFs` leaves `remove_file`/`rename`/`sync_dir` as unhooked pass-throughs (`simulation/src/lib.rs:419-435`), and `sst_compact_crash.rs` never deletes a key.

### C-5 ✅ Cluster followers never invalidate RBAC/claims caches
Verified: `src/cluster/state_machine.rs` contains **zero** cache-related lines, and `RaftCommand` (`types.rs:24`) has only `Put/Delete/Batch/PutIfAbsent` — no invalidation variant. The only invalidation hook is `src/rbac/engine.rs:75`, called at the *local* write site.

A follower applying a Raft entry writes straight to storage, bypassing both the RBAC cache and the token-claims `ArcSwap`. **A permission revoked on the leader is durable everywhere but still honored by followers indefinitely** — the exact privilege-escalation class already fixed for single-node in HEA-1770/1777.

### C-6 Cluster membership cannot be changed
`add_learner` and `change_membership` **do not exist anywhere in the repo**. The only membership call is `raft.initialize(members)` fed from static YAML (`engine.rs:163-208`). You cannot add a node, replace a dead node, or scale out without a full-cluster restart with hand-edited config. The doc comment at `engine.rs:199` ("Other nodes join via the normal Raft membership protocol") is **false**.

---

## 2. HIGH severity

| # | Finding | Evidence |
|---|---|---|
| H-1 ✅ | **TLS path drops `ConnectInfo` → every client IP is `127.0.0.1`.** Plaintext uses `into_make_service_with_connect_info` (`serve.rs:44`); TLS uses bare `into_service()` (`serve.rs:112`), so `PeerAddr` silently returns `FALLBACK_PEER` (`client_info.rs:18,40`). TLS is the production path. Consequence: the per-IP shaper and per-IP login limiter become **one global bucket** (one client at 100 rps 429s every tenant), and every session/audit record stores `127.0.0.1`, destroying forensic attribution. | `serve.rs:112` |
| H-2 ✅ | **`X-Forwarded-For` honored without verifying the peer is a trusted proxy.** `extract_client_ip` walks XFF right-to-left but never checks `peer.ip()` is in `trusted_proxies` (`client_info.rs:54-86`). Any direct-reachable path allows per-request IP spoofing → unlimited credential stuffing. | `client_info.rs:54` |
| H-3 | Writes to a follower return **HTTP 500** — `ForwardToLeader` is flattened into a stringly-typed `StorageError::Io` no caller parses. No 307, no proxying. | `engine.rs:697-726` |
| H-4 | Backup export has **no consistent snapshot** — paginates live reads with no lock; concurrent writes tear the archive. | `export.rs:227-279` |
| H-5 | Unencrypted (default) backup **silently drops the realm signing key** with only a `warn`. | `import.rs:242` |
| H-6 | **No PITR, no WAL archiving, no incremental backup.** RPO = last full backup. | absent repo-wide |
| H-7 | `/readyz` is a genuine storage probe, but **every deployment artifact probes always-200 `/health`** — Helm liveness *and* readiness, Dockerfile, compose. Readiness gating is inert. | `values.yaml`, `Dockerfile:140` |
| H-8 | systemd unit declares `Type=notify` but **no sd_notify anywhere** → start hangs to timeout, then restart-loops. | `deploy/systemd/hearth.service` |
| H-9 | Fail-soft prod defaults: missing KEK → private keys stored **plaintext, silently** (`main.rs:1188`); no TLS → `error!` and **continue** with non-`Secure` cookies (`main.rs:2513`); `demo.enabled` with hardcoded `DemoPassw0rd!` is **ungated in prod** (`types.rs:2157`, `main.rs:1573`). | — |
| H-10 ✅ | **All 7 SDKs ship `createRealm`, which the server 405s** with the message *"Remove this endpoint from your client."* No deprecation. Go and TypeScript integration tests are **RED at HEAD**. CI tests **1 of 7 SDKs** (`ci.yml:417` — node only), which is why. | `admin.rs:1046` |
| H-11 | SCIM advertises `"etag": {"supported": true}` but **`If-Match` is accepted and ignored** — silent lost updates under concurrent Okta/Azure provisioning. | `discovery.rs:51`, `scim/mod.rs:22` |
| H-12 | Documented `branding.*` config keys don't exist in `BrandingConfig`; under `deny_unknown_fields` the documented YAML **crashes startup**. Upgrade/DR guides cite CLI subcommands that don't exist. | `CONFIGURATION.md:381-397` vs `types.rs:696-721` |

---

## 3. Documentation credibility — a launch risk in its own right

The brief asked me not to trust the docs. That instinct was correct. These are the claims that would embarrass the company in front of a technical evaluator:

| Claim | Verdict | Reality |
|---|---|---|
| ✅ "Hot path runs against **memory-mapped**, cache-line-aligned structures" (README:13,141; VISION; landing page) | **FALSE** | The hot tier is a heap `ArcSwap<HashMap<CompositeKey, HotEntry>>` (`tiered.rs:89`). mmap is used only for **cold** SSTs — the claim is exactly inverted. No cache-line alignment anywhere. |
| ✅ "Single **static** binary" (README:13,184) | **FALSE** | All Linux release targets are `*-unknown-linux-**gnu**`; no musl, no `crt-static`. Disprovable with one `ldd`. |
| "<1 ms p99" as the landing-page headline | **MISLEADING** | Engine-plane only. README:206 itself says the only HTTP-plane figure they stand behind is **20.1 ms p50** login, and calls mixing planes "a category error." The landing page does exactly that. |
| "All engine-plane figures HEAD-verified at `1b6b7745`" (README:210) | **FALSE** | Not an ancestor of HEAD; lives on a feature branch. |
| "RFC 7592" client management (README:175) | **FALSE** | Zero occurrences in `src/`. |
| "Phase 1 — 135/135 scenarios complete" | **FALSE** | 3 still open, **two of them security** (admin rate limiting, mass-enumeration timing leak). |
| VISION: "**100x** vs app-on-Postgres"; import tools for "Clerk, Cognito, Firebase, Okta" | **FALSE / UNVERIFIABLE** | No benchmark in-repo; only Keycloak + Auth0 importers exist. VISION contradicts README, which pointedly refuses competitor multipliers. |
| "Tiered storage" with a cold tier | **MISLEADING** | `tiered.rs` is an in-process LRU cache. No S3/object-store client exists. |
| "O(1) RAM" | **FALSE** | The repo's own perf reports measure growth exponents of 0.648 and 0.878. |
| ✅ Version | **Incoherent** | `Cargo.toml` = `1.0.0`; releases at `v1.6.9`. semantic-release rewrites it at publish but `.releaserc` has no `@semantic-release/git`, so it's never committed. Source builds report 1.0.0 and stamp it into backup manifests (`backup/types.rs:129`). |

---

## 4. What is genuinely strong

I want to be equally objective about this — several areas are better than the industry norm:

- **Test suite is real.** 4,685 tests, **0 failures**, 88 seconds. `cargo clippy -D warnings` and `cargo fmt --check` both clean. Measured vacuity is ~3% — unusually low. CI is honestly green: 12/12 jobs at job level, no `continue-on-error` masking on the required path.
- **Multi-tenancy isolation is well built** — the highest-severity class for an identity DB, and it holds. `X-Realm-ID` is not trusted alone: the token is validated *under* the header realm (`http/auth.rs:57,84-92`), path-param BOLA is closed by one mandatory `scoped_realm` helper, and gRPC/SCIM mirror it.
- **Crypto discipline.** Ed25519-only with alg checked before verification (no HS256, no `alg:none`); Argon2id at OWASP params with a versioned HMAC pepper; `subtle::ct_eq` with deliberate non-short-circuiting; zeroizing secret types; 3 `unsafe` blocks total, all `mmap`, none in protocol/identity.
- **WAL durability is production-grade** — the best-engineered part of the system. True fsync-before-ack, real group commit, parent-dir fsync, corrupt-tail truncation with re-keying.
- **Supply chain clean.** `cargo audit` 0 vulnerabilities; `cargo deny` advisories/bans/licenses/sources all ok; Apache-2.0 with a strict permissive-only allowlist and zero GPL/AGPL in `THIRD_PARTY_LICENSES`.
- **Deployment artifacts are high quality** — digest-pinned multi-stage Dockerfile, non-root UID 10001, complete Helm chart, strongly hardened systemd unit.
- **Protocol surface is genuinely broad and mostly complete.** OIDC/OAuth2 is complete with **mandatory** PKCE (S256) and ROPC correctly unrouted; gRPC has 68/68 RPCs implemented with zero `unimplemented`; SCIM Users+Groups incl. real PATCH and filtering; LDAP with a live-OpenLDAP CI job; webhooks with SSRF guards; Keycloak and Auth0 migration importers; OpenAPI verified in sync and `buf breaking` gated.

---

## 5. Material gaps that are not blockers

- **Admin UI is incomplete for an identity product**: IdP/federation config is **read-only** (with orphan half-built templates shipping dead), no signing-key rotation UI, permissions and scopes read-only, no realm create/edit, no agent management UI despite agent auth shipping server-side, no end-user profile editing.
- **No i18n of any kind** — no framework, no catalogs, `<html lang="en">` hardcoded across 127 templates. Blocks non-English deployment; expensive to retrofit.
- **Zero coverage tooling** — no tarpaulin/llvm-cov/codecov anywhere. Coverage is unmeasured and unenforceable.
- **SAML has no assertion encryption at all**, and SP-side SLO is unrouted. Discovery advertises `backchannel_logout_supported: true` with no delivery route found.
- **SDK feature gaps across all 7**: no token revoke (RFC 7009), no DPoP, no token exchange, no MFA — all of which the *server* supports. READMEs tell integrators to hand-roll DPoP proofs.
- UI, fuzz, bench-regression and loadtest signal is **non-blocking** in CI; `fuzz` and `bench-regression` are currently red on a dependabot branch.

---

## 6. Recommendation

**Do not release as GA.** Sequenced plan:

1. **This week — free credibility win.** Correct the false claims in README/VISION/landing page (mmap hot path, static binary, p99 framing, RFC 7592, 135/135, 100x, tiered storage, O(1) RAM). These cost hours and are the highest embarrassment-to-effort ratio in the audit.
2. **Before any release — the six criticals.** C-1 (backup restore) and C-2 (SIGTERM) are days of work each and are the two most likely to cause a customer-visible catastrophe. C-3 (host-key fsync) is also days. Add a backup round-trip test with *non-empty* RBAC fixtures and a `FaultFs` hook on `rename`/`unlink`.
3. **Reposition clustering as experimental.** C-4/C-5/C-6 plus H-3 are weeks-to-months. Ship single-node, document the exclusive `data_dir` lock honestly, and stop implying HA.
4. **Fix H-1/H-2 before exposing to the internet** — together they nullify all per-IP abuse controls on the TLS path.
5. **Put the other 6 SDKs in CI** and delete `createRealm`.

**Realistic timelines:** honest single-node 1.x GA in **4–6 weeks**. Credible HA story in **3–4 months**.

**Framing:** this is a strong late-beta, not a GA product. Released today as "production identity database," the first customer to test disaster recovery or run a rolling update would hit a severe incident — and the first engineer to read `tiered.rs` would find the central architectural claim inverted. Released in 6 weeks as an honest single-node 1.x, it is a defensible product.
