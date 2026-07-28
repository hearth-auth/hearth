# Hearth — Code-Derived Feature Inventory (HEA-1817)

**Test Suite Audit — Phase 1 (P1).** A machine-checkable inventory of features that are actually **BUILT**, derived from code (not docs). One section per surface; each row names the surface, its entry point (`file:line` or route), and a spec reference. This is the ground-truth "what exists" map that later audit phases test-coverage-check against.

- **Method:** 8 parallel read-only subagents, one per surface. Sources: axum routers in `src/protocol/`, `proto/**` + tonic impls, `src/protocol/web/mod.rs` + `templates/ui/`, `hearth.example.yaml` × `src/config/types.rs` × `docs/specs/CONFIGURATION.md`, clap in `src/main.rs`, `sdks/` (TS/Go/PHP), `src/storage/` + `src/cluster/`, and the security specs + HEA-1717 / HEA-1749 sweeps.
- **Scope:** read-only analysis, no code changes.

## Surface totals

| # | Surface | Count | Entry point | Section |
|---|---------|-------|-------------|---------|
| 1 | HTTP / REST routes | 340 route registrations (123 machine-API + 217 web UI) | axum routers in `src/protocol/` | [01](#http--rest-routes) |
| 2 | gRPC services / RPCs | 4 services, 60 RPCs | `proto/**` + `src/protocol/grpc/`, `src/cluster/server.rs` | [02](#grpc-services--methods) |
| 3 | UI routes / templates | 217 routes, 130 templates | `src/protocol/web/mod.rs`, `templates/ui/` | [03](#ui-routes--templates) |
| 4 | Config keys | ~120 keys, 17 sections | `src/config/types.rs` | [04](#configuration-surface) |
| 5 | CLI | 8 top-level cmds (23 rows), ~45 flags | `src/main.rs` | [05](#cli-commands--flags) |
| 6 | SDK exports | TS/Go/PHP (see per-SDK counts) | `sdks/` | [06](#sdk-exports-ts--go--php) |
| 7 | Storage / cluster behaviors | 43 behaviors | `src/storage/`, `src/cluster/` | [07](#storage--cluster-behaviors) |
| 8 | Security behaviors | 20 enforced behaviors | across `src/identity/`, `src/protocol/` | [08](#security-behaviors) |

## Cross-surface findings for later audit phases

These are drift/gaps surfaced during inventory — inputs for P2 (coverage mapping) and P4 (triage), **not** action items for this issue:

- **Config drift (§4):** documented-but-unimplemented keys silently ignored (no `deny_unknown_fields`) — `auth.audit_log_retention`, `security.password.pepper.*`, `security.bearer_token` (real field is `metrics.bearer_token`), and several `realms.<name>.auth.*` keys that are admin-API-only. Implemented-but-undocumented: `server.{default_realm,grpc_port,grpc_bind_address,assets_dir}`, `storage.compaction.*`, `observability.otlp.*`, session concurrency keys. Stale example.yaml comments still show removed opt-outs `oidc.enforce_nonces`/`require_pkce` (startup-rejected, HEA-SEC-29).
- **SDK parity (§6):** TS is the weakest — WebAuthn (4 methods), DCR `registerClient`, permissions/userinfo/decision calls, and first-class `refreshToken`/`exchangeCode` exist in Go+PHP but not on the TS `HearthClient`. No spec-mandated op is entirely missing from any SDK.
- **Storage untested/aspirational (§7):** follower bounded-staleness read enforcement (ARCHITECTURE §32.1) appears unimplemented; encryption-at-rest DEK and crash-recovery paths reachable only via module/madsim tests, not the nextest black-box harness; format-version migration is greenfield-minimal.
- **Spec-less surfaces (§1):** SCIM and SAML have no `docs/specs/` file (only external RFCs). Many account/settings/webhook/audit UI routes map to no spec.
- **gRPC-only surface (§2):** many Rbac/Identity RPCs have no REST binding (tracked under HEA-969).
- **Dev-only / feature-gated routes (§1):** `POST /admin/bootstrap` + `/dev/mail/*` are dev-only; all agent-auth routers are capability-gated (silently absent unless enabled). `POST/PATCH /admin/realms` intentionally 405 (realms managed via `hearth.yaml`).
- **Template naming (§3):** parallel `required_action/` (interstitial) vs `required-actions/` (routed) dirs — cleanup candidate.

---
