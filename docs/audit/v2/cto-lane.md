# CTO Lane Re-Audit — HEA-771

**Auditor:** CTO  
**Date:** 2026-05-25  
**Branch audited:** `main` (commit `93ce8e6`)  
**Methodology:** grep-first, file:line evidence required for every claim. No reliance on prior reports or issue tracker status.

---

## Verdict

**production-ready-with-caveats**

The core Raft engine, RAII correctness, and layer architecture are solid. However, three gaps block a clean production-ready verdict: (1) no clippy lint enforcement exists anywhere in the project, (2) ~30 Mutex `.unwrap()` calls carry zero INVARIANT documentation, and (3) the v1 audit lane description referenced `src/identity/engine.rs` — a file that does not exist in this codebase, making all v1 hot-path and zero-alloc claims unverifiable against current code.

---

## Verified Claims

### 1. Layer dependency rules — CLEAN
No upward imports detected. The dependency graph is acyclic:

```
storage (infra)  ←  cluster (domain)  ←  protocol (API)
```

Evidence:
- `hearth/src/lib.rs:1-3` — three modules declared: `cluster`, `protocol`, `storage`
- `hearth/src/cluster/engine.rs:11-14` — cluster imports only `crate::cluster::*` and `crate::storage`; no protocol import
- `hearth/src/protocol/http.rs:9-10` — protocol imports `crate::cluster::ClusterEngine`; no storage import
- `hearth/src/protocol/cluster_admin.rs:12-13` — protocol imports `crate::cluster::ClusterError` and `crate::protocol::http`; no storage import
- `hearth/src/storage.rs` — no internal crate imports whatsoever

### 2. No `println!` / `eprintln!` — CLEAN

```
$ grep -rn "println!\|eprintln!\|dbg!" hearth/src/  # 0 results
```

All diagnostic output goes through the `tracing` crate (declared as a dependency in `Cargo.toml`). No violations found.

### 3. RAII guard for `transfer_leadership` (HEA-762) — CORRECTLY IMPLEMENTED

`hearth/src/cluster/engine.rs:714-724`:

```rust
struct ElectRestoreGuard(Arc<HearthRaft>);

impl Drop for ElectRestoreGuard {
    fn drop(&mut self) {
        self.0.runtime_config().elect(true);
    }
}
```

Guard is constructed at `engine.rs:682` immediately after `elect(false)` at `engine.rs:681`, before any `await` point. The doc comment at `engine.rs:664-666` correctly names the cancellation-safety invariant.

### 4. Module structure of new subsystems — CLEAN

`hearth/src/cluster/`:
- Uses `mod.rs` pattern with clean public re-exports at `cluster/mod.rs`
- Re-exports: `BootstrapResult, ClusterEngine, ClusterError, ClusterNode, HearthRaft, MembershipView, PeerInfo, StatusResult` from `engine`; `KVCommand, KVResponse, NodeId, TypeConfig` from `types`
- No circular module references; `router`, `store`, `types`, `engine` form a one-way dependency chain

`hearth/src/protocol/`:
- Uses `mod.rs` pattern; `http.rs` and `cluster_admin.rs` are sibling modules
- `cluster_admin.rs:13` imports from `crate::protocol::http` — a sibling import, not circular

### 5. Cluster admin routes — OPERATIONALLY WIRED (with caveat)

Three HTTP routes are defined and fully implemented:
- `POST /admin/cluster/bootstrap` → `cluster_admin.rs:48-70`
- `GET /admin/cluster/status` → `cluster_admin.rs:73-95`
- `POST /admin/cluster/transfer-leadership` → `cluster_admin.rs:102-131`

All three routes are guarded by `extract_admin_auth()` (`http.rs:24-40`), which enforces Bearer token auth.

**Caveat:** Hearth is a library crate — there is no `main.rs`. The `cluster_admin_routes()` builder (`http.rs:43-49`) must be wired into an integrating application. The routes themselves are correct, but operational reachability depends on the embedder.

---

## Falsified or Unverified v1 Claims

### F1. `validate_token` hot-path zero-alloc claim — **FALSIFIED**

> v1 claim: "hot-path zero-alloc claims (validate_token in `src/identity/engine.rs`)"

`src/identity/engine.rs` does not exist. There is no `identity` module in this codebase. The project is a Raft consensus library named "hearth," not an identity/auth service. This entire v1 sub-lane was written against a non-existent module. No zero-alloc claim can be verified or falsified because the described function does not exist in any form.

```
$ grep -rn "identity\|validate_token" hearth/src/
hearth/src/cluster/engine.rs:589: # comment referencing "own node identity" (natural language)
```

No `identity` module. No `validate_token` function. The v1 finding was aspirational or targeted a different codebase.

### F2. `unwrap_used` denials with INVARIANT comments — **FALSIFIED**

> v1 claim: "`unwrap_used` denials respected with INVARIANT comments"

Reality: there are no lint denials for `unwrap_used` anywhere in the project, and there are **zero INVARIANT comments** near any `.unwrap()` call. All ~30 `.unwrap()` calls are on `Mutex::lock()` — which panics on poisoned locks — without any justification comment.

Representative evidence (all lack INVARIANT comments):
- `storage.rs:18,22,26,30,38,46,50` — all `self.data.lock().unwrap()`
- `cluster/store.rs:59,73,82,98,105,109,114,126,136,142,239,343,353` — all `self.0.lock().unwrap()`
- `cluster/router.rs:59,63,67,77,84,91,102,107,111,115` — all `self.nodes/delays/partitions.lock().unwrap()`

### F3. `clippy::pedantic` clean — **UNVERIFIABLE / LIKELY FALSE**

> v1 claim: "clippy::pedantic clean"

No clippy enforcement exists to make this claim meaningful:
- `hearth/Cargo.toml` — no `[lints]` section
- No `.clippy.toml`
- No `#![deny(clippy::pedantic)]` or `#![warn(clippy::pedantic)]` in `lib.rs` or any source file

Without enforcement, "clippy::pedantic clean" is not a verifiable state — it would require running `cargo clippy -- -W clippy::pedantic` and observing zero warnings, which is not part of any CI gate in the visible configuration.

---

## New Gaps Discovered

### G1. No clippy lint configuration anywhere

`hearth/Cargo.toml` has no `[lints]` section. Neither `[lints.clippy]` nor `[lints.rust]` are configured. No crate-level `#![deny(...)]` attributes exist. A library of this ambition should at minimum deny `clippy::unwrap_used`, `clippy::panic`, and warn on `clippy::pedantic`.

### G2. Mutex `.unwrap()` — 30+ calls, zero INVARIANT documentation

See F2 above. The pattern `self.data.lock().unwrap()` appears in hot-path storage methods. While Mutex poisoning is unlikely in correctly-structured async code (panic in a non-lock-holding context won't poison), the lack of justification comments means future maintainers cannot distinguish "we thought about this" from "we forgot."

### G3. KV read/write and membership APIs not exposed via HTTP

`ClusterEngine` exposes:
- `write()` at `engine.rs:125` — Raft-replicated KV write
- `get()` at `engine.rs:135` — linearizable KV read
- `add_learner()` at `engine.rs:166`
- `add_voter()` at `engine.rs:184`
- `remove_voter()` at `engine.rs:201`

**None of these are wired to HTTP routes.** The only HTTP surface is the 3 admin endpoints (bootstrap, status, transfer-leadership). An operator using Hearth as an embedded library gets the full API; an operator expecting an HTTP-first consensus service gets only cluster lifecycle operations.

### G4. No binary / server entrypoint

There is no `src/main.rs` and no `[[bin]]` entry in `Cargo.toml`. Hearth is purely a library. The `cluster_admin_routes()` function is a composable Axum sub-router, but it is never bound to a socket by this crate. Documentation at `docs/guides/getting-started.md` (if it exists) should make this explicit.

### G5. `status()` allocates on every call

`engine.rs:642` — `.to_string()` for the role string  
`engine.rs:654` — `addr.clone()` per peer  
`engine.rs:656` — `.collect()` into a `Vec<PeerInfo>`

These allocations are reasonable for an admin endpoint but would be inappropriate on a hot read path. This is only a concern if `status()` is called in a tight loop.

---

## Operational Reachability Matrix

| Feature | Method | HTTP Route | Auth | Wired? | Notes |
|---------|--------|------------|------|--------|-------|
| Cluster bootstrap | `ClusterEngine::bootstrap()` | `POST /admin/cluster/bootstrap` | Bearer token | **Yes** | Handler at `cluster_admin.rs:48`. Returns 409 if already bootstrapped. |
| Cluster status | `ClusterEngine::status()` | `GET /admin/cluster/status` | Bearer token | **Yes** | Non-blocking; reads Raft metrics snapshot. `cluster_admin.rs:73`. |
| Transfer leadership | `ClusterEngine::transfer_leadership()` | `POST /admin/cluster/transfer-leadership` | Bearer token | **Yes** | RAII guard prevents stuck election state. `cluster_admin.rs:102`. |
| KV write (Raft-replicated) | `ClusterEngine::write()` | — | — | **No** | Rust API only. `engine.rs:125`. No HTTP handler exists. |
| Membership change (add/remove voter) | `add_voter()` / `remove_voter()` | — | — | **No** | Rust API only. `engine.rs:184,201`. No HTTP handler exists. |

---

## Summary

| Category | Finding | Severity |
|----------|---------|----------|
| Layer deps | Clean, acyclic, no upward imports | ✓ Pass |
| `println!`/`eprintln!` | Zero occurrences | ✓ Pass |
| RAII guard (HEA-762) | Correctly implemented | ✓ Pass |
| Module structure | Clean re-exports, no circular refs | ✓ Pass |
| `validate_token` zero-alloc | Module does not exist — v1 claim was fabricated | ✗ Falsified |
| `unwrap_used` + INVARIANT comments | ~30 unwraps, 0 INVARIANT comments, no lint deny | ✗ Falsified |
| `clippy::pedantic` enforcement | No lint config exists anywhere | ✗ Unverifiable |
| KV/membership HTTP exposure | 5 methods unreachable via HTTP | ⚠ Gap |
| Binary entrypoint | Library-only crate; no server binary | ⚠ Gap (by design?) |
