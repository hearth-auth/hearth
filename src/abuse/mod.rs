//! Abuse-prevention primitives (Phase 0 builtins).
//!
//! This module owns all HTTP-layer + strictness-default guards that the rest of
//! the abuse plane depends on.  Phase 0 delivers:
//!
//! | ID   | Feature                                  | Location in module |
//! |------|------------------------------------------|--------------------|
//! | A-2  | Global request shaper (per-IP + realm)   | [`shaper`]         |
//! | A-15 | gRPC rate-limit interceptor              | [`shaper`]         |
//! | A-21 | JSON parse-bomb guard (depth + length)   | [`guards`]         |
//! | A-22 | Decompression-bomb cap                   | [`guards`]         |
//! | A-23 | Trait-level pagination hard cap          | (constant here)    |
//! | A-39 | HTTP/2 rapid-reset defense               | `src/protocol/http`|
//! | A-40 | Host allowlist + COOP/COEP + cookies     | `src/protocol/web` |
//! | A-47 | `deny_unknown_fields` on request shapes  | (annotations)      |
//! | A-52 | Unified `return_to` allowlist            | [`redirect`]       |

pub mod guards;
pub mod redirect;
pub mod shaper;

/// Maximum page size accepted at every paginated list endpoint (A-23).
///
/// Enforced at the trait layer in `src/identity/mod.rs`.  Individual handlers
/// pass at most this value; callers supplying `limit > MAX_PAGE_SIZE` receive
/// `IdentityError::InvalidInput`.
pub const MAX_PAGE_SIZE: usize = 1_000;

/// Fail-open vs fail-closed decision for Phase 0 guards.
///
/// Per §6.1 of the abuse-prevention plan: Phase 0 primitives that check
/// configuration that *might* not be set (e.g. `allowed_hosts` not configured)
/// MUST fail-open so existing deployments do not break on upgrade.  Guards that
/// protect against universal attacks (JSON depth, decompression bombs, pagination
/// overflow) MUST fail-closed because they have hard-coded safe limits.
///
/// Each guard documents its own failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// Silently allow the request if the guard cannot make a decision.
    Open,
    /// Reject the request if the guard cannot make a decision.
    Closed,
}
