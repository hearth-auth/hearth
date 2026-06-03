//! Abuse-prevention plane: policy trait, guard middleware anchor, and config types.
//!
//! # Architecture
//!
//! ```text
//!   ┌──────────────────────────────────────────────┐
//!   │  protocol/http.rs   (abuse_guard middleware)  │
//!   │  protocol/grpc/server.rs  (AbuseGuard layer)  │
//!   └────────────────────┬─────────────────────────┘
//!                        │ calls
//!                        ▼
//!   ┌──────────────────────────────────────────────┐
//!   │  AbusePolicy trait  (this module)            │
//!   │  ├─ NoopAbusePolicy  (default, zero-cost)    │
//!   │  └─ future: RateLimitPolicy, ThreatPolicy    │
//!   └──────────────────────────────────────────────┘
//! ```
//!
//! # Hot-path contract
//!
//! [`AbusePolicy::check`] MUST obey ALL hot-path rules from `ARCHITECTURE.md §3`:
//! - Zero heap allocations.
//! - No syscalls.
//! - No locks on the read path.
//! - No `.await` — synchronous, non-blocking.
//!
//! The ≤ 5 µs p99 budget applies to the sum of all `check` calls per request.
//!
//! # Fail-open vs fail-closed
//!
//! The default behavior is **fail-open**: if no realm ID is present in the
//! request headers, or if the policy cannot be evaluated, the guard allows
//! the request through. This prevents the abuse subsystem from becoming an
//! availability risk. Individual realms may opt into fail-closed via the
//! YAML `abuse.fail_closed: true` flag.
//!
//! See `docs/specs/ABUSE.md` for the normative threat model and full YAML schema.

mod error;
mod policy;
mod types;

pub use error::AbuseError;
pub use policy::NoopAbusePolicy;
pub use types::{AbuseDecision, AbuseRequest, RealmAbuseConfig};

use crate::core::RealmId;

/// Trait that all abuse-prevention policy implementations must satisfy.
///
/// Implementations MUST be `Send + Sync` so they can be shared across async
/// tasks without locking. The `check` method is intentionally synchronous
/// to enforce the zero-allocation, no-I/O hot-path contract.
///
/// # Implementors
///
/// - [`NoopAbusePolicy`] — passes everything, used when abuse prevention is
///   not yet configured for a realm.
///
/// # Example
///
/// ```rust,ignore
/// use hearth::abuse::{AbusePolicy, AbuseDecision, AbuseRequest};
///
/// struct MyPolicy;
///
/// impl AbusePolicy for MyPolicy {
///     fn check(&self, req: &AbuseRequest<'_>) -> AbuseDecision {
///         AbuseDecision::Allow
///     }
/// }
/// ```
pub trait AbusePolicy: Send + Sync {
    /// Evaluates whether the given request should be allowed, blocked, or
    /// challenged.
    ///
    /// # Contract
    ///
    /// - MUST complete synchronously (no `.await`).
    /// - MUST NOT allocate on the heap.
    /// - MUST NOT perform any I/O or syscalls.
    /// - MUST return within ≤ 5 µs p99 summed across all enabled features.
    fn check(&self, req: &AbuseRequest<'_>) -> AbuseDecision;
}

/// Returns the [`AbuseDecision`] for an optional realm ID.
///
/// Convenience helper used by the HTTP and gRPC guard implementations.
/// When `realm_id` is `None` (unauthenticated or realm-less endpoint), the
/// guard always returns `Allow` (fail-open).
#[inline]
pub fn guard_check(
    policy: &dyn AbusePolicy,
    realm_id: Option<&RealmId>,
    client_ip: std::net::IpAddr,
    endpoint: &'static str,
) -> AbuseDecision {
    let Some(realm_id) = realm_id else {
        return AbuseDecision::Allow;
    };
    policy.check(&AbuseRequest {
        realm_id,
        client_ip,
        endpoint,
    })
}
