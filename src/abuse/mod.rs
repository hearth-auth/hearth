//! Abuse-prevention primitives — built-in guards and pluggable provider traits.
//!
//! | ID   | Feature                                  | Location in module       |
//! |------|------------------------------------------|--------------------------|
//! | A-2  | Global request shaper (per-IP + realm)   | [`shaper`]               |
//! | A-3  | Distributed-attack detector              | [`detector`]             |
//! | A-4  | Outbound email/SMS volume shield         | [`detector`]             |
//! | A-9  | Tenant-managed CIDR allow/deny lists     | [`cidr`]                 |
//! | A-12 | Adaptive exponential lockout backoff     | [`backoff`]              |
//! | A-15 | gRPC rate-limit interceptor              | [`shaper`]               |
//! | A-16 | CAPTCHA-of-last-resort challenge          | [`challenge`]            |
//! | A-17 | Login tarpit (deterministic delay)       | [`tarpit`]               |
//! | A-21 | JSON parse-bomb guard (depth + length)   | [`guards`]               |
//! | A-22 | Decompression-bomb cap                   | [`guards`]               |
//! | A-23 | Trait-level pagination hard cap          | (constant here)          |
//! | A-38 | ACT actor-chain depth cap                | (constant here)          |
//! | A-39 | HTTP/2 rapid-reset defense               | `src/protocol/http`      |
//! | A-40 | Host allowlist + COOP/COEP + cookies     | `src/protocol/web`       |
//! | A-44 | SAML XML parse-event cap                 | (constant here)          |
//! | A-45 | Tenant HTML/CSS/SVG sanitization         | [`sanitize`]             |
//! | A-47 | `deny_unknown_fields` on request shapes  | (annotations)            |
//! | A-50 | Cross-realm SMS/email aggregation cap    | [`detector`]             |
//! | A-52 | Unified `return_to` allowlist            | [`redirect`]             |
//! | P-2  | IP-reputation trait + Spamhaus DROP + MaxMind ASN | [`ip_reputation`] |
//! | P-3  | Bot-signal trait + UA/JA3/JA4 heuristics | [`bot_signal`]           |
//! | P-4  | RiskScorer trait + rule-based engine (A-11) | [`risk_scorer`]       |
//! | P-5  | Email-reputation trait + disposable list | [`email_reputation`]     |

pub mod backoff;
pub mod bot_signal;
pub mod challenge;
pub mod cidr;
pub mod detector;
pub mod email_reputation;
pub mod guards;
pub mod ip_reputation;
pub mod redirect;
pub mod risk_scorer;
pub mod sanitize;
pub mod shaper;
pub mod tarpit;

/// Maximum page size accepted at every paginated list endpoint (A-23).
pub const MAX_PAGE_SIZE: usize = 1_000;

/// Maximum RFC 8693 `act` actor-chain depth accepted in inbound access tokens (A-38).
pub const MAX_ACT_CHAIN_DEPTH: usize = 3;

/// Maximum number of SCIM `Operations` in a single PATCH body (A-35a).
pub const MAX_SCIM_OPERATIONS: usize = 1_000;

/// Maximum SAML XML parse-event count per `AuthnResponse` (A-44).
pub const MAX_SAML_XML_EVENTS: usize = 10_000;

/// Fail-open vs fail-closed decision for Phase 0 guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// Silently allow the request if the guard cannot make a decision.
    Open,
    /// Reject the requests if the guard cannot make a decision.
    Closed,
}
