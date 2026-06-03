//! P-2 `IpReputationProvider` — pluggable IP-reputation trait + reference adapters.
//!
//! # Reference adapters
//!
//! Two reference adapters ship with Hearth:
//!
//! 1. [`spamhaus::SpamhausDropProvider`] — checks the source IP against the
//!    Spamhaus DROP (IPv4) and EDROP (IPv6) blocklists.  The lists are loaded
//!    in-memory and refreshed daily via a background Tokio task.  Hot-path
//!    lookup is lock-free via an [`arc_swap::ArcSwap`]-wrapped [`CidrFilter`].
//!
//! 2. [`maxmind::MaxMindAsnProvider`] — looks up the Autonomous System Number
//!    (ASN) for an IP from a local MaxMind GeoLite2-ASN or GeoIP2-ASN MMDB
//!    file.  The operator downloads the database separately and configures
//!    `security.ip_reputation.maxmind_db_path` in `hearth.yaml`.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: `IpReputation` is **fail-open**.
//! Implementations MUST return a permissive verdict (`is_blocklisted: false`,
//! `asn: None`) on any internal error so that legitimate requests are never
//! blocked by a provider outage or misconfiguration.
//!
//! # Hot-path contract
//!
//! `check()` MUST be synchronous.  Both reference adapters satisfy this:
//! - `SpamhausDropProvider`: O(n) scan over in-memory `Vec<Cidr>` via
//!   `ArcSwap::load()` (zero allocation, no locks on the read path).
//! - `MaxMindAsnProvider`: memory-mapped B-tree search inside the MMDB reader.
//!
//! # Per-realm policy
//!
//! Operators configure IP reputation checks per-realm in `hearth.yaml` under
//! `security.ip_reputation`.  The default is **disabled** (fail-open) until
//! the operator explicitly enables a provider and sets an action.
//!
//! ```yaml
//! security:
//!   ip_reputation:
//!     enabled: true
//!     action: block          # block | challenge | log (default: log)
//!     spamhaus:
//!       drop_url: https://www.spamhaus.org/drop/drop.txt
//!       dropv6_url: https://www.spamhaus.org/drop/dropv6.txt
//!       refresh_interval_secs: 86400
//!     maxmind_db_path: /etc/hearth/GeoLite2-ASN.mmdb
//! ```

pub mod maxmind;
pub mod spamhaus;

use std::net::IpAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Verdict returned by an [`IpReputationProvider`] check.
///
/// Callers decide policy: which fields trigger blocking, challenge, or logging
/// is determined by the per-realm [`IpReputationPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpReputationVerdict {
    /// IP was found in a known-malicious CIDR blocklist (e.g. Spamhaus DROP).
    pub is_blocklisted: bool,
    /// Autonomous System Number for this IP, if determined.
    pub asn: Option<u32>,
    /// Organization name associated with the ASN.
    pub asn_org: Option<String>,
}

impl IpReputationVerdict {
    /// `true` when no adverse signals are present in this verdict.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.is_blocklisted
    }
}

/// Pluggable IP-reputation provider trait (P-2 extension point).
///
/// # Contract
///
/// - `check()` MUST be synchronous and allocation-free on the happy path.
/// - `check()` MUST fail-open: return a permissive verdict (all flags `false`,
///   `asn: None`) on any internal error so that legitimate requests are never
///   blocked due to a provider failure or database unavailability.
/// - Implementations that require network calls (e.g. AbuseIPDB, IPQualityScore)
///   MUST cache results locally and refresh asynchronously.
pub trait IpReputationProvider: Send + Sync {
    /// Evaluates the IP address and returns a reputation verdict.
    fn check(&self, ip: IpAddr) -> IpReputationVerdict;
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider (fail-open default)
// ─────────────────────────────────────────────────────────────────────────────

/// No-op IP-reputation provider.
///
/// Always returns a clean verdict (all flags `false`, `asn: None`).  This is
/// the safe default for deployments that have not yet configured a provider —
/// no request is ever blocked by this implementation.
pub struct NoopIpReputation;

impl IpReputationProvider for NoopIpReputation {
    fn check(&self, _ip: IpAddr) -> IpReputationVerdict {
        IpReputationVerdict::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-realm policy
// ─────────────────────────────────────────────────────────────────────────────

/// Action to take when an IP-reputation check flags an IP.
///
/// Configured under `security.ip_reputation.action` in `hearth.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpReputationAction {
    /// Deny the request outright (HTTP 403).
    Block,
    /// Return a challenge response (used with A-16 CAPTCHA-of-last-resort).
    Challenge,
    /// Allow the request but record the reputation signal in the risk score
    /// and emit an `AbuseDetected` audit event.  This is the default.
    #[default]
    Log,
}

/// Per-realm IP reputation policy.
///
/// Deserialized from `security.ip_reputation` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct IpReputationPolicy {
    /// Whether IP reputation checks are enabled for this realm.
    ///
    /// Default: `false` (disabled — no requests are ever blocked by reputation
    /// checks until the operator explicitly opts in).
    pub enabled: bool,
    /// Action to take when the configured provider flags an IP.
    pub action: IpReputationAction,
}

impl Default for IpReputationPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            action: IpReputationAction::Log,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn noop_always_returns_default_verdict() {
        let p = NoopIpReputation;
        let v = p.check(v4(1, 2, 3, 4));
        assert_eq!(v, IpReputationVerdict::default());
    }

    #[test]
    fn verdict_is_clean_only_when_no_adverse_signals() {
        let clean = IpReputationVerdict::default();
        assert!(clean.is_clean());

        let blocked = IpReputationVerdict {
            is_blocklisted: true,
            ..Default::default()
        };
        assert!(!blocked.is_clean());
    }

    #[test]
    fn default_policy_is_disabled_with_log_action() {
        let policy = IpReputationPolicy::default();
        assert!(!policy.enabled);
        assert_eq!(policy.action, IpReputationAction::Log);
    }
}
