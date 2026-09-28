//! Tenant-managed IPv4/IPv6 CIDR allow/deny lists (A-9).
//!
//! Operators set per-realm allow/deny lists in
//! `realms.<name>.security.cidr_policy` and a [`CidrFilter`] is built from
//! them for in-memory lookup. The Spamhaus DROP feed is compiled into the same
//! type.
//!
//! # Entries
//!
//! Each entry is a [`crate::core::IpRange`]: a single address or a CIDR range,
//! parsed by the one strict grammar Hearth uses for every network list (host
//! bits, signed or zero-padded prefixes, zone ids, brackets and ports are all
//! refused). Unlike `server.trusted_proxies`, no breadth rule applies — a deny
//! list may block `0.0.0.0/0` on purpose. The config validator runs the same
//! parser over `cidr_policy`, so a policy that loads is a policy that matches.
//! IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`) are matched as IPv4.
//!
//! # Evaluation order
//!
//! Evaluation is deny first, then allow: a `deny` match refuses outright;
//! otherwise a non-empty `allow` list refuses every address it does not
//! contain. Both lists empty means no network restriction.
//!
//! 1. If the IP matches the **deny list** → [`CidrOutcome::Deny`], even when
//!    it is also inside the allow list (a deny exception in an allowed range).
//! 2. If the allow list is **non-empty** and the IP is **not** in it →
//!    [`CidrOutcome::Deny`] (strict allowlist mode).
//! 3. Otherwise → [`CidrOutcome::Allow`] (fail-open, §6.1).
//!
//! Deny-first loses no expressible policy — a non-empty allow list already
//! refuses everything outside it — and it is the only order in which a deny
//! entry inside an allowed range has any effect.
//!
//! # Failure mode: fail-open
//!
//! An empty filter (both lists empty) always returns [`CidrOutcome::Allow`].
//! This ensures that misconfiguration does not lock operators out of their
//! own realm.

use std::net::IpAddr;

use crate::core::{IpRange, IpRangeError};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// A list entry that is not a valid [`IpRange`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{entry}' {reason}")]
pub struct CidrEntryError {
    /// The entry as written.
    pub entry: String,
    /// Why it was refused.
    pub reason: IpRangeError,
}

/// Parses one allow/deny entry, keeping the entry text in the error.
///
/// # Errors
///
/// Returns [`CidrEntryError`] when `entry` is not a valid [`IpRange`].
pub fn parse_entry(entry: &str) -> Result<IpRange, CidrEntryError> {
    entry.parse().map_err(|reason| CidrEntryError {
        entry: entry.to_string(),
        reason,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a [`CidrFilter`] evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrOutcome {
    /// IP is permitted; request may proceed.
    Allow,
    /// IP is blocked by the deny list or falls outside the allow list.
    Deny,
}

// ─────────────────────────────────────────────────────────────────────────────
// CidrFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Per-realm CIDR allow/deny filter (A-9).
///
/// Build once from the stored configuration and share via `Arc`.  Replace the
/// entire filter on policy change (read-copy-update).  The `check` method is
/// lock-free and allocation-free.
#[derive(Debug, Clone)]
pub struct CidrFilter {
    allow: Vec<IpRange>,
    deny: Vec<IpRange>,
}

impl CidrFilter {
    /// Constructs a filter from pre-parsed allow and deny lists.
    #[must_use]
    pub fn new(allow: Vec<IpRange>, deny: Vec<IpRange>) -> Self {
        Self { allow, deny }
    }

    /// Returns a no-op filter — both lists empty, every IP allowed (fail-open).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Parses and constructs a filter from string slices.
    ///
    /// Refuses the whole filter at the first bad entry: dropping it would
    /// silently change who is allowed or denied.
    ///
    /// # Errors
    ///
    /// Returns [`CidrEntryError`] naming the first entry that is not a valid
    /// [`IpRange`].
    pub fn from_strs<A, D>(allow: A, deny: D) -> Result<Self, CidrEntryError>
    where
        A: IntoIterator,
        A::Item: AsRef<str>,
        D: IntoIterator,
        D::Item: AsRef<str>,
    {
        let allow = allow
            .into_iter()
            .map(|s| parse_entry(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        let deny = deny
            .into_iter()
            .map(|s| parse_entry(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { allow, deny })
    }

    /// Returns `true` if both the allow and deny lists are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Evaluates the filter for `ip`.
    ///
    /// See the [module-level documentation](self) for the evaluation order.
    /// This method is allocation-free and safe to call on the hot path.
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> CidrOutcome {
        // Step 1: a deny match refuses outright — even inside the allow list,
        // so an operator can carve an exception out of an allowed range.
        if self.deny.iter().any(|c| c.contains(ip)) {
            return CidrOutcome::Deny;
        }

        // Step 2: a non-empty allow list refuses every address it does not
        // contain.
        if !self.allow.is_empty() && !self.allow.iter().any(|c| c.contains(ip)) {
            return CidrOutcome::Deny;
        }

        // Step 3: allowed (both lists empty = no restriction, §6.1).
        CidrOutcome::Allow
    }
}

impl Default for CidrFilter {
    fn default() -> Self {
        Self::empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6_loopback() -> IpAddr {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }

    // ── parse_entry ──────────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_cidr() {
        let c = parse_entry("192.168.1.0/24").expect("valid test CIDR");
        assert_eq!(c.prefix_len(), 24);
        assert_eq!(c.network(), v4(192, 168, 1, 0));
    }

    #[test]
    fn parse_ipv4_host_bits_refused() {
        // "192.168.1.5/24" is either the host or the /24; refuse to guess.
        let err = parse_entry("192.168.1.5/24").expect_err("host bits");
        assert_eq!(err.entry, "192.168.1.5/24");
        assert_eq!(
            err.reason,
            IpRangeError::HostBitsSet {
                network: v4(192, 168, 1, 0),
                prefix: 24
            }
        );
    }

    #[test]
    fn parse_ipv4_slash32_is_host_route() {
        let c = parse_entry("10.0.0.1/32").expect("valid test CIDR");
        assert!(c.contains(v4(10, 0, 0, 1)));
        assert!(!c.contains(v4(10, 0, 0, 2)));
    }

    #[test]
    fn parse_ipv4_slash0_matches_all() {
        let c = parse_entry("0.0.0.0/0").expect("valid test CIDR");
        assert!(c.contains(v4(1, 2, 3, 4)));
        assert!(c.contains(v4(255, 255, 255, 255)));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let c = parse_entry("2001:db8::/32").expect("valid test CIDR");
        assert_eq!(c.prefix_len(), 32);
    }

    #[test]
    fn parse_bare_address_is_a_host_route() {
        let c = parse_entry("192.168.0.9").expect("bare address");
        assert_eq!(c.prefix_len(), 32);
        assert!(c.contains(v4(192, 168, 0, 9)));
        assert!(!c.contains(v4(192, 168, 0, 10)));
    }

    #[test]
    fn parse_error_bad_address() {
        let err = parse_entry("999.0.0.0/24").expect_err("bad address");
        assert_eq!(err.reason, IpRangeError::Malformed);
        assert!(err.to_string().starts_with("'999.0.0.0/24' "), "{err}");
    }

    #[test]
    fn parse_error_signed_or_padded_prefix() {
        for bad in ["10.0.0.0/+8", "10.0.0.0/08"] {
            assert_eq!(
                parse_entry(bad).expect_err(bad).reason,
                IpRangeError::Malformed
            );
        }
    }

    #[test]
    fn parse_error_prefix_too_long() {
        assert_eq!(
            parse_entry("192.168.0.0/33").expect_err("/33").reason,
            IpRangeError::PrefixOutOfRange { max: 32 }
        );
    }

    // ── CidrFilter::check — deny list only ───────────────────────────────────

    #[test]
    fn empty_filter_allows_all() {
        let f = CidrFilter::empty();
        assert_eq!(f.check(v4(1, 2, 3, 4)), CidrOutcome::Allow);
        assert_eq!(f.check(v6_loopback()), CidrOutcome::Allow);
    }

    #[test]
    fn deny_list_blocks_matching_ip() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["10.0.0.0/8"]).expect("valid test CIDR");
        assert_eq!(f.check(v4(10, 1, 2, 3)), CidrOutcome::Deny);
    }

    #[test]
    fn deny_list_allows_non_matching_ip() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["10.0.0.0/8"]).expect("valid test CIDR");
        assert_eq!(f.check(v4(192, 168, 0, 1)), CidrOutcome::Allow);
    }

    #[test]
    fn deny_list_matches_a_v4_mapped_client() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["10.0.0.0/8"]).expect("valid test CIDR");
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().expect("ip");
        assert_eq!(f.check(mapped), CidrOutcome::Deny);
    }

    // ── CidrFilter::check — allow list only ──────────────────────────────────

    #[test]
    fn allow_list_permits_matching_ip() {
        let f =
            CidrFilter::from_strs(["192.168.1.0/24"], [] as [&str; 0]).expect("valid test CIDR");
        assert_eq!(f.check(v4(192, 168, 1, 42)), CidrOutcome::Allow);
    }

    #[test]
    fn allow_list_blocks_non_matching_ip() {
        let f =
            CidrFilter::from_strs(["192.168.1.0/24"], [] as [&str; 0]).expect("valid test CIDR");
        assert_eq!(f.check(v4(10, 0, 0, 1)), CidrOutcome::Deny);
    }

    // ── CidrFilter::check — deny is evaluated before allow ───────────────────

    #[test]
    fn deny_list_wins_over_allow_list() {
        // IP is in both allow and deny — deny wins.
        let f = CidrFilter::from_strs(["10.0.0.0/8"], ["10.0.0.0/8"]).expect("valid test CIDR");
        assert_eq!(
            f.check(v4(10, 1, 2, 3)),
            CidrOutcome::Deny,
            "a deny match refuses outright, even inside the allow list"
        );
    }

    // ── Adversarial ──────────────────────────────────────────────────────────

    #[test]
    fn boundary_just_inside_network() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["172.16.0.0/12"]).expect("valid test CIDR");
        // 172.16.0.1 is inside 172.16.0.0/12
        assert_eq!(f.check(v4(172, 16, 0, 1)), CidrOutcome::Deny);
    }

    #[test]
    fn boundary_just_outside_network() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["172.16.0.0/12"]).expect("valid test CIDR");
        // 172.32.0.0 is outside 172.16.0.0/12
        assert_eq!(f.check(v4(172, 32, 0, 0)), CidrOutcome::Allow);
    }

    #[test]
    fn ipv4_address_does_not_match_ipv6_cidr() {
        let f = CidrFilter::from_strs([] as [&str; 0], ["::1/128"]).expect("valid test CIDR");
        // IPv4 loopback must not match IPv6 ::1/128
        assert_eq!(f.check(v4(127, 0, 0, 1)), CidrOutcome::Allow);
    }

    #[test]
    fn multiple_deny_cidrs_any_match_blocks() {
        let f = CidrFilter::from_strs(
            [] as [&str; 0],
            ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        )
        .expect("valid test CIDR");
        assert_eq!(f.check(v4(192, 168, 5, 5)), CidrOutcome::Deny);
        assert_eq!(f.check(v4(1, 2, 3, 4)), CidrOutcome::Allow);
    }
}
