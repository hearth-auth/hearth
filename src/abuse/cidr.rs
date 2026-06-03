//! Tenant-managed IPv4/IPv6 CIDR allow/deny lists (A-9).
//!
//! Operators load per-realm allow/deny CIDR lists from storage (key prefix
//! `abuse:{realm}:cidr:*`) and build a [`CidrFilter`] for fast in-memory
//! lookup.  The filter is replaced atomically on reload — store it behind an
//! `Arc<ArcSwap<CidrFilter>>` at the call site.
//!
//! # Evaluation order
//!
//! 1. If the IP matches the **allow list** → [`CidrOutcome::Allow`].
//!    (Explicit trust cannot be overridden by the deny list.)
//! 2. If the IP matches the **deny list** → [`CidrOutcome::Deny`].
//! 3. If the allow list is **non-empty** and the IP is **not** in it →
//!    [`CidrOutcome::Deny`] (strict allowlist mode).
//! 4. Otherwise → [`CidrOutcome::Allow`] (fail-open, §6.1).
//!
//! # Failure mode: fail-open
//!
//! An empty filter (both lists empty) always returns [`CidrOutcome::Allow`].
//! This ensures that misconfiguration does not lock operators out of their
//! own realm.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when a CIDR string cannot be parsed.
#[derive(Debug, thiserror::Error)]
pub enum CidrParseError {
    /// The string is not in `address/prefix` format.
    #[error("missing '/' separator in CIDR '{0}'")]
    MissingSeparator(String),
    /// The host address portion is not a valid IP address.
    #[error("invalid IP address in CIDR '{0}': {1}")]
    InvalidAddress(String, std::net::AddrParseError),
    /// The prefix length is not a valid decimal integer.
    #[error("invalid prefix length in CIDR '{0}': {1}")]
    InvalidPrefixLen(String, std::num::ParseIntError),
    /// The prefix length exceeds the maximum for the address family.
    #[error("prefix length {1} exceeds maximum for address family in CIDR '{0}'")]
    PrefixLenTooLong(String, u8),
}

// ─────────────────────────────────────────────────────────────────────────────
// Cidr
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed IPv4 or IPv6 CIDR network.
///
/// Constructed via [`Cidr::parse`] or the [`FromStr`] implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    /// The masked network address (host bits zeroed).
    network: IpAddr,
    /// Prefix length (0–32 for IPv4, 0–128 for IPv6).
    prefix_len: u8,
}

impl Cidr {
    /// Parses a CIDR string such as `"192.168.0.0/16"` or `"::1/128"`.
    ///
    /// Host bits beyond the prefix length are silently masked to zero so
    /// `"192.168.1.1/24"` is treated the same as `"192.168.1.0/24"`.
    ///
    /// # Errors
    ///
    /// Returns [`CidrParseError`] when the string is malformed.
    pub fn parse(s: &str) -> Result<Self, CidrParseError> {
        let (addr_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| CidrParseError::MissingSeparator(s.to_owned()))?;

        let addr = IpAddr::from_str(addr_part)
            .map_err(|e| CidrParseError::InvalidAddress(s.to_owned(), e))?;

        let prefix_len: u8 = prefix_part
            .parse()
            .map_err(|e| CidrParseError::InvalidPrefixLen(s.to_owned(), e))?;

        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CidrParseError::PrefixLenTooLong(s.to_owned(), prefix_len));
        }

        // Mask host bits in the network address.
        let network = mask_addr(addr, prefix_len);
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Returns `true` if `ip` falls within this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        contains_inner(self.network, self.prefix_len, ip)
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cidr::parse(s)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
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
/// entire filter on policy change (arc-swap pattern).  The `check` method is
/// lock-free and allocation-free.
#[derive(Debug, Clone)]
pub struct CidrFilter {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl CidrFilter {
    /// Constructs a filter from pre-parsed allow and deny lists.
    #[must_use]
    pub fn new(allow: Vec<Cidr>, deny: Vec<Cidr>) -> Self {
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
    /// Returns the first parse error encountered. Use this for loading from
    /// YAML configuration or API input.
    ///
    /// # Errors
    ///
    /// Returns [`CidrParseError`] when any entry is malformed.
    pub fn from_strs<A, D>(allow: A, deny: D) -> Result<Self, CidrParseError>
    where
        A: IntoIterator,
        A::Item: AsRef<str>,
        D: IntoIterator,
        D::Item: AsRef<str>,
    {
        let allow = allow
            .into_iter()
            .map(|s| Cidr::parse(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        let deny = deny
            .into_iter()
            .map(|s| Cidr::parse(s.as_ref()))
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
        // Step 1: explicit trust — allow list match bypasses the deny list.
        if !self.allow.is_empty() {
            if self.allow.iter().any(|c| c.contains(ip)) {
                return CidrOutcome::Allow;
            }
            // Step 3: strict allowlist mode — IP not in the allow list.
            // We defer until after the deny check only for clarity; the
            // deny list is irrelevant here because we already know the IP
            // is not explicitly trusted.
            return CidrOutcome::Deny;
        }

        // Step 2: deny list.
        if self.deny.iter().any(|c| c.contains(ip)) {
            return CidrOutcome::Deny;
        }

        // Step 4: fail-open default.
        CidrOutcome::Allow
    }
}

impl Default for CidrFilter {
    fn default() -> Self {
        Self::empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Masks host bits in `addr` beyond `prefix_len`.
fn mask_addr(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let n = u32::from(v4);
            let masked = if prefix_len == 0 {
                0
            } else {
                n & (!0u32 << (32 - prefix_len))
            };
            IpAddr::V4(masked.into())
        }
        IpAddr::V6(v6) => {
            let n = u128::from(v6);
            let masked = if prefix_len == 0 {
                0
            } else {
                n & (!0u128 << (128 - prefix_len))
            };
            IpAddr::V6(masked.into())
        }
    }
}

/// Returns `true` if `addr` falls within `network/prefix_len`.
///
/// Mismatched address families (e.g. IPv4 network vs IPv6 address) always
/// return `false`.  IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are NOT
/// transparently unwrapped — the caller is responsible for normalisation.
fn contains_inner(network: IpAddr, prefix_len: u8, addr: IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if prefix_len == 0 {
                return true;
            }
            let shift = 32 - u32::from(prefix_len);
            (u32::from(net) >> shift) == (u32::from(ip) >> shift)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if prefix_len == 0 {
                return true;
            }
            let shift = 128 - u32::from(prefix_len);
            (u128::from(net) >> shift) == (u128::from(ip) >> shift)
        }
        // Mixed address families never match.
        _ => false,
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

    // ── Cidr::parse ──────────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_cidr() {
        let c = Cidr::parse("192.168.1.0/24").expect("valid test CIDR");
        assert_eq!(c.prefix_len, 24);
        assert_eq!(c.network, v4(192, 168, 1, 0));
    }

    #[test]
    fn parse_ipv4_host_bits_masked() {
        // "192.168.1.5/24" → network should be 192.168.1.0
        let c = Cidr::parse("192.168.1.5/24").expect("valid test CIDR");
        assert_eq!(c.network, v4(192, 168, 1, 0));
    }

    #[test]
    fn parse_ipv4_slash32_is_host_route() {
        let c = Cidr::parse("10.0.0.1/32").expect("valid test CIDR");
        assert!(c.contains(v4(10, 0, 0, 1)));
        assert!(!c.contains(v4(10, 0, 0, 2)));
    }

    #[test]
    fn parse_ipv4_slash0_matches_all() {
        let c = Cidr::parse("0.0.0.0/0").expect("valid test CIDR");
        assert!(c.contains(v4(1, 2, 3, 4)));
        assert!(c.contains(v4(255, 255, 255, 255)));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let c = Cidr::parse("2001:db8::/32").expect("valid test CIDR");
        assert_eq!(c.prefix_len, 32);
    }

    #[test]
    fn parse_error_missing_slash() {
        assert!(matches!(
            Cidr::parse("192.168.0.0"),
            Err(CidrParseError::MissingSeparator(_))
        ));
    }

    #[test]
    fn parse_error_bad_address() {
        assert!(matches!(
            Cidr::parse("999.0.0.0/24"),
            Err(CidrParseError::InvalidAddress(_, _))
        ));
    }

    #[test]
    fn parse_error_prefix_too_long() {
        assert!(matches!(
            Cidr::parse("192.168.0.0/33"),
            Err(CidrParseError::PrefixLenTooLong(_, 33))
        ));
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

    // ── CidrFilter::check — allow overrides deny ─────────────────────────────

    #[test]
    fn allow_list_overrides_deny_list() {
        // IP is in both allow and deny — allow wins.
        let f = CidrFilter::from_strs(["10.0.0.0/8"], ["10.0.0.0/8"]).expect("valid test CIDR");
        assert_eq!(
            f.check(v4(10, 1, 2, 3)),
            CidrOutcome::Allow,
            "allow list must take precedence over deny list"
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
