//! `server.trusted_proxies` entries: single addresses and CIDR ranges.
//!
//! One type, one parser, one matcher. Every consumer of the operator's
//! trusted-proxy list — the `X-Forwarded-For` trust walk, the
//! `X-Forwarded-Proto` peer check, the per-address connection-cap exemption —
//! and the config validator all go through [`TrustedProxy::from_str`] and
//! [`TrustedProxies::contains`]. Validation and runtime used to parse the
//! list differently (the validator accepted a CIDR the runtime then threw
//! away, task 26.24); sharing the parser makes that disagreement impossible.
//!
//! The grammar — address or `address/prefix`, strict, host bits refused,
//! IPv4-mapped forms folded to IPv4 — is [`IpRange`]'s, shared with every
//! other network list in Hearth. On top of it, a trusted proxy must not be a
//! catch-all:
//!
//! * the unspecified address or any range starting at it (`0.0.0.0`,
//!   `0.0.0.0/0`, `::/0`, `::/16`) is refused — it trusts every peer;
//! * a range broader than `/8` (IPv4) or `/16` (IPv6)
//!   ([`MIN_IPV4_PREFIX`], [`MIN_IPV6_PREFIX`]) is refused. The largest private
//!   IPv4 block is `10.0.0.0/8`, and real proxy fleets — Kubernetes pod
//!   networks, a CDN's published ranges — are far narrower than either floor.
//!
//! These breadth rules are specific to trusted proxies: a deny list may block
//! `0.0.0.0/0` on purpose, so [`IpRange`] itself does not apply them.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::ip_range::{IpRange, IpRangeError};

/// The broadest IPv4 range accepted as a trusted proxy (`/8`).
pub const MIN_IPV4_PREFIX: u8 = 8;

/// The broadest IPv6 range accepted as a trusted proxy (`/16`).
pub const MIN_IPV6_PREFIX: u8 = 16;

/// Why a `server.trusted_proxies` entry was refused.
///
/// The `Display` text is written for an operator: it is the reason shown by
/// `hearth config validate` after the offending entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustedProxyError {
    /// Not a valid address or CIDR range (see [`IpRange`]).
    Invalid(IpRangeError),
    /// The unspecified address, or a range starting at it.
    Unspecified,
    /// A range broader than the family's floor.
    TooBroad {
        /// The entry's prefix length.
        prefix: u8,
        /// The broadest prefix accepted for this family.
        min: u8,
    },
}

impl From<IpRangeError> for TrustedProxyError {
    fn from(e: IpRangeError) -> Self {
        Self::Invalid(e)
    }
}

impl fmt::Display for TrustedProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => e.fmt(f),
            Self::Unspecified => f.write_str(
                "is the unspecified address or a range starting at it — a catch-all that \
                 trusts every peer as a proxy and bypasses every IP-based protection. List \
                 only your reverse proxies' addresses or ranges",
            ),
            Self::TooBroad { prefix, min } => write!(
                f,
                "is a /{prefix} range, broader than /{min}, the widest accepted: it would \
                 trust a large share of the internet as proxies. List only your reverse \
                 proxies' addresses or ranges"
            ),
        }
    }
}

impl std::error::Error for TrustedProxyError {}

/// One `server.trusted_proxies` entry: a single address or a CIDR range.
///
/// Construct with [`str::parse`]; see the [module docs](self) for exactly
/// what is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustedProxy(IpRange);

impl TrustedProxy {
    /// `true` when `ip` (canonicalized, so `::ffff:a.b.c.d` is `a.b.c.d`)
    /// falls inside this entry.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(ip)
    }

    /// `true` when the entry lies in the loopback range.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.0.network().is_loopback()
    }
}

impl FromStr for TrustedProxy {
    type Err = TrustedProxyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let range: IpRange = s.parse()?;
        let network = range.network();
        if network.is_unspecified() {
            return Err(TrustedProxyError::Unspecified);
        }
        let min = match network {
            IpAddr::V4(_) => MIN_IPV4_PREFIX,
            IpAddr::V6(_) => MIN_IPV6_PREFIX,
        };
        if range.prefix_len() < min {
            return Err(TrustedProxyError::TooBroad {
                prefix: range.prefix_len(),
                min,
            });
        }
        Ok(Self(range))
    }
}

impl fmt::Display for TrustedProxy {
    /// A single address prints bare (`10.0.0.7`), a range as `net/prefix`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The parsed `server.trusted_proxies` list.
///
/// Empty (the default) trusts no peer: `X-Forwarded-For` and
/// `X-Forwarded-Proto` are ignored from everyone, and no peer is exempt from
/// the per-address connection cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<TrustedProxy>);

/// A `server.trusted_proxies` entry that failed to parse, with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxyListError {
    /// Zero-based position of the entry in the list.
    pub index: usize,
    /// The entry as written.
    pub entry: String,
    /// Why it was refused.
    pub reason: TrustedProxyError,
}

impl fmt::Display for TrustedProxyListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "server.trusted_proxies[{}]: '{}' {}",
            self.index, self.entry, self.reason
        )
    }
}

impl std::error::Error for TrustedProxyListError {}

impl TrustedProxies {
    /// Parses every entry, refusing the whole list at the first bad one.
    ///
    /// There is no "skip the bad entry" mode: a dropped entry silently
    /// changes whose headers are trusted (task 26.24).
    ///
    /// # Errors
    ///
    /// Returns the first entry [`TrustedProxy::from_str`] refuses.
    pub fn parse<I, S>(entries: I) -> Result<Self, TrustedProxyListError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                let entry = entry.as_ref();
                entry
                    .parse::<TrustedProxy>()
                    .map_err(|reason| TrustedProxyListError {
                        index,
                        entry: entry.to_string(),
                        reason,
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// `true` when `ip` falls inside any entry.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|entry| entry.contains(ip))
    }

    /// `true` when the list trusts no peer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The entries, in configured order.
    pub fn iter(&self) -> impl Iterator<Item = &TrustedProxy> {
        self.0.iter()
    }
}

impl FromIterator<TrustedProxy> for TrustedProxies {
    fn from_iter<T: IntoIterator<Item = TrustedProxy>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP")
    }

    fn entry(s: &str) -> TrustedProxy {
        s.parse()
            .unwrap_or_else(|e| panic!("'{s}' must be accepted: {e}"))
    }

    fn refused(s: &str) -> TrustedProxyError {
        match s.parse::<TrustedProxy>() {
            Ok(p) => panic!("'{s}' must be refused, parsed as {p}"),
            Err(e) => e,
        }
    }

    // ── single addresses ──────────────────────────────────────────────────

    #[test]
    fn a_bare_ipv4_address_matches_only_itself() {
        let p = entry("10.0.0.7");
        assert!(p.contains(ip("10.0.0.7")));
        assert!(!p.contains(ip("10.0.0.8")));
        assert!(!p.contains(ip("10.0.0.6")));
        assert_eq!(p.to_string(), "10.0.0.7");
    }

    #[test]
    fn a_bare_ipv6_address_matches_only_itself() {
        let p = entry("2001:db8::7");
        assert!(p.contains(ip("2001:db8::7")));
        assert!(!p.contains(ip("2001:db8::8")));
        assert_eq!(p.to_string(), "2001:db8::7");
    }

    // ── CIDR ranges ───────────────────────────────────────────────────────

    #[test]
    fn an_ipv4_cidr_matches_inside_and_not_outside() {
        let p = entry("10.42.0.0/16");
        assert!(p.contains(ip("10.42.0.0")), "network address");
        assert!(p.contains(ip("10.42.7.19")), "interior");
        assert!(p.contains(ip("10.42.255.255")), "last address");
        assert!(!p.contains(ip("10.43.0.0")), "one past the range");
        assert!(!p.contains(ip("10.41.255.255")), "one before the range");
        assert!(!p.contains(ip("2001:db8::1")), "other family");
        assert_eq!(p.to_string(), "10.42.0.0/16");
    }

    #[test]
    fn an_ipv6_cidr_matches_inside_and_not_outside() {
        let p = entry("2001:db8:42::/48");
        assert!(p.contains(ip("2001:db8:42::1")));
        assert!(p.contains(ip("2001:db8:42:ffff:ffff:ffff:ffff:ffff")));
        assert!(!p.contains(ip("2001:db8:43::1")));
        assert!(!p.contains(ip("10.0.0.1")), "other family");
    }

    #[test]
    fn a_full_length_prefix_is_a_single_address() {
        assert_eq!(entry("10.0.0.7/32"), entry("10.0.0.7"));
        assert_eq!(entry("2001:db8::7/128"), entry("2001:db8::7"));
    }

    #[test]
    fn the_prefix_floors_are_accepted() {
        assert!(entry("10.0.0.0/8").contains(ip("10.255.0.1")));
        assert!(entry("fd00::/16").contains(ip("fd00:1::1")));
    }

    // ── v4-mapped peers and entries ───────────────────────────────────────

    #[test]
    fn a_v4_mapped_peer_matches_an_ipv4_entry() {
        assert!(entry("10.0.0.0/24").contains(ip("::ffff:10.0.0.9")));
        assert!(entry("10.0.0.7").contains(ip("::ffff:10.0.0.7")));
        assert!(!entry("10.0.0.0/24").contains(ip("::ffff:10.0.1.9")));
    }

    #[test]
    fn a_v4_mapped_entry_is_stored_as_ipv4() {
        assert_eq!(entry("::ffff:10.0.0.7"), entry("10.0.0.7"));
        assert_eq!(entry("::ffff:10.0.0.0/120"), entry("10.0.0.0/24"));
        assert!(entry("::ffff:10.0.0.0/120").contains(ip("10.0.0.200")));
    }

    // ── refusals ──────────────────────────────────────────────────────────

    /// The grammar is `IpRange`'s (tested in `core::ip_range`); its refusals
    /// surface as `Invalid`.
    #[test]
    fn grammar_refusals_are_ip_range_errors() {
        assert_eq!(
            refused("10.0.0.0/+8"),
            TrustedProxyError::Invalid(IpRangeError::Malformed)
        );
        assert_eq!(
            refused("10.0.0.0/33"),
            TrustedProxyError::Invalid(IpRangeError::PrefixOutOfRange { max: 32 })
        );
        let err = refused("10.0.0.7/8");
        assert_eq!(
            err,
            TrustedProxyError::Invalid(IpRangeError::HostBitsSet {
                network: ip("10.0.0.0"),
                prefix: 8
            })
        );
        assert!(err.to_string().contains("10.0.0.0/8"), "got: {err}");
    }

    #[test]
    fn catch_alls_are_refused() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0",
            "::",
            "0.0.0.0/8",
            "::/16",
            "::/64",
        ] {
            assert_eq!(refused(bad), TrustedProxyError::Unspecified, "'{bad}'");
        }
        // `::ffff:0:0/96` is every IPv4 address, spelled as IPv6.
        assert!(
            "::ffff:0.0.0.0/96".parse::<TrustedProxy>().is_err(),
            "the whole v4-mapped block is 0.0.0.0/0"
        );
    }

    #[test]
    fn ranges_broader_than_the_floor_are_refused() {
        assert_eq!(
            refused("8.0.0.0/7"),
            TrustedProxyError::TooBroad { prefix: 7, min: 8 }
        );
        assert_eq!(
            refused("128.0.0.0/1"),
            TrustedProxyError::TooBroad { prefix: 1, min: 8 }
        );
        assert_eq!(
            refused("2000::/3"),
            TrustedProxyError::TooBroad { prefix: 3, min: 16 }
        );
        assert_eq!(
            refused("fd00::/15"),
            TrustedProxyError::TooBroad {
                prefix: 15,
                min: 16
            }
        );
    }

    #[test]
    fn loopback_entries_report_it() {
        assert!(entry("127.0.0.1").is_loopback());
        assert!(entry("127.0.0.0/8").is_loopback());
        assert!(entry("::1").is_loopback());
        assert!(!entry("10.0.0.1").is_loopback());
    }

    // ── the list ──────────────────────────────────────────────────────────

    #[test]
    fn a_list_matches_any_entry() {
        let list = TrustedProxies::parse(["10.0.0.7", "10.42.0.0/16", "2001:db8::/32"])
            .expect("valid list");
        assert_eq!(list.len(), 3);
        assert!(list.contains(ip("10.0.0.7")));
        assert!(list.contains(ip("10.42.9.9")));
        assert!(list.contains(ip("2001:db8:1::1")));
        assert!(!list.contains(ip("10.0.0.8")));
        assert!(!list.contains(ip("203.0.113.9")));
    }

    #[test]
    fn an_empty_list_trusts_nobody() {
        let list = TrustedProxies::default();
        assert!(list.is_empty());
        assert!(!list.contains(ip("127.0.0.1")));
        assert!(!list.contains(ip("10.0.0.1")));
    }

    #[test]
    fn one_bad_entry_refuses_the_whole_list_and_names_it() {
        let err = TrustedProxies::parse(["10.0.0.7", "10.0.0.7/8"]).expect_err("host bits");
        assert_eq!(err.index, 1);
        assert_eq!(err.entry, "10.0.0.7/8");
        let text = err.to_string();
        assert!(
            text.contains("server.trusted_proxies[1]") && text.contains("10.0.0.7/8"),
            "got: {text}"
        );
    }
}
