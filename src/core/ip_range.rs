//! [`IpRange`]: the one strict parser for "an IP address or a CIDR range".
//!
//! Every operator-supplied network list in Hearth goes through
//! [`IpRange::from_str`]: `server.trusted_proxies` (via
//! [`crate::core::TrustedProxy`], which adds its own breadth policy on top),
//! the per-realm `security.cidr_policy` allow/deny lists and the Spamhaus DROP
//! feed (via `abuse::cidr::CidrFilter`), and the webhook SSRF blocklist. The
//! config validator uses the same function, so an entry validation accepts is
//! an entry the runtime matches — and an entry the runtime would refuse is
//! refused at load, naming the entry, instead of being dropped.
//!
//! # Grammar
//!
//! | Form | Example | Meaning |
//! |------|---------|---------|
//! | IPv4 address | `192.0.2.7` | exactly that address (`/32`) |
//! | IPv6 address | `2001:db8::7` | exactly that address (`/128`) |
//! | IPv4 CIDR | `10.42.0.0/16` | every address in the range |
//! | IPv6 CIDR | `2001:db8:42::/48` | every address in the range |
//!
//! Refused, because a lenient parse in an allow/deny/trust decision is a
//! bypass (HEA-2165):
//!
//! * anything that is not exactly an address or `address/prefix`: whitespace,
//!   a second `/`, a zone index (`fe80::1%eth0`), brackets, a port;
//! * a prefix that is signed (`/+8`), zero-padded (`/08`), non-decimal, or
//!   wider than the address family;
//! * a range with **host bits set** (`10.1.2.255/24`). The writer meant either
//!   the single address or the network, and those differ; refusing is safer
//!   than guessing. The error names the network form.
//!
//! This type has no opinion on breadth: `0.0.0.0/0` and `::/0` are valid
//! ranges (a deny list may legitimately block everything). Policies that must
//! refuse broad ranges — trusted proxies — add that check themselves.
//!
//! An IPv4-mapped IPv6 range (`::ffff:192.0.2.0/120`) is stored as its IPv4
//! form, and [`IpRange::contains`] canonicalizes the address it is asked
//! about, so a dual-stack listener's `::ffff:a.b.c.d` peers match IPv4 entries.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Why a string is not an [`IpRange`].
///
/// The `Display` text is written for an operator and reads after the quoted
/// entry: `'10.1.2.255/24' has host bits set …`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpRangeError {
    /// Not an IP address or `address/prefix`.
    Malformed,
    /// The prefix length exceeds the address family's width.
    PrefixOutOfRange {
        /// 32 for IPv4, 128 for IPv6.
        max: u8,
    },
    /// A CIDR whose address has bits set below the prefix.
    HostBitsSet {
        /// The network the writer probably meant.
        network: IpAddr,
        /// The entry's prefix length.
        prefix: u8,
    },
}

impl fmt::Display for IpRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str(
                "is not an IP address or CIDR range (expected e.g. 192.0.2.7, 10.42.0.0/16, \
                 2001:db8::7 or 2001:db8:42::/48; no spaces, zone ids, brackets, ports, or \
                 signed or zero-padded prefixes)",
            ),
            Self::PrefixOutOfRange { max } => write!(
                f,
                "has a prefix length above {max}, the width of its address family"
            ),
            Self::HostBitsSet { network, prefix } => write!(
                f,
                "has host bits set below its /{prefix} prefix. Write the network address \
                 {network}/{prefix} for the whole range, or drop the prefix for the single \
                 address"
            ),
        }
    }
}

impl std::error::Error for IpRangeError {}

/// A single IP address or a CIDR range, parsed strictly.
///
/// Construct with [`str::parse`]; see the [module docs](self) for the grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange(IpNet);

impl IpRange {
    /// `true` when `ip` — canonicalized, so `::ffff:a.b.c.d` is `a.b.c.d` —
    /// falls inside this range. Addresses of the other family never match.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip.to_canonical())
    }

    /// The network address (the range's first address).
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.0.network()
    }

    /// The prefix length: 32 or 128 for a single address.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.0.prefix_len()
    }
}

impl FromStr for IpRange {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `IpAddr::from_str` is itself strict: no whitespace, no zone index,
        // no brackets or port, no zero-padded IPv4 octets.
        let (addr, prefix) = match s.split_once('/') {
            None => {
                let addr = s.parse::<IpAddr>().map_err(|_| IpRangeError::Malformed)?;
                (addr, u16::from(max_prefix(addr)))
            }
            Some((addr, prefix)) => (
                addr.parse::<IpAddr>()
                    .map_err(|_| IpRangeError::Malformed)?,
                parse_prefix(prefix)?,
            ),
        };
        let max = max_prefix(addr);
        let prefix = u8::try_from(prefix)
            .ok()
            .filter(|p| *p <= max)
            .ok_or(IpRangeError::PrefixOutOfRange { max })?;
        let net = canonical_net(addr, prefix)?;
        let network = net.network();
        if net.addr() != network {
            return Err(IpRangeError::HostBitsSet {
                network,
                prefix: net.prefix_len(),
            });
        }
        Ok(Self(net))
    }
}

impl fmt::Display for IpRange {
    /// A single address prints bare (`192.0.2.7`), a range as `net/prefix`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.prefix_len() == self.0.max_prefix_len() {
            write!(f, "{}", self.0.addr())
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// The width of `addr`'s family: 32 or 128.
fn max_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Parses a prefix length: 1–3 ASCII digits, no sign, no zero padding.
///
/// `u8::from_str` alone would take `+8`; `08` is refused so that the only
/// spelling of a prefix is the one every other tool prints. The range check
/// against the address family is the caller's.
fn parse_prefix(prefix: &str) -> Result<u16, IpRangeError> {
    let digits_only = !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit());
    let padded = prefix.len() > 1 && prefix.starts_with('0');
    if !digits_only || padded || prefix.len() > 3 {
        return Err(IpRangeError::Malformed);
    }
    prefix.parse().map_err(|_| IpRangeError::Malformed)
}

/// Builds the network, folding an IPv4-mapped IPv6 range into IPv4 so it
/// matches canonicalized addresses.
///
/// A mapped address with a prefix below 96 cannot be a network address — bits
/// 80–95 of `::ffff:0:0` are ones — so it is left as IPv6 and refused by the
/// host-bits check.
fn canonical_net(addr: IpAddr, prefix: u8) -> Result<IpNet, IpRangeError> {
    let (addr, prefix) = match addr {
        IpAddr::V6(v6) if prefix >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), prefix - 96),
            None => (addr, prefix),
        },
        _ => (addr, prefix),
    };
    IpNet::new(addr, prefix).map_err(|_| IpRangeError::PrefixOutOfRange {
        max: max_prefix(addr),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP")
    }

    fn range(s: &str) -> IpRange {
        s.parse()
            .unwrap_or_else(|e| panic!("'{s}' must be accepted: {e}"))
    }

    fn refused(s: &str) -> IpRangeError {
        match s.parse::<IpRange>() {
            Ok(r) => panic!("'{s}' must be refused, parsed as {r}"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let r = range("192.0.2.7");
        assert!(r.contains(ip("192.0.2.7")));
        assert!(!r.contains(ip("192.0.2.8")));
        assert_eq!(r.prefix_len(), 32);
        assert_eq!(r.to_string(), "192.0.2.7");
        assert_eq!(range("2001:db8::7"), range("2001:db8::7/128"));
        assert_eq!(range("192.0.2.7"), range("192.0.2.7/32"));
    }

    #[test]
    fn a_cidr_matches_inside_and_not_outside() {
        let r = range("10.42.0.0/16");
        assert!(r.contains(ip("10.42.0.0")));
        assert!(r.contains(ip("10.42.255.255")));
        assert!(!r.contains(ip("10.43.0.0")));
        assert!(!r.contains(ip("10.41.255.255")));
        assert!(!r.contains(ip("2001:db8::1")), "other family");
        assert_eq!(r.network(), ip("10.42.0.0"));
        assert_eq!(r.to_string(), "10.42.0.0/16");

        let v6 = range("2001:db8:42::/48");
        assert!(v6.contains(ip("2001:db8:42:ffff::1")));
        assert!(!v6.contains(ip("2001:db8:43::1")));
        assert!(!v6.contains(ip("10.0.0.1")), "other family");
    }

    /// No breadth policy here — that belongs to the caller.
    #[test]
    fn whole_family_ranges_are_valid() {
        assert!(range("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(range("::/0").contains(ip("2001:db8::1")));
        assert!(range("0.0.0.0").contains(ip("0.0.0.0")));
        assert!(range("::/128").contains(ip("::")));
    }

    #[test]
    fn v4_mapped_addresses_and_ranges_are_canonicalized() {
        assert!(range("192.0.2.0/24").contains(ip("::ffff:192.0.2.9")));
        assert!(!range("192.0.2.0/24").contains(ip("::ffff:192.0.3.9")));
        assert_eq!(range("::ffff:192.0.2.7"), range("192.0.2.7"));
        assert_eq!(range("::ffff:192.0.2.0/120"), range("192.0.2.0/24"));
    }

    #[test]
    fn malformed_entries_are_refused() {
        for bad in [
            "",
            " ",
            "10.0.0.7 ",
            " 10.0.0.7",
            "10.0.0",
            "10.0.0.256",
            "010.0.0.7",
            "999.0.0.0/24",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/8/8",
            "10.0.0.0/+8",
            "10.0.0.0/-8",
            "10.0.0.0/08",
            "10.0.0.0/ 8",
            "10.0.0.0 /8",
            "10.0.0.0/8 ",
            "10.0.0.0/x",
            "10.0.0.0/0x8",
            "10.0.0.0/1000",
            "localhost",
            "fe80::1%eth0",
            "fe80::%eth0/64",
            "[2001:db8::1]",
            "[2001:db8::]/32",
            "10.0.0.7:443",
            "10.0.0.0:443/8",
            "*",
        ] {
            assert_eq!(refused(bad), IpRangeError::Malformed, "'{bad}'");
        }
    }

    #[test]
    fn a_prefix_wider_than_the_family_is_refused() {
        assert_eq!(
            refused("10.0.0.0/33"),
            IpRangeError::PrefixOutOfRange { max: 32 }
        );
        assert_eq!(
            refused("2001:db8::/129"),
            IpRangeError::PrefixOutOfRange { max: 128 }
        );
    }

    #[test]
    fn host_bits_are_refused_and_the_error_names_the_network() {
        let err = refused("10.1.2.255/24");
        assert_eq!(
            err,
            IpRangeError::HostBitsSet {
                network: ip("10.1.2.0"),
                prefix: 24
            }
        );
        assert!(err.to_string().contains("10.1.2.0/24"), "got: {err}");
        assert_eq!(
            refused("2001:db8:42::1/48"),
            IpRangeError::HostBitsSet {
                network: ip("2001:db8:42::"),
                prefix: 48
            }
        );
        // A mapped address below /96 is never a network address.
        assert!(matches!(
            refused("::ffff:192.0.2.0/95"),
            IpRangeError::HostBitsSet { .. }
        ));
    }
}
