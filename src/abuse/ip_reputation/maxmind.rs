//! MaxMind GeoIP2 / GeoLite2-ASN reference adapter for [`IpReputationProvider`].
//!
//! # What it provides
//!
//! Looks up the Autonomous System Number (ASN) and organization name for a
//! source IP from a local MaxMind MMDB database file.  The verdict's
//! [`IpReputationVerdict::asn`] and [`IpReputationVerdict::asn_org`] fields
//! are populated; [`IpReputationVerdict::is_blocklisted`] is always `false`
//! (ASN information is a signal, not a block decision — callers use it for
//! risk scoring or for combining with operator-managed ASN denylist rules).
//!
//! # Database setup
//!
//! The operator downloads the GeoLite2-ASN or GeoIP2-ASN database from
//! MaxMind (free registration required for GeoLite2) and configures the path:
//!
//! ```yaml
//! security:
//!   ip_reputation:
//!     maxmind_db_path: /etc/hearth/GeoLite2-ASN.mmdb
//! ```
//!
//! # Failure mode: fail-open
//!
//! If the database file is missing, unreadable, or corrupt, the provider
//! operates in a no-op mode and returns a clean verdict for every IP.  A
//! `tracing::warn` is emitted at startup if the file cannot be opened.
//!
//! # Database format
//!
//! The `maxminddb` crate reads any MMDB v2 file.  Both GeoLite2-ASN
//! (`autonomous_system_number` + `autonomous_system_organization` fields) and
//! GeoIP2-ASN are supported; the record fields used are a subset present in
//! both editions.

use std::net::IpAddr;
use std::path::PathBuf;

use maxminddb::geoip2::Asn;
use tracing::warn;

use crate::abuse::ip_reputation::{IpReputationProvider, IpReputationVerdict};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`MaxMindAsnProvider`].
///
/// Serialised under `security.ip_reputation` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct MaxMindAsnConfig {
    /// Filesystem path to the MaxMind GeoLite2-ASN or GeoIP2-ASN `.mmdb` file.
    ///
    /// If the file does not exist or cannot be opened at startup, the provider
    /// falls back to fail-open mode.
    pub db_path: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────────────────

/// Internal state: either a live MMDB reader or absent (fail-open noop).
enum Inner {
    Live(maxminddb::Reader<Vec<u8>>),
    Absent,
}

/// MaxMind GeoLite2-ASN / GeoIP2-ASN reference adapter.
///
/// Implements [`IpReputationProvider`] by reading the MMDB database file
/// on disk.  The file is loaded into memory at construction time.
///
/// # Construction
///
/// Use [`MaxMindAsnProvider::open`] to create the provider.  Construction
/// never fails — if the file cannot be opened the provider enters fail-open
/// mode and returns clean verdicts for all IPs.
pub struct MaxMindAsnProvider {
    inner: Inner,
}

impl MaxMindAsnProvider {
    /// Opens the MMDB file at `config.db_path` and creates the provider.
    ///
    /// If the file is missing, unreadable, or not a valid MMDB file, the
    /// provider is created in fail-open mode (returns clean verdicts for all
    /// IPs).  A warning is logged in that case.
    #[must_use]
    pub fn open(config: MaxMindAsnConfig) -> Self {
        match maxminddb::Reader::open_readfile(&config.db_path) {
            Ok(reader) => Self {
                inner: Inner::Live(reader),
            },
            Err(e) => {
                warn!(
                    path = %config.db_path.display(),
                    error = %e,
                    "MaxMind ASN database could not be opened; \
                     IP reputation ASN lookups will be skipped (fail-open)"
                );
                Self {
                    inner: Inner::Absent,
                }
            }
        }
    }

    /// Creates a no-op (fail-open) provider without loading any database.
    ///
    /// Useful in tests when no MMDB file is available.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            inner: Inner::Absent,
        }
    }
}

impl IpReputationProvider for MaxMindAsnProvider {
    /// Looks up the ASN for `ip` in the MMDB database.
    ///
    /// Returns a clean verdict with `asn` and `asn_org` populated if the
    /// database is available and the IP has an ASN record.  Returns the
    /// default clean verdict (all `None`) if:
    ///
    /// - The provider is in fail-open mode (no database loaded).
    /// - The IP is not found in the database (e.g. private addresses, reserved
    ///   ranges).
    /// - Any lookup error occurs.
    fn check(&self, ip: IpAddr) -> IpReputationVerdict {
        let reader = match &self.inner {
            Inner::Absent => return IpReputationVerdict::default(),
            Inner::Live(r) => r,
        };

        match reader.lookup::<Asn>(ip) {
            Ok(record) => IpReputationVerdict {
                is_blocklisted: false,
                asn: record.autonomous_system_number,
                asn_org: record.autonomous_system_organization.map(str::to_owned),
            },
            Err(_) => {
                // Lookup failed (IP not in database, or read error) — fail-open.
                IpReputationVerdict::default()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (inline)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn noop_provider_returns_clean() {
        let p = MaxMindAsnProvider::noop();
        let v = p.check(v4(8, 8, 8, 8));
        assert!(v.is_clean());
        assert!(v.asn.is_none());
        assert!(v.asn_org.is_none());
    }

    #[test]
    fn missing_db_opens_as_fail_open() {
        let config = MaxMindAsnConfig {
            db_path: "/does/not/exist/GeoLite2-ASN.mmdb".into(),
        };
        let p = MaxMindAsnProvider::open(config);
        let v = p.check(v4(8, 8, 8, 8));
        assert!(v.is_clean());
    }
}
