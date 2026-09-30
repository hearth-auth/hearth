//! Global request shaper (A-2) and gRPC rate-limit interceptor (A-15).
//!
//! Implements a per-IP + per-realm sliding-window rate limiter that applies to
//! all public routes.  The gRPC surface is covered by a `tonic` interceptor
//! that shares the same state.
//!
//! # Defaults (configurable via `security.request_shaper` in `hearth.yaml`)
//!
//! | Dimension | Default  | Description                     |
//! |-----------|----------|---------------------------------|
//! | IP RPS    | 100      | Requests per second per client  |
//! | Realm RPS | 1 000    | Requests per second per realm   |
//! | Window    | 1 second | Sliding window length           |
//!
//! The shaper is **on by default**: when `security.request_shaper` is absent
//! the defaults above apply. `0` in either field disables that dimension, the
//! same sentinel every other limiter uses.
//!
//! # Keys (GA sweep 3, E-1 / E-2 / E-3)
//!
//! * The per-IP dimension counts a client under
//!   [`rate_limit_key`](crate::core::rate_limit_key): IPv4 per address, IPv6 per
//!   `/64`.
//! * The per-realm dimension counts a request only when it names a realm — a
//!   [`RealmKey`]. A request that names none is counted per IP alone. The
//!   HTTP surface used to count *every* request in one `""` bucket, so ten
//!   addresses at the per-IP cap spent the whole server's realm budget and
//!   every other caller answered 429.
//! * Both maps are [`ExpiringMap`]s: idle windows are swept and the entry
//!   count is hard-capped, so a caller inventing keys (rotating IPv6 sources,
//!   random realm names) cannot grow them without bound.

use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::core::{rate_limit_key, ExpiringMap, LimiterClock, RealmId};

/// Most per-IP windows held at once.
///
/// A window lives one second, so this is the number of distinct clients the
/// shaper can track per second before it starts evicting the soonest-expiring
/// windows — far above what one node serves.
pub const SHAPER_IP_CAPACITY: usize = 100_000;

/// Most per-realm windows held at once.
pub const SHAPER_REALM_CAPACITY: usize = 16_384;

/// Longest realm name the shaper will open a bucket for; matches the realm
/// name rules in `identity::validation::validate_realm_name`.
const MAX_REALM_NAME_LEN: usize = 63;

/// Window length.
const WINDOW: Duration = Duration::from_secs(1);

/// Per-IP and per-realm sliding-window rate limiter.
///
/// Shared across HTTP and gRPC surfaces (via `Arc`) so a caller cannot evade
/// the limit by switching protocols.
#[derive(Debug)]
pub struct RequestShaper {
    config: ShaperConfig,
    ip_windows: Mutex<ExpiringMap<IpAddr, SlidingWindow>>,
    realm_windows: Mutex<ExpiringMap<RealmKey, SlidingWindow>>,
}

/// Configuration for the request shaper.
#[derive(Debug, Clone)]
pub struct ShaperConfig {
    /// Maximum requests per second per client (IPv4 address, IPv6 `/64`).
    /// `None` = disabled.
    pub ip_rps: Option<u32>,
    /// Maximum requests per second per realm. Requests that name no realm are
    /// not counted in this dimension. `None` = disabled.
    pub realm_rps: Option<u32>,
}

impl ShaperConfig {
    /// Builds a config from the operator's `security.request_shaper` values,
    /// where `0` disables a dimension (the sentinel every limiter shares). A
    /// literal `Some(0)` would shed every request.
    #[must_use]
    pub fn from_operator(ip_rps: u32, realm_rps: u32) -> Self {
        Self {
            ip_rps: (ip_rps > 0).then_some(ip_rps),
            realm_rps: (realm_rps > 0).then_some(realm_rps),
        }
    }
}

impl Default for ShaperConfig {
    fn default() -> Self {
        Self {
            ip_rps: Some(100),
            realm_rps: Some(1_000),
        }
    }
}

/// The realm a request is counted against in the per-realm dimension.
///
/// Built only from a value that *can* name a realm: a UUID (an `X-Realm-ID`
/// header or gRPC `x-realm-id` metadata) or a string that is a well-formed
/// realm name (a `/realms/{name}` path segment). Anything else names no realm
/// and opens no bucket, so an attacker-chosen header of arbitrary length can
/// no longer become a map key.
///
/// A realm addressed by name and by id is counted in two buckets: the shaper
/// does not resolve names, because doing so would put a storage read in front
/// of the limiter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RealmKey {
    /// A realm named by id.
    Id(RealmId),
    /// A realm named by its URL name.
    Name(String),
}

impl RealmKey {
    /// A realm id header value, or `None` when it is not a UUID.
    #[must_use]
    pub fn from_id_header(value: &str) -> Option<Self> {
        value
            .trim()
            .parse::<uuid::Uuid>()
            .ok()
            .map(|id| Self::Id(RealmId::new(id)))
    }

    /// A realm name from a URL path, or `None` when it is not a well-formed
    /// realm name (1–63 ASCII letters, digits, `-` or `_`).
    #[must_use]
    pub fn from_path_name(name: &str) -> Option<Self> {
        let well_formed = !name.is_empty()
            && name.len() <= MAX_REALM_NAME_LEN
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        well_formed.then(|| Self::Name(name.to_owned()))
    }
}

/// Outcome of a shaper check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaperOutcome {
    /// The request may proceed.
    Allow,
    /// Caller exceeded the per-IP limit; respond 429.
    IpLimited,
    /// Caller exceeded the per-realm limit; respond 429.
    RealmLimited,
}

/// One-second sliding window.
#[derive(Debug)]
struct SlidingWindow {
    count: u32,
    window_start: Instant,
}

impl SlidingWindow {
    fn new(now: Instant) -> Self {
        // Start at 0 so the first `increment()` call counts as request 1.
        Self {
            count: 0,
            window_start: now,
        }
    }

    /// Increments counter; returns the new count and the window's expiry.
    /// Resets on window expiry.
    fn increment(&mut self, now: Instant) -> (u32, Instant) {
        if now.duration_since(self.window_start) >= WINDOW {
            self.count = 1;
            self.window_start = now;
        } else {
            self.count = self.count.saturating_add(1);
        }
        (self.count, self.window_start.plus(WINDOW))
    }
}

impl RequestShaper {
    /// Creates a shaper with default limits (100 rps/client, 1000 rps/realm).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ShaperConfig::default())
    }

    /// Creates a shaper with custom limits.  Disabled dimensions (e.g.
    /// `ip_rps: None`) are skipped entirely — no map entry is created.
    #[must_use]
    pub fn with_config(config: ShaperConfig) -> Self {
        Self {
            config,
            ip_windows: Mutex::new(ExpiringMap::new(SHAPER_IP_CAPACITY, WINDOW)),
            realm_windows: Mutex::new(ExpiringMap::new(SHAPER_REALM_CAPACITY, WINDOW)),
        }
    }

    /// Creates a no-op shaper (both limits disabled).  Used by the loopback
    /// load-test boot path and by tests.
    #[must_use]
    pub fn disabled() -> Self {
        Self::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: None,
        })
    }

    /// Checks whether a request from `peer_ip` naming `realm` is within rate
    /// limits.
    ///
    /// `peer_ip` is counted under its [`rate_limit_key`]. `realm` is `None`
    /// for a request that names no realm; such a request is limited per IP
    /// only.
    ///
    /// Holds each mutex only for a map lookup + counter increment.
    pub fn check(&self, peer_ip: IpAddr, realm: Option<RealmKey>) -> ShaperOutcome {
        self.check_at(peer_ip, realm, Instant::now())
    }

    /// [`check`](Self::check) at an explicit time (tests drive the clock).
    fn check_at(&self, peer_ip: IpAddr, realm: Option<RealmKey>, now: Instant) -> ShaperOutcome {
        // Per-IP check.
        if let Some(ip_limit) = self.config.ip_rps {
            let count = self
                .ip_windows
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .upsert(
                    rate_limit_key(peer_ip),
                    now,
                    || SlidingWindow::new(now),
                    |w| w.increment(now),
                );
            if count > ip_limit {
                return ShaperOutcome::IpLimited;
            }
        }

        // Per-realm check — only for a request that names a realm.
        if let (Some(realm_limit), Some(realm)) = (self.config.realm_rps, realm) {
            let count = self
                .realm_windows
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .upsert(realm, now, || SlidingWindow::new(now), |w| w.increment(now));
            if count > realm_limit {
                return ShaperOutcome::RealmLimited;
            }
        }

        ShaperOutcome::Allow
    }

    /// Number of realm buckets currently held (observability / test support).
    #[must_use]
    pub fn realm_bucket_count(&self) -> usize {
        self.realm_windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Number of per-IP buckets currently held (observability / test support).
    #[must_use]
    pub fn ip_bucket_count(&self) -> usize {
        self.ip_windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Default for RequestShaper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn name(n: &str) -> Option<RealmKey> {
        Some(RealmKey::from_path_name(n).expect("well-formed realm name"))
    }

    #[test]
    fn allows_under_limit() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(10),
            realm_rps: Some(100),
        });
        for _ in 0..10 {
            assert_eq!(
                shaper.check(loopback(), name("realm1")),
                ShaperOutcome::Allow
            );
        }
    }

    #[test]
    fn ip_rate_limit_triggers() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(3),
            realm_rps: None,
        });
        for _ in 0..3 {
            assert_eq!(shaper.check(loopback(), None), ShaperOutcome::Allow);
        }
        assert_eq!(shaper.check(loopback(), None), ShaperOutcome::IpLimited);
    }

    #[test]
    fn realm_rate_limit_triggers() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: Some(2),
        });
        assert_eq!(shaper.check(loopback(), name("r1")), ShaperOutcome::Allow);
        assert_eq!(shaper.check(loopback(), name("r1")), ShaperOutcome::Allow);
        assert_eq!(
            shaper.check(loopback(), name("r1")),
            ShaperOutcome::RealmLimited
        );
        // Different realm still passes.
        assert_eq!(shaper.check(loopback(), name("r2")), ShaperOutcome::Allow);
    }

    #[test]
    fn disabled_always_allows() {
        let shaper = RequestShaper::disabled();
        for _ in 0..10_000 {
            assert_eq!(shaper.check(loopback(), name("any")), ShaperOutcome::Allow);
        }
    }

    // ── E-1: a request naming no realm is never realm-limited ───────────────

    #[test]
    fn requests_naming_no_realm_share_no_realm_bucket() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: Some(1),
        });
        for octet in 1..=50u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet));
            assert_eq!(shaper.check(ip, None), ShaperOutcome::Allow);
        }
        assert_eq!(shaper.realm_bucket_count(), 0);
    }

    #[test]
    fn realm_keys_accept_only_what_can_name_a_realm() {
        assert!(RealmKey::from_id_header("11111111-1111-1111-1111-111111111111").is_some());
        assert!(RealmKey::from_id_header("not-a-uuid").is_none());
        assert!(RealmKey::from_id_header("").is_none());
        assert!(RealmKey::from_path_name("acme_prod-1").is_some());
        assert!(RealmKey::from_path_name("").is_none());
        assert!(RealmKey::from_path_name(&"a".repeat(64)).is_none());
        assert!(RealmKey::from_path_name("a%2Fb").is_none());
        assert!(RealmKey::from_path_name("caf\u{e9}").is_none());
    }

    #[test]
    fn operator_zero_disables_a_dimension_instead_of_shedding_everything() {
        let shaper = RequestShaper::with_config(ShaperConfig::from_operator(0, 0));
        for _ in 0..1_000 {
            assert_eq!(shaper.check(loopback(), name("r")), ShaperOutcome::Allow);
        }
        let cfg = ShaperConfig::from_operator(7, 9);
        assert_eq!((cfg.ip_rps, cfg.realm_rps), (Some(7), Some(9)));
    }

    // ── E-2: the maps shrink after their windows expire, and are capped ─────

    #[test]
    fn idle_windows_are_swept_after_expiry() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(1_000),
            realm_rps: Some(1_000),
        });
        let t0 = Instant::now();
        for i in 0..5_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            let realm = name(&format!("realm-{i}"));
            assert_eq!(shaper.check_at(ip, realm, t0), ShaperOutcome::Allow);
        }
        assert_eq!(shaper.ip_bucket_count(), 5_000);
        assert_eq!(shaper.realm_bucket_count(), 5_000);

        let later = t0 + Duration::from_secs(3);
        assert_eq!(
            shaper.check_at(loopback(), name("live"), later),
            ShaperOutcome::Allow
        );
        assert_eq!(
            shaper.ip_bucket_count(),
            1,
            "expired per-IP windows are swept"
        );
        assert_eq!(
            shaper.realm_bucket_count(),
            1,
            "expired realm windows are swept"
        );
    }

    #[test]
    fn realm_map_is_hard_capped_under_a_flood_of_distinct_realms() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: Some(1_000),
        });
        let t0 = Instant::now();
        for i in 0..(SHAPER_REALM_CAPACITY + 5_000) {
            let _ = shaper.check_at(loopback(), name(&format!("r{i}")), t0);
        }
        assert!(
            shaper.realm_bucket_count() <= SHAPER_REALM_CAPACITY,
            "{} realm buckets exceed the cap",
            shaper.realm_bucket_count()
        );
    }

    // ── E-3: IPv6 is counted per /64 ─────────────────────────────────────────

    #[test]
    fn ipv6_addresses_in_one_slash64_share_the_per_ip_budget() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(2),
            realm_rps: None,
        });
        let host = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 7, 0, 0, 0, last));
        assert_eq!(shaper.check(host(1), None), ShaperOutcome::Allow);
        assert_eq!(shaper.check(host(2), None), ShaperOutcome::Allow);
        assert_eq!(
            shaper.check(host(3), None),
            ShaperOutcome::IpLimited,
            "a third address in the same /64 is the same client"
        );
        let elsewhere = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 8, 0, 0, 0, 1));
        assert_eq!(shaper.check(elsewhere, None), ShaperOutcome::Allow);
    }

    #[test]
    fn a_v4_mapped_peer_shares_its_ipv4_budget() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(1),
            realm_rps: None,
        });
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 4).to_ipv6_mapped());
        assert_eq!(shaper.check(v4, None), ShaperOutcome::Allow);
        assert_eq!(shaper.check(mapped, None), ShaperOutcome::IpLimited);
    }
}
