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
//! | IP RPS    | 100      | Requests per second per IP      |
//! | Realm RPS | 1 000    | Requests per second per realm   |
//! | Window    | 1 second | Sliding window length           |
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the plan: if the shaper is not configured (feature disabled),
//! all requests pass without rate limiting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-IP and per-realm sliding-window rate limiter.
///
/// Shared across HTTP and gRPC surfaces (via `Arc`) so a caller cannot evade
/// the limit by switching protocols.
#[derive(Debug)]
pub struct RequestShaper {
    config: ShaperConfig,
    ip_windows: Mutex<HashMap<IpAddr, SlidingWindow>>,
    realm_windows: Mutex<HashMap<String, SlidingWindow>>,
}

/// Configuration for the request shaper.
#[derive(Debug, Clone)]
pub struct ShaperConfig {
    /// Maximum requests per second per source IP.  `None` = disabled.
    pub ip_rps: Option<u32>,
    /// Maximum requests per second per realm (empty string = no-realm path).
    /// `None` = disabled.
    pub realm_rps: Option<u32>,
}

impl Default for ShaperConfig {
    fn default() -> Self {
        Self {
            ip_rps: Some(100),
            realm_rps: Some(1_000),
        }
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

    /// Increments counter; returns the new count.  Resets on window expiry.
    fn increment(&mut self, now: Instant) -> u32 {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 1;
            self.window_start = now;
        } else {
            self.count = self.count.saturating_add(1);
        }
        self.count
    }
}

impl RequestShaper {
    /// Creates a shaper with default limits (100 rps/IP, 1000 rps/realm).
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
            ip_windows: Mutex::new(HashMap::new()),
            realm_windows: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a no-op shaper (both limits disabled).  Used when the operator
    /// does not configure `security.request_shaper`.
    #[must_use]
    pub fn disabled() -> Self {
        Self::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: None,
        })
    }

    /// Checks whether a request from `peer_ip` targeting `realm_key` is
    /// within rate limits.
    ///
    /// `realm_key` is an arbitrary string used to bucket per-realm counts.
    /// Pass the realm name or ID; pass `""` for unauthenticated / pre-realm
    /// endpoints.
    ///
    /// This method is called on the hot path.  It holds the mutex only for
    /// the duration of a `HashMap` lookup + counter increment.
    pub fn check(&self, peer_ip: IpAddr, realm_key: &str) -> ShaperOutcome {
        let now = Instant::now();

        // Per-IP check.
        if let Some(ip_limit) = self.config.ip_rps {
            let count = {
                let mut map = self
                    .ip_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                map.entry(peer_ip)
                    .or_insert_with(|| SlidingWindow::new(now))
                    .increment(now)
            };
            if count > ip_limit {
                return ShaperOutcome::IpLimited;
            }
        }

        // Per-realm check.
        if let Some(realm_limit) = self.config.realm_rps {
            let count = {
                let mut map = self
                    .realm_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                map.entry(realm_key.to_string())
                    .or_insert_with(|| SlidingWindow::new(now))
                    .increment(now)
            };
            if count > realm_limit {
                return ShaperOutcome::RealmLimited;
            }
        }

        ShaperOutcome::Allow
    }
}

impl Default for RequestShaper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn allows_under_limit() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(10),
            realm_rps: Some(100),
        });
        for _ in 0..10 {
            assert_eq!(shaper.check(loopback(), "realm1"), ShaperOutcome::Allow);
        }
    }

    #[test]
    fn ip_rate_limit_triggers() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: Some(3),
            realm_rps: None,
        });
        for _ in 0..3 {
            assert_eq!(shaper.check(loopback(), ""), ShaperOutcome::Allow);
        }
        assert_eq!(shaper.check(loopback(), ""), ShaperOutcome::IpLimited);
    }

    #[test]
    fn realm_rate_limit_triggers() {
        let shaper = RequestShaper::with_config(ShaperConfig {
            ip_rps: None,
            realm_rps: Some(2),
        });
        assert_eq!(shaper.check(loopback(), "r1"), ShaperOutcome::Allow);
        assert_eq!(shaper.check(loopback(), "r1"), ShaperOutcome::Allow);
        assert_eq!(shaper.check(loopback(), "r1"), ShaperOutcome::RealmLimited);
        // Different realm still passes.
        assert_eq!(shaper.check(loopback(), "r2"), ShaperOutcome::Allow);
    }

    #[test]
    fn disabled_always_allows() {
        let shaper = RequestShaper::disabled();
        for _ in 0..10_000 {
            assert_eq!(shaper.check(loopback(), "any"), ShaperOutcome::Allow);
        }
    }
}
