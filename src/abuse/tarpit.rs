//! Login-event tarpit (A-17).
//!
//! Once a source IP exceeds the failure threshold, every subsequent auth
//! `POST` from that IP receives a deterministic delay of
//! [`TarpitConfig::delay_ms`] milliseconds.  The delay is applied by the
//! *caller* (e.g. via `tokio::time::sleep`) — the `check()` method itself is
//! synchronous and allocation-free so it stays within the hot-path budget.
//!
//! # Usage
//!
//! ```text
//! // In a login handler:
//! match tarpit.check(peer_ip) {
//!     TarpitOutcome::Delay(d) => tokio::time::sleep(d).await,
//!     TarpitOutcome::Allow    => {}
//! }
//! // … proceed with credential verification …
//! tarpit.record_failure(peer_ip);
//! ```
//!
//! The `record_failure` call is made regardless of credential outcome so the
//! tarpit counter stays accurate even when the attacker supplies invalid
//! input that is rejected before reaching the hash verifier.
//!
//! # Failure mode: fail-open
//!
//! When `threshold = None` (the default) all calls return
//! [`TarpitOutcome::Allow`].  The existing rate limiter (A-2) and account
//! lockout remain as backstops.
//!
//! # Relationship to A-16 (challenge)
//!
//! A-16 gates the request entirely (CAPTCHA required).  A-17 *adds latency*
//! but does not gate.  Both can be active simultaneously — the tarpit fires
//! before the CAPTCHA check in handler order.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the IP tarpit.
///
/// Serialised under `security.tarpit` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct TarpitConfig {
    /// Number of failed auth events (per IP, within `window_secs`) before
    /// tarpit delays are applied.
    ///
    /// `None` (default) = disabled (fail-open).
    pub threshold: Option<u32>,

    /// Rolling window length for counting failures.
    ///
    /// Default: 60 s.
    pub window_secs: u64,

    /// Fixed delay injected for each tarpitted request, in milliseconds.
    ///
    /// Must be in the range 100–500 ms per plan §4.1 A-17.
    /// Default: 200 ms.
    pub delay_ms: u64,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            threshold: None,
            window_secs: 60,
            delay_ms: 200,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a [`TarpitStore::check`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarpitOutcome {
    /// IP is not over threshold; proceed immediately.
    Allow,
    /// IP is over threshold; caller must `sleep` for the given duration before
    /// processing the request.
    Delay(Duration),
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct IpEntry {
    /// Failure count within the current window.
    count: u32,
    /// Start of the current counting window.
    window_start: Instant,
}

impl IpEntry {
    fn new(now: Instant) -> Self {
        Self {
            count: 0,
            window_start: now,
        }
    }

    /// Increments the failure counter, resetting on window expiry.
    fn increment(&mut self, now: Instant, window: Duration) -> u32 {
        if now.duration_since(self.window_start) >= window {
            self.count = 1;
            self.window_start = now;
        } else {
            self.count = self.count.saturating_add(1);
        }
        self.count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TarpitStore
// ─────────────────────────────────────────────────────────────────────────────

/// Per-IP tarpit failure counter (A-17).
///
/// Shared via `Arc` across HTTP login/registration handlers.  The `Mutex` is
/// held only for the duration of a hash-map lookup + counter update.
#[derive(Debug)]
pub struct TarpitStore {
    config: TarpitConfig,
    entries: Mutex<HashMap<IpAddr, IpEntry>>,
}

impl TarpitStore {
    /// Creates a disabled tarpit store (fail-open).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            config: TarpitConfig::default(), // threshold = None
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a tarpit store with the given configuration.
    #[must_use]
    pub fn with_config(config: TarpitConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether `ip` is over the failure threshold and should be
    /// tarpitted.
    ///
    /// This method is synchronous and allocation-free.  It does not advance
    /// any counter — call [`record_failure`](Self::record_failure) after the
    /// auth attempt regardless of outcome.
    pub fn check(&self, ip: IpAddr) -> TarpitOutcome {
        let Some(threshold) = self.config.threshold else {
            return TarpitOutcome::Allow;
        };

        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);
        let delay = Duration::from_millis(self.config.delay_ms);

        let map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(entry) = map.get(&ip) {
            // If still inside the same window and count is over threshold…
            if now.duration_since(entry.window_start) < window && entry.count >= threshold {
                return TarpitOutcome::Delay(delay);
            }
        }

        TarpitOutcome::Allow
    }

    /// Records a failed authentication attempt for `ip`.
    ///
    /// Increments the per-IP failure counter within the rolling window.  Call
    /// this after every failed login / registration attempt so the tarpit
    /// activates on the *next* request once the threshold is crossed.
    pub fn record_failure(&self, ip: IpAddr) {
        if self.config.threshold.is_none() {
            return;
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        map.entry(ip)
            .or_insert_with(|| IpEntry::new(now))
            .increment(now, window);
    }

    /// Clears tarpit state for `ip`.
    ///
    /// Call this after a successful authentication or admin unlock so the IP
    /// returns to the `Allow` state.
    pub fn clear(&self, ip: IpAddr) {
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(&ip);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn ip(b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
    }

    fn store_with_threshold(n: u32) -> TarpitStore {
        TarpitStore::with_config(TarpitConfig {
            threshold: Some(n),
            window_secs: 60,
            delay_ms: 200,
        })
    }

    // ── Unit: disabled store ─────────────────────────────────────────────────

    #[test]
    fn disabled_store_always_allows() {
        let s = TarpitStore::disabled();
        for _ in 0..1_000 {
            assert_eq!(s.check(ip(1)), TarpitOutcome::Allow);
            s.record_failure(ip(1));
        }
        assert_eq!(s.check(ip(1)), TarpitOutcome::Allow);
    }

    // ── Unit: below threshold — no tarpit ────────────────────────────────────

    #[test]
    fn below_threshold_allows() {
        let s = store_with_threshold(5);
        for _ in 0..4 {
            s.record_failure(ip(1));
        }
        assert_eq!(
            s.check(ip(1)),
            TarpitOutcome::Allow,
            "4 failures below threshold of 5 must not trigger tarpit"
        );
    }

    // ── Unit: at threshold — tarpit activates ────────────────────────────────

    #[test]
    fn at_threshold_triggers_tarpit() {
        let s = store_with_threshold(3);
        s.record_failure(ip(2));
        s.record_failure(ip(2));
        s.record_failure(ip(2)); // now at 3
        assert_eq!(
            s.check(ip(2)),
            TarpitOutcome::Delay(Duration::from_millis(200)),
            "reaching threshold must trigger tarpit delay"
        );
    }

    // ── Unit: configured delay is returned ───────────────────────────────────

    #[test]
    fn configured_delay_is_returned() {
        let s = TarpitStore::with_config(TarpitConfig {
            threshold: Some(1),
            window_secs: 60,
            delay_ms: 350,
        });
        s.record_failure(ip(3));
        assert_eq!(
            s.check(ip(3)),
            TarpitOutcome::Delay(Duration::from_millis(350))
        );
    }

    // ── Unit: IP isolation ───────────────────────────────────────────────────

    #[test]
    fn different_ips_are_independent() {
        let s = store_with_threshold(1);
        s.record_failure(ip(10));
        assert_eq!(
            s.check(ip(10)),
            TarpitOutcome::Delay(Duration::from_millis(200))
        );
        assert_eq!(
            s.check(ip(11)),
            TarpitOutcome::Allow,
            "failures on ip(10) must not tarpit ip(11)"
        );
    }

    // ── Unit: clear resets tarpit ────────────────────────────────────────────

    #[test]
    fn clear_resets_tarpit() {
        let s = store_with_threshold(2);
        s.record_failure(ip(5));
        s.record_failure(ip(5));
        assert_eq!(
            s.check(ip(5)),
            TarpitOutcome::Delay(Duration::from_millis(200))
        );
        s.clear(ip(5));
        assert_eq!(
            s.check(ip(5)),
            TarpitOutcome::Allow,
            "clear must reset tarpit"
        );
    }

    #[test]
    fn clear_on_unknown_ip_is_noop() {
        let s = store_with_threshold(2);
        s.clear(ip(99)); // must not panic
        assert_eq!(s.check(ip(99)), TarpitOutcome::Allow);
    }

    // ── Adversarial: threshold=1 triggers immediately ────────────────────────

    #[test]
    fn threshold_one_triggers_on_first_failure() {
        let s = store_with_threshold(1);
        s.record_failure(ip(20));
        assert_eq!(
            s.check(ip(20)),
            TarpitOutcome::Delay(Duration::from_millis(200)),
            "threshold=1: first failure must immediately trigger tarpit"
        );
    }

    // ── Adversarial: check before record_failure does not trigger ────────────

    #[test]
    fn check_before_record_never_triggers() {
        let s = store_with_threshold(1);
        // check without ever calling record_failure must not trigger
        assert_eq!(
            s.check(ip(30)),
            TarpitOutcome::Allow,
            "check without prior failures must always allow"
        );
    }
}
