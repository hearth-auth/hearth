//! CAPTCHA-of-last-resort challenge plumbing (A-16).
//!
//! Tracks per-IP failed-authentication counts and places an IP into "challenge"
//! state when the threshold is crossed.  In challenge state:
//!
//! - UI login/registration forms must render a CAPTCHA widget slot.
//! - API callers receive `HEARTH_ABUSE_CHALLENGE_REQUIRED` (HTTP 403).
//!
//! # Provider slot (P-1 — HEA-1202)
//!
//! The [`CaptchaProvider`] trait is the P-1 extension point.  The built-in
//! [`NoopCaptchaProvider`] always passes verification, so no CAPTCHA is
//! surfaced until a real adapter (Cloudflare Turnstile, hCaptcha, etc.) is
//! configured.  Wire one by implementing [`CaptchaProvider`] and injecting
//! it via the challenge store (HEA-1202 ships the Turnstile reference adapter).
//!
//! # State machine
//!
//! ```text
//! Allow → (n failures in window) → ChallengeRequired
//! ChallengeRequired → (clear() / window expiry) → Allow
//! ```
//!
//! The challenge state persists for `challenge_ttl_secs` after the threshold
//! is crossed.  Within a single window the counter continues accumulating so
//! the TTL is refreshed on every new failure.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: when `threshold = None` (the
//! default) all calls return [`ChallengeOutcome::Allow`].  The hard
//! rate limiter (A-2) remains the primary defence.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a per-IP challenge check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeOutcome {
    /// IP is not in challenge state; the request may proceed normally.
    Allow,
    /// IP is in challenge state; CAPTCHA verification is required.
    ///
    /// UI handlers should render the challenge widget.
    /// API handlers should return HTTP 403 with
    /// `error_code: "HEARTH_ABUSE_CHALLENGE_REQUIRED"`.
    ChallengeRequired,
}

/// Configuration for the IP challenge store.
///
/// Serialised under `security.captcha` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    /// Number of failed auth events (per IP, within `window_secs`) that
    /// triggers challenge state.  `None` (default) = disabled (fail-open).
    pub threshold: Option<u32>,

    /// Rolling window length for counting failures.  Default: 60 s.
    pub window_secs: u64,

    /// How long challenge state persists after the threshold is crossed.
    /// Refreshed on every additional failure within the window.
    /// Default: 1800 s (30 min).
    pub challenge_ttl_secs: u64,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            threshold: None,
            window_secs: 60,
            challenge_ttl_secs: 1_800,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct IpEntry {
    /// Failed attempts in the current counting window.
    count: u32,
    /// Start of the current counting window.
    window_start: Instant,
    /// When challenge state expires (`None` = not in challenge state).
    challenge_until: Option<Instant>,
}

impl IpEntry {
    fn new(now: Instant) -> Self {
        Self {
            count: 0,
            window_start: now,
            challenge_until: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IpChallengeStore
// ─────────────────────────────────────────────────────────────────────────────

/// Per-IP failed-authentication counter and challenge-state store (A-16).
///
/// Shared via `Arc` across HTTP handlers so all login/registration surfaces
/// see the same IP state.  The `Mutex` is held only for the duration of a
/// hash-map lookup + counter update — no I/O inside the critical section.
#[derive(Debug)]
pub struct IpChallengeStore {
    config: ChallengeConfig,
    entries: Mutex<HashMap<IpAddr, IpEntry>>,
}

impl IpChallengeStore {
    /// Creates a disabled store (`threshold = None`).
    ///
    /// All `check()` and `record_failure()` calls return
    /// [`ChallengeOutcome::Allow`].  This is the safe default for
    /// deployments that have not configured a CAPTCHA provider.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            config: ChallengeConfig::default(),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a store with the given configuration.
    #[must_use]
    pub fn with_config(config: ChallengeConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the current challenge state for `ip` without mutating counters.
    ///
    /// Call this at the start of every protected handler to gate the request
    /// before performing any work.
    pub fn check(&self, ip: IpAddr) -> ChallengeOutcome {
        if self.config.threshold.is_none() {
            return ChallengeOutcome::Allow;
        }

        let now = Instant::now();
        let map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(entry) = map.get(&ip) {
            if let Some(until) = entry.challenge_until {
                if now < until {
                    return ChallengeOutcome::ChallengeRequired;
                }
            }
        }

        ChallengeOutcome::Allow
    }

    /// Records a failed authentication attempt for `ip`.
    ///
    /// Returns [`ChallengeOutcome::ChallengeRequired`] if this failure
    /// pushed the IP into challenge state (i.e., the threshold was crossed).
    /// Returns [`ChallengeOutcome::Allow`] otherwise.
    ///
    /// Call this after every failed login / registration attempt so the
    /// counter advances regardless of whether the caller acted on the
    /// previous `check()`.
    pub fn record_failure(&self, ip: IpAddr) -> ChallengeOutcome {
        let Some(threshold) = self.config.threshold else {
            return ChallengeOutcome::Allow;
        };

        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);
        let ttl = Duration::from_secs(self.config.challenge_ttl_secs);

        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let entry = map.entry(ip).or_insert_with(|| IpEntry::new(now));

        // Reset counter on window expiry.
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
            entry.challenge_until = None;
        }

        entry.count = entry.count.saturating_add(1);

        if entry.count >= threshold {
            entry.challenge_until = Some(now + ttl);
            ChallengeOutcome::ChallengeRequired
        } else {
            ChallengeOutcome::Allow
        }
    }

    /// Clears challenge state and failure count for `ip`.
    ///
    /// Call this after a successful CAPTCHA verification so the IP returns
    /// to the `Allow` state.  No-op when the IP has no tracked entry.
    pub fn clear(&self, ip: IpAddr) {
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(entry) = map.get_mut(&ip) {
            entry.count = 0;
            entry.challenge_until = None;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptchaProvider trait (P-1 extension point)
// ─────────────────────────────────────────────────────────────────────────────

/// Pluggable CAPTCHA provider trait (P-1 extension point — HEA-1202).
///
/// Implement this trait to add Cloudflare Turnstile, hCaptcha, reCAPTCHA v3,
/// Friendly Captcha, or an on-prem PoW provider.  The reference Turnstile
/// adapter ships in HEA-1202.
///
/// # Failure mode
///
/// `verify()` MUST fail-open on transport errors (return `true`) so that
/// legitimate users are not blocked while the CAPTCHA backend is down.
/// Log the error at `warn` level and let the request proceed.  The hard
/// rate limiter (A-2) and account lockout remain as backstops.
pub trait CaptchaProvider: Send + Sync {
    /// Returns the HTML snippet to inject into challenge-gated forms.
    ///
    /// The snippet is inserted verbatim into the login/registration template
    /// at the `<!-- captcha-widget-slot -->` marker.  Returns an empty string
    /// when no widget is needed (noop provider).
    fn widget_html(&self) -> &str;

    /// Verifies a CAPTCHA response token submitted by the client.
    ///
    /// `token` is the value from the hidden `captcha_token` form field or
    /// the `X-Captcha-Token` header.  `ip` is the client's real IP for
    /// providers that use server-side IP validation.
    ///
    /// Returns `true` when the challenge passes (or when failing open on error).
    fn verify(&self, token: &str, ip: IpAddr) -> bool;
}

/// No-op CAPTCHA provider (built-in, shipped with A-16).
///
/// `widget_html()` returns an empty string — no widget is rendered.
/// `verify()` always returns `true` — all challenges pass without verification.
///
/// This is the safe default for deployments that have not configured a real
/// provider.  Wire Cloudflare Turnstile (HEA-1202) to enable real CAPTCHA.
pub struct NoopCaptchaProvider;

impl CaptchaProvider for NoopCaptchaProvider {
    fn widget_html(&self) -> &str {
        ""
    }

    fn verify(&self, _token: &str, _ip: IpAddr) -> bool {
        true
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

    fn store_with_threshold(n: u32) -> IpChallengeStore {
        IpChallengeStore::with_config(ChallengeConfig {
            threshold: Some(n),
            ..ChallengeConfig::default()
        })
    }

    // ── Unit: disabled store ─────────────────────────────────────────────────

    #[test]
    fn disabled_store_check_always_allows() {
        let store = IpChallengeStore::disabled();
        assert_eq!(store.check(ip(1)), ChallengeOutcome::Allow);
    }

    #[test]
    fn disabled_store_record_failure_always_allows() {
        let store = IpChallengeStore::disabled();
        for _ in 0..1_000 {
            assert_eq!(
                store.record_failure(ip(1)),
                ChallengeOutcome::Allow,
                "disabled store must never return ChallengeRequired"
            );
        }
    }

    // ── Unit: threshold crossing ─────────────────────────────────────────────

    #[test]
    fn threshold_not_reached_allows() {
        let store = store_with_threshold(5);
        for i in 0..4 {
            assert_eq!(
                store.record_failure(ip(1)),
                ChallengeOutcome::Allow,
                "failure {i} of 4 must still allow"
            );
        }
    }

    #[test]
    fn threshold_reached_triggers_challenge() {
        let store = store_with_threshold(3);
        store.record_failure(ip(1));
        store.record_failure(ip(1));
        assert_eq!(
            store.record_failure(ip(1)),
            ChallengeOutcome::ChallengeRequired,
            "3rd failure must cross threshold"
        );
    }

    #[test]
    fn check_reflects_challenge_state() {
        let store = store_with_threshold(2);
        store.record_failure(ip(2));
        store.record_failure(ip(2));
        assert_eq!(
            store.check(ip(2)),
            ChallengeOutcome::ChallengeRequired,
            "check must reflect challenge state after threshold crossed"
        );
    }

    #[test]
    fn check_before_threshold_allows() {
        let store = store_with_threshold(5);
        store.record_failure(ip(3));
        assert_eq!(
            store.check(ip(3)),
            ChallengeOutcome::Allow,
            "check before threshold must allow"
        );
    }

    // ── Unit: clear ──────────────────────────────────────────────────────────

    #[test]
    fn clear_resets_challenge_state() {
        let store = store_with_threshold(2);
        store.record_failure(ip(4));
        store.record_failure(ip(4));
        assert_eq!(store.check(ip(4)), ChallengeOutcome::ChallengeRequired);

        store.clear(ip(4));
        assert_eq!(
            store.check(ip(4)),
            ChallengeOutcome::Allow,
            "clear() must reset challenge state"
        );
    }

    #[test]
    fn clear_on_unknown_ip_is_noop() {
        let store = store_with_threshold(2);
        // Must not panic.
        store.clear(ip(99));
        assert_eq!(store.check(ip(99)), ChallengeOutcome::Allow);
    }

    // ── Unit: IP isolation ───────────────────────────────────────────────────

    #[test]
    fn different_ips_are_independent() {
        let store = store_with_threshold(1);
        store.record_failure(ip(10));
        assert_eq!(
            store.check(ip(10)),
            ChallengeOutcome::ChallengeRequired,
            "ip(10) must be in challenge"
        );
        assert_eq!(
            store.check(ip(11)),
            ChallengeOutcome::Allow,
            "ip(11) must not be affected by ip(10) failures"
        );
    }

    // ── Unit: noop provider ──────────────────────────────────────────────────

    #[test]
    fn noop_provider_widget_is_empty() {
        assert_eq!(NoopCaptchaProvider.widget_html(), "");
    }

    #[test]
    fn noop_provider_always_passes_verification() {
        let provider = NoopCaptchaProvider;
        assert!(provider.verify("any-token", ip(1)));
        assert!(provider.verify("", ip(1)));
        assert!(provider.verify("garbage-token-xyz", ip(1)));
    }

    // ── Adversarial: threshold-adjacent ─────────────────────────────────────

    #[test]
    fn threshold_one_triggers_on_first_failure() {
        let store = store_with_threshold(1);
        assert_eq!(
            store.record_failure(ip(20)),
            ChallengeOutcome::ChallengeRequired,
            "threshold=1: first failure must immediately trigger challenge"
        );
    }

    #[test]
    fn subsequent_failures_keep_ip_in_challenge() {
        let store = store_with_threshold(2);
        store.record_failure(ip(30));
        store.record_failure(ip(30)); // crosses threshold
        assert_eq!(
            store.record_failure(ip(30)),
            ChallengeOutcome::ChallengeRequired,
            "additional failures must keep IP in challenge state"
        );
        assert_eq!(store.check(ip(30)), ChallengeOutcome::ChallengeRequired);
    }
}
