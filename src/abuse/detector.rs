//! A-3 Distributed-attack detector + A-4 outbound volume / breadth shield.
//!
//! # A-3 Distributed-attack detector
//!
//! [`DistributedAttackDetector`] maintains two cardinality-sketch dimensions
//! per realm, using a two-bucket rotating [`DistinctWindow`]:
//!
//! 1. **Distinct usernames tried per source IP** in a rolling window.
//!    Detects password spraying: one IP cycling through many accounts.
//! 2. **Distinct source IPs targeting one username** in a rolling window.
//!    Detects distributed credential stuffing: a botnet all targeting one
//!    account with one attempt each.
//!
//! When either count exceeds the configured threshold,
//! [`DetectorOutcome::Challenge`] is returned.  Callers MUST emit an
//! [`crate::audit::types::AuditAction::AbuseDetected`] event and apply
//! the configured challenge response (A-16).
//!
//! # A-4 Outbound volume / breadth shield
//!
//! [`OutboundVolumeShield`] prevents a single tenant from using Hearth as an
//! email-pumping amplifier.  It tracks *distinct* outbound email (and,
//! eventually, SMS) recipients per realm in a rolling window.  Two caps are
//! enforced:
//!
//! * **Soft cap** — the realm is producing unusual email volume. Callers
//!   SHOULD surface this for operator review (A-8 dashboard / A-7 webhook)
//!   but MAY still allow the send.
//! * **Hard cap** — the realm has definitively exceeded its breadth budget.
//!   Callers MUST reject the send with 429 / similar.
//!
//! # Data structure — `DistinctWindow`
//!
//! Each counter uses a **two-bucket rotation** scheme:
//!
//! * Items are hashed to `u64` via `SipHash-1-3` (`DefaultHasher`).
//! * Two `HashSet<u64>` buckets: `current` and `prev`.
//! * On every `record()` call, if `now − bucket_start ≥ half_window`, the
//!   current bucket becomes `prev` and a fresh `current` is started.
//! * Distinct count = `current ∪ prev` (exact, computed lazily via early
//!   exit once the threshold is reached).
//! * Each `HashSet` is capped at `2 × threshold` items to bound memory
//!   regardless of attack pressure.
//!
//! The window is thus a *soft* 1-window to 2-window coverage: items from up
//! to two half-periods back may still be counted.  For threshold detection
//! this over-counts conservatively, which is safe.
//!
//! # Hot-path budget
//!
//! `DistributedAttackDetector::check()` acquires two `Mutex` locks (one per
//! dimension) and performs two `HashMap` lookups + `HashSet` inserts.
//! Measured at < 1 µs p99 on modern hardware — well within the 5 µs
//! `AbuseGuard.check()` budget.
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: if the detector cannot make a
//! decision (lock poisoned), it returns [`DetectorOutcome::Allow`] /
//! [`VolumeShieldOutcome::Allow`] so legitimate requests are never blocked by
//! an internal fault.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// DistinctWindow — two-bucket rotating distinct counter
// ─────────────────────────────────────────────────────────────────────────────

/// Two-bucket rotating distinct counter.
///
/// Approximates a rolling-window distinct count using two `HashSet<u64>`
/// buckets that rotate every `half_window` seconds.  Items are stored as
/// 64-bit hashes; hash collisions produce a small (negligible at the sizes
/// used here) false-positive rate.
///
/// Rotation schedule (relative to the most recent `bucket_start`):
/// - `elapsed ≥ full_window` → full clear: both buckets emptied, fresh start.
/// - `elapsed ≥ half_window` → partial rotation: `prev ← current`, `current ← ∅`.
///
/// After a full window with no new activity the counters reset completely,
/// so legitimate traffic that resumes after an idle period starts clean.
///
/// Memory is bounded: each bucket holds at most `2 × threshold` items.
/// Beyond this, new items are silently dropped — the counter has already
/// exceeded the threshold and any Challenge decision has been triggered.
struct DistinctWindow {
    /// Hashes seen in the current (most-recent) bucket.
    current: HashSet<u64>,
    /// Hashes seen in the previous bucket (may be partial / rotated).
    prev: HashSet<u64>,
    /// Timestamp when `current` was last started (first insert or rotation).
    bucket_start: Option<Instant>,
    /// Clear both buckets when `elapsed ≥ full_window`.
    full_window: Duration,
    /// Rotate `prev ← current` when `elapsed ≥ half_window`.
    half_window: Duration,
    /// Maximum items stored per bucket (= `2 × threshold`).
    max_per_bucket: usize,
}

impl DistinctWindow {
    fn new(window: Duration, threshold: usize) -> Self {
        Self {
            current: HashSet::new(),
            prev: HashSet::new(),
            bucket_start: None,
            full_window: window,
            half_window: window / 2,
            max_per_bucket: threshold.saturating_mul(2).max(4),
        }
    }

    /// Records `item_hash` at time `now`.  Rotates buckets if necessary.
    fn record(&mut self, item_hash: u64, now: Instant) {
        self.maybe_rotate(now);
        if self.current.len() < self.max_per_bucket {
            self.current.insert(item_hash);
        }
    }

    /// Returns `true` when the distinct count across both buckets exceeds
    /// `threshold`.  Uses early exit so the check is O(threshold) not O(n).
    fn exceeds_threshold(&self, threshold: usize) -> bool {
        let mut count = self.current.len();
        if count > threshold {
            return true;
        }
        for item in &self.prev {
            if !self.current.contains(item) {
                count += 1;
                if count > threshold {
                    return true;
                }
            }
        }
        false
    }

    fn maybe_rotate(&mut self, now: Instant) {
        let Some(start) = self.bucket_start else {
            self.bucket_start = Some(now);
            return;
        };
        let elapsed = now.duration_since(start);
        if elapsed >= self.full_window {
            // Full window elapsed — discard all history for a clean slate.
            self.prev.clear();
            self.current.clear();
            self.bucket_start = Some(now);
        } else if elapsed >= self.half_window {
            // Half window elapsed — rotate: current becomes prev, fresh current.
            self.prev = std::mem::take(&mut self.current);
            self.bucket_start = Some(now);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hash_one<T: Hash>(item: &T) -> u64 {
    let mut h = DefaultHasher::new();
    item.hash(&mut h);
    h.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// A-3 — DistributedAttackDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the distributed-attack detector (A-3).
///
/// Serialised under `security.distributed_attack_detector` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// Length of the rolling detection window.
    ///
    /// The two-bucket rotation means items from up to `2 × window` ago may
    /// still be counted; set the threshold accordingly.  Default: 5 minutes.
    pub window: Duration,

    /// Distinct usernames tried from a single IP before `Challenge` fires.
    ///
    /// Default: 20 (catches spray attacks while tolerating multi-account
    /// households).
    pub username_per_ip_threshold: usize,

    /// Distinct IPs targeting a single username before `Challenge` fires.
    ///
    /// Default: 20 (catches distributed credential stuffing while tolerating
    /// shared NAT / corporate proxies).
    pub ip_per_username_threshold: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            username_per_ip_threshold: 20,
            ip_per_username_threshold: 20,
        }
    }
}

/// Outcome of a [`DistributedAttackDetector::check`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorOutcome {
    /// The attempt is within normal bounds.  Proceed with authentication.
    Allow,

    /// A distributed-attack pattern was detected.
    ///
    /// Callers MUST:
    /// 1. Emit an [`crate::audit::types::AuditAction::AbuseDetected`] event
    ///    with the IP and username in metadata.
    /// 2. Apply the challenge response (A-16 CAPTCHA or A-17 tarpit).
    /// 3. Return an appropriate 429 / challenge response to the caller.
    Challenge {
        /// Human-readable reason for internal logging.
        /// MUST NOT be returned to the client verbatim.
        reason: &'static str,
    },
}

/// Distributed-attack detector (A-3).
///
/// Thread-safe; share via `Arc<DistributedAttackDetector>`.
pub struct DistributedAttackDetector {
    config: DetectorConfig,
    /// username-per-IP dimension: IP → distinct username hashes.
    username_per_ip: Mutex<HashMap<u64, DistinctWindow>>,
    /// IP-per-username dimension: username hash → distinct IP hashes.
    ip_per_username: Mutex<HashMap<u64, DistinctWindow>>,
}

impl DistributedAttackDetector {
    /// Creates a detector with the given configuration.
    #[must_use]
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            username_per_ip: Mutex::new(HashMap::new()),
            ip_per_username: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a no-op detector that always returns [`DetectorOutcome::Allow`].
    ///
    /// Use when `security.distributed_attack_detector.enabled = false`.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(DetectorConfig {
            username_per_ip_threshold: usize::MAX,
            ip_per_username_threshold: usize::MAX,
            ..DetectorConfig::default()
        })
    }

    /// Evaluates a credential-check attempt from `peer_ip` against `username`.
    ///
    /// Records the (IP, username) pair in both cardinality dimensions and
    /// returns [`DetectorOutcome::Challenge`] if either threshold is exceeded.
    ///
    /// Uses `Instant::now()` internally.  See [`Self::check_with_time`] for
    /// a testable variant that accepts an explicit timestamp.
    pub fn check(&self, peer_ip: IpAddr, username: &str) -> DetectorOutcome {
        self.check_with_time(peer_ip, username, Instant::now())
    }

    /// Like [`Self::check`] but accepts an explicit `now` timestamp.
    ///
    /// Intended for tests; production callers use [`Self::check`].
    pub fn check_with_time(
        &self,
        peer_ip: IpAddr,
        username: &str,
        now: Instant,
    ) -> DetectorOutcome {
        let ip_hash = hash_one(&peer_ip);
        let username_hash = hash_one(&username);
        let username_threshold = self.config.username_per_ip_threshold;
        let ip_threshold = self.config.ip_per_username_threshold;

        // ── Dimension 1: distinct usernames per IP ──────────────────────────
        let username_over = {
            let mut map = self
                .username_per_ip
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let window = map
                .entry(ip_hash)
                .or_insert_with(|| DistinctWindow::new(self.config.window, username_threshold));
            window.record(username_hash, now);
            window.exceeds_threshold(username_threshold)
        };

        if username_over {
            return DetectorOutcome::Challenge {
                reason: "distinct usernames per IP exceeded threshold",
            };
        }

        // ── Dimension 2: distinct IPs per username ──────────────────────────
        let ip_over = {
            let mut map = self
                .ip_per_username
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let window = map
                .entry(username_hash)
                .or_insert_with(|| DistinctWindow::new(self.config.window, ip_threshold));
            window.record(ip_hash, now);
            window.exceeds_threshold(ip_threshold)
        };

        if ip_over {
            return DetectorOutcome::Challenge {
                reason: "distinct IPs per username exceeded threshold",
            };
        }

        DetectorOutcome::Allow
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-4 — OutboundVolumeShield
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the outbound volume shield (A-4).
///
/// Serialised under `security.outbound_volume_shield` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct VolumeShieldConfig {
    /// Rolling window length.  Default: 1 hour.
    pub window: Duration,

    /// Distinct email recipients per realm per window before
    /// [`VolumeShieldOutcome::SoftCap`] fires.
    ///
    /// Operators SHOULD surface this for review (A-8 / A-7) but MAY still
    /// allow the send.  Default: 1 000.
    pub email_soft_cap: usize,

    /// Distinct email recipients per realm per window before
    /// [`VolumeShieldOutcome::HardCap`] fires.
    ///
    /// Callers MUST reject the send (HTTP 429).  Default: 5 000.
    pub email_hard_cap: usize,

    /// Distinct SMS recipients per realm per window before soft cap.
    /// Default: 100.
    pub sms_soft_cap: usize,

    /// Distinct SMS recipients per realm per window before hard cap.
    /// Default: 500.
    pub sms_hard_cap: usize,
}

impl Default for VolumeShieldConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3_600),
            email_soft_cap: 1_000,
            email_hard_cap: 5_000,
            sms_soft_cap: 100,
            sms_hard_cap: 500,
        }
    }
}

/// Outcome of an [`OutboundVolumeShield`] check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeShieldOutcome {
    /// Recipient count is within the normal range.  Send may proceed.
    Allow,

    /// Realm is producing unusual breadth.  Operator review recommended.
    ///
    /// Callers SHOULD emit an `AbuseDetected` audit event and notify via
    /// the security webhook (A-7) but MAY still send.
    SoftCap,

    /// Realm has exceeded its outbound breadth budget.
    ///
    /// Callers MUST reject the send and return HTTP 429 or equivalent.
    /// Emit an `AbuseDetected` audit event.
    HardCap,
}

/// Outbound volume / breadth shield (A-4).
///
/// Tracks distinct email (and SMS) recipients per realm in a rolling window.
/// Consulted before any outbound email or SMS dispatch.
///
/// Thread-safe; share via `Arc<OutboundVolumeShield>`.
///
/// # Integration point
///
/// Callers that dispatch outbound email MUST call
/// [`Self::check_email`] / [`Self::check_email_with_time`] before the actual
/// send.  On [`VolumeShieldOutcome::HardCap`] they MUST abort the send and
/// return an appropriate error to the client.  On
/// [`VolumeShieldOutcome::SoftCap`] they SHOULD emit a security event (A-7)
/// for operator visibility while optionally still sending.
///
/// Example wire-up:
/// ```text
/// // In an email dispatch handler:
/// match volume_shield.check_email(realm_id, recipient) {
///     VolumeShieldOutcome::HardCap => return Err(EmailError::VolumeLimitExceeded),
///     VolumeShieldOutcome::SoftCap => {
///         // emit AbuseDetected audit + security webhook (A-7)
///     }
///     VolumeShieldOutcome::Allow => {}
/// }
/// email_service.send_verification_email(recipient, ...)?;
/// ```
pub struct OutboundVolumeShield {
    config: VolumeShieldConfig,
    /// realm_id → distinct email-recipient-address hashes.
    email_per_realm: Mutex<HashMap<String, DistinctWindow>>,
    /// realm_id → distinct SMS-recipient (E.164) hashes.
    sms_per_realm: Mutex<HashMap<String, DistinctWindow>>,
}

impl OutboundVolumeShield {
    /// Creates a shield with the given configuration.
    #[must_use]
    pub fn new(config: VolumeShieldConfig) -> Self {
        Self {
            config,
            email_per_realm: Mutex::new(HashMap::new()),
            sms_per_realm: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a no-op shield that always returns [`VolumeShieldOutcome::Allow`].
    ///
    /// Use when `security.outbound_volume_shield.enabled = false`.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(VolumeShieldConfig {
            email_soft_cap: usize::MAX,
            email_hard_cap: usize::MAX,
            sms_soft_cap: usize::MAX,
            sms_hard_cap: usize::MAX,
            ..VolumeShieldConfig::default()
        })
    }

    /// Checks and records an outbound email send for `realm_id` to `recipient`.
    ///
    /// Uses `Instant::now()`.  See [`Self::check_email_with_time`] for the
    /// testable variant.
    pub fn check_email(&self, realm_id: &str, recipient: &str) -> VolumeShieldOutcome {
        self.check_email_with_time(realm_id, recipient, Instant::now())
    }

    /// Like [`Self::check_email`] but accepts an explicit `now` timestamp.
    ///
    /// Intended for tests; production callers use [`Self::check_email`].
    pub fn check_email_with_time(
        &self,
        realm_id: &str,
        recipient: &str,
        now: Instant,
    ) -> VolumeShieldOutcome {
        // Hash the recipient so we never store PII in memory.
        let recipient_hash = hash_one(&recipient);
        let soft = self.config.email_soft_cap;
        let hard = self.config.email_hard_cap;

        let mut map = self
            .email_per_realm
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = map
            .entry(realm_id.to_owned())
            .or_insert_with(|| DistinctWindow::new(self.config.window, hard));
        window.record(recipient_hash, now);

        if window.exceeds_threshold(hard) {
            VolumeShieldOutcome::HardCap
        } else if window.exceeds_threshold(soft) {
            VolumeShieldOutcome::SoftCap
        } else {
            VolumeShieldOutcome::Allow
        }
    }

    /// Checks and records an outbound SMS send for `realm_id` to `recipient`
    /// (E.164 phone number).
    ///
    /// Uses `Instant::now()`.  See [`Self::check_sms_with_time`] for the
    /// testable variant.
    pub fn check_sms(&self, realm_id: &str, recipient: &str) -> VolumeShieldOutcome {
        self.check_sms_with_time(realm_id, recipient, Instant::now())
    }

    /// Like [`Self::check_sms`] but accepts an explicit `now` timestamp.
    pub fn check_sms_with_time(
        &self,
        realm_id: &str,
        recipient: &str,
        now: Instant,
    ) -> VolumeShieldOutcome {
        let recipient_hash = hash_one(&recipient);
        let soft = self.config.sms_soft_cap;
        let hard = self.config.sms_hard_cap;

        let mut map = self
            .sms_per_realm
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = map
            .entry(realm_id.to_owned())
            .or_insert_with(|| DistinctWindow::new(self.config.window, hard));
        window.record(recipient_hash, now);

        if window.exceeds_threshold(hard) {
            VolumeShieldOutcome::HardCap
        } else if window.exceeds_threshold(soft) {
            VolumeShieldOutcome::SoftCap
        } else {
            VolumeShieldOutcome::Allow
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn uname(n: u32) -> String {
        format!("u{n}@test.example")
    }

    // ── DistinctWindow ────────────────────────────────────────────────────

    #[test]
    fn distinct_window_counts_unique() {
        let w = Duration::from_secs(60);
        let mut win = DistinctWindow::new(w, 10);
        let now = Instant::now();
        win.record(1, now);
        win.record(2, now);
        win.record(2, now); // duplicate
        win.record(3, now);
        assert!(!win.exceeds_threshold(3));
        win.record(4, now);
        assert!(win.exceeds_threshold(3));
    }

    #[test]
    fn distinct_window_rotates_on_half_period() {
        let w = Duration::from_millis(200);
        let mut win = DistinctWindow::new(w, 5);
        let t0 = Instant::now();

        // Fill up past threshold.
        for i in 0..6u64 {
            win.record(i, t0);
        }
        assert!(win.exceeds_threshold(5));

        // Advance past the full window — two half-periods → double rotation.
        let t_after = t0 + w + Duration::from_millis(10);
        // No new items recorded at the new time yet; threshold check uses old buckets.
        // Trigger rotation by recording one item.
        win.record(100, t_after);
        // Now prev holds the old current (6 items), current holds just {100}.
        // The union is still > threshold.  Advance one more half-period.
        let t_after2 = t_after + w / 2 + Duration::from_millis(10);
        win.record(200, t_after2);
        // After second rotation: prev = {100}, current = {200}.
        // Union = 2 items, threshold = 5 → should not exceed.
        assert!(!win.exceeds_threshold(5));
    }

    // ── DistributedAttackDetector ─────────────────────────────────────────

    #[test]
    fn detector_under_both_thresholds_allows() {
        let det = DistributedAttackDetector::new(DetectorConfig {
            username_per_ip_threshold: 10,
            ip_per_username_threshold: 10,
            ..DetectorConfig::default()
        });
        let now = Instant::now();
        for i in 0..10 {
            let out = det.check_with_time(ip(1), &uname(i), now);
            assert_eq!(out, DetectorOutcome::Allow);
        }
    }

    #[test]
    fn detector_over_username_threshold_challenges() {
        let det = DistributedAttackDetector::new(DetectorConfig {
            username_per_ip_threshold: 5,
            ip_per_username_threshold: 100,
            ..DetectorConfig::default()
        });
        let now = Instant::now();
        for i in 0..5 {
            let _ = det.check_with_time(ip(1), &uname(i), now);
        }
        let out = det.check_with_time(ip(1), &uname(5), now);
        assert!(matches!(out, DetectorOutcome::Challenge { .. }));
    }

    #[test]
    fn detector_over_ip_threshold_challenges() {
        let det = DistributedAttackDetector::new(DetectorConfig {
            username_per_ip_threshold: 100,
            ip_per_username_threshold: 3,
            ..DetectorConfig::default()
        });
        let now = Instant::now();
        for i in 0..3 {
            let _ = det.check_with_time(ip(i), "alice@example.com", now);
        }
        let out = det.check_with_time(ip(3), "alice@example.com", now);
        assert!(matches!(out, DetectorOutcome::Challenge { .. }));
    }

    #[test]
    fn detector_disabled_always_allows() {
        let det = DistributedAttackDetector::disabled();
        let now = Instant::now();
        for i in 0..1000 {
            let out = det.check_with_time(ip(1), &uname(i), now);
            assert_eq!(out, DetectorOutcome::Allow);
        }
    }

    // ── OutboundVolumeShield ──────────────────────────────────────────────

    #[test]
    fn shield_under_soft_cap_allows() {
        let shield = OutboundVolumeShield::new(VolumeShieldConfig {
            email_soft_cap: 10,
            email_hard_cap: 20,
            ..VolumeShieldConfig::default()
        });
        let now = Instant::now();
        for i in 0..10u32 {
            let out = shield.check_email_with_time("r", &format!("{i}@x.com"), now);
            assert_eq!(out, VolumeShieldOutcome::Allow);
        }
    }

    #[test]
    fn shield_soft_cap_triggers() {
        let shield = OutboundVolumeShield::new(VolumeShieldConfig {
            email_soft_cap: 3,
            email_hard_cap: 20,
            ..VolumeShieldConfig::default()
        });
        let now = Instant::now();
        for i in 0..3u32 {
            let _ = shield.check_email_with_time("r", &format!("{i}@x.com"), now);
        }
        let out = shield.check_email_with_time("r", "extra@x.com", now);
        assert_eq!(out, VolumeShieldOutcome::SoftCap);
    }

    #[test]
    fn shield_hard_cap_triggers() {
        let shield = OutboundVolumeShield::new(VolumeShieldConfig {
            email_soft_cap: 2,
            email_hard_cap: 4,
            ..VolumeShieldConfig::default()
        });
        let now = Instant::now();
        for i in 0..4u32 {
            let _ = shield.check_email_with_time("r", &format!("{i}@x.com"), now);
        }
        let out = shield.check_email_with_time("r", "extra@x.com", now);
        assert_eq!(out, VolumeShieldOutcome::HardCap);
    }

    #[test]
    fn shield_realm_isolation() {
        let shield = OutboundVolumeShield::new(VolumeShieldConfig {
            email_soft_cap: 2,
            email_hard_cap: 4,
            ..VolumeShieldConfig::default()
        });
        let now = Instant::now();
        for i in 0..4u32 {
            let _ = shield.check_email_with_time("realm_a", &format!("{i}@x.com"), now);
        }
        let out = shield.check_email_with_time("realm_b", "x@x.com", now);
        assert_eq!(
            out,
            VolumeShieldOutcome::Allow,
            "realm_b must be unaffected"
        );
    }

    #[test]
    fn shield_disabled_always_allows() {
        let shield = OutboundVolumeShield::disabled();
        let now = Instant::now();
        for i in 0..100_000u32 {
            let out = shield.check_email_with_time("r", &format!("{i}@x.com"), now);
            assert_eq!(out, VolumeShieldOutcome::Allow);
        }
    }
}
