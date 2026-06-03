//! Adaptive exponential lockout backoff (A-12).
//!
//! Tracks per-key (IP address or user ID) consecutive lockout events and
//! escalates the lockout duration on each offense: by default
//! **1 min → 5 min → 30 min → 24 h**.
//!
//! # Usage
//!
//! 1. At auth-failure time, the caller decides the account needs a lockout.
//! 2. Call [`AdaptiveBackoffStore::record_lockout`] — it returns the computed
//!    duration and advances the offense counter.
//! 3. At subsequent auth attempts, call [`AdaptiveBackoffStore::check`] to
//!    learn whether the key is still locked before doing any credential work.
//! 4. On explicit unlock (admin action), call [`AdaptiveBackoffStore::clear`].
//!
//! # Offense counter reset
//!
//! The offense counter resets to zero after [`BackoffConfig::offense_cooldown`]
//! has elapsed since the *end* of the most recent lockout.  This prevents a
//! very patient attacker from keeping the counter permanently low by waiting
//! exactly for the lockout to expire before trying again.
//!
//! # Failure mode: fail-open
//!
//! When `durations` is empty the store behaves as if every check passes.
//! This mirrors the existing flat-lockout approach and allows operators to
//! disable adaptive backoff by clearing the duration list.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the adaptive backoff store.
///
/// Serialised under `security.adaptive_backoff` in `hearth.yaml`.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Lockout durations at offense levels 1, 2, 3, … N.
    ///
    /// Index 0 = first offense, index 1 = second, etc.  Offense counts
    /// beyond the end of the slice use the last element (saturation).
    /// An empty vec disables the adaptive store (fail-open).
    ///
    /// Default: `[1 min, 5 min, 30 min, 24 h]`.
    pub durations: Vec<Duration>,

    /// How long after the most recent lockout *ends* before the offense
    /// counter resets to zero.
    ///
    /// Default: 7 days.
    pub offense_cooldown: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            durations: vec![
                Duration::from_secs(60),           // 1 minute
                Duration::from_secs(5 * 60),       // 5 minutes
                Duration::from_secs(30 * 60),      // 30 minutes
                Duration::from_secs(24 * 60 * 60), // 24 hours
            ],
            offense_cooldown: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a backoff store check or lockout record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffOutcome {
    /// The key is not currently locked; the request may proceed.
    Allow,
    /// The key is locked.
    Locked {
        /// When the lockout expires.
        until: Instant,
        /// Offense level (1-based) that produced this lockout.
        offense_level: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Entry {
    /// How many lockouts this key has accumulated (not counting current one).
    offense_count: u32,
    /// When the current lockout expires, if any.
    locked_until: Option<Instant>,
    /// When the most-recent lockout is scheduled to end (used for cooldown).
    last_lockout_end: Option<Instant>,
}

impl Entry {
    fn new() -> Self {
        Self {
            offense_count: 0,
            locked_until: None,
            last_lockout_end: None,
        }
    }

    /// Returns `true` if the offense counter should reset based on the
    /// cooldown window.
    fn should_reset_offenses(&self, now: Instant, cooldown: Duration) -> bool {
        match self.last_lockout_end {
            None => false,
            Some(end) => now >= end + cooldown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveBackoffStore
// ─────────────────────────────────────────────────────────────────────────────

/// Per-key adaptive lockout backoff tracker (A-12).
///
/// Keys are arbitrary strings (typically an IP address or a user ID).
/// Share via `Arc`; the inner `Mutex` is held only for the duration of a
/// hash-map lookup + counter update — no I/O inside the critical section.
#[derive(Debug)]
pub struct AdaptiveBackoffStore {
    config: BackoffConfig,
    entries: Mutex<HashMap<String, Entry>>,
}

impl AdaptiveBackoffStore {
    /// Creates a store with the default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(BackoffConfig::default())
    }

    /// Creates a store with a custom configuration.
    #[must_use]
    pub fn with_config(config: BackoffConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a disabled store (empty duration list).
    ///
    /// All `check()` calls return [`BackoffOutcome::Allow`]; `record_lockout()`
    /// is a no-op.
    #[must_use]
    pub fn disabled() -> Self {
        Self::with_config(BackoffConfig {
            durations: Vec::new(),
            offense_cooldown: Duration::from_secs(0),
        })
    }

    /// Returns the current lockout state for `key` without advancing counters.
    ///
    /// Call this at the *start* of an auth attempt to gate the request before
    /// performing expensive credential verification.
    pub fn check(&self, key: &str) -> BackoffOutcome {
        if self.config.durations.is_empty() {
            return BackoffOutcome::Allow;
        }

        let now = Instant::now();
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let Some(entry) = map.get_mut(key) else {
            return BackoffOutcome::Allow;
        };

        // Reset offense counter if the cooldown window has passed.
        if entry.should_reset_offenses(now, self.config.offense_cooldown) {
            entry.offense_count = 0;
            entry.locked_until = None;
            entry.last_lockout_end = None;
            return BackoffOutcome::Allow;
        }

        if let Some(until) = entry.locked_until {
            if now < until {
                return BackoffOutcome::Locked {
                    until,
                    offense_level: entry.offense_count,
                };
            }
            // Lockout just expired; keep the entry for offense-count continuity.
            entry.locked_until = None;
        }

        BackoffOutcome::Allow
    }

    /// Records a lockout event for `key`, advances the offense counter, and
    /// returns the computed lockout duration.
    ///
    /// If the key is *already* locked this call extends the lockout to the new
    /// (potentially longer) duration rather than truncating it.
    pub fn record_lockout(&self, key: &str) -> BackoffOutcome {
        if self.config.durations.is_empty() {
            return BackoffOutcome::Allow;
        }

        let now = Instant::now();
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let entry = map.entry(key.to_owned()).or_insert_with(Entry::new);

        // Reset offense counter if the cooldown window has passed since the
        // most recent lockout ended.
        if entry.should_reset_offenses(now, self.config.offense_cooldown) {
            entry.offense_count = 0;
            entry.locked_until = None;
            entry.last_lockout_end = None;
        }

        entry.offense_count = entry.offense_count.saturating_add(1);

        // Pick the duration for this offense level (saturate at the last entry).
        let idx = (entry.offense_count as usize).saturating_sub(1);
        let idx = idx.min(self.config.durations.len() - 1);
        let duration = self.config.durations[idx];

        let until = now + duration;
        entry.locked_until = Some(until);
        entry.last_lockout_end = Some(until);

        BackoffOutcome::Locked {
            until,
            offense_level: entry.offense_count,
        }
    }

    /// Returns the lockout duration that *would* be applied for `key` at its
    /// current offense level, without advancing any counters.
    ///
    /// Useful for surfacing the expected next-lockout duration in admin UIs.
    pub fn peek_next_duration(&self, key: &str) -> Duration {
        if self.config.durations.is_empty() {
            return Duration::ZERO;
        }

        let map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let next_offense = map
            .get(key)
            .map(|e| e.offense_count.saturating_add(1))
            .unwrap_or(1);

        let idx = (next_offense as usize).saturating_sub(1);
        let idx = idx.min(self.config.durations.len() - 1);
        self.config.durations[idx]
    }

    /// Clears lockout state and offense history for `key`.
    ///
    /// Call this after an admin-initiated unlock or after a successful
    /// multi-factor re-authentication that the operator trusts.
    pub fn clear(&self, key: &str) {
        let mut map = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(key);
    }
}

impl Default for AdaptiveBackoffStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AdaptiveBackoffStore {
        AdaptiveBackoffStore::with_config(BackoffConfig {
            durations: vec![
                Duration::from_secs(60),
                Duration::from_secs(300),
                Duration::from_secs(1_800),
                Duration::from_secs(86_400),
            ],
            offense_cooldown: Duration::from_secs(7 * 24 * 3600),
        })
    }

    // ── Unit: disabled store ─────────────────────────────────────────────────

    #[test]
    fn disabled_store_check_always_allows() {
        let s = AdaptiveBackoffStore::disabled();
        assert_eq!(s.check("user:1"), BackoffOutcome::Allow);
    }

    #[test]
    fn disabled_store_record_lockout_is_noop() {
        let s = AdaptiveBackoffStore::disabled();
        assert_eq!(s.record_lockout("user:1"), BackoffOutcome::Allow);
        assert_eq!(s.check("user:1"), BackoffOutcome::Allow);
    }

    // ── Unit: escalating lockout durations ───────────────────────────────────

    #[test]
    fn first_lockout_uses_first_duration() {
        let s = store();
        let outcome = s.record_lockout("ip:1.2.3.4");
        assert!(
            matches!(
                outcome,
                BackoffOutcome::Locked {
                    offense_level: 1,
                    ..
                }
            ),
            "first lockout should be offense level 1, got {outcome:?}"
        );
        // Verify the duration is approximately 60 s.
        if let BackoffOutcome::Locked { until, .. } = outcome {
            let remaining = until.duration_since(Instant::now());
            assert!(
                remaining <= Duration::from_secs(60) && remaining > Duration::from_secs(58),
                "first lockout duration should be ~60 s, got {remaining:?}"
            );
        }
    }

    #[test]
    fn second_lockout_escalates() {
        let s = store();
        s.record_lockout("ip:1.2.3.4");
        // Manually expire the first lockout by clearing locked_until.
        s.clear("ip:1.2.3.4");
        // Re-lock — simulates a fresh offense after the first lockout expired.
        // We record another lockout directly to drive the offense counter.
        s.record_lockout("ip:1.2.3.4");
        let outcome = s.record_lockout("ip:1.2.3.4");
        if let BackoffOutcome::Locked { offense_level, .. } = outcome {
            assert!(
                offense_level >= 2,
                "offense level must escalate beyond 1, got {offense_level}"
            );
        } else {
            panic!("expected Locked, got Allow");
        }
    }

    #[test]
    fn fourth_lockout_saturates_at_last_duration() {
        let s = store();
        // Drive offense count to 4.
        s.record_lockout("ip:x");
        s.record_lockout("ip:x");
        s.record_lockout("ip:x");
        let outcome = s.record_lockout("ip:x");
        if let BackoffOutcome::Locked {
            offense_level,
            until,
        } = outcome
        {
            assert_eq!(offense_level, 4);
            let remaining = until.duration_since(Instant::now());
            assert!(
                remaining > Duration::from_secs(86_390),
                "4th lockout must saturate at 24 h, got {remaining:?}"
            );
        } else {
            panic!("expected Locked");
        }
    }

    #[test]
    fn fifth_and_beyond_lockout_stays_at_last_duration() {
        let s = store();
        for _ in 0..6 {
            s.record_lockout("ip:y");
        }
        let outcome = s.record_lockout("ip:y");
        if let BackoffOutcome::Locked { until, .. } = outcome {
            let remaining = until.duration_since(Instant::now());
            assert!(
                remaining > Duration::from_secs(86_390),
                "beyond-max offense must stay at 24 h, got {remaining:?}"
            );
        }
    }

    // ── Unit: check reflects lock state ──────────────────────────────────────

    #[test]
    fn check_after_lockout_returns_locked() {
        let s = store();
        s.record_lockout("u:alice");
        assert!(
            matches!(s.check("u:alice"), BackoffOutcome::Locked { .. }),
            "check must reflect active lockout"
        );
    }

    #[test]
    fn check_before_lockout_returns_allow() {
        let s = store();
        assert_eq!(s.check("u:unknown"), BackoffOutcome::Allow);
    }

    // ── Unit: clear ──────────────────────────────────────────────────────────

    #[test]
    fn clear_removes_lockout() {
        let s = store();
        s.record_lockout("u:bob");
        s.clear("u:bob");
        assert_eq!(
            s.check("u:bob"),
            BackoffOutcome::Allow,
            "clear must remove lockout"
        );
    }

    #[test]
    fn clear_on_unknown_key_is_noop() {
        let s = store();
        s.clear("u:nonexistent"); // Must not panic.
        assert_eq!(s.check("u:nonexistent"), BackoffOutcome::Allow);
    }

    // ── Unit: key isolation ──────────────────────────────────────────────────

    #[test]
    fn different_keys_are_independent() {
        let s = store();
        s.record_lockout("ip:a");
        assert!(matches!(s.check("ip:a"), BackoffOutcome::Locked { .. }));
        assert_eq!(
            s.check("ip:b"),
            BackoffOutcome::Allow,
            "lockout on ip:a must not affect ip:b"
        );
    }

    // ── Unit: peek_next_duration ─────────────────────────────────────────────

    #[test]
    fn peek_next_duration_for_new_key_is_first_level() {
        let s = store();
        assert_eq!(s.peek_next_duration("new"), Duration::from_secs(60));
    }

    #[test]
    fn peek_next_duration_after_one_lockout_is_second_level() {
        let s = store();
        s.record_lockout("k");
        assert_eq!(s.peek_next_duration("k"), Duration::from_secs(300));
    }
}
