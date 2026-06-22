//! D.6 Per-agent request-rate monitor with fail-closed auto-suspend.
//!
//! [`AgentRateMonitor`] tracks the number of requests per `(RealmId, AgentId)`
//! pair within a rolling window, using the same two-bucket rotation scheme as
//! [`super::detector::DistributedAttackDetector`].
//!
//! ## Fail-closed contract
//!
//! When the monitor cannot make a determination (lock poisoned or counter
//! corrupt), it returns [`RateDecision::Deny`] — the **opposite** of the
//! fail-open behaviour in `DistributedAttackDetector` (§6.1 of the
//! abuse-prevention plan).  Fail-closed is required for agent-facing checks
//! because agents are autonomous entities: silently allowing a misbehaving
//! agent is worse than temporarily denying a legitimate one.
//!
//! ## Distributed correctness (D.6 / Q5)
//!
//! Counters are in-memory and per-node.  After a node restart they reset to
//! zero — a conservative choice that is safe because the threshold is a
//! rolling-window cap, not a lifetime cap.  A restarted node starts fresh
//! rather than at pre-crash rate, so the worst case is a brief under-count
//! on recovery before the window fills again.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::core::{AgentId, RealmId};

// ─────────────────────────────────────────────────────────────────────────────
// RateWindow — two-bucket rotating request counter
// ─────────────────────────────────────────────────────────────────────────────

/// Two-bucket rotating **count** window.
///
/// Mirrors the rotation logic of `detector::DistinctWindow` but tracks a
/// simple `u64` count per bucket instead of a `HashSet`.  No cap on the
/// count — the threshold check is the signal, not memory pressure.
///
/// Rotation schedule (relative to `bucket_start`):
/// - `elapsed ≥ full_window` → full clear: both buckets → 0, fresh start,
///   `suspension_fired` flag reset.
/// - `elapsed ≥ half_window` → half rotation: `prev ← current`, `current ← 0`.
///   `suspension_fired` is **not** reset on a half-rotation: the threshold
///   could still be exceeded by `prev + current`.
struct RateWindow {
    current: u64,
    prev: u64,
    /// Timestamp when `current` bucket was last started (first insert or rotation).
    bucket_start: Option<Instant>,
    full_window: Duration,
    half_window: Duration,
    /// Whether the first-threshold-crossing event has already been fired this
    /// full window.  Reset only on full-window clear.  Prevents duplicate
    /// `triggered_suspension: true` events within a single window.
    suspension_fired: bool,
}

impl RateWindow {
    fn new(window: Duration) -> Self {
        Self {
            current: 0,
            prev: 0,
            bucket_start: None,
            full_window: window,
            half_window: window / 2,
            suspension_fired: false,
        }
    }

    /// Records one request at `now`, rotating buckets as needed.
    fn record(&mut self, now: Instant) {
        self.maybe_rotate(now);
        self.current = self.current.saturating_add(1);
    }

    /// Returns the approximate request count across both buckets.
    ///
    /// Uses saturating addition — any overflow produces `u64::MAX`, which
    /// always exceeds any reasonable threshold.
    fn count(&self) -> u64 {
        self.current.saturating_add(self.prev)
    }

    fn maybe_rotate(&mut self, now: Instant) {
        let Some(start) = self.bucket_start else {
            self.bucket_start = Some(now);
            return;
        };
        let elapsed = now.duration_since(start);
        if elapsed >= self.full_window {
            // Full window elapsed — discard all history and reset the suspension flag.
            self.prev = 0;
            self.current = 0;
            self.suspension_fired = false;
            self.bucket_start = Some(now);
        } else if elapsed >= self.half_window {
            // Half window elapsed — rotate: current becomes prev, fresh current.
            self.prev = self.current;
            self.current = 0;
            self.bucket_start = Some(now);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RateDecision
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a per-agent rate-monitor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Request is within the configured rate limit — allow it.
    Allow,
    /// Rate limit exceeded (or monitor state unavailable — fail-closed).
    ///
    /// `triggered_suspension` is `true` on the **first** threshold crossing
    /// within a window.  The caller MUST call `suspend_agent()` and emit
    /// `AgentSuspended` when this flag is set.  Subsequent calls for the
    /// same window return `Deny { triggered_suspension: false }` to prevent
    /// duplicate suspension events.
    Deny {
        /// Whether this is the first threshold crossing in the current window.
        triggered_suspension: bool,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentRateConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the per-agent rate monitor (D.6).
#[derive(Debug, Clone)]
pub struct AgentRateConfig {
    /// Rolling window length.
    ///
    /// Default: 60 seconds (requests-per-minute semantics).
    pub window: Duration,
    /// Maximum requests allowed within `window` before the agent is suspended.
    ///
    /// Default: 1 000 requests / minute.  Operators may lower this for
    /// tightly-scoped agents or raise it for high-throughput integrations.
    pub threshold: u64,
}

impl Default for AgentRateConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            threshold: 1_000,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentRateMonitor
// ─────────────────────────────────────────────────────────────────────────────

/// Per-agent request-rate monitor (D.6).
///
/// Tracks request-per-window counts for each `(RealmId, AgentId)` pair.
/// When the configured threshold is crossed the monitor returns
/// [`RateDecision::Deny`] with `triggered_suspension = true` exactly once per
/// window.  The caller is responsible for the actual agent suspension and
/// audit event emission.
///
/// **Fail-closed**: a poisoned lock returns `Deny { triggered_suspension:
/// false }` rather than `Allow`, so a degraded monitor never silently passes
/// over-limit agents.
pub struct AgentRateMonitor {
    config: AgentRateConfig,
    /// Per-agent rate windows.
    ///
    /// Key: `"{realm_uuid}:{agent_uuid}"` — avoids requiring `Hash` on newtypes.
    ///
    // INVARIANT: guard released before method returns; no .await in scope.
    windows: Mutex<HashMap<String, RateWindow>>,
}

impl AgentRateMonitor {
    /// Creates a monitor with the supplied configuration.
    pub fn new(config: AgentRateConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a monitor whose threshold is effectively infinite (disabled).
    ///
    /// Useful in tests that exercise agent operations without triggering
    /// rate-limit side effects.
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self::new(AgentRateConfig {
            window: Duration::from_secs(60),
            threshold: u64::MAX,
        })
    }

    /// Records a request for `(realm_id, agent_id)` at `now` and returns the
    /// rate-limit decision.
    ///
    /// Must be called on every request touching the agent identity, regardless
    /// of whether the credentials are correct.  Counting unauthenticated
    /// attempts ensures that an attacker probing with many wrong keys is also
    /// subject to the rate cap.
    ///
    /// # Fail-closed
    ///
    /// Returns `Deny { triggered_suspension: false }` if the internal mutex
    /// is poisoned.
    pub fn check_and_record(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
        now: Instant,
    ) -> RateDecision {
        let key = format!("{}:{}", realm_id.as_uuid(), agent_id.as_uuid());

        let mut windows = match self.windows.lock() {
            Ok(g) => g,
            // Fail-closed: poisoned lock → deny without triggering suspension.
            Err(_) => {
                return RateDecision::Deny {
                    triggered_suspension: false,
                }
            }
        };

        let window = windows
            .entry(key)
            .or_insert_with(|| RateWindow::new(self.config.window));

        window.record(now);

        if window.count() > self.config.threshold {
            // Emit `triggered_suspension = true` exactly once per window.
            let first_trip = !window.suspension_fired;
            window.suspension_fired = true;
            return RateDecision::Deny {
                triggered_suspension: first_trip,
            };
        }

        RateDecision::Allow
    }

    /// Evicts idle windows older than two full window durations.
    ///
    /// Call from the engine's periodic cleanup sweep (`sweep_expired`) to
    /// prevent unbounded memory growth when agents become inactive.
    pub fn prune_idle(&self, now: Instant) {
        let cutoff_age = self.config.window.saturating_mul(2);
        let Ok(mut windows) = self.windows.lock() else {
            return;
        };
        windows.retain(|_, w| {
            if let Some(start) = w.bucket_start {
                // Keep the window if any bucket activity is recent enough.
                now.duration_since(start) < cutoff_age
            } else {
                // Never had any activity — eligible for eviction.
                false
            }
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn realm() -> RealmId {
        RealmId::new(uuid::Uuid::new_v4())
    }

    fn agent() -> AgentId {
        AgentId::new(uuid::Uuid::new_v4())
    }

    // ── RateWindow unit tests ─────────────────────────────────────────────────

    #[test]
    fn rate_window_counts_requests() {
        let mut w = RateWindow::new(Duration::from_secs(60));
        let now = Instant::now();
        w.record(now);
        w.record(now);
        w.record(now);
        assert_eq!(w.count(), 3);
    }

    #[test]
    fn rate_window_rotates_on_half_period() {
        let window = Duration::from_millis(200);
        let mut w = RateWindow::new(window);
        let t0 = Instant::now();

        // Add 5 requests in the first bucket.
        for _ in 0..5 {
            w.record(t0);
        }
        assert_eq!(w.count(), 5);

        // Advance past the half window — rotation: prev=5, current=0.
        let t1 = t0 + window / 2 + Duration::from_millis(5);
        // Recording at t1 rotates first, then adds the new request.
        w.record(t1);
        assert_eq!(w.count(), 6, "prev=5 + current=1");
    }

    #[test]
    fn rate_window_full_rotation_resets_count() {
        let window = Duration::from_millis(200);
        let mut w = RateWindow::new(window);
        let t0 = Instant::now();

        for _ in 0..100 {
            w.record(t0);
        }
        assert_eq!(w.count(), 100);

        // Advance past the full window — both buckets cleared.
        let t1 = t0 + window + Duration::from_millis(10);
        w.record(t1);
        assert_eq!(w.count(), 1, "only the single new request should count");
    }

    #[test]
    fn rate_window_full_rotation_resets_suspension_flag() {
        let window = Duration::from_millis(200);
        let mut w = RateWindow::new(window);
        let t0 = Instant::now();

        // Trip the threshold.
        for _ in 0..10 {
            w.record(t0);
        }
        w.suspension_fired = true;

        // Full rotation should clear the flag.
        let t1 = t0 + window + Duration::from_millis(10);
        w.record(t1);
        assert!(!w.suspension_fired);
    }

    // ── AgentRateMonitor tests ────────────────────────────────────────────────

    #[test]
    fn monitor_allows_within_threshold() {
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 10,
            window: Duration::from_secs(60),
        });
        let (rid, aid) = (realm(), agent());
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(
                monitor.check_and_record(&rid, &aid, now),
                RateDecision::Allow
            );
        }
    }

    #[test]
    fn monitor_denies_after_threshold_exceeded() {
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 5,
            window: Duration::from_secs(60),
        });
        let (rid, aid) = (realm(), agent());
        let now = Instant::now();

        for _ in 0..5 {
            assert_eq!(
                monitor.check_and_record(&rid, &aid, now),
                RateDecision::Allow
            );
        }
        // 6th request exceeds threshold of 5.
        let decision = monitor.check_and_record(&rid, &aid, now);
        assert_eq!(
            decision,
            RateDecision::Deny {
                triggered_suspension: true
            }
        );
    }

    #[test]
    fn monitor_triggered_suspension_fires_exactly_once_per_window() {
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 3,
            window: Duration::from_secs(60),
        });
        let (rid, aid) = (realm(), agent());
        let now = Instant::now();

        // Fill threshold.
        for _ in 0..3 {
            let _ = monitor.check_and_record(&rid, &aid, now);
        }

        // First crossing — should trigger suspension.
        let first = monitor.check_and_record(&rid, &aid, now);
        assert_eq!(
            first,
            RateDecision::Deny {
                triggered_suspension: true
            }
        );

        // Subsequent calls in same window — NO re-trigger.
        let second = monitor.check_and_record(&rid, &aid, now);
        assert_eq!(
            second,
            RateDecision::Deny {
                triggered_suspension: false
            }
        );

        let third = monitor.check_and_record(&rid, &aid, now);
        assert_eq!(
            third,
            RateDecision::Deny {
                triggered_suspension: false
            }
        );
    }

    #[test]
    fn monitor_resets_after_full_window_elapses() {
        let window = Duration::from_millis(100);
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 3,
            window,
        });
        let (rid, aid) = (realm(), agent());
        let t0 = Instant::now();

        // Trip threshold.
        for _ in 0..4 {
            let _ = monitor.check_and_record(&rid, &aid, t0);
        }
        assert_eq!(
            monitor.check_and_record(&rid, &aid, t0),
            RateDecision::Deny {
                triggered_suspension: false
            }
        );

        // Advance past full window — counters and suspension_fired reset.
        let t1 = t0 + window + Duration::from_millis(10);
        // First request of the new window — should be Allow.
        assert_eq!(
            monitor.check_and_record(&rid, &aid, t1),
            RateDecision::Allow
        );
    }

    #[test]
    fn monitor_isolates_agents_per_realm_and_id() {
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 1,
            window: Duration::from_secs(60),
        });
        let r1 = realm();
        let r2 = realm();
        let a1 = agent();
        let a2 = agent();
        let now = Instant::now();

        // Each (realm, agent) combo has its own independent bucket.
        assert_eq!(monitor.check_and_record(&r1, &a1, now), RateDecision::Allow);
        assert_eq!(monitor.check_and_record(&r1, &a2, now), RateDecision::Allow);
        assert_eq!(monitor.check_and_record(&r2, &a1, now), RateDecision::Allow);
        assert_eq!(monitor.check_and_record(&r2, &a2, now), RateDecision::Allow);

        // Second request on (r1, a1) — now over threshold.
        let d = monitor.check_and_record(&r1, &a1, now);
        assert_eq!(
            d,
            RateDecision::Deny {
                triggered_suspension: true
            }
        );

        // (r2, a2) still at 1 — still within budget.
        assert_eq!(
            monitor.check_and_record(&r2, &a2, now),
            RateDecision::Deny {
                triggered_suspension: true
            }
        );
    }

    #[test]
    fn monitor_disabled_always_allows() {
        let monitor = AgentRateMonitor::disabled();
        let (rid, aid) = (realm(), agent());
        let now = Instant::now();
        for _ in 0..10_000 {
            assert_eq!(
                monitor.check_and_record(&rid, &aid, now),
                RateDecision::Allow
            );
        }
    }

    // ── Adversarial ───────────────────────────────────────────────────────────

    #[test]
    fn monitor_saturation_does_not_overflow() {
        // Ensure saturating_add in RateWindow::count() prevents u64 overflow.
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: u64::MAX - 1,
            window: Duration::from_secs(60),
        });
        let (rid, aid) = (realm(), agent());
        let now = Instant::now();

        // Drive both buckets to near-max.
        {
            let mut windows = monitor
                .windows
                .lock()
                .expect("INVARIANT: Mutex not poisoned");
            let w = windows
                .entry(format!("{}:{}", rid.as_uuid(), aid.as_uuid()))
                .or_insert_with(|| RateWindow::new(Duration::from_secs(60)));
            w.current = u64::MAX / 2;
            w.prev = u64::MAX / 2 + 1;
        }

        // count() saturates rather than wrapping.  The next check_and_record
        // should return Deny (threshold = u64::MAX - 1, count saturates to u64::MAX).
        let decision = monitor.check_and_record(&rid, &aid, now);
        assert!(matches!(decision, RateDecision::Deny { .. }));
    }

    #[test]
    fn monitor_different_agents_same_realm_do_not_cross_contaminate() {
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 5,
            window: Duration::from_secs(60),
        });
        let rid = realm();
        let agents: Vec<AgentId> = (0..10).map(|_| agent()).collect();
        let now = Instant::now();

        // Each agent sends exactly 5 requests — all at threshold, none over.
        for a in &agents {
            for _ in 0..5 {
                assert_eq!(monitor.check_and_record(&rid, a, now), RateDecision::Allow);
            }
        }

        // 6th request per agent should deny only that agent.
        for a in &agents {
            let d = monitor.check_and_record(&rid, a, now);
            assert_eq!(
                d,
                RateDecision::Deny {
                    triggered_suspension: true
                }
            );
        }
    }

    #[test]
    fn prune_idle_removes_old_windows() {
        let window = Duration::from_millis(100);
        let monitor = AgentRateMonitor::new(AgentRateConfig {
            threshold: 1000,
            window,
        });
        let (rid, aid) = (realm(), agent());
        let t0 = Instant::now();

        // Record one request so a window entry exists.
        let _ = monitor.check_and_record(&rid, &aid, t0);
        assert_eq!(
            monitor
                .windows
                .lock()
                .expect("INVARIANT: Mutex not poisoned")
                .len(),
            1
        );

        // Prune with a time that's older than 2× the window.
        let t_prune = t0 + window.saturating_mul(2) + Duration::from_millis(10);
        monitor.prune_idle(t_prune);
        assert_eq!(
            monitor
                .windows
                .lock()
                .expect("INVARIANT: Mutex not poisoned")
                .len(),
            0,
            "idle window should be evicted"
        );
    }
}
