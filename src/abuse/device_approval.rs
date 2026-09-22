//! Brute-force guard for the RFC 8628 device-approval endpoint
//! (task 22.26, audit 2026-08-28 §4.25#4).
//!
//! `POST /ui/device` takes a user code typed off a screen. A user code is 8
//! characters from a 28-symbol alphabet, so the whole space is `28^8 ≈ 3.8e11`
//! — but an attacker does not have to find a *specific* code, only **any**
//! code that is currently pending in the realm. With no attempt ceiling an
//! authenticated user could grind the live-code set at whatever rate the
//! server would serve, and every hit approves a device the attacker controls.
//!
//! This guard is composed from the two rate-limiting primitives the codebase
//! already has rather than a third hand-rolled one:
//!
//! * [`RequestShaper`] — per-IP and per-realm sliding-window RPS, the same
//!   shaper that fronts the public routes. It bounds the *rate* of guesses.
//! * [`AdaptiveBackoffStore`] — escalating lockout (1 min → 5 min → 30 min →
//!   24 h) keyed by an arbitrary string. It bounds the *total* number of
//!   guesses: after [`DeviceApprovalConfig::max_attempts`] wrong codes the key
//!   is locked, and each subsequent burst locks it for longer.
//!
//! The only new state here is the per-key wrong-code counter that decides when
//! to hand a lockout to the backoff store.
//!
//! # Keying
//!
//! `/ui/device` requires an authenticated session, so the lockout key is the
//! `realm:user` pair — the identity that would end up owning the approved
//! device. The shaper is keyed on the peer IP so a single host cannot spread
//! a fast grind across many accounts.
//!
//! # Failure mode
//!
//! Fail-closed on the attempt ceiling (a locked key is refused) and fail-open
//! when the guard is explicitly [`DeviceApprovalGuard::disabled`], which
//! mirrors how the shaper and backoff store behave when unconfigured.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::abuse::backoff::{AdaptiveBackoffStore, BackoffConfig, BackoffOutcome};
use crate::abuse::shaper::{RequestShaper, ShaperConfig, ShaperOutcome};

/// Tuning for [`DeviceApprovalGuard`].
#[derive(Debug, Clone)]
pub struct DeviceApprovalConfig {
    /// Consecutive wrong user codes tolerated before the key is locked out.
    ///
    /// `None` disables the attempt ceiling (fail-open).
    pub max_attempts: Option<u32>,
    /// Request shaping applied to the approval endpoint itself.
    pub shaper: ShaperConfig,
    /// Escalating lockout schedule applied once `max_attempts` is exceeded.
    pub backoff: BackoffConfig,
}

impl Default for DeviceApprovalConfig {
    fn default() -> Self {
        Self {
            // Five wrong codes is well beyond a human mistyping an 8-character
            // code off a TV screen and far below anything useful for a grind.
            max_attempts: Some(5),
            shaper: ShaperConfig {
                // Much tighter than the global 100 rps: nobody types user codes
                // at five per second.
                ip_rps: Some(5),
                realm_rps: Some(50),
            },
            backoff: BackoffConfig::default(),
        }
    }
}

/// What the caller should do with an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceApprovalDecision {
    /// Proceed with the approval attempt.
    Allow,
    /// Too many requests per second from this IP or realm — respond 429.
    RateLimited,
    /// The attempt ceiling was exceeded; the key is locked until `until`.
    LockedOut {
        /// When the lockout expires.
        until: Instant,
        /// 1-based offense level that produced this lockout.
        offense_level: u32,
    },
}

/// Composed rate + attempt guard for the device-approval endpoint.
#[derive(Debug)]
pub struct DeviceApprovalGuard {
    config: DeviceApprovalConfig,
    shaper: RequestShaper,
    backoff: AdaptiveBackoffStore,
    /// Consecutive wrong codes per key since the last success or lockout.
    failures: Mutex<HashMap<String, u32>>,
}

impl DeviceApprovalGuard {
    /// Builds a guard with the default limits (5 attempts, 5 rps/IP).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DeviceApprovalConfig::default())
    }

    /// Builds a guard with caller-supplied limits.
    #[must_use]
    pub fn with_config(config: DeviceApprovalConfig) -> Self {
        Self {
            shaper: RequestShaper::with_config(config.shaper.clone()),
            backoff: AdaptiveBackoffStore::with_config(config.backoff.clone()),
            config,
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Builds a fully disabled (fail-open) guard. Intended for tests that are
    /// not exercising the guard itself.
    #[must_use]
    pub fn disabled() -> Self {
        Self::with_config(DeviceApprovalConfig {
            max_attempts: None,
            shaper: ShaperConfig {
                ip_rps: None,
                realm_rps: None,
            },
            backoff: BackoffConfig {
                durations: Vec::new(),
                ..BackoffConfig::default()
            },
        })
    }

    /// Gate an approval attempt before any storage lookup.
    ///
    /// `key` identifies the actor whose attempts are being counted (the
    /// `realm:user` pair); `peer_ip` and `realm_key` feed the shaper.
    pub fn check(&self, key: &str, peer_ip: IpAddr, realm_key: &str) -> DeviceApprovalDecision {
        if let BackoffOutcome::Locked {
            until,
            offense_level,
        } = self.backoff.check(key)
        {
            return DeviceApprovalDecision::LockedOut {
                until,
                offense_level,
            };
        }
        match self.shaper.check(peer_ip, realm_key) {
            ShaperOutcome::Allow => DeviceApprovalDecision::Allow,
            ShaperOutcome::IpLimited | ShaperOutcome::RealmLimited => {
                DeviceApprovalDecision::RateLimited
            }
        }
    }

    /// Records one wrong user code for `key`.
    ///
    /// Returns [`DeviceApprovalDecision::LockedOut`] on the attempt that trips
    /// the ceiling, so the caller can surface the lockout immediately rather
    /// than on the next request.
    pub fn record_failure(&self, key: &str) -> DeviceApprovalDecision {
        let Some(max) = self.config.max_attempts else {
            return DeviceApprovalDecision::Allow;
        };

        let tripped = {
            let mut map = self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = map.entry(key.to_owned()).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= max {
                // The lockout itself now carries the state; drop the counter so
                // the next window starts clean.
                map.remove(key);
                true
            } else {
                false
            }
        };

        if tripped {
            if let BackoffOutcome::Locked {
                until,
                offense_level,
            } = self.backoff.record_lockout(key)
            {
                return DeviceApprovalDecision::LockedOut {
                    until,
                    offense_level,
                };
            }
        }
        DeviceApprovalDecision::Allow
    }

    /// Clears the consecutive-failure counter for `key` after a correct code.
    ///
    /// The *offense* history in the backoff store is deliberately left alone:
    /// one lucky hit must not reset an attacker's escalation ladder.
    pub fn record_success(&self, key: &str) {
        let mut map = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(key);
    }

    /// Seconds a caller should wait, for a `Retry-After` header.
    #[must_use]
    pub fn retry_after_secs(until: Instant) -> u64 {
        until
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1))
            .as_secs()
    }
}

impl Default for DeviceApprovalGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// A guard with a generous shaper so the attempt ceiling — not the RPS
    /// limit — is what the test observes.
    fn attempt_only_guard(max_attempts: u32) -> DeviceApprovalGuard {
        DeviceApprovalGuard::with_config(DeviceApprovalConfig {
            max_attempts: Some(max_attempts),
            shaper: ShaperConfig {
                ip_rps: None,
                realm_rps: None,
            },
            backoff: BackoffConfig::default(),
        })
    }

    #[test]
    fn nth_wrong_code_locks_the_key() {
        let guard = attempt_only_guard(5);
        for i in 1..5 {
            assert_eq!(
                guard.check("realm:user", ip(), "realm"),
                DeviceApprovalDecision::Allow,
                "attempt {i} must still be allowed"
            );
            assert_eq!(
                guard.record_failure("realm:user"),
                DeviceApprovalDecision::Allow,
                "attempt {i} must not trip the ceiling"
            );
        }
        // The 5th wrong code trips it.
        assert!(matches!(
            guard.record_failure("realm:user"),
            DeviceApprovalDecision::LockedOut { .. }
        ));
        // And the 6th request is refused before any lookup happens.
        assert!(matches!(
            guard.check("realm:user", ip(), "realm"),
            DeviceApprovalDecision::LockedOut { .. }
        ));
    }

    #[test]
    fn lockout_is_scoped_to_the_key() {
        let guard = attempt_only_guard(2);
        guard.record_failure("realm:alice");
        guard.record_failure("realm:alice");
        assert!(matches!(
            guard.check("realm:alice", ip(), "realm"),
            DeviceApprovalDecision::LockedOut { .. }
        ));
        assert_eq!(
            guard.check("realm:bob", ip(), "realm"),
            DeviceApprovalDecision::Allow,
            "one user's lockout must not lock everyone else out"
        );
    }

    #[test]
    fn success_resets_the_consecutive_counter() {
        let guard = attempt_only_guard(3);
        guard.record_failure("k");
        guard.record_failure("k");
        guard.record_success("k");
        // Counter restarted: two more failures must not trip the ceiling.
        assert_eq!(guard.record_failure("k"), DeviceApprovalDecision::Allow);
        assert_eq!(guard.record_failure("k"), DeviceApprovalDecision::Allow);
        assert_eq!(
            guard.check("k", ip(), "realm"),
            DeviceApprovalDecision::Allow
        );
    }

    #[test]
    fn repeat_offenders_escalate() {
        let guard = attempt_only_guard(1);
        let first = guard.record_failure("k");
        let DeviceApprovalDecision::LockedOut { offense_level, .. } = first else {
            panic!("expected lockout, got {first:?}");
        };
        assert_eq!(offense_level, 1);
        let second = guard.record_failure("k");
        let DeviceApprovalDecision::LockedOut { offense_level, .. } = second else {
            panic!("expected lockout, got {second:?}");
        };
        assert_eq!(offense_level, 2, "a second burst must escalate the lockout");
    }

    #[test]
    fn request_rate_is_shaped() {
        let guard = DeviceApprovalGuard::with_config(DeviceApprovalConfig {
            max_attempts: Some(1_000),
            shaper: ShaperConfig {
                ip_rps: Some(3),
                realm_rps: Some(1_000),
            },
            backoff: BackoffConfig::default(),
        });
        for _ in 0..3 {
            assert_eq!(
                guard.check("k", ip(), "realm"),
                DeviceApprovalDecision::Allow
            );
        }
        assert_eq!(
            guard.check("k", ip(), "realm"),
            DeviceApprovalDecision::RateLimited,
            "the 4th request in the same second must be shaped"
        );
    }

    #[test]
    fn disabled_guard_never_refuses() {
        let guard = DeviceApprovalGuard::disabled();
        for _ in 0..100 {
            assert_eq!(
                guard.check("k", ip(), "realm"),
                DeviceApprovalDecision::Allow
            );
            assert_eq!(guard.record_failure("k"), DeviceApprovalDecision::Allow);
        }
    }
}
