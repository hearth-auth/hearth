//! Production wiring for the abuse-prevention guards (audit §4.17#9, task 20.13).
//!
//! # The defect this closes
//!
//! `openspec/specs/abuse-prevention/spec.md` marked guards **Shipped** that were never
//! constructed anywhere except their own `#[cfg(test)]` blocks:
//!
//! | Guard | Type |
//! |-------|------|
//! | A-3 distributed-attack detector | [`DistributedAttackDetector`] |
//! | A-4 outbound volume shield | [`OutboundVolumeShield`] |
//! | A-9 tenant CIDR allow/deny | [`CidrFilter`] |
//! | A-16 CAPTCHA-of-last-resort | [`IpChallengeStore`] |
//! | A-50 cross-realm aggregation cap | [`CrossRealmAggregationCap`] |
//!
//! Their documented config keys compounded it: `SecurityYaml` carries
//! `#[serde(deny_unknown_fields)]`, and none of
//! `security.distributed_attack_detector`, `security.outbound_volume_shield`,
//! `security.cross_realm_aggregation_cap`, `security.adaptive_backoff`,
//! `security.captcha.challenge_threshold` or
//! `realms.<name>.security.cidr_policy` existed as fields — so an operator who
//! pasted the documented block got a server that refused to boot.
//!
//! # The shape of the fix
//!
//! [`AbuseGuards`] is built once at start-up from the `security:` block and
//! held in the HTTP and web application states. Every guard is off by default
//! (`enabled: false`), so an existing deployment sees no behaviour change until
//! an operator opts in — the fail-open posture openspec/specs/abuse-prevention/spec.md requires.
//!
//! The pre-auth entry point is [`AbuseGuards::pre_auth_login`], consulted by
//! the login form's pre-gate phase before any Argon2 work is admitted, and
//! [`AbuseGuards::record_login_failure`] / [`AbuseGuards::record_login_success`]
//! feed the per-IP counters afterwards. Outbound mail goes through
//! [`AbuseGuards::check_outbound_email`].

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::abuse::backoff::BackoffConfig;
use crate::abuse::challenge::{
    CaptchaProvider, ChallengeConfig, ChallengeOutcome, IpChallengeStore,
};
use crate::abuse::cidr::{CidrFilter, CidrOutcome};
use crate::abuse::detector::{
    CrossRealmAggCapConfig, CrossRealmAggregationCap, CrossRealmOutcome, DetectorConfig,
    DetectorOutcome, DistributedAttackDetector, OutboundVolumeShield, VolumeShieldConfig,
    VolumeShieldOutcome,
};
use crate::abuse::device_approval::{DeviceApprovalConfig, DeviceApprovalGuard};
use crate::config::SecurityYaml;
use crate::core::{rate_limit_key, ExpiringMap, LimiterClock};
use crate::identity::CidrPolicy;

/// What the pre-authentication guards decided about one login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreAuthVerdict {
    /// Nothing fired. Continue with authentication.
    Allow,
    /// The attempt MUST be refused. The reason is for operator logs only and
    /// MUST NOT reach the client — every refusal renders the same generic
    /// page, so login enumeration properties are unchanged.
    Deny {
        /// Which guard fired, for `tracing` only.
        reason: &'static str,
    },
    /// The attempt MUST be challenged (A-16 CAPTCHA / A-3 detector). The
    /// caller audits it and answers as the A-16 challenge-response table says.
    Challenge(Challenge),
}

/// Which login guard challenged an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeGuard {
    /// The A-3 distributed-attack detector.
    A3,
    /// The A-16 per-IP challenge state.
    A16,
}

impl ChallengeGuard {
    /// The `guard` value written to the `AbuseDetected` audit metadata.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A3 => "a3",
            Self::A16 => "a16",
        }
    }
}

/// One challenge decided by A-3 or A-16.
///
/// Nothing here reaches the client except `retry_after`, as the
/// `Retry-After` of the no-provider lockout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The guard that fired, for the audit log.
    pub guard: ChallengeGuard,
    /// Which dimension fired, for `tracing` only.
    pub reason: &'static str,
    /// Time until the guard's window ends: the no-provider lockout's
    /// `Retry-After`.
    pub retry_after: Duration,
}

/// What an outbound-volume guard decided about one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundVerdict {
    /// Within budget. Send.
    Allow,
    /// Over the soft cap. Send, but the operator should see it.
    Warn {
        /// Which cap fired, for `tracing` only.
        reason: &'static str,
    },
    /// Over the hard cap. The send MUST be abandoned.
    Deny {
        /// Which cap fired, for `tracing` only.
        reason: &'static str,
    },
}

/// The abuse-prevention guards, constructed once at start-up.
///
/// Cheap to `Arc`-clone; every guard is internally thread-safe.
pub struct AbuseGuards {
    /// A-16 CAPTCHA-of-last-resort failure counter.
    challenge: IpChallengeStore,
    /// A-3 distributed-attack cardinality detector.
    detector: DistributedAttackDetector,
    /// A-4 per-realm outbound breadth shield.
    volume_shield: OutboundVolumeShield,
    /// A-50 cross-realm per-recipient fan-out cap.
    agg_cap: CrossRealmAggregationCap,
    /// The configured CAPTCHA provider. `None` means a challenge is answered
    /// with a timed lockout instead of a widget.
    captcha: Option<Arc<dyn CaptchaProvider>>,
    /// When each `(guard, client, username)` key may next write an
    /// `AbuseDetected` event, so an attack cannot flood the audit log.
    audit_limiter: Mutex<ExpiringMap<u64, Instant>>,
}

impl std::fmt::Debug for AbuseGuards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbuseGuards").finish_non_exhaustive()
    }
}

impl Default for AbuseGuards {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AbuseGuards {
    /// Every guard off. The default for embedded use and for tests that do not
    /// exercise abuse controls.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            challenge: IpChallengeStore::disabled(),
            detector: DistributedAttackDetector::disabled(),
            volume_shield: OutboundVolumeShield::disabled(),
            agg_cap: CrossRealmAggregationCap::disabled(),
            captcha: None,
            audit_limiter: audit_limiter(),
        }
    }

    /// Builds the guard set from the `security:` block.
    ///
    /// Every guard whose block says `enabled: false` (the default) is
    /// constructed in its own `disabled()` form rather than skipped, so the
    /// call sites have no conditional branches and the fail-open posture is a
    /// property of one constructor rather than of every caller.
    #[must_use]
    pub fn from_security(security: &SecurityYaml) -> Self {
        Self {
            challenge: build_challenge(security),
            detector: build_detector(security),
            volume_shield: build_volume_shield(security),
            agg_cap: build_agg_cap(security),
            captcha: None,
            audit_limiter: audit_limiter(),
        }
    }

    /// Installs the CAPTCHA provider that challenged callers are asked to
    /// solve. Without one, a challenge is a timed lockout.
    #[must_use]
    pub fn with_captcha_provider(mut self, provider: Arc<dyn CaptchaProvider>) -> Self {
        self.captcha = Some(provider);
        self
    }

    /// The configured CAPTCHA provider, if any.
    #[must_use]
    pub fn captcha_provider(&self) -> Option<&Arc<dyn CaptchaProvider>> {
        self.captcha.as_ref()
    }

    /// Whether `ip` is in the A-16 challenge state. Counts nothing.
    ///
    /// The login page reads this to show the widget to a caller that an
    /// earlier attempt put in the challenge state.
    #[must_use]
    pub fn challenge_pending(&self, ip: Option<IpAddr>) -> bool {
        ip.is_some_and(|ip| self.challenge.check(ip) == ChallengeOutcome::ChallengeRequired)
    }

    /// A-16 alone, for a sign-in that has no username (a passkey assertion).
    #[must_use]
    pub fn pre_auth_passkey(&self, ip: Option<IpAddr>) -> PreAuthVerdict {
        ip.map_or(PreAuthVerdict::Allow, |ip| self.a16_challenge(ip))
    }

    /// Verifies a CAPTCHA token presented by a challenged caller.
    ///
    /// A verified token clears the IP's A-16 state; a rejected one counts as a
    /// failed attempt. An empty token, or no configured provider, is not a
    /// solution and counts nothing.
    ///
    /// Blocking: the provider may make a network call. Run it on the blocking
    /// pool from async handlers.
    #[must_use]
    pub fn verify_captcha(&self, ip: Option<IpAddr>, token: &str) -> bool {
        let Some(provider) = self.captcha.as_ref() else {
            return false;
        };
        if token.is_empty() {
            return false;
        }
        // The provider gets the caller's address where there is one; a
        // provider that checks it simply sees a loopback caller otherwise.
        let peer = ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        if provider.verify(token, peer) {
            self.record_login_success(ip);
            true
        } else {
            self.record_login_failure(ip);
            false
        }
    }

    /// Whether this challenge should write an `AbuseDetected` event: at most
    /// one per guard, client and username per window.
    #[must_use]
    pub fn should_audit_challenge(
        &self,
        challenge: &Challenge,
        ip: IpAddr,
        username: Option<&str>,
    ) -> bool {
        self.should_audit_challenge_at(challenge, ip, username, Instant::now())
    }

    /// [`should_audit_challenge`](Self::should_audit_challenge) at an
    /// explicit time.
    fn should_audit_challenge_at(
        &self,
        challenge: &Challenge,
        ip: IpAddr,
        username: Option<&str>,
        now: Instant,
    ) -> bool {
        let window = match challenge.guard {
            ChallengeGuard::A3 => self.detector.window(),
            ChallengeGuard::A16 => self.challenge.window(),
        }
        .max(Duration::from_secs(1));
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        challenge.guard.hash(&mut hasher);
        rate_limit_key(ip).hash(&mut hasher);
        username.hash(&mut hasher);
        let key = hasher.finish();

        self.audit_limiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .upsert(
                key,
                now,
                || now,
                |next_write| {
                    let write = now >= *next_write;
                    if write {
                        *next_write = now.plus(window);
                    }
                    (write, *next_write)
                },
            )
    }

    /// Runs every pre-authentication guard for one login attempt.
    ///
    /// Ordered most-decisive first: the tenant CIDR policy is a tenant's
    /// explicit instruction and outranks every heuristic; the A-16 challenge
    /// and the A-3 detector, which only challenge, come last.
    ///
    /// Every arm is username-independent apart from the detector's cardinality
    /// record, which is not observable in the response, so this MUST NOT
    /// change login enumeration properties.
    #[must_use]
    pub fn pre_auth_login(
        &self,
        ip: Option<IpAddr>,
        username: &str,
        realm_cidr: Option<&CidrPolicy>,
    ) -> PreAuthVerdict {
        // A-9 — tenant CIDR allow/deny.
        if let Some(policy) = realm_cidr.filter(|p| !p.is_empty()) {
            if let Some(ip) = ip {
                if compile_filter(policy).check(ip) == CidrOutcome::Deny {
                    return PreAuthVerdict::Deny {
                        reason: "a9_cidr_policy",
                    };
                }
            }
        }

        let Some(ip) = ip else {
            return PreAuthVerdict::Allow;
        };

        // A-3 — distributed-attack cardinality. Consulted even when A-16
        // fires below, so the detector keeps counting through a challenge and
        // a solved CAPTCHA does not reset it.
        let a3 = match self.detector.check(ip, username) {
            DetectorOutcome::Challenge {
                reason,
                retry_after,
            } => Some(Challenge {
                guard: ChallengeGuard::A3,
                reason,
                retry_after,
            }),
            DetectorOutcome::Allow => None,
        };

        // A-16 — CAPTCHA of last resort.
        match self.a16_challenge(ip) {
            PreAuthVerdict::Allow => a3.map_or(PreAuthVerdict::Allow, PreAuthVerdict::Challenge),
            verdict => verdict,
        }
    }

    /// The A-16 verdict for `ip`.
    fn a16_challenge(&self, ip: IpAddr) -> PreAuthVerdict {
        match self.challenge.challenge_remaining(ip) {
            Some(retry_after) => PreAuthVerdict::Challenge(Challenge {
                guard: ChallengeGuard::A16,
                reason: "a16_challenge",
                retry_after,
            }),
            None => PreAuthVerdict::Allow,
        }
    }

    /// Records a failed authentication against the per-IP counters.
    pub fn record_login_failure(&self, ip: Option<IpAddr>) {
        if let Some(ip) = ip {
            let _ = self.challenge.record_failure(ip);
        }
    }

    /// Clears the per-IP counters after a successful authentication.
    pub fn record_login_success(&self, ip: Option<IpAddr>) {
        if let Some(ip) = ip {
            self.challenge.clear(ip);
        }
    }

    /// A-4 + A-50 — the two outbound breadth checks for one email recipient.
    ///
    /// Both must pass. The per-realm budget is checked first so a single
    /// runaway realm is attributed to itself rather than to the global cap.
    #[must_use]
    pub fn check_outbound_email(&self, realm_id: &str, recipient: &str) -> OutboundVerdict {
        let shield = match self.volume_shield.check_email(realm_id, recipient) {
            VolumeShieldOutcome::HardCap => {
                return OutboundVerdict::Deny {
                    reason: "a4_email_hard_cap",
                }
            }
            VolumeShieldOutcome::SoftCap => Some("a4_email_soft_cap"),
            VolumeShieldOutcome::Allow => None,
        };
        match self.agg_cap.check_email(realm_id, recipient) {
            CrossRealmOutcome::HardCap { .. } => OutboundVerdict::Deny {
                reason: "a50_email_hard_cap",
            },
            CrossRealmOutcome::SoftCap { .. } => OutboundVerdict::Warn {
                reason: "a50_email_soft_cap",
            },
            CrossRealmOutcome::MultiRealmAlert { .. } => OutboundVerdict::Warn {
                reason: "a50_multi_realm_alert",
            },
            CrossRealmOutcome::Allow => match shield {
                Some(reason) => OutboundVerdict::Warn { reason },
                None => OutboundVerdict::Allow,
            },
        }
    }
}

/// Most `(guard, client, username)` keys the audit limiter holds at once.
const AUDIT_LIMITER_CAPACITY: usize = 65_536;

/// An empty audit limiter, swept once a minute.
fn audit_limiter() -> Mutex<ExpiringMap<u64, Instant>> {
    Mutex::new(ExpiringMap::new(
        AUDIT_LIMITER_CAPACITY,
        Duration::from_secs(60),
    ))
}

/// A-16 CAPTCHA-of-last-resort failure counter.
fn build_challenge(security: &SecurityYaml) -> IpChallengeStore {
    let Some(captcha) = security.captcha.as_ref() else {
        return IpChallengeStore::disabled();
    };
    let Some(threshold) = captcha.challenge_threshold else {
        return IpChallengeStore::disabled();
    };
    IpChallengeStore::with_config(ChallengeConfig {
        threshold: Some(threshold),
        window_secs: captcha.window_secs,
        challenge_ttl_secs: captcha.challenge_ttl_secs,
    })
}

/// A-3 distributed-attack cardinality detector.
fn build_detector(security: &SecurityYaml) -> DistributedAttackDetector {
    let yaml = &security.distributed_attack_detector;
    if !yaml.enabled {
        return DistributedAttackDetector::disabled();
    }
    DistributedAttackDetector::new(DetectorConfig {
        window: parse_window(&yaml.window, Duration::from_secs(300)),
        username_per_ip_threshold: yaml.username_per_ip_threshold,
        ip_per_username_threshold: yaml.ip_per_username_threshold,
    })
}

/// A-12 `POST /ui/device` guard built from `security.adaptive_backoff`.
///
/// The lockout ladder is `durations`, reset after `offense_cooldown`.
/// `durations: []` turns escalation off but keeps a flat lockout of the
/// compiled first step (one minute) after the attempt ceiling, so the guard
/// never stops locking. A duration that does not parse falls back to the
/// compiled schedule with a warning.
#[must_use]
pub fn build_device_approval_guard(security: &SecurityYaml) -> DeviceApprovalGuard {
    let yaml = &security.adaptive_backoff;
    let compiled = BackoffConfig::default();
    let parsed: Option<Vec<Duration>> = yaml
        .durations
        .iter()
        .map(|text| {
            crate::config::parse_duration_to_micros(text)
                .ok()
                .and_then(|micros| u64::try_from(micros).ok())
                .filter(|micros| *micros > 0)
                .map(Duration::from_micros)
        })
        .collect();
    let durations = match parsed {
        Some(d) if d.is_empty() => compiled.durations.iter().take(1).copied().collect(),
        Some(d) => d,
        None => {
            tracing::warn!(
                "security.adaptive_backoff.durations has an entry that is not a positive \
                 duration; using the compiled schedule"
            );
            compiled.durations.clone()
        }
    };
    DeviceApprovalGuard::with_config(DeviceApprovalConfig {
        backoff: BackoffConfig {
            durations,
            offense_cooldown: parse_window(&yaml.offense_cooldown, compiled.offense_cooldown),
        },
        ..DeviceApprovalConfig::default()
    })
}

/// A-4 per-realm outbound breadth shield.
fn build_volume_shield(security: &SecurityYaml) -> OutboundVolumeShield {
    let yaml = &security.outbound_volume_shield;
    if !yaml.enabled {
        return OutboundVolumeShield::disabled();
    }
    OutboundVolumeShield::new(VolumeShieldConfig {
        window: parse_window(&yaml.window, Duration::from_secs(3_600)),
        email_soft_cap: yaml.email_soft_cap,
        email_hard_cap: yaml.email_hard_cap,
    })
}

/// A-50 cross-realm per-recipient fan-out cap.
fn build_agg_cap(security: &SecurityYaml) -> CrossRealmAggregationCap {
    let yaml = &security.cross_realm_aggregation_cap;
    if !yaml.enabled {
        return CrossRealmAggregationCap::disabled();
    }
    CrossRealmAggregationCap::new(CrossRealmAggCapConfig {
        window: parse_window(&yaml.window, Duration::from_secs(3_600)),
        alert_threshold: yaml.alert_threshold,
        email_realm_soft_cap: yaml.email_realm_soft_cap,
        email_realm_hard_cap: yaml.email_realm_hard_cap,
    })
}

/// Whether a realm's [`CidrPolicy`] refuses `ip` (A-9).
///
/// The one decision every session-establishing path applies — the web
/// password form through [`AbuseGuards::pre_auth_login`], and every other path
/// through the identity engine's session gate (GA audit M13). An empty policy
/// refuses nothing.
#[must_use]
pub fn cidr_policy_denies(policy: &CidrPolicy, ip: IpAddr) -> bool {
    !policy.is_empty() && compile_filter(policy).check(ip) == CidrOutcome::Deny
}

/// Compiles a stored [`CidrPolicy`] into a [`CidrFilter`].
///
/// Entries are parsed with [`crate::abuse::cidr::parse_entry`] — the same
/// `core::IpRange` grammar `hearth config validate` and start-up run over
/// `realms.<name>.security.cidr_policy` (`validate_cidr_policies`), so a
/// policy that loaded has no entry this can refuse. Should one appear anyway
/// (a stored realm record from outside the config path), it is dropped with a
/// warning rather than failing the request (§6.1 fail-open).
fn compile_filter(policy: &CidrPolicy) -> CidrFilter {
    let parse = |v: &Vec<String>| {
        v.iter()
            .filter_map(|s| match crate::abuse::cidr::parse_entry(s) {
                Ok(range) => Some(range),
                Err(e) => {
                    tracing::warn!(error = %e, "ignoring invalid cidr_policy entry");
                    None
                }
            })
            .collect::<Vec<_>>()
    };
    CidrFilter::new(parse(&policy.allow), parse(&policy.deny))
}

/// Parses a `"300s"` / `"1h"` style window, falling back to `default`.
fn parse_window(text: &str, default: Duration) -> Duration {
    crate::config::parse_duration_to_micros(text)
        .ok()
        .and_then(|micros| u64::try_from(micros).ok())
        .map_or(default, Duration::from_micros)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn security_yaml(body: &str) -> SecurityYaml {
        serde_norway::from_str(body).expect("security block must parse")
    }

    // ===== The documented config keys must parse (§4.17#9) =====

    /// Every `security.*` block `openspec/specs/abuse-prevention/spec.md` documents must
    /// deserialize. `SecurityYaml` carries `deny_unknown_fields`, so a missing
    /// field is not a no-op — it is a server that refuses to boot.
    #[test]
    fn every_documented_abuse_security_block_parses() {
        for (name, body) in [
            (
                "distributed_attack_detector",
                "distributed_attack_detector:\n  window: 300s\n  \
                 username_per_ip_threshold: 20\n  ip_per_username_threshold: 20\n",
            ),
            (
                "outbound_volume_shield",
                "outbound_volume_shield:\n  window: 3600s\n  email_soft_cap: 1000\n  \
                 email_hard_cap: 5000\n",
            ),
            (
                "cross_realm_aggregation_cap",
                "cross_realm_aggregation_cap:\n  window: 3600s\n  alert_threshold: 3\n  \
                 email_realm_soft_cap: 5\n  email_realm_hard_cap: 10\n",
            ),
            (
                "adaptive_backoff",
                "adaptive_backoff:\n  durations: [\"1m\", \"5m\", \"30m\", \"24h\"]\n  \
                 offense_cooldown: \"7d\"\n",
            ),
            (
                "captcha A-16 knobs",
                "captcha:\n  provider: turnstile\n  challenge_threshold: 30\n  \
                 window_secs: 60\n  challenge_ttl_secs: 1800\n",
            ),
        ] {
            let parsed = serde_norway::from_str::<SecurityYaml>(body);
            assert!(
                parsed.is_ok(),
                "documented security.{name} block must parse, got: {:?}",
                parsed.err()
            );
        }
    }

    // ===== Each guard must actually be constructed and consulted =====

    /// A-3: distinct usernames from one IP must trip the detector.
    #[test]
    fn distributed_attack_detector_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "distributed_attack_detector:\n  enabled: true\n  window: 300s\n  \
             username_per_ip_threshold: 3\n  ip_per_username_threshold: 100\n",
        ));
        let src = ip(198, 51, 100, 9);
        for i in 0..3 {
            let _ = guards.pre_auth_login(Some(src), &format!("u{i}@example.com"), None);
        }
        assert!(
            matches!(
                guards.pre_auth_login(Some(src), "u9@example.com", None),
                PreAuthVerdict::Challenge { .. }
            ),
            "a spray across the configured username threshold must be challenged"
        );
    }

    /// A-3 stays off unless the operator opts in.
    #[test]
    fn distributed_attack_detector_is_off_by_default() {
        let guards = AbuseGuards::from_security(&SecurityYaml::default());
        let src = ip(198, 51, 100, 10);
        for i in 0..50 {
            assert_eq!(
                guards.pre_auth_login(Some(src), &format!("u{i}@example.com"), None),
                PreAuthVerdict::Allow,
                "guards must be fail-open until an operator enables them"
            );
        }
    }

    /// A-9: a tenant deny list must refuse a matching source.
    #[test]
    fn tenant_cidr_deny_list_refuses_the_login() {
        let guards = AbuseGuards::disabled();
        let policy = CidrPolicy {
            allow: Vec::new(),
            deny: vec!["198.51.100.0/24".to_string()],
        };
        assert_eq!(
            guards.pre_auth_login(Some(ip(198, 51, 100, 5)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Deny {
                reason: "a9_cidr_policy"
            }
        );
        assert_eq!(
            guards.pre_auth_login(Some(ip(203, 0, 113, 5)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Allow
        );
    }

    /// A-9: a non-empty allow list refuses everything outside it.
    #[test]
    fn tenant_cidr_allow_list_refuses_sources_outside_it() {
        let guards = AbuseGuards::disabled();
        let policy = CidrPolicy {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: Vec::new(),
        };
        assert_eq!(
            guards.pre_auth_login(Some(ip(10, 1, 2, 3)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Allow
        );
        assert_eq!(
            guards.pre_auth_login(Some(ip(203, 0, 113, 5)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Deny {
                reason: "a9_cidr_policy"
            }
        );
    }

    /// A-9: deny is evaluated first, then allow — on both gates that apply the
    /// policy (the web form's pre-auth check and the engine's session gate).
    #[test]
    fn tenant_cidr_deny_exception_inside_the_allow_list_refuses_the_login() {
        let guards = AbuseGuards::disabled();
        let policy = CidrPolicy {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec!["10.1.2.3/32".to_string()],
        };
        assert_eq!(
            guards.pre_auth_login(Some(ip(10, 1, 2, 3)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Deny {
                reason: "a9_cidr_policy"
            }
        );
        assert_eq!(
            guards.pre_auth_login(Some(ip(10, 1, 2, 4)), "a@example.com", Some(&policy)),
            PreAuthVerdict::Allow
        );
        assert!(cidr_policy_denies(&policy, ip(10, 1, 2, 3)));
        assert!(!cidr_policy_denies(&policy, ip(10, 1, 2, 4)));
    }

    /// A-4: the per-realm outbound hard cap must refuse a send.
    #[test]
    fn outbound_volume_shield_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "outbound_volume_shield:\n  enabled: true\n  window: 3600s\n  \
             email_soft_cap: 1\n  email_hard_cap: 2\n",
        ));
        assert_eq!(
            guards.check_outbound_email("realm-a", "one@example.com"),
            OutboundVerdict::Allow
        );
        // Second distinct recipient hits the soft cap, third the hard cap.
        assert!(matches!(
            guards.check_outbound_email("realm-a", "two@example.com"),
            OutboundVerdict::Warn { .. }
        ));
        assert!(matches!(
            guards.check_outbound_email("realm-a", "three@example.com"),
            OutboundVerdict::Deny { .. }
        ));
    }

    /// A-50: the same recipient reached by too many realms must be refused
    /// even though no single realm exceeded its own budget.
    #[test]
    fn cross_realm_aggregation_cap_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "cross_realm_aggregation_cap:\n  enabled: true\n  window: 3600s\n  \
             alert_threshold: 100\n  email_realm_soft_cap: 100\n  email_realm_hard_cap: 2\n",
        ));
        assert_eq!(
            guards.check_outbound_email("realm-a", "victim@example.com"),
            OutboundVerdict::Allow
        );
        assert_eq!(
            guards.check_outbound_email("realm-b", "victim@example.com"),
            OutboundVerdict::Allow,
            "the cap is `count > threshold`, so two realms is still inside a cap of 2"
        );
        assert!(
            matches!(
                guards.check_outbound_email("realm-c", "victim@example.com"),
                OutboundVerdict::Deny { .. }
            ),
            "a third realm targeting the same recipient must trip the configured hard cap \
             even though no single realm exceeded its own A-4 budget"
        );
    }

    /// Outbound guards stay off by default.
    #[test]
    fn outbound_guards_are_off_by_default() {
        let guards = AbuseGuards::from_security(&SecurityYaml::default());
        for i in 0..200 {
            assert_eq!(
                guards.check_outbound_email("realm-a", &format!("u{i}@example.com")),
                OutboundVerdict::Allow
            );
        }
    }

    /// A-16: the documented CAPTCHA knobs must build a live challenge store.
    #[test]
    fn captcha_challenge_store_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "captcha:\n  provider: turnstile\n  turnstile:\n    site_key: \"k\"\n  \
             challenge_threshold: 2\n  window_secs: 60\n  challenge_ttl_secs: 1800\n",
        ));
        let src = ip(203, 0, 113, 21);
        guards.record_login_failure(Some(src));
        guards.record_login_failure(Some(src));
        assert!(
            matches!(
                guards.pre_auth_login(Some(src), "a@example.com", None),
                PreAuthVerdict::Challenge { .. }
            ),
            "the A-16 threshold must demand a challenge once reached"
        );
    }

    /// Accepts the token `solved` and nothing else.
    struct FakeCaptcha;

    impl CaptchaProvider for FakeCaptcha {
        fn widget_html(&self) -> &str {
            "<div class=\"fake-captcha\"></div>"
        }

        fn verify(&self, token: &str, _ip: IpAddr) -> bool {
            token == "solved"
        }
    }

    fn a16_guards(threshold: u32) -> AbuseGuards {
        AbuseGuards::from_security(&security_yaml(&format!(
            "captcha:\n  provider: turnstile\n  challenge_threshold: {threshold}\n  \
             window_secs: 60\n  challenge_ttl_secs: 1800\n"
        )))
        .with_captcha_provider(Arc::new(FakeCaptcha))
    }

    fn a3_guards() -> AbuseGuards {
        AbuseGuards::from_security(&security_yaml(
            "distributed_attack_detector:\n  enabled: true\n  window: 300s\n  \
             username_per_ip_threshold: 1\n  ip_per_username_threshold: 100\n",
        ))
    }

    /// A-3 without a provider is a lockout until the window ends, so the
    /// challenge carries the time left in the window that fired.
    #[test]
    fn a3_challenge_carries_the_time_left_in_its_window() {
        let guards = a3_guards();
        let src = ip(198, 51, 100, 30);
        let _ = guards.pre_auth_login(Some(src), "a@example.com", None);
        let PreAuthVerdict::Challenge(challenge) =
            guards.pre_auth_login(Some(src), "b@example.com", None)
        else {
            panic!("the second distinct username must be challenged");
        };
        assert_eq!(challenge.guard, ChallengeGuard::A3);
        assert!(
            challenge.retry_after > Duration::from_secs(290)
                && challenge.retry_after <= Duration::from_secs(300),
            "retry_after must be the time left in the 300 s window, got {:?}",
            challenge.retry_after
        );
    }

    /// A-16 challenges name their guard.
    #[test]
    fn a16_challenge_names_its_guard() {
        let guards = a16_guards(1);
        let src = ip(203, 0, 113, 31);
        guards.record_login_failure(Some(src));
        let PreAuthVerdict::Challenge(challenge) =
            guards.pre_auth_login(Some(src), "a@example.com", None)
        else {
            panic!("an IP at the threshold must be challenged");
        };
        assert_eq!(challenge.guard, ChallengeGuard::A16);
        assert!(challenge.retry_after > Duration::from_secs(1_700));
    }

    /// A passkey sign-in has no username: only the per-IP A-16 state applies.
    #[test]
    fn pre_auth_passkey_applies_the_a16_state_only() {
        let guards = a16_guards(2);
        let src = ip(203, 0, 113, 32);
        assert_eq!(guards.pre_auth_passkey(Some(src)), PreAuthVerdict::Allow);
        guards.record_login_failure(Some(src));
        guards.record_login_failure(Some(src));
        assert!(
            matches!(
                guards.pre_auth_passkey(Some(src)),
                PreAuthVerdict::Challenge(Challenge {
                    guard: ChallengeGuard::A16,
                    ..
                })
            ),
            "an IP in the challenge state must be challenged on passkey sign-in"
        );
        assert!(guards.challenge_pending(Some(src)));
        assert!(!guards.challenge_pending(Some(ip(203, 0, 113, 33))));
    }

    /// A verified token clears the A-16 state.
    #[test]
    fn a_solved_captcha_clears_the_challenge_state() {
        let guards = a16_guards(1);
        let src = ip(203, 0, 113, 34);
        guards.record_login_failure(Some(src));
        assert!(guards.challenge_pending(Some(src)));
        assert!(guards.verify_captcha(Some(src), "solved"));
        assert!(
            !guards.challenge_pending(Some(src)),
            "a solved CAPTCHA must return the IP to Allow"
        );
    }

    /// A rejected token counts as a failed attempt; an empty one counts nothing.
    #[test]
    fn a_rejected_captcha_token_counts_as_a_failure() {
        let guards = a16_guards(2);
        let src = ip(203, 0, 113, 35);
        guards.record_login_failure(Some(src));
        assert!(!guards.verify_captcha(Some(src), ""));
        assert!(
            !guards.challenge_pending(Some(src)),
            "an empty token is not an attempt"
        );
        assert!(!guards.verify_captcha(Some(src), "wrong"));
        assert!(
            guards.challenge_pending(Some(src)),
            "a rejected token must count as the second failure"
        );
    }

    /// Without a provider nothing can be solved.
    #[test]
    fn no_provider_means_no_token_is_accepted() {
        let guards = AbuseGuards::disabled();
        assert!(!guards.verify_captcha(Some(ip(203, 0, 113, 36)), "solved"));
    }

    /// At most one `AbuseDetected` event per guard, client and username per
    /// window.
    #[test]
    fn challenge_audit_is_written_once_per_key_per_window() {
        let guards = a3_guards();
        let src = ip(198, 51, 100, 37);
        let challenge = Challenge {
            guard: ChallengeGuard::A3,
            reason: "test",
            retry_after: Duration::from_secs(1),
        };
        let t0 = Instant::now();
        assert!(guards.should_audit_challenge_at(&challenge, src, Some("a@example.com"), t0));
        assert!(
            !guards.should_audit_challenge_at(
                &challenge,
                src,
                Some("a@example.com"),
                t0 + Duration::from_secs(1)
            ),
            "a repeat inside the window must not write a second event"
        );
        assert!(
            guards.should_audit_challenge_at(
                &challenge,
                src,
                Some("b@example.com"),
                t0 + Duration::from_secs(1)
            ),
            "another username is another key"
        );
        let a16 = Challenge {
            guard: ChallengeGuard::A16,
            ..challenge.clone()
        };
        assert!(
            guards.should_audit_challenge_at(&a16, src, Some("a@example.com"), t0),
            "another guard is another key"
        );
        assert!(
            guards.should_audit_challenge_at(
                &challenge,
                src,
                Some("a@example.com"),
                t0 + Duration::from_secs(300)
            ),
            "the next window writes again"
        );
    }

    #[test]
    fn parse_window_falls_back_on_garbage() {
        assert_eq!(
            parse_window("not-a-duration", Duration::from_secs(300)),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_window("300s", Duration::from_secs(1)),
            Duration::from_secs(300)
        );
    }
}
