//! Production wiring for the abuse-prevention guards (audit §4.17#9, task 20.13).
//!
//! # The defect this closes
//!
//! `docs/specs/ABUSE.md` marked guards **Shipped** that were never
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
//! an operator opts in — the fail-open posture ABUSE.md §6.1 requires.
//!
//! The pre-auth entry point is [`AbuseGuards::pre_auth_login`], consulted by
//! the login form's pre-gate phase before any Argon2 work is admitted, and
//! [`AbuseGuards::record_login_failure`] / [`AbuseGuards::record_login_success`]
//! feed the per-IP counters afterwards. Outbound mail goes through
//! [`AbuseGuards::check_outbound_email`].

use std::net::IpAddr;
use std::time::Duration;

use crate::abuse::challenge::{ChallengeConfig, ChallengeOutcome, IpChallengeStore};
use crate::abuse::cidr::{CidrFilter, CidrOutcome};
use crate::abuse::detector::{
    CrossRealmAggCapConfig, CrossRealmAggregationCap, CrossRealmOutcome, DetectorConfig,
    DetectorOutcome, DistributedAttackDetector, OutboundVolumeShield, VolumeShieldConfig,
    VolumeShieldOutcome,
};
use crate::config::SecurityYaml;
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
    /// The attempt MUST be challenged (A-16 CAPTCHA / A-3 detector). Callers
    /// without a challenge surface treat this as [`Self::Allow`] and record
    /// the signal.
    Challenge {
        /// Which guard fired, for `tracing` only.
        reason: &'static str,
    },
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
        }
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

        // A-16 — CAPTCHA of last resort.
        if self.challenge.check(ip) == ChallengeOutcome::ChallengeRequired {
            return PreAuthVerdict::Challenge {
                reason: "a16_challenge",
            };
        }

        // A-3 — distributed-attack cardinality.
        if let DetectorOutcome::Challenge { reason } = self.detector.check(ip, username) {
            return PreAuthVerdict::Challenge { reason };
        }
        PreAuthVerdict::Allow
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

    /// Every `security.*` block `docs/specs/ABUSE.md` documents must
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
