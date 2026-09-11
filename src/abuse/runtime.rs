//! Production wiring for the abuse-prevention guards (audit §4.17#9, task 20.13).
//!
//! # The defect this closes
//!
//! `docs/specs/ABUSE.md` marks sixteen guards **Shipped**. Nine of them were
//! never constructed anywhere except their own `#[cfg(test)]` blocks:
//!
//! | Guard | Type |
//! |-------|------|
//! | A-3 distributed-attack detector | [`DistributedAttackDetector`] |
//! | A-4 outbound volume shield | [`OutboundVolumeShield`] |
//! | A-9 tenant CIDR allow/deny | [`CidrFilter`] |
//! | A-16 CAPTCHA-of-last-resort | [`IpChallengeStore`] |
//! | A-17 login tarpit | [`TarpitStore`] |
//! | A-50 cross-realm aggregation cap | [`CrossRealmAggregationCap`] |
//! | P-2 IP reputation | [`SpamhausDropProvider`] / [`MaxMindAsnProvider`] |
//! | P-3 bot signal | [`HeuristicBotSignalProvider`] |
//! | P-5 email reputation | [`BuiltinEmailReputation`] |
//!
//! Their documented config keys compounded it: `SecurityYaml` carries
//! `#[serde(deny_unknown_fields)]`, and none of `security.tarpit`,
//! `security.distributed_attack_detector`, `security.outbound_volume_shield`,
//! `security.cross_realm_aggregation_cap`, `security.risk_scorer`,
//! `security.adaptive_backoff`, `security.providers.*`,
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
//! feed the per-IP counters afterwards. Outbound mail and SMS go through
//! [`AbuseGuards::check_outbound_email`] / [`AbuseGuards::check_outbound_sms`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::abuse::bot_signal::{
    BotSignalContext, BotSignalProvider, BotSignalVerdict, HeuristicBotSignalProvider,
    NoopBotSignalProvider,
};
use crate::abuse::challenge::{ChallengeConfig, ChallengeOutcome, IpChallengeStore};
use crate::abuse::cidr::{CidrFilter, CidrOutcome};
use crate::abuse::detector::{
    CrossRealmAggCapConfig, CrossRealmAggregationCap, CrossRealmOutcome, DetectorConfig,
    DetectorOutcome, DistributedAttackDetector, OutboundVolumeShield, VolumeShieldConfig,
    VolumeShieldOutcome,
};
use crate::abuse::email_reputation::{
    BuiltinEmailReputation, EmailReputation, EmailReputationConfig, EmailReputationVerdict,
    NoopEmailReputation,
};
use crate::abuse::ip_reputation::maxmind::{MaxMindAsnConfig, MaxMindAsnProvider};
use crate::abuse::ip_reputation::spamhaus::{SpamhausDropConfig, SpamhausDropProvider};
use crate::abuse::ip_reputation::{IpReputationAction, IpReputationPolicy, IpReputationProvider};
use crate::abuse::tarpit::{TarpitConfig, TarpitOutcome, TarpitStore};
use crate::config::{IpReputationActionYaml, SecurityYaml};
use crate::identity::CidrPolicy;

/// What the pre-authentication guards decided about one login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreAuthVerdict {
    /// Nothing fired. Continue with authentication.
    Allow,
    /// The caller MUST sleep for this long before continuing. Used by the A-17
    /// tarpit, which slows an abusive source without telling it why.
    Delay(Duration),
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
    /// A-17 per-IP login tarpit.
    tarpit: TarpitStore,
    /// A-16 CAPTCHA-of-last-resort failure counter.
    challenge: IpChallengeStore,
    /// A-3 distributed-attack cardinality detector.
    detector: DistributedAttackDetector,
    /// A-4 per-realm outbound breadth shield.
    volume_shield: OutboundVolumeShield,
    /// A-50 cross-realm per-recipient fan-out cap.
    agg_cap: CrossRealmAggregationCap,
    /// P-3 bot-signal adapter.
    bot_signal: Arc<dyn BotSignalProvider>,
    /// P-5 email-reputation adapter.
    email_reputation: Arc<dyn EmailReputation>,
    /// P-2 IP-reputation adapters, consulted in order.
    ip_reputation: Vec<Arc<dyn IpReputationProvider>>,
    /// P-2 policy: whether to run at all, and what a hit means.
    ip_reputation_policy: IpReputationPolicy,
    /// Concrete handle to the Spamhaus provider, kept so
    /// [`AbuseGuards::spawn_background_tasks`] can start its refresh loop
    /// without downcasting through the trait object.
    spamhaus: Option<Arc<SpamhausDropProvider>>,
}

impl std::fmt::Debug for AbuseGuards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbuseGuards")
            .field("ip_reputation_providers", &self.ip_reputation.len())
            .field("ip_reputation_policy", &self.ip_reputation_policy)
            .finish_non_exhaustive()
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
            tarpit: TarpitStore::disabled(),
            challenge: IpChallengeStore::disabled(),
            detector: DistributedAttackDetector::disabled(),
            volume_shield: OutboundVolumeShield::disabled(),
            agg_cap: CrossRealmAggregationCap::disabled(),
            bot_signal: Arc::new(NoopBotSignalProvider),
            email_reputation: Arc::new(NoopEmailReputation),
            ip_reputation: Vec::new(),
            ip_reputation_policy: IpReputationPolicy::default(),
            spamhaus: None,
        }
    }

    /// Builds the guard set from the `security:` block.
    ///
    /// Every guard whose block says `enabled: false` (the default) is
    /// constructed in its own `disabled()` form rather than skipped, so the
    /// call sites have no conditional branches and the fail-open posture is a
    /// property of one constructor rather than of every caller.
    ///
    /// The Spamhaus background refresh is **not** started here — it needs a
    /// Tokio runtime. Call [`Self::spawn_background_tasks`] once the runtime
    /// is up.
    #[must_use]
    pub fn from_security(security: &SecurityYaml) -> Self {
        let mut ip_reputation: Vec<Arc<dyn IpReputationProvider>> = Vec::new();
        let mut spamhaus = None;
        if security.ip_reputation.enabled {
            // Starts empty (fail-open) and is populated by the background
            // refresh task; see `spawn_background_tasks`.
            let provider = Arc::new(SpamhausDropProvider::empty());
            spamhaus = Some(Arc::clone(&provider));
            ip_reputation.push(provider);
            if let Some(path) = security
                .ip_reputation
                .maxmind_db_path
                .as_deref()
                .filter(|p| !p.trim().is_empty())
            {
                // `open` never fails: an unreadable database degrades the
                // provider to fail-open and logs the reason itself.
                ip_reputation.push(Arc::new(MaxMindAsnProvider::open(MaxMindAsnConfig {
                    db_path: std::path::PathBuf::from(path),
                })));
            }
        }

        Self {
            tarpit: build_tarpit(security),
            challenge: build_challenge(security),
            detector: build_detector(security),
            volume_shield: build_volume_shield(security),
            agg_cap: build_agg_cap(security),
            bot_signal: build_bot_signal(security),
            email_reputation: build_email_reputation(security),
            ip_reputation,
            ip_reputation_policy: IpReputationPolicy {
                enabled: security.ip_reputation.enabled,
                action: match security.ip_reputation.action {
                    IpReputationActionYaml::Block => IpReputationAction::Block,
                    IpReputationActionYaml::Challenge => IpReputationAction::Challenge,
                    IpReputationActionYaml::Log => IpReputationAction::Log,
                },
            },
            spamhaus,
        }
    }

    /// Starts the background refresh for any provider that needs one.
    ///
    /// MUST be called from inside a Tokio runtime. Separate from
    /// [`Self::from_security`] so the guard set can be built in synchronous
    /// start-up code and in tests without a runtime.
    pub fn spawn_background_tasks(&self, security: &SecurityYaml) {
        let Some(spamhaus) = self.spamhaus.as_ref() else {
            return;
        };
        spamhaus.spawn_refresh(SpamhausDropConfig {
            drop_url: security.ip_reputation.spamhaus.drop_url.clone(),
            dropv6_url: security.ip_reputation.spamhaus.dropv6_url.clone(),
            refresh_interval_secs: security.ip_reputation.spamhaus.refresh_interval_secs,
        });
    }

    /// Runs every pre-authentication guard for one login attempt.
    ///
    /// Ordered cheapest-and-most-decisive first: the tenant CIDR policy is a
    /// tenant's explicit instruction and outranks every heuristic; IP
    /// reputation and the bot signal come next; the tarpit and the A-3
    /// detector, which only slow or challenge, come last.
    ///
    /// Every arm is username-independent apart from the detector's cardinality
    /// record, which is not observable in the response, so this MUST NOT
    /// change login enumeration properties.
    #[must_use]
    pub fn pre_auth_login(
        &self,
        ip: Option<IpAddr>,
        username: &str,
        user_agent: Option<&str>,
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

        // P-2 — IP reputation.
        if self.ip_reputation_policy.enabled {
            if let Some(ip) = ip {
                if self.ip_reputation.iter().any(|p| !p.check(ip).is_clean()) {
                    match self.ip_reputation_policy.action {
                        IpReputationAction::Block => {
                            return PreAuthVerdict::Deny {
                                reason: "p2_ip_reputation",
                            }
                        }
                        IpReputationAction::Challenge => {
                            return PreAuthVerdict::Challenge {
                                reason: "p2_ip_reputation",
                            }
                        }
                        IpReputationAction::Log => {
                            tracing::warn!("abuse: ip reputation flagged a login source");
                        }
                    }
                }
            }
        }

        // P-3 — bot signal.
        match self.bot_signal.check(&BotSignalContext {
            user_agent,
            ja3_hash: None,
            ja4_hash: None,
            ip,
        }) {
            BotSignalVerdict::Block { .. } => {
                return PreAuthVerdict::Deny {
                    reason: "p3_bot_signal",
                }
            }
            BotSignalVerdict::Suspect { .. } => {
                return PreAuthVerdict::Challenge {
                    reason: "p3_bot_signal",
                }
            }
            BotSignalVerdict::Allow => {}
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

        // A-17 — tarpit. Last, because it is the only arm that costs the
        // caller wall-clock time.
        match self.tarpit.check(ip) {
            TarpitOutcome::Delay(d) => PreAuthVerdict::Delay(d),
            TarpitOutcome::Allow => PreAuthVerdict::Allow,
        }
    }

    /// Records a failed authentication against the per-IP counters.
    pub fn record_login_failure(&self, ip: Option<IpAddr>) {
        if let Some(ip) = ip {
            self.tarpit.record_failure(ip);
            let _ = self.challenge.record_failure(ip);
        }
    }

    /// Clears the per-IP counters after a successful authentication.
    pub fn record_login_success(&self, ip: Option<IpAddr>) {
        if let Some(ip) = ip {
            self.tarpit.clear(ip);
            self.challenge.clear(ip);
        }
    }

    /// P-5 — email reputation for a self-service registration.
    #[must_use]
    pub fn check_email_reputation(&self, email: &str) -> EmailReputationVerdict {
        self.email_reputation.check(email)
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

    /// A-4 + A-50 — the same two checks for one SMS recipient.
    #[must_use]
    pub fn check_outbound_sms(&self, realm_id: &str, recipient: &str) -> OutboundVerdict {
        let shield = match self.volume_shield.check_sms(realm_id, recipient) {
            VolumeShieldOutcome::HardCap => {
                return OutboundVerdict::Deny {
                    reason: "a4_sms_hard_cap",
                }
            }
            VolumeShieldOutcome::SoftCap => Some("a4_sms_soft_cap"),
            VolumeShieldOutcome::Allow => None,
        };
        match self.agg_cap.check_sms(realm_id, recipient) {
            CrossRealmOutcome::HardCap { .. } => OutboundVerdict::Deny {
                reason: "a50_sms_hard_cap",
            },
            CrossRealmOutcome::SoftCap { .. } => OutboundVerdict::Warn {
                reason: "a50_sms_soft_cap",
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

/// A-17 tarpit. An absent `threshold` is the disabled form.
fn build_tarpit(security: &SecurityYaml) -> TarpitStore {
    TarpitStore::with_config(TarpitConfig {
        threshold: security.tarpit.threshold,
        window_secs: security.tarpit.window_secs,
        delay_ms: security.tarpit.delay_ms,
    })
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
        sms_soft_cap: yaml.sms_soft_cap,
        sms_hard_cap: yaml.sms_hard_cap,
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
        sms_realm_soft_cap: yaml.sms_realm_soft_cap,
        sms_realm_hard_cap: yaml.sms_realm_hard_cap,
    })
}

/// P-3 bot-signal adapter.
fn build_bot_signal(security: &SecurityYaml) -> Arc<dyn BotSignalProvider> {
    let yaml = &security.providers.bot_signal;
    if !yaml.enabled {
        return Arc::new(NoopBotSignalProvider);
    }
    Arc::new(HeuristicBotSignalProvider::new(
        crate::abuse::bot_signal::BotSignalConfig {
            extra_ja3_blocklist: yaml.extra_ja3_blocklist.clone(),
            extra_ja4_blocklist: yaml.extra_ja4_blocklist.clone(),
        },
    ))
}

/// P-5 email-reputation adapter.
fn build_email_reputation(security: &SecurityYaml) -> Arc<dyn EmailReputation> {
    let yaml = &security.providers.email_reputation;
    if !yaml.enabled {
        return Arc::new(NoopEmailReputation);
    }
    Arc::new(BuiltinEmailReputation::new(EmailReputationConfig {
        extra_disposable_domains: yaml.extra_disposable_domains.clone(),
    }))
}

/// Compiles a stored [`CidrPolicy`] into a [`CidrFilter`].
///
/// Unparseable entries are dropped rather than failing the request: the
/// start-up validator already refused them, so reaching here with a bad entry
/// means the record was written by an older binary, and a tenant must not be
/// locked out of their own realm by one stale line (§6.1 fail-open).
fn compile_filter(policy: &CidrPolicy) -> CidrFilter {
    let parse = |v: &Vec<String>| {
        v.iter()
            .filter_map(|s| crate::abuse::cidr::Cidr::parse(s).ok())
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
                 email_hard_cap: 5000\n  sms_soft_cap: 100\n  sms_hard_cap: 500\n",
            ),
            (
                "cross_realm_aggregation_cap",
                "cross_realm_aggregation_cap:\n  window: 3600s\n  alert_threshold: 3\n  \
                 email_realm_soft_cap: 5\n  email_realm_hard_cap: 10\n  \
                 sms_realm_soft_cap: 3\n  sms_realm_hard_cap: 6\n",
            ),
            (
                "risk_scorer",
                "risk_scorer:\n  enabled: true\n  step_up_threshold: 0.5\n  \
                 new_device_weight: 0.3\n  new_country_weight: 0.4\n  \
                 password_age_weight: 0.2\n  password_age_days_threshold: 365\n  \
                 breach_corpus_weight: 1.0\n  refresh_context_delta_weight: 0.35\n",
            ),
            (
                "adaptive_backoff",
                "adaptive_backoff:\n  durations: [\"1m\", \"5m\", \"30m\", \"24h\"]\n  \
                 offense_cooldown: \"7d\"\n",
            ),
            (
                "tarpit",
                "tarpit:\n  threshold: 5\n  window_secs: 60\n  delay_ms: 200\n",
            ),
            (
                "providers.bot_signal",
                "providers:\n  bot_signal:\n    extra_ja3_blocklist:\n      - \
                 \"deadbeef00000000deadbeef00000000\"\n    extra_ja4_blocklist: []\n",
            ),
            (
                "providers.email_reputation",
                "providers:\n  email_reputation:\n    extra_disposable_domains:\n      - \
                 \"my-internal-throwaway.example\"\n",
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

    /// A-17: an operator who sets `security.tarpit.threshold` must see delays
    /// after that many failures. Before task 20.13 nothing built a
    /// `TarpitStore` outside its own test module.
    #[test]
    fn tarpit_is_constructed_from_config_and_delays_after_threshold() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "tarpit:\n  threshold: 2\n  window_secs: 60\n  delay_ms: 150\n",
        ));
        let src = ip(203, 0, 113, 7);
        assert_eq!(
            guards.pre_auth_login(Some(src), "a@example.com", None, None),
            PreAuthVerdict::Allow
        );
        guards.record_login_failure(Some(src));
        guards.record_login_failure(Some(src));
        assert_eq!(
            guards.pre_auth_login(Some(src), "a@example.com", None, None),
            PreAuthVerdict::Delay(Duration::from_millis(150)),
            "the configured tarpit must fire once the threshold is reached"
        );
        guards.record_login_success(Some(src));
        assert_eq!(
            guards.pre_auth_login(Some(src), "a@example.com", None, None),
            PreAuthVerdict::Allow,
            "a successful login must clear the counter"
        );
    }

    /// A-3: distinct usernames from one IP must trip the detector.
    #[test]
    fn distributed_attack_detector_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "distributed_attack_detector:\n  enabled: true\n  window: 300s\n  \
             username_per_ip_threshold: 3\n  ip_per_username_threshold: 100\n",
        ));
        let src = ip(198, 51, 100, 9);
        for i in 0..3 {
            let _ = guards.pre_auth_login(Some(src), &format!("u{i}@example.com"), None, None);
        }
        assert!(
            matches!(
                guards.pre_auth_login(Some(src), "u9@example.com", None, None),
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
                guards.pre_auth_login(Some(src), &format!("u{i}@example.com"), None, None),
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
            guards.pre_auth_login(
                Some(ip(198, 51, 100, 5)),
                "a@example.com",
                None,
                Some(&policy)
            ),
            PreAuthVerdict::Deny {
                reason: "a9_cidr_policy"
            }
        );
        assert_eq!(
            guards.pre_auth_login(
                Some(ip(203, 0, 113, 5)),
                "a@example.com",
                None,
                Some(&policy)
            ),
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
            guards.pre_auth_login(Some(ip(10, 1, 2, 3)), "a@example.com", None, Some(&policy)),
            PreAuthVerdict::Allow
        );
        assert_eq!(
            guards.pre_auth_login(
                Some(ip(203, 0, 113, 5)),
                "a@example.com",
                None,
                Some(&policy)
            ),
            PreAuthVerdict::Deny {
                reason: "a9_cidr_policy"
            }
        );
    }

    /// P-3: the heuristic adapter must be installed when enabled, and a
    /// scripted client refused.
    #[test]
    fn bot_signal_provider_is_constructed_when_enabled() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "providers:\n  bot_signal:\n    enabled: true\n",
        ));
        assert!(
            matches!(
                guards.pre_auth_login(
                    Some(ip(203, 0, 113, 11)),
                    "a@example.com",
                    Some("curl/8.4.0"),
                    None
                ),
                PreAuthVerdict::Deny { .. } | PreAuthVerdict::Challenge { .. }
            ),
            "an enabled bot-signal adapter must flag a scripted client"
        );
        let off = AbuseGuards::from_security(&SecurityYaml::default());
        assert_eq!(
            off.pre_auth_login(
                Some(ip(203, 0, 113, 11)),
                "a@example.com",
                Some("curl/8.4.0"),
                None
            ),
            PreAuthVerdict::Allow,
            "the adapter is opt-in; the default must not block anything"
        );
    }

    /// P-5: the built-in adapter must be installed when enabled.
    #[test]
    fn email_reputation_provider_is_constructed_when_enabled() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "providers:\n  email_reputation:\n    enabled: true\n    \
             extra_disposable_domains:\n      - \"throwaway.example\"\n",
        ));
        assert!(
            guards
                .check_email_reputation("someone@throwaway.example")
                .is_disposable,
            "the operator-supplied disposable domain must reach the adapter"
        );
        let off = AbuseGuards::from_security(&SecurityYaml::default());
        assert!(
            off.check_email_reputation("someone@throwaway.example")
                .is_clean(),
            "the adapter is opt-in; the default must stay clean"
        );
    }

    /// A-4: the per-realm outbound hard cap must refuse a send.
    #[test]
    fn outbound_volume_shield_is_constructed_from_config() {
        let guards = AbuseGuards::from_security(&security_yaml(
            "outbound_volume_shield:\n  enabled: true\n  window: 3600s\n  \
             email_soft_cap: 1\n  email_hard_cap: 2\n  sms_soft_cap: 1\n  sms_hard_cap: 2\n",
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
             alert_threshold: 100\n  email_realm_soft_cap: 100\n  email_realm_hard_cap: 2\n  \
             sms_realm_soft_cap: 100\n  sms_realm_hard_cap: 100\n",
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
                guards.pre_auth_login(Some(src), "a@example.com", None, None),
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
