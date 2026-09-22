//! Start-up liveness registry for security-relevant configuration keys.
//!
//! Audit 2026-08-28 §1A item 5, §9 item 2 (task 20.17).
//!
//! # The class of defect this closes
//!
//! `security.http2.max_concurrent_streams` parses, validates, lands in
//! [`SecurityYaml`](super::types::SecurityYaml) — and is then never read: the
//! HTTP/2 rapid-reset caps come from compiled-in constants in
//! `protocol::http`. An operator who tightens that knob after a CVE advisory
//! gets a clean boot, a clean `hearth config validate`, and no change in
//! behaviour. `storage.fsync` had the same shape, and so did
//! `security.reserved_slugs` when the `security:` block was omitted. A field
//! reaching the domain struct is *not* evidence that anything consumes it.
//!
//! # The mechanism
//!
//! [`SECURITY_KEYS`] names every leaf key an operator can write under
//! `security:`, and `AUTH_KEYS` does the same for `auth:` (task 25.25 — the
//! `security.*` boundary was arbitrary, and widening it immediately found
//! `auth.session_ttl` reaching `RealmConfig` and being read by nothing). For
//! each key the table names the module that actually reads it. Three checks
//! hang off it:
//!
//! 1. **Start-up, fail closed** — [`liveness_issues`] walks the leaf keys the
//!    operator actually wrote in their YAML. A key that is not in the registry,
//!    or is registered with [`Consumer::None`], is a hard configuration error.
//!    Defaults are never flagged: only a key the operator explicitly set can
//!    fail, so a dead key with a compiled-in default degrades to a refusal only
//!    for the operator who believed it did something.
//! 2. **Test time, forced registration** — `registry_covers_every_security_leaf`
//!    (in this module's test block) re-derives the leaf key set from
//!    `types.rs` and asserts it equals the registry. Adding a field without
//!    naming its consumer fails the build.
//! 3. **Test time, proven consumer** — `every_registered_consumer_still_exists`
//!    and `every_registered_consumer_is_reachable_from_main`. The first rejects
//!    a consumer entry that names only the config layer, or whose only mention
//!    of the field is in a comment or behind `#[cfg(test)]`. The second walks a
//!    symbol-reference graph from `fn main` and rejects an entry whose consumer
//!    file nothing reachable refers to. Together these close the hole task
//!    25.25 names: `security.ip_reputation.*` was registered against a file that
//!    mentioned the field but whose provider nothing ever constructed, so the
//!    registry asserted a liveness it had not verified.
//!
//! Secret-bearing keys additionally carry [`Sensitivity::Secret`], which makes
//! an empty value a hard error rather than a credential that matches the empty
//! string (§4.13#4 — see [`super::validate`]).

use super::types::ValidationIssue;

/// Whether a key carries credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensitivity {
    /// An ordinary tunable. Empty / zero values are the key's own business.
    Value,
    /// Credential material. An empty value MUST NOT be accepted: an empty
    /// expected secret compares equal to an absent one supplied by a caller.
    Secret,
}

/// Where a configuration key is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Consumer {
    /// The module path that reads the resolved value. Free text — the point is
    /// that a human had to name one, and the accompanying test checks the file
    /// exists and mentions the field.
    At(&'static str),
    /// **Nothing reads this key.** Setting it is refused at start-up until a
    /// consumer is wired or the key is removed.
    None,
}

/// One registered configuration key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SecurityKey {
    /// Dotted path from the config root, e.g. `security.jwks_rps_limit`.
    pub path: &'static str,
    /// The module that reads it, or [`Consumer::None`] for a dead key.
    pub consumer: Consumer,
    /// Whether an empty value is a credential hazard.
    pub sensitivity: Sensitivity,
}

const fn key(path: &'static str, consumer: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::At(consumer),
        sensitivity: Sensitivity::Value,
    }
}

const fn secret(path: &'static str, consumer: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::At(consumer),
        sensitivity: Sensitivity::Secret,
    }
}

/// Marks a key that parses but has no consumer yet.
///
/// The registry currently holds none: task 22.12 wired the last two
/// (`security.http2.*`). It is kept because the next key to be added may land
/// before its consumer does, and because the unwired arm of
/// [`liveness_issues_against`] is tested through it.
#[cfg_attr(not(test), allow(dead_code))]
const fn unwired(path: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::None,
        sensitivity: Sensitivity::Value,
    }
}

/// Every leaf key reachable under `security:` in `hearth.yaml`.
///
/// Keep sorted by path. A new field in `SecurityYaml` (or any struct it
/// contains) MUST be added here with the module that consumes it, or
/// `registry_covers_every_security_leaf` fails.
pub(crate) const SECURITY_KEYS: &[SecurityKey] = &[
    key(
        "security.adaptive_backoff.durations",
        "src/abuse/backoff.rs (AdaptiveBackoffStore, via DeviceApprovalGuard)",
    ),
    key(
        "security.adaptive_backoff.offense_cooldown",
        "src/abuse/backoff.rs (AdaptiveBackoffStore, via DeviceApprovalGuard)",
    ),
    key(
        "security.allowed_hosts",
        "src/protocol/http/state.rs (host allowlist middleware)",
    ),
    key(
        "security.allowed_return_to_origins",
        // The guard itself lives in `src/abuse/redirect.rs`, but it takes the
        // allowlist as a parameter, and every call site passed `&[]` until the
        // accessor below was added — the registry's old entry named a file that
        // only mentioned the key in a doc comment.
        "src/protocol/web/mod.rs (WebState::allowed_return_to_origins)",
    ),
    key(
        "security.backup.export_rate_limit",
        // `ExportRateLimiter` lives in `src/protocol/admin_auth.rs`, but it is
        // `src/main.rs` that reads the configured value and hands it over —
        // naming only the type's file is not evidence the value is consumed.
        "src/main.rs (ExportRateLimiter wiring), src/protocol/http/auth.rs",
    ),
    secret(
        "security.backup.verify_key",
        "src/main.rs (backup manifest verification)",
    ),
    key(
        "security.captcha.challenge_threshold",
        "src/abuse/runtime.rs (IpChallengeStore, A-16)",
    ),
    key(
        "security.captcha.challenge_ttl_secs",
        "src/abuse/runtime.rs (IpChallengeStore, A-16)",
    ),
    key(
        "security.captcha.provider",
        "src/abuse/captcha/mod.rs, src/main.rs",
    ),
    key(
        "security.captcha.window_secs",
        "src/abuse/runtime.rs (IpChallengeStore, A-16)",
    ),
    key(
        "security.cross_realm_aggregation_cap.alert_threshold",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.email_realm_hard_cap",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.email_realm_soft_cap",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.enabled",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.sms_realm_hard_cap",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.sms_realm_soft_cap",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.cross_realm_aggregation_cap.window",
        "src/abuse/runtime.rs (CrossRealmAggregationCap, A-50)",
    ),
    key(
        "security.captcha.turnstile.site_key",
        "src/abuse/captcha/mod.rs",
    ),
    secret(
        "security.captcha.turnstile.secret_key",
        "src/abuse/captcha/mod.rs",
    ),
    key(
        "security.captcha.turnstile.verify_url",
        "src/abuse/captcha/mod.rs",
    ),
    key(
        "security.dev_csp_form_action_origins",
        "src/protocol/web/security.rs, src/protocol/web/mod.rs",
    ),
    key(
        "security.distributed_attack_detector.enabled",
        "src/abuse/runtime.rs (DistributedAttackDetector, A-3)",
    ),
    key(
        "security.distributed_attack_detector.ip_per_username_threshold",
        "src/abuse/runtime.rs (DistributedAttackDetector, A-3)",
    ),
    key(
        "security.distributed_attack_detector.username_per_ip_threshold",
        "src/abuse/runtime.rs (DistributedAttackDetector, A-3)",
    ),
    key(
        "security.distributed_attack_detector.window",
        "src/abuse/runtime.rs (DistributedAttackDetector, A-3)",
    ),
    secret(
        "security.dpop_nonce_secret",
        "src/main.rs (DPoP nonce HMAC key)",
    ),
    key(
        "security.grpc.reflection_enabled",
        "src/protocol/grpc/server.rs",
    ),
    // Wired by 22.12: `main.rs` installs these through
    // `protocol::http::limits::init_server_limits`, and BOTH accept loops
    // (`serve_router_on` and `serve_tls_router`) read them. They were
    // compiled-in constants applied on the TLS loop only.
    key(
        "security.http2.max_concurrent_streams",
        "src/protocol/http/limits.rs (both accept loops)",
    ),
    key(
        "security.http2.max_pending_reset_streams",
        "src/protocol/http/limits.rs (both accept loops)",
    ),
    key(
        "security.ip_reputation.action",
        "src/abuse/ip_reputation/mod.rs",
    ),
    key(
        "security.ip_reputation.enabled",
        "src/abuse/ip_reputation/mod.rs",
    ),
    key(
        "security.ip_reputation.maxmind_db_path",
        "src/abuse/ip_reputation/maxmind.rs, src/abuse/runtime.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.drop_url",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.dropv6_url",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.refresh_interval_secs",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.jwks_rps_limit",
        "src/protocol/admin_auth.rs (JwksRateLimiter), src/main.rs",
    ),
    secret(
        "security.key_encryption_key",
        "src/identity/key_encryption.rs",
    ),
    key(
        "security.load_test_unthrottled",
        "src/main.rs (loopback-gated)",
    ),
    key(
        "security.outbound_volume_shield.email_hard_cap",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.outbound_volume_shield.email_soft_cap",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.outbound_volume_shield.enabled",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.outbound_volume_shield.sms_hard_cap",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.outbound_volume_shield.sms_soft_cap",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.outbound_volume_shield.window",
        "src/abuse/runtime.rs (OutboundVolumeShield, A-4)",
    ),
    key(
        "security.password.kdf.admin_max_in_flight",
        "src/config/validate.rs::resolve_admin_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.admin_max_queue_wait_ms",
        "src/config/validate.rs::resolve_admin_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.max_in_flight",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.max_queue_wait_ms",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.retry_after_seconds",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    secret(
        "security.password.pepper.key_hex",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    secret(
        "security.password.pepper.previous_key_hex",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.password.pepper.previous_version",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.password.pepper.version",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.providers.bot_signal.enabled",
        "src/abuse/runtime.rs (HeuristicBotSignalProvider, P-3)",
    ),
    key(
        "security.providers.bot_signal.extra_ja3_blocklist",
        "src/abuse/runtime.rs (HeuristicBotSignalProvider, P-3)",
    ),
    key(
        "security.providers.bot_signal.extra_ja4_blocklist",
        "src/abuse/runtime.rs (HeuristicBotSignalProvider, P-3)",
    ),
    key(
        "security.providers.email_reputation.enabled",
        "src/abuse/runtime.rs (BuiltinEmailReputation, P-5)",
    ),
    key(
        "security.providers.email_reputation.extra_disposable_domains",
        "src/abuse/runtime.rs (BuiltinEmailReputation, P-5)",
    ),
    key(
        "security.rate_limiting.admin_per_minute",
        "src/protocol/admin_auth.rs (AdminRateLimiter), src/main.rs",
    ),
    key(
        "security.rate_limiting.login_per_account.lockout_seconds",
        "src/main.rs (account lockout policy)",
    ),
    key(
        "security.rate_limiting.login_per_account.max_failures",
        "src/main.rs (account lockout policy)",
    ),
    key(
        "security.rate_limiting.login_per_ip.max_attempts",
        "src/main.rs (per-IP login limiter)",
    ),
    key(
        "security.rate_limiting.login_per_ip.window_seconds",
        "src/main.rs (per-IP login limiter)",
    ),
    key(
        "security.rate_limiting.token_per_minute",
        "src/protocol/admin_auth.rs (TokenRateLimiter), src/main.rs",
    ),
    key("security.request_shaper.ip_rps", "src/abuse/shaper.rs"),
    key("security.request_shaper.realm_rps", "src/abuse/shaper.rs"),
    key(
        "security.reserved_slugs",
        "src/identity/engine/mod.rs (slug reservation)",
    ),
    key(
        "security.risk_scorer.breach_corpus_weight",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.enabled",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.new_country_weight",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.new_device_weight",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.password_age_days_threshold",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.password_age_weight",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.refresh_context_delta_weight",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.risk_scorer.step_up_threshold",
        "src/identity/reconcile.rs -> RealmConfig::risk_scorer_config -> src/abuse/risk_scorer.rs",
    ),
    key(
        "security.slug_cooldown_days",
        "src/identity/keys.rs (slug reservation key TTL), src/main.rs",
    ),
    key(
        "security.tarpit.delay_ms",
        "src/abuse/runtime.rs (TarpitStore, A-17)",
    ),
    key(
        "security.tarpit.threshold",
        "src/abuse/runtime.rs (TarpitStore, A-17)",
    ),
    key(
        "security.tarpit.window_secs",
        "src/abuse/runtime.rs (TarpitStore, A-17)",
    ),
    key("security.tls.crl_paths", "src/protocol/tls.rs"),
    key(
        "security.tls.min_version",
        "src/protocol/tls.rs, src/main.rs",
    ),
];

/// Secret-bearing keys outside the `security:` tree.
///
/// These are not part of the `security:` liveness walk but obey the same
/// empty-value rule: an empty expected credential compares equal to a caller
/// who supplied nothing (§4.13#4). Wildcards use `*` for one path segment and
/// `[]` for "every element of a sequence".
pub(crate) const SECRET_KEYS_OUTSIDE_SECURITY: &[&str] = &[
    "metrics.bearer_token",
    "email.smtp.password",
    "email.sendgrid.api_key",
    "email.mailgun.api_key",
    "email.postmark.server_token",
    "email.mailtrap.api_token",
    "sms.twilio.auth_token",
    "sms.sns.secret_access_key",
    "realms.*.scim.bearer_token",
    // `applications` and `federation.providers` are YAML *maps* keyed by client
    // id, so their leaf paths are `realms.<realm>.applications.<id>.<field>`.
    // A `[]` pattern here never matched, which is how an empty client secret
    // reached the config unflagged.
    "realms.*.applications.*.client_secret",
    "realms.*.oauth_clients.*.client_secret",
    "realms.*.federation.providers.*.client_secret",
    "realms.*.federation.providers[].client_secret",
];

// ── `auth.*` (task 25.25) ────────────────────────────────────────────────────

/// Every leaf key an operator can write under `auth:`.
///
/// The registry began at `security.*` because that is where the audit found its
/// first dead knob. The boundary was arbitrary: `auth:` carries the session
/// lifetime, the Argon2 cost parameters and the WebAuthn policy — controls an
/// operator is at least as likely to set and just as unlikely to verify.
/// Widening it here immediately found one: `auth.session_ttl` parsed,
/// validated, reached `RealmConfig::session_ttl_micros` and was read by nothing,
/// so every session expired on the compiled-in 24 h default. It is wired in
/// `create_session` as part of this task; without the widening nothing would
/// have asked.
const AUTH_KEYS: &[SecurityKey] = &[
    key(
        "auth.session_ttl",
        "src/config/types.rs -> src/identity/engine/mod.rs (create_session reads \
         RealmConfig::session_ttl_micros)",
    ),
    key(
        "auth.password_memory_cost",
        "src/config/types.rs -> src/main.rs (base_credential_config)",
    ),
    key(
        "auth.password_time_cost",
        "src/config/types.rs -> src/main.rs (base_credential_config)",
    ),
    key(
        "auth.mfa_required",
        "src/config/types.rs -> src/identity/engine/mod.rs (create_session)",
    ),
    key(
        "auth.mfa_methods",
        "src/config/types.rs -> src/identity/engine/mod.rs (require_mfa_method gates \
         TOTP, WebAuthn, SMS-OTP and email-OTP enrolment and presentation)",
    ),
    key(
        "auth.passkey_requires_mfa",
        "src/config/types.rs -> src/protocol/web/handlers.rs",
    ),
    key(
        "auth.session_max_concurrent",
        "src/config/types.rs -> src/identity/engine/mod.rs (max_concurrent_sessions)",
    ),
    key(
        "auth.session_over_limit_policy",
        "src/config/types.rs -> src/identity/engine/mod.rs (session_over_limit_policy)",
    ),
    key(
        "auth.webauthn_required",
        "src/config/types.rs -> src/identity/engine/mod.rs (create_session, use-time via \
         MfaProof::satisfies_webauthn_required) + src/protocol/web/required_action.rs \
         (inject_enroll_mfa_if_needed, enrolment-time)",
    ),
    key(
        "auth.webauthn_resident_key",
        "src/config/types.rs -> src/protocol/web/account.rs",
    ),
    key(
        "auth.webauthn_user_verification",
        "src/config/types.rs -> src/protocol/web/handlers.rs",
    ),
];

/// Every registered path in every block, for external assertions.
pub(crate) fn registered_paths() -> impl Iterator<Item = &'static str> {
    SECURITY_KEYS.iter().chain(AUTH_KEYS.iter()).map(|k| k.path)
}

/// Looks a dotted path up in whichever block registry owns it.
fn lookup_any(path: &str) -> Option<&'static SecurityKey> {
    lookup_in(SECURITY_KEYS, path).or_else(|| lookup_in(AUTH_KEYS, path))
}

fn lookup_in<'a>(registry: &'a [SecurityKey], path: &str) -> Option<&'a SecurityKey> {
    registry.iter().find(|k| k.path == path)
}

/// Collects every leaf path present in `value`, prefixed by `prefix`.
///
/// A sequence contributes its own path once (it is a leaf as far as the
/// registry is concerned — `allowed_hosts`, `crl_paths`), and is not walked
/// element-by-element.
fn collect_leaves(prefix: &str, value: &serde_norway::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_norway::Value::Mapping(map) => {
            for (k, v) in map {
                let Some(name) = k.as_str() else { continue };
                let path = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}.{name}")
                };
                match v {
                    serde_norway::Value::Mapping(_) => collect_leaves(&path, v, out),
                    other => out.push((path, scalar_text(other))),
                }
            }
        }
        other => out.push((prefix.to_string(), scalar_text(other))),
    }
}

/// Renders a scalar for the empty-value check. Non-scalars render as a
/// non-empty placeholder so only genuinely empty strings trip the rule.
fn scalar_text(value: &serde_norway::Value) -> String {
    match value {
        serde_norway::Value::String(s) => s.clone(),
        serde_norway::Value::Null => String::new(),
        other => format!("{other:?}"),
    }
}

/// Reports every `security.*` key the operator set that no consumer reads.
///
/// `yaml` is the **post-substitution** config text (see
/// [`super::env::substitute_env_vars`]). Returns one issue per offending key so
/// `validate_all` can surface them all at once; [`assert_wired`] turns the
/// first into a hard error for the start-up path.
pub(crate) fn liveness_issues(yaml: &str) -> Vec<ValidationIssue> {
    let mut issues = liveness_issues_against(SECURITY_KEYS, yaml);
    issues.extend(liveness_issues_in_block(AUTH_KEYS, yaml, "auth"));
    issues
}

/// [`liveness_issues`] against an explicit registry.
///
/// Production always passes [`SECURITY_KEYS`]. The seam exists so the unwired
/// arm stays testable: every real key currently has a consumer, so a test that
/// used a real key as its example would silently stop exercising the arm the
/// moment that key was wired. That is exactly what happened when task 22.12
/// wired `security.http2.*`.
fn liveness_issues_against(registry: &[SecurityKey], yaml: &str) -> Vec<ValidationIssue> {
    liveness_issues_in_block(registry, yaml, "security")
}

/// [`liveness_issues_against`] for an arbitrary top-level block.
///
/// The registry covers `security:` and — since task 25.25 — `auth:`. The block
/// name is a parameter rather than two copies of the walk so a third block
/// cannot be added with a subtly different rule.
fn liveness_issues_in_block(
    registry: &[SecurityKey],
    yaml: &str,
    block: &str,
) -> Vec<ValidationIssue> {
    let Ok(root) = serde_norway::from_str::<serde_norway::Value>(yaml) else {
        // A YAML parse failure is reported by the caller's own parse; there is
        // nothing to walk here.
        return Vec::new();
    };
    let serde_norway::Value::Mapping(top) = &root else {
        return Vec::new();
    };
    let Some(section) = top
        .iter()
        .find(|(k, _)| k.as_str() == Some(block))
        .map(|(_, v)| v)
    else {
        return Vec::new();
    };
    if !matches!(section, serde_norway::Value::Mapping(_)) {
        return Vec::new();
    }

    let mut leaves = Vec::new();
    collect_leaves(block, section, &mut leaves);

    let mut issues = Vec::new();
    for (path, _) in &leaves {
        match lookup_in(registry, path) {
            None => issues.push(ValidationIssue {
                field: path.clone(),
                reason: format!(
                    "is not a registered configuration key. Every key under `{block}:` must \
                     name the module that consumes it in `src/config/security_keys.rs`; a key \
                     nobody reads is a control the operator believes is on and is not."
                ),
            }),
            Some(k) if k.consumer == Consumer::None => issues.push(ValidationIssue {
                field: path.clone(),
                reason: "is parsed but no code reads it, so setting it has no effect. Remove \
                         the key from your config; it is tracked in \
                         `src/config/security_keys.rs` and will start working once a consumer \
                         is wired."
                    .to_string(),
            }),
            Some(_) => {}
        }
    }
    issues
}

/// Reports every registered secret key that is present but empty.
///
/// An empty expected credential is worse than an absent one: the `/metrics`
/// guard and `client_secret_basic` both compare the caller's supplied value
/// against it, and a caller who supplies nothing compares equal (§4.13#4).
pub(crate) fn empty_secret_issues(yaml: &str) -> Vec<ValidationIssue> {
    let Ok(root) = serde_norway::from_str::<serde_norway::Value>(yaml) else {
        return Vec::new();
    };
    let mut leaves = Vec::new();
    collect_leaves("", &root, &mut leaves);

    let mut issues = Vec::new();
    for (path, text) in &leaves {
        if !text.is_empty() {
            continue;
        }
        let is_secret = lookup_any(path).is_some_and(|k| k.sensitivity == Sensitivity::Secret)
            || SECRET_KEYS_OUTSIDE_SECURITY
                .iter()
                .any(|pat| matches_pattern(pat, path));
        if is_secret {
            issues.push(ValidationIssue {
                field: path.clone(),
                reason: "must not be the empty string. An empty expected secret compares equal \
                         to a caller that supplied none, so the credential check passes for \
                         everyone. Remove the key to disable the check, or set a real value."
                    .to_string(),
            });
        }
    }
    issues
}

/// Matches a dotted path against a registry pattern.
///
/// `*` matches exactly one path segment. A `[]` suffix on a segment means the
/// value is a sequence, whose elements the walker flattens into
/// `<segment>` — sequences are leaves here, so `[]` patterns are matched
/// against the sequence path itself plus the trailing field name.
fn matches_pattern(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('.').collect();
    let seg: Vec<&str> = path.split('.').collect();
    if pat.len() != seg.len() {
        return false;
    }
    pat.iter()
        .zip(seg.iter())
        .all(|(p, s)| *p == "*" || p.trim_end_matches("[]") == *s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The registry is only a control if it is forced to match the struct.
    ///
    /// Re-derives the leaf key set from `src/config/types.rs` and compares it
    /// to [`SECURITY_KEYS`]. Adding a field to `SecurityYaml` (or any struct it
    /// contains) without naming a consumer fails here, which is the whole
    /// point: a new security key cannot merge unregistered.
    #[test]
    fn registry_covers_every_security_leaf() {
        let source = include_str!("types.rs");
        let mut derived = derive_leaves(source, "SecurityYaml", "security");
        // Task 25.25 — `auth:` is registered on exactly the same terms.
        derived.extend(derive_leaves(source, "AuthConfig", "auth"));
        let registered: BTreeSet<&str> = registered_paths().collect();
        let derived_refs: BTreeSet<&str> = derived.iter().map(String::as_str).collect();

        let missing: Vec<&&str> = derived_refs.difference(&registered).collect();
        assert!(
            missing.is_empty(),
            "these `security:` / `auth:` keys exist in types.rs but are not registered in \
             SECURITY_KEYS / AUTH_KEYS — add each one with the module that consumes it: \
             {missing:?}"
        );

        let stale: Vec<&&str> = registered.difference(&derived_refs).collect();
        assert!(
            stale.is_empty(),
            "these registry entries no longer match a field in types.rs (renamed or \
             removed?): {stale:?}"
        );
    }

    /// Every registered consumer must name a file that still exists, and at
    /// least one of the named files must still mention the field, so a key
    /// cannot keep a stale consumer after the code that read it is deleted.
    ///
    /// Task 25.25 tightened "mentions the field" three ways, because the loose
    /// form was satisfiable without a consumer at all:
    ///
    /// * the mention must survive comment-stripping — a doc comment describing
    ///   a knob is not a consumer of it;
    /// * the mention must survive `#[cfg(test)]`-stripping — a test fixture is
    ///   not a consumer either;
    /// * at least one named file must live outside `src/config/`. Every key's
    ///   own declaration is in `src/config/types.rs` and every validator in
    ///   `src/config/validate.rs`, so an entry naming only those two provably
    ///   proves nothing. No shipped entry named only config files when this
    ///   rule was added, so it is a forward guard rather than a cleanup.
    #[test]
    fn every_registered_consumer_still_exists() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut failures: Vec<String> = Vec::new();
        for k in SECURITY_KEYS.iter().chain(AUTH_KEYS.iter()) {
            let Consumer::At(consumer) = k.consumer else {
                continue;
            };
            let field = k.path.rsplit('.').next().unwrap_or(k.path);
            let mut named_any = false;
            let mut named_outside_config = false;
            let mut mentions_field = false;
            // The consumer string may name several hops ("a -> b") and may
            // carry a parenthesised note; check every `src/...rs` token in it.
            for token in consumer.split_whitespace() {
                let file = token.trim_matches(|c: char| !c.is_ascii_graphic());
                let file = file.split("::").next().unwrap_or(file);
                let is_rust_source = std::path::Path::new(file)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
                if !file.starts_with("src/") || !is_rust_source {
                    continue;
                }
                named_any = true;
                if !file.starts_with("src/config/") {
                    named_outside_config = true;
                }
                let path = repo_root.join(file);
                assert!(
                    path.exists(),
                    "{}: registered consumer {file} does not exist",
                    k.path
                );
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{}: reading {file}: {e}", k.path));
                if strip_tests(&strip_comments(&body)).contains(field) {
                    mentions_field = true;
                }
            }
            // Accumulate rather than failing at the first offender: a registry
            // sweep is only useful if one run names EVERY key that lost its
            // consumer, otherwise fixing them is a one-per-run grind.
            if !named_any {
                failures.push(format!(
                    "{}: the consumer entry names no `src/**.rs` file",
                    k.path
                ));
            } else if !named_outside_config {
                failures.push(format!(
                    "{}: the consumer entry names only files under `src/config/`. Every key is \
                     declared in `src/config/types.rs` and checked in `src/config/validate.rs`, \
                     so naming those is not evidence that anything reads the resolved value — \
                     name the module that acts on it",
                    k.path
                ));
            } else if !mentions_field {
                failures.push(format!(
                    "{}: no registered consumer file mentions `{field}` in live, non-test code \
                     (comments and `#[cfg(test)]` blocks are stripped before this check) — the \
                     key may have lost its consumer",
                    k.path
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} registered key(s) have no live consumer:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }

    /// Every registered consumer file must be reachable from `fn main`.
    ///
    /// This is the check task 25.25 asks for: "a constructor is reachable from
    /// `main`", not merely "a file mentions the field".
    /// `security.ip_reputation.*` was registered against a file that mentioned
    /// the field while nothing ever constructed its provider — the registry
    /// asserted a liveness nobody had verified, which is worse than no registry,
    /// because an operator reads a clean boot as proof the knob works.
    ///
    /// The graph is textual and deliberately over-approximating: a file A
    /// reaches a file B when A's live code names any distinctive symbol that B
    /// defines. Over-approximation means this test does not cry wolf; what it
    /// still catches with certainty is the shape that matters — a consumer file
    /// that **nothing reachable refers to at all**, which is what a constructor
    /// nobody calls looks like from here. Its limits are real: it cannot see
    /// that a reachable file calls a *different* function than the one that
    /// reads the key, so it is a floor under the consumer claim and not a proof
    /// of it.
    #[test]
    fn every_registered_consumer_is_reachable_from_main() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let sources = live_sources(&repo_root.join("src"));
        let reachable = reachable_from_main(&sources);
        assert!(
            reachable.len() > 10,
            "the reachability walk found only {} files from `src/main.rs`; the graph is \
             broken and every assertion below would pass vacuously",
            reachable.len()
        );

        for k in SECURITY_KEYS.iter().chain(AUTH_KEYS.iter()) {
            let Consumer::At(consumer) = k.consumer else {
                continue;
            };
            let files = consumer_files(consumer);
            assert!(
                files.iter().any(|f| reachable.contains(f)),
                "{}: no registered consumer file is reachable from `fn main` \
                 ({files:?}). Nothing in the live call graph refers to any symbol these \
                 files define, so the key's consumer is dead code and setting the key does \
                 nothing",
                k.path
            );
        }
    }

    /// A key nobody reads is refused when the operator sets it explicitly, and
    /// ignored when it is only a compiled-in default.
    #[test]
    fn unwired_key_is_refused_only_when_explicitly_set() {
        // A synthetic registry, not a real key. Every real key has a consumer
        // today, so pinning this arm to one would make the test evaporate the
        // moment that key was wired.
        let registry = &[
            unwired("security.jwks_rps_limit"),
            key("security.slug_cooldown_days", "src/identity/reconcile.rs"),
        ];

        let set = "security:\n  jwks_rps_limit: 60\n";
        let issues = liveness_issues_against(registry, set);
        assert_eq!(
            issues.len(),
            1,
            "expected exactly one issue, got {issues:?}"
        );
        assert_eq!(issues[0].field, "security.jwks_rps_limit");
        assert!(
            issues[0].reason.contains("no code reads it"),
            "the operator must be told the key is dead, not merely unknown: {issues:?}"
        );

        let other = "security:\n  slug_cooldown_days: 30\n";
        assert!(
            liveness_issues_against(registry, other).is_empty(),
            "a registered, wired key must not be flagged"
        );

        // And nothing at all is flagged when the operator sets no security key.
        assert!(
            liveness_issues_against(registry, "storage:\n  data_dir: \"/tmp/x\"\n").is_empty(),
            "a compiled-in default must never be flagged"
        );
    }

    /// The real registry has no dead keys. If this fails, a key was added
    /// without a consumer — wire it, or mark it `unwired` deliberately.
    #[test]
    fn the_shipped_registry_has_no_unwired_keys() {
        let dead: Vec<_> = SECURITY_KEYS
            .iter()
            .filter(|k| k.consumer == Consumer::None)
            .map(|k| k.path)
            .collect();
        assert!(
            dead.is_empty(),
            "these security keys parse but nothing reads them: {dead:?}"
        );
    }

    #[test]
    fn unknown_security_key_is_refused() {
        // `deny_unknown_fields` catches this at parse time too; the registry is
        // the belt to that suspenders, and covers keys added to the struct but
        // never registered.
        let issues = liveness_issues("security:\n  totally_made_up: true\n");
        assert_eq!(issues.len(), 1);
        assert!(issues[0]
            .reason
            .contains("not a registered configuration key"));
    }

    #[test]
    fn empty_secret_is_reported_and_empty_tunable_is_not() {
        let issues = empty_secret_issues("metrics:\n  bearer_token: \"\"\n");
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert_eq!(issues[0].field, "metrics.bearer_token");

        assert!(
            empty_secret_issues("server:\n  bind_address: \"\"\n").is_empty(),
            "a non-secret empty value is not this check's business"
        );
    }

    #[test]
    fn wildcard_patterns_match_a_realm_scoped_secret() {
        assert!(matches_pattern(
            "realms.*.scim.bearer_token",
            "realms.acme.scim.bearer_token"
        ));
        assert!(!matches_pattern(
            "realms.*.scim.bearer_token",
            "realms.acme.scim.other"
        ));
    }

    // ── Task 25.25 — source analysis helpers ────────────────────────────────
    //
    // These parse SOURCE rather than reflecting over `serde`, deliberately:
    // the whole point is to notice a field that was *added to the struct*,
    // which no runtime value can tell us about. They are textual, and say so.
    // A borrow-checked call graph is what `cargo` has and a test does not; the
    // question here is narrower than a real one — "does anything live still
    // refer to this file at all" — and text answers it well enough to catch a
    // consumer nobody calls.

    /// Extracts every `src/**.rs` file named in a consumer entry.
    fn consumer_files(consumer: &str) -> Vec<String> {
        consumer
            .split_whitespace()
            .filter_map(|token| {
                let file = token.trim_matches(|c: char| !c.is_ascii_graphic());
                let file = file.split("::").next().unwrap_or(file);
                let is_rust = std::path::Path::new(file)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
                (file.starts_with("src/") && is_rust).then(|| file.to_string())
            })
            .collect()
    }

    /// Removes line and block comments, leaving string literals intact.
    ///
    /// String awareness matters: `"https://example.com"` must not be truncated
    /// at the `//`, or a field name later on that line disappears and the
    /// consumer check fails for a consumer that is perfectly alive.
    fn strip_comments(src: &str) -> String {
        let b: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                '/' if i + 1 < b.len() && b[i + 1] == '/' => {
                    while i < b.len() && b[i] != '\n' {
                        i += 1;
                    }
                }
                '/' if i + 1 < b.len() && b[i + 1] == '*' => {
                    i += 2;
                    while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                        i += 1;
                    }
                    i = (i + 2).min(b.len());
                    out.push(' ');
                }
                'r' if i + 1 < b.len() && (b[i + 1] == '"' || b[i + 1] == '#') => {
                    let start = i;
                    i += 1;
                    let mut hashes = 0;
                    while i < b.len() && b[i] == '#' {
                        hashes += 1;
                        i += 1;
                    }
                    if i >= b.len() || b[i] != '"' {
                        // Not a raw string after all (`r` was an identifier).
                        out.push(b[start]);
                        i = start + 1;
                        continue;
                    }
                    i += 1;
                    while i < b.len() {
                        if b[i] == '"' && b[i + 1..].iter().take(hashes).all(|c| *c == '#') {
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                    out.extend(&b[start..i.min(b.len())]);
                }
                '"' => {
                    let start = i;
                    i += 1;
                    while i < b.len() && b[i] != '"' {
                        i += if b[i] == '\\' { 2 } else { 1 };
                    }
                    i = (i + 1).min(b.len());
                    out.extend(&b[start..i]);
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }

    /// Removes every `#[cfg(test)]` item, brace- or semicolon-delimited.
    fn strip_tests(src: &str) -> String {
        const MARKER: &str = "#[cfg(test)]";
        let mut out = src.to_string();
        while let Some(at) = out.find(MARKER) {
            let rest = &out[at + MARKER.len()..];
            let Some(end) = cfg_item_end(rest) else {
                // Malformed tail: drop everything from the marker rather than
                // loop forever, and let the caller's assertion speak.
                out.truncate(at);
                break;
            };
            out.replace_range(at..at + MARKER.len() + end, "");
        }
        out
    }

    /// Byte offset just past the `#[cfg(test)]` item that starts `rest`.
    fn cfg_item_end(rest: &str) -> Option<usize> {
        let mut depth = 0usize;
        for (i, c) in rest.char_indices() {
            match c {
                ';' if depth == 0 => return Some(i + 1),
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Every `src/**.rs` file, keyed by repo-relative path, comment- and
    /// test-stripped.
    fn live_sources(dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let Ok(body) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    let Ok(rel) = path.strip_prefix(root) else {
                        continue;
                    };
                    out.insert(
                        rel.to_string_lossy().replace('\\', "/"),
                        strip_tests(&strip_comments(&body)),
                    );
                }
            }
        }
        out
    }

    /// Identifiers too generic to carry a file attribution.
    ///
    /// `new` is defined in almost every file, so treating a mention of it as an
    /// edge would make every file reachable from every other and the test would
    /// assert nothing.
    const GENERIC_SYMBOLS: &[&str] = &[
        "new", "default", "from", "into", "run", "get", "set", "build", "init", "next", "name",
        "path", "value", "state", "config", "error", "Error", "Config", "State", "Value", "Result",
        "tests", "main", "len", "push", "insert", "check", "parse", "clone", "Builder", "Request",
        "Response", "Handler", "Entry", "Key", "Id",
    ];

    /// Collects the distinctive symbols each file defines.
    fn symbol_defs(
        sources: &std::collections::BTreeMap<String, String>,
    ) -> std::collections::HashMap<String, Vec<String>> {
        const KINDS: &[&str] = &[
            "fn ", "struct ", "enum ", "trait ", "const ", "static ", "type ", "union ",
        ];
        let mut defs: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (file, body) in sources {
            for line in body.lines() {
                let t = line.trim_start();
                for kind in KINDS {
                    // `find` rather than `strip_prefix` so `pub(crate) async fn`,
                    // `pub(super) const` and the rest are all covered by one rule.
                    // The offset bound keeps a `fn ` deep inside a signature from
                    // being read as a definition.
                    let Some(rest) = t
                        .find(kind)
                        .filter(|i| *i < 40)
                        .map(|i| &t[i + kind.len()..])
                    else {
                        continue;
                    };
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if name.len() >= 4 && !GENERIC_SYMBOLS.contains(&name.as_str()) {
                        defs.entry(name).or_default().push(file.clone());
                    }
                    break;
                }
            }
        }
        defs
    }

    /// Splits a source file into the identifiers it mentions.
    fn identifiers(body: &str) -> std::collections::HashSet<&str> {
        body.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| t.len() >= 4)
            .collect()
    }

    /// Breadth-first file reachability from `src/main.rs`.
    fn reachable_from_main(
        sources: &std::collections::BTreeMap<String, String>,
    ) -> std::collections::BTreeSet<String> {
        let defs = symbol_defs(sources);
        let mut reached: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut frontier = vec!["src/main.rs".to_string()];
        reached.insert("src/main.rs".to_string());
        while let Some(file) = frontier.pop() {
            let Some(body) = sources.get(&file) else {
                continue;
            };
            for ident in identifiers(body) {
                let Some(owners) = defs.get(ident) else {
                    continue;
                };
                for owner in owners {
                    if reached.insert(owner.clone()) {
                        frontier.push(owner.clone());
                    }
                }
            }
        }
        reached
    }

    fn derive_leaves(source: &str, root_struct: &str, prefix: &str) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut structs: std::collections::HashMap<String, Vec<(String, String)>> =
            std::collections::HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("pub struct ") else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let mut fields = Vec::new();
            for body in &lines[i + 1..] {
                if body.starts_with('}') {
                    break;
                }
                let b = body.trim();
                let Some(decl) = b.strip_prefix("pub ") else {
                    continue;
                };
                let Some(stripped) = decl.strip_suffix(',') else {
                    continue;
                };
                let Some((field, ty)) = stripped.split_once(": ") else {
                    continue;
                };
                if field.contains(' ') {
                    continue;
                }
                fields.push((field.to_string(), ty.to_string()));
            }
            structs.insert(name, fields);
        }

        fn walk(
            structs: &std::collections::HashMap<String, Vec<(String, String)>>,
            ty: &str,
            prefix: &str,
            out: &mut Vec<String>,
            depth: usize,
        ) {
            if depth > 6 {
                return;
            }
            let Some(fields) = structs.get(ty) else {
                return;
            };
            for (field, field_ty) in fields {
                let inner = field_ty
                    .strip_prefix("Option<")
                    .and_then(|s| s.strip_suffix('>'))
                    .unwrap_or(field_ty);
                let base: String = inner
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let path = format!("{prefix}.{field}");
                if structs.contains_key(&base) {
                    walk(structs, &base, &path, out, depth + 1);
                } else {
                    out.push(path);
                }
            }
        }

        let mut out = Vec::new();
        walk(&structs, root_struct, prefix, &mut out, 0);
        assert!(
            !out.is_empty(),
            "derive_leaves found no fields on `{root_struct}` — the struct was renamed or the \
             parser no longer matches its declaration, which would make every assertion built \
             on it pass vacuously"
        );
        out
    }
}
