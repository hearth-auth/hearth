//! Black-box tests for the `src/abuse/` foundation (HEA-1187).
//!
//! Covers:
//! - `AbusePolicy` trait contract
//! - `NoopAbusePolicy` always-allow behaviour
//! - `guard_check` fail-open semantics for missing realm IDs
//! - `RealmAbuseConfig` YAML deserialization (defaults + overrides)
//! - `AbuseDecision` equality
//! - Adversarial: a custom blocking policy is correctly wired through `guard_check`

use std::net::IpAddr;
use std::sync::Arc;

use hearth::abuse::{guard_check, AbuseDecision, AbusePolicy, AbuseRequest, NoopAbusePolicy};
use hearth::core::RealmId;

// ── helpers ──────────────────────────────────────────────────────────────────

fn realm() -> RealmId {
    RealmId::new(uuid::Uuid::new_v4())
}

fn localhost() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

fn make_req(realm_id: &RealmId) -> AbuseRequest<'_> {
    AbuseRequest {
        realm_id,
        client_ip: localhost(),
        endpoint: "token",
    }
}

// ── NoopAbusePolicy ───────────────────────────────────────────────────────────

#[test]
fn noop_always_allows_token() {
    let policy = NoopAbusePolicy;
    let r = realm();
    assert_eq!(policy.check(&make_req(&r)), AbuseDecision::Allow);
}

#[test]
fn noop_always_allows_all_endpoints() {
    let policy = NoopAbusePolicy;
    let r = realm();
    for endpoint in ["token", "authorize", "introspect", "revoke", "users", "other"] {
        let req = AbuseRequest {
            realm_id: &r,
            client_ip: localhost(),
            endpoint,
        };
        assert_eq!(
            policy.check(&req),
            AbuseDecision::Allow,
            "expected Allow for endpoint={endpoint}"
        );
    }
}

#[test]
fn noop_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NoopAbusePolicy>();
}

// ── guard_check fail-open semantics ──────────────────────────────────────────

#[test]
fn guard_check_allows_when_no_realm() {
    // Endpoints without a realm header (e.g. /health, /jwks) must not be blocked.
    let policy = NoopAbusePolicy;
    let decision = guard_check(&policy, None, localhost(), "health");
    assert_eq!(decision, AbuseDecision::Allow);
}

#[test]
fn guard_check_delegates_to_policy_when_realm_present() {
    let policy = NoopAbusePolicy;
    let r = realm();
    let decision = guard_check(&policy, Some(&r), localhost(), "token");
    assert_eq!(decision, AbuseDecision::Allow);
}

// ── AbuseDecision equality ────────────────────────────────────────────────────

#[test]
fn abuse_decision_allow_eq() {
    assert_eq!(AbuseDecision::Allow, AbuseDecision::Allow);
}

#[test]
fn abuse_decision_block_eq_same_reason() {
    assert_eq!(
        AbuseDecision::Block { reason: "rate" },
        AbuseDecision::Block { reason: "rate" }
    );
}

#[test]
fn abuse_decision_block_ne_different_reason() {
    assert_ne!(
        AbuseDecision::Block { reason: "rate" },
        AbuseDecision::Block { reason: "threat" }
    );
}

#[test]
fn abuse_decision_allow_ne_block() {
    assert_ne!(
        AbuseDecision::Allow,
        AbuseDecision::Block { reason: "x" }
    );
}

// ── Adversarial: custom blocking policy ──────────────────────────────────────

/// A policy that blocks every token endpoint request.
struct BlockTokenPolicy;

impl AbusePolicy for BlockTokenPolicy {
    fn check(&self, req: &AbuseRequest<'_>) -> AbuseDecision {
        if req.endpoint == "token" {
            AbuseDecision::Block { reason: "token-blocked" }
        } else {
            AbuseDecision::Allow
        }
    }
}

#[test]
fn custom_policy_blocks_token() {
    let policy = BlockTokenPolicy;
    let r = realm();
    let req = AbuseRequest {
        realm_id: &r,
        client_ip: localhost(),
        endpoint: "token",
    };
    assert_eq!(
        policy.check(&req),
        AbuseDecision::Block { reason: "token-blocked" }
    );
}

#[test]
fn custom_policy_allows_non_token() {
    let policy = BlockTokenPolicy;
    let r = realm();
    let req = AbuseRequest {
        realm_id: &r,
        client_ip: localhost(),
        endpoint: "authorize",
    };
    assert_eq!(policy.check(&req), AbuseDecision::Allow);
}

#[test]
fn guard_check_delegates_block_to_blocking_policy() {
    let policy = BlockTokenPolicy;
    let r = realm();
    let decision = guard_check(&policy, Some(&r), localhost(), "token");
    assert_eq!(decision, AbuseDecision::Block { reason: "token-blocked" });
}

#[test]
fn guard_check_allows_missing_realm_even_with_blocking_policy() {
    // Fail-open: no realm ID → always Allow, regardless of policy.
    let policy = BlockTokenPolicy;
    let decision = guard_check(&policy, None, localhost(), "token");
    assert_eq!(decision, AbuseDecision::Allow);
}

// ── RealmAbuseConfig YAML deserialization ─────────────────────────────────────

#[test]
fn realm_abuse_config_defaults_when_present() {
    let yaml = "enabled: true";
    let cfg: hearth::abuse::RealmAbuseConfig =
        serde_norway::from_str(yaml).expect("deserialize");
    assert!(cfg.enabled);
    assert!(!cfg.fail_closed);
}

#[test]
fn realm_abuse_config_fail_closed_override() {
    let yaml = "enabled: true\nfail_closed: true";
    let cfg: hearth::abuse::RealmAbuseConfig =
        serde_norway::from_str(yaml).expect("deserialize");
    assert!(cfg.enabled);
    assert!(cfg.fail_closed);
}

#[test]
fn realm_abuse_config_disabled() {
    let yaml = "enabled: false";
    let cfg: hearth::abuse::RealmAbuseConfig =
        serde_norway::from_str(yaml).expect("deserialize");
    assert!(!cfg.enabled);
}

#[test]
fn realm_abuse_config_default_impl_has_enabled_true() {
    let cfg = hearth::abuse::RealmAbuseConfig::default();
    assert!(cfg.enabled, "default RealmAbuseConfig must have enabled=true");
    assert!(
        !cfg.fail_closed,
        "default RealmAbuseConfig must be fail-open"
    );
}

// ── Arc<dyn AbusePolicy> interop ──────────────────────────────────────────────

#[test]
fn noop_policy_as_arc_dyn() {
    let policy: Arc<dyn AbusePolicy> = Arc::new(NoopAbusePolicy);
    let r = realm();
    let decision = guard_check(policy.as_ref(), Some(&r), localhost(), "token");
    assert_eq!(decision, AbuseDecision::Allow);
}
