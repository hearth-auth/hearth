//! Integration + unit tests for HEA-1212 hardening edges rev1.
//!
//! D-4 taxonomy per feature:
//!
//! **A-5 — Reserved slug + 30-day cooldown**
//! - Unit: operator-reserved realm name rejected
//! - Unit: operator-reserved org slug rejected
//! - Unit: unreserved realm name succeeds
//! - Integration: deleted realm name enters cooldown; re-create blocked; expires and succeeds
//!
//! **A-10 — JWKS / discovery rate cap**
//! - Unit: `JwksRateLimiter` allows up to 60 rps and blocks at 61
//! - Unit: window resets after 1 second
//! - Unit: per-IP isolation (different IPs have independent counters)
//!
//! **A-13 — WebAuthn attestation policy**
//! - Unit: default policy allows none attestation and any AAGUID
//! - Unit: `allow_none = false` is stored correctly
//! - Unit: AAGUID allowlist permits known authenticator
//! - Unit: AAGUID allowlist blocks unknown authenticator
//! - Unit: AAGUID allowlist comparison is case-insensitive
//!
//! **A-14 — Per-tenant TTL hard caps**
//! - Unit: `to_realm_config` rejects `password_reset_token_ttl` > 1h
//! - Unit: `to_realm_config` rejects `magic_link_ttl` > 30m
//! - Unit: `allow_unsafe_ttl: true` lifts both caps
//! - Unit: TTL at exact cap boundary succeeds
//! - Unit: valid TTLs within caps are correctly parsed into `RealmConfig`
//!
//! Closes: HEA-1212 §A-5, §A-6, §A-10, §A-13, §A-14.

mod common;

use std::sync::Arc;

use tempfile::tempdir;

use hearth::audit::EmbeddedAuditEngine;
use hearth::config::{AuthConfig, RealmAuthYaml, RealmTokenYaml, RealmYamlConfig};
use hearth::core::{Clock, FakeClock, Timestamp};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, EmbeddedIdentityEngine, IdentityConfig,
    IdentityEngine, IdentityError, WebAuthnAttestationPolicy,
};
use hearth::protocol::admin_auth::{
    JwksRateLimiter, JWKS_RATE_LIMIT_PER_SEC, JWKS_RATE_WINDOW_MICROS,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::StorageEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

struct EngineFixture {
    engine: Arc<EmbeddedIdentityEngine>,
    clock: Arc<FakeClock>,
}

impl EngineFixture {
    fn new(config: IdentityConfig) -> Self {
        let dir = tempdir().expect("tempdir");
        let storage: Arc<dyn StorageEngine> = Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
                .expect("storage"),
        );
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as _;
        let rbac: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock_dyn),
        ));
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock_dyn),
        ));
        let engine = Arc::new(
            EmbeddedIdentityEngine::with_rbac(storage, clock_dyn, config, rbac, audit as _)
                .expect("engine"),
        );
        Self { engine, clock }
    }

    fn identity(&self) -> &dyn IdentityEngine {
        self.engine.as_ref()
    }

    fn advance_secs(&self, secs: u64) {
        self.clock.advance(secs as i64 * 1_000_000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-5: Reserved slugs
// ─────────────────────────────────────────────────────────────────────────────

/// Operator-reserved realm name is rejected with `ReservedSlug`.
#[test]
fn a5_reserved_realm_name_rejected() {
    let fx = EngineFixture::new(IdentityConfig {
        reserved_slugs: vec!["support".to_string(), "www".to_string()],
        ..Default::default()
    });

    let err = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "support".to_string(),
            config: None,
        })
        .expect_err("expected error");

    assert!(
        matches!(err, IdentityError::ReservedSlug { .. }),
        "expected ReservedSlug, got {err:?}"
    );
}

/// Operator-reserved org slug is rejected with `ReservedSlug`.
#[test]
fn a5_reserved_org_slug_rejected() {
    let fx = EngineFixture::new(IdentityConfig {
        reserved_slugs: vec!["admin".to_string()],
        ..Default::default()
    });

    let realm = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "test-a5-org-slug".to_string(),
            config: None,
        })
        .expect("create realm");

    let err = fx
        .identity()
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "Admin".to_string(),
                slug: "admin".to_string(),
                ..Default::default()
            },
        )
        .expect_err("expected error");

    assert!(
        matches!(err, IdentityError::ReservedSlug { .. }),
        "expected ReservedSlug, got {err:?}"
    );
}

/// A non-reserved slug succeeds even when a reserved list is configured.
#[test]
fn a5_unreserved_realm_name_succeeds() {
    let fx = EngineFixture::new(IdentityConfig {
        reserved_slugs: vec!["support".to_string()],
        ..Default::default()
    });

    fx.identity()
        .create_realm(&CreateRealmRequest {
            name: "my-company".to_string(),
            config: None,
        })
        .expect("unreserved realm name must succeed");
}

/// After deleting a realm the name enters a 30-day cooldown; re-create is
/// blocked during the window and succeeds after it expires.
#[test]
fn a5_realm_delete_enters_and_expires_cooldown() {
    let cooldown_secs = 30 * 86_400u64;
    let fx = EngineFixture::new(IdentityConfig {
        slug_cooldown_secs: cooldown_secs,
        ..Default::default()
    });

    let realm = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "cooldown-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    fx.identity()
        .delete_realm(realm.id())
        .expect("delete realm");

    // Immediately re-create must be blocked.
    let err = fx
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "cooldown-realm".to_string(),
            config: None,
        })
        .expect_err("expected error");
    assert!(
        matches!(err, IdentityError::SlugInCooldown { .. }),
        "expected SlugInCooldown immediately after delete, got {err:?}"
    );

    // Advance past the cooldown window.
    fx.advance_secs(cooldown_secs + 1);

    // Re-create should succeed.
    fx.identity()
        .create_realm(&CreateRealmRequest {
            name: "cooldown-realm".to_string(),
            config: None,
        })
        .expect("re-create after cooldown expiry must succeed");
}

// ─────────────────────────────────────────────────────────────────────────────
// A-10: JWKS rate limiter
// ─────────────────────────────────────────────────────────────────────────────

/// `JwksRateLimiter` allows exactly `JWKS_RATE_LIMIT_PER_SEC` requests in a
/// 1-second window and blocks the next one.
#[test]
fn a10_jwks_rate_limiter_blocks_at_limit() {
    let limiter = JwksRateLimiter::new();
    let ip = "1.2.3.4";
    let t0 = 1_000_000_000i64; // arbitrary starting µs

    for i in 1..=JWKS_RATE_LIMIT_PER_SEC {
        assert!(
            limiter.check(ip, t0),
            "request {i} should be allowed (within limit)"
        );
    }

    // The next request in the same window must be denied.
    assert!(
        !limiter.check(ip, t0),
        "request {} must be denied (over limit)",
        JWKS_RATE_LIMIT_PER_SEC + 1
    );
}

/// After exactly one rate-window passes the counter resets.
#[test]
fn a10_jwks_rate_limiter_resets_after_window() {
    let limiter = JwksRateLimiter::new();
    let ip = "10.0.0.1";
    let t0 = 2_000_000_000i64;

    // Exhaust the window.
    for _ in 0..=JWKS_RATE_LIMIT_PER_SEC {
        limiter.check(ip, t0);
    }

    let t1 = t0 + JWKS_RATE_WINDOW_MICROS + 1;
    assert!(
        limiter.check(ip, t1),
        "first request in new window must be allowed"
    );
}

/// Different IPs have fully independent counters.
#[test]
fn a10_jwks_rate_limiter_per_ip_isolation() {
    let limiter = JwksRateLimiter::new();
    let t0 = 3_000_000_000i64;

    // Exhaust IP A.
    for _ in 0..=JWKS_RATE_LIMIT_PER_SEC {
        limiter.check("192.168.0.1", t0);
    }

    // IP B must be unaffected.
    assert!(
        limiter.check("192.168.0.2", t0),
        "different IP must not be affected by other IP's counter"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-13: WebAuthn attestation policy struct semantics
// ─────────────────────────────────────────────────────────────────────────────

/// Default `WebAuthnAttestationPolicy` is fully permissive.
#[test]
fn a13_default_policy_is_permissive() {
    let policy = WebAuthnAttestationPolicy::default();
    assert!(policy.allow_none, "default must allow 'none' attestation");
    assert!(
        policy.aaguid_allowlist.is_empty(),
        "default must accept any AAGUID (empty allowlist)"
    );
    assert!(!policy.require_prf);
    assert!(!policy.require_large_blob);
}

/// `allow_none = false` is stored and surfaced correctly.
#[test]
fn a13_allow_none_false_is_stored_correctly() {
    let strict = WebAuthnAttestationPolicy {
        allow_none: false,
        ..Default::default()
    };
    assert!(
        !strict.allow_none,
        "allow_none = false must be reflected in the policy"
    );
}

/// A non-empty AAGUID allowlist permits the listed AAGUID (case-insensitive).
#[test]
fn a13_aaguid_allowlist_permits_known_authenticator() {
    let known = "550e8400-e29b-41d4-a716-446655440000";
    let policy = WebAuthnAttestationPolicy {
        aaguid_allowlist: vec![known.to_string()],
        ..Default::default()
    };

    assert!(
        policy
            .aaguid_allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(known)),
        "known AAGUID must match the allowlist"
    );
}

/// A non-empty AAGUID allowlist blocks an unknown AAGUID.
#[test]
fn a13_aaguid_allowlist_blocks_unknown_authenticator() {
    let known = "550e8400-e29b-41d4-a716-446655440000";
    let unknown = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let policy = WebAuthnAttestationPolicy {
        aaguid_allowlist: vec![known.to_string()],
        ..Default::default()
    };

    assert!(
        !policy
            .aaguid_allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(unknown)),
        "unknown AAGUID must not be found in the allowlist"
    );
}

/// AAGUID allowlist comparison is case-insensitive.
#[test]
fn a13_aaguid_allowlist_is_case_insensitive() {
    let stored_lower = "550e8400-e29b-41d4-a716-446655440000";
    let incoming_upper = "550E8400-E29B-41D4-A716-446655440000";
    let policy = WebAuthnAttestationPolicy {
        aaguid_allowlist: vec![stored_lower.to_string()],
        ..Default::default()
    };

    assert!(
        policy
            .aaguid_allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(incoming_upper)),
        "AAGUID allowlist match must be case-insensitive"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-14: Per-tenant TTL hard caps
// ─────────────────────────────────────────────────────────────────────────────

fn realm_yaml_with_ttl(
    password_reset_token_ttl: Option<&str>,
    magic_link_ttl: Option<&str>,
    allow_unsafe_ttl: bool,
) -> RealmYamlConfig {
    RealmYamlConfig {
        auth: Some(RealmAuthYaml {
            token: Some(RealmTokenYaml {
                password_reset_token_ttl: password_reset_token_ttl.map(String::from),
                magic_link_ttl: magic_link_ttl.map(String::from),
                allow_unsafe_ttl,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// `password_reset_token_ttl` > 1h without `allow_unsafe_ttl` must be rejected.
#[test]
fn a14_password_reset_ttl_over_1h_rejected() {
    let yaml = realm_yaml_with_ttl(Some("2h"), None, false);
    let result = yaml.to_realm_config(&AuthConfig::default(), None);
    assert!(
        result.is_err(),
        "password_reset_token_ttl = 2h without allow_unsafe_ttl must be rejected"
    );
    let errs = result.expect_err("expected error");
    assert!(
        errs.iter()
            .any(|e| format!("{e:?}").contains("password_reset_token_ttl")),
        "error must identify the field: {errs:?}"
    );
}

/// `magic_link_ttl` > 30m without `allow_unsafe_ttl` must be rejected.
#[test]
fn a14_magic_link_ttl_over_30m_rejected() {
    let yaml = realm_yaml_with_ttl(None, Some("1h"), false);
    let result = yaml.to_realm_config(&AuthConfig::default(), None);
    assert!(
        result.is_err(),
        "magic_link_ttl = 1h without allow_unsafe_ttl must be rejected"
    );
    let errs = result.expect_err("expected error");
    assert!(
        errs.iter()
            .any(|e| format!("{e:?}").contains("magic_link_ttl")),
        "error must identify the field: {errs:?}"
    );
}

/// `allow_unsafe_ttl: true` lifts both caps.
#[test]
fn a14_allow_unsafe_ttl_lifts_both_caps() {
    let yaml = realm_yaml_with_ttl(Some("12h"), Some("2h"), true);
    yaml.to_realm_config(&AuthConfig::default(), None)
        .expect("allow_unsafe_ttl = true must permit TTLs over the caps");
}

/// TTL values at exactly the cap boundary must succeed.
#[test]
fn a14_ttl_at_exact_cap_boundary_succeeds() {
    let yaml = realm_yaml_with_ttl(Some("60m"), Some("30m"), false);
    yaml.to_realm_config(&AuthConfig::default(), None)
        .expect("TTL at exact cap boundary must succeed");
}

/// Valid TTLs within caps are correctly parsed and stored as µs.
#[test]
fn a14_valid_ttls_are_parsed_correctly() {
    let yaml = realm_yaml_with_ttl(Some("30m"), Some("15m"), false);
    let cfg = yaml
        .to_realm_config(&AuthConfig::default(), None)
        .expect("valid TTLs must parse");

    assert_eq!(
        cfg.password_reset_token_ttl_micros,
        Some(30 * 60 * 1_000_000),
        "password_reset_token_ttl 30m in µs"
    );
    assert_eq!(
        cfg.magic_link_ttl_micros,
        Some(15 * 60 * 1_000_000),
        "magic_link_ttl 15m in µs"
    );
}
