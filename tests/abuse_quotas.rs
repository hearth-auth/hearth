//! Tests for A-24 (per-realm resource quotas) and A-25 (audit auto-retention
//! max_rows backstop).
//!
//! D-4 taxonomy: unit (config serde + count), integration (quota enforcement
//! on create), adversarial (exact-limit boundary, fail-closed, bypass attempt).
//!
//! Plan sections §3.25 (A-24) and §3.26 (A-25) from
//! `openspec/specs/abuse-prevention/spec.md`.

mod common;

use std::collections::BTreeMap;

use hearth::audit::AuditRetentionConfig;
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, IdentityError, RealmConfig,
    RealmQuotaConfig, RegisterClientRequest, SessionContext, User,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@quota-test.invalid", uuid::Uuid::new_v4())
}

fn create_user(h: &common::TestHarness, realm: &hearth::core::RealmId, n: u32) -> User {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: unique_email(&format!("u{n}")),
                display_name: format!("User {n}"),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("create_user {n} failed: {e}"))
}

fn realm_with_quota(h: &common::TestHarness, quota: RealmQuotaConfig) -> hearth::core::RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("quota-realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                quotas: Some(quota),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm with quota")
        .id()
        .clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: config types
// ─────────────────────────────────────────────────────────────────────────────

/// A `RealmQuotaConfig` with all `None` fields round-trips through JSON.
#[test]
fn quota_config_default_roundtrip() {
    let cfg = RealmQuotaConfig::default();
    let json = serde_json::to_string(&cfg).expect("serialize");
    let back: RealmQuotaConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cfg, back);
}

/// A fully-populated `RealmQuotaConfig` round-trips through JSON.
#[test]
fn quota_config_populated_roundtrip() {
    let cfg = RealmQuotaConfig {
        max_users: Some(1000),
        max_orgs: Some(50),
        max_clients: Some(10),
        max_agents: Some(20),
        max_sessions: Some(5000),
        max_audit_rows: Some(100_000),
        max_disk_bytes: Some(1_073_741_824), // 1 GiB
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let back: RealmQuotaConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cfg, back);
}

/// `RealmConfig` with a `quotas` field round-trips cleanly.
#[test]
fn realm_config_quotas_field_roundtrip() {
    let config = RealmConfig {
        quotas: Some(RealmQuotaConfig {
            max_users: Some(100),
            ..RealmQuotaConfig::default()
        }),
        ..RealmConfig::default()
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let back: RealmConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        config.quotas, back.quotas,
        "quotas field must survive round-trip"
    );
}

/// Legacy `RealmConfig` JSON without a `quotas` field deserializes to `None`.
#[test]
fn realm_config_missing_quotas_deserializes_to_none() {
    // Minimal valid RealmConfig JSON that has no `quotas` key.
    let legacy = "{}";
    let config: RealmConfig = serde_json::from_str(legacy).expect("deserialize");
    assert!(
        config.quotas.is_none(),
        "quotas must be None when absent from stored JSON"
    );
}

/// `AuditRetentionConfig` with `max_rows` round-trips through JSON.
#[test]
fn audit_retention_max_rows_roundtrip() {
    let cfg = AuditRetentionConfig {
        retention_days: 30,
        max_rows: Some(50_000),
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let back: AuditRetentionConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cfg.retention_days, back.retention_days);
    assert_eq!(cfg.max_rows, back.max_rows);
}

/// Legacy `AuditRetentionConfig` without `max_rows` deserializes to `None`.
#[test]
fn audit_retention_legacy_missing_max_rows() {
    let legacy = r#"{"retention_days": 90}"#;
    let cfg: AuditRetentionConfig = serde_json::from_str(legacy).expect("deserialize");
    assert_eq!(cfg.retention_days, 90);
    assert!(cfg.max_rows.is_none(), "max_rows must default to None");
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: A-24 user quota
// ─────────────────────────────────────────────────────────────────────────────

/// Creating users up to the limit succeeds; the next create fails with
/// `QuotaExceeded` naming the "users" resource.
#[tokio::test]
async fn a24_user_quota_enforced() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_users: Some(2),
            ..RealmQuotaConfig::default()
        },
    );

    create_user(&harness, &realm, 1);
    create_user(&harness, &realm, 2);

    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: unique_email("overflow"),
                display_name: "Overflow".to_string(),
                ..Default::default()
            },
        )
        .expect_err("3rd create must fail when max_users=2");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "users",
                limit: 2,
                ..
            }
        ),
        "expected QuotaExceeded(users,2), got: {err:?}"
    );
}

/// Without a quota, user creates are unlimited.
#[tokio::test]
async fn a24_no_quota_unlimited_users() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    // TestHarness::create_realm() sets no quota.
    let realm = harness.create_realm();

    for i in 0..10 {
        create_user(&harness, &realm, i);
    }

    // Assert against production output (not just "no panic"): all 10 users must
    // be persisted and countable via list_users. A regression that silently
    // capped creates would show a total < 10 here.
    let listed = harness
        .identity()
        .list_users(&realm, &hearth::core::PageRequest::new(0, 50))
        .expect("list users");
    assert_eq!(
        listed.total, 10,
        "all 10 creates must persist when no quota is configured, got {}",
        listed.total
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: A-24 org quota
// ─────────────────────────────────────────────────────────────────────────────

/// Org quota blocks create once the limit is reached.
#[tokio::test]
async fn a24_org_quota_enforced() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_orgs: Some(1),
            ..RealmQuotaConfig::default()
        },
    );

    harness
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "First Org".to_string(),
                slug: "first-org".to_string(),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect("first org must succeed");

    let err = harness
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Second Org".to_string(),
                slug: "second-org".to_string(),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect_err("second org must fail when max_orgs=1");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "orgs",
                limit: 1,
                ..
            }
        ),
        "expected QuotaExceeded(orgs,1), got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: A-24 client quota
// ─────────────────────────────────────────────────────────────────────────────

/// Client quota blocks registration once the limit is reached.
#[tokio::test]
async fn a24_client_quota_enforced() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_clients: Some(1),
            ..RealmQuotaConfig::default()
        },
    );

    harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "client-one".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("first client must succeed");

    let err = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "client-two".to_string(),
                redirect_uris: vec!["https://app2.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect_err("second client must fail when max_clients=1");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "clients",
                limit: 1,
                ..
            }
        ),
        "expected QuotaExceeded(clients,1), got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: A-24 session quota
// ─────────────────────────────────────────────────────────────────────────────

/// Realm-wide session quota blocks new sessions once the limit is reached.
#[tokio::test]
async fn a24_session_quota_enforced() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_sessions: Some(1),
            ..RealmQuotaConfig::default()
        },
    );

    // Two different users — first fills the realm quota, second is rejected.
    let user_a = create_user(&harness, &realm, 1);
    let user_b = create_user(&harness, &realm, 2);

    harness
        .identity()
        .create_session(
            &realm,
            user_a.id(),
            &SessionContext {
                ..Default::default()
            },
        )
        .expect("first session (user A) must succeed");

    let err = harness
        .identity()
        .create_session(
            &realm,
            user_b.id(),
            &SessionContext {
                ..Default::default()
            },
        )
        .expect_err("second realm-level session must fail when max_sessions=1");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "sessions",
                limit: 1,
                ..
            }
        ),
        "expected QuotaExceeded(sessions,1), got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: A-25 audit count_events + prune_oldest
// ─────────────────────────────────────────────────────────────────────────────

/// `count_events` returns a stable count for a fresh realm (may include
/// realm-creation audit events, but must not grow without appends).
#[tokio::test]
async fn a25_count_events_stable_without_appends() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness.create_realm();
    let count_a = harness
        .audit()
        .count_events(&realm)
        .expect("count_events first call");
    let count_b = harness
        .audit()
        .count_events(&realm)
        .expect("count_events second call");
    assert_eq!(
        count_a, count_b,
        "count_events must be stable without appends"
    );
}

/// `count_events` accurately tracks appended events.
#[tokio::test]
async fn a25_count_events_tracks_appends() {
    use hearth::audit::{AuditAction, CreateAuditEvent};

    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness.create_realm();
    let before = harness.audit().count_events(&realm).expect("count before");

    for _ in 0..5 {
        harness
            .audit()
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: uuid::Uuid::new_v4().to_string(),
                metadata: None,
            })
            .expect("append");
    }

    let after = harness.audit().count_events(&realm).expect("count after");
    assert_eq!(
        after - before,
        5,
        "count_events must reflect all appended events"
    );
}

/// `prune_oldest` removes exactly the requested number of oldest events.
#[tokio::test]
async fn a25_prune_oldest_removes_n_events() {
    use hearth::audit::{AuditAction, CreateAuditEvent};

    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness.create_realm();
    let initial = harness.audit().count_events(&realm).expect("initial count");

    for _ in 0..10 {
        harness
            .audit()
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: uuid::Uuid::new_v4().to_string(),
                metadata: None,
            })
            .expect("append");
    }

    let total = harness.audit().count_events(&realm).expect("total count");
    assert_eq!(total, initial + 10);

    let deleted = harness
        .audit()
        .prune_oldest(&realm, 4)
        .expect("prune_oldest");
    assert_eq!(deleted, 4, "prune_oldest(4) must delete exactly 4 events");

    let remaining = harness.audit().count_events(&realm).expect("count_events");
    assert_eq!(remaining, total - 4, "remaining must be total minus pruned");
}

/// `prune_oldest` with n > total events deletes all events and returns actual count.
#[tokio::test]
async fn a25_prune_oldest_capped_at_total() {
    use hearth::audit::{AuditAction, CreateAuditEvent};

    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness.create_realm();
    let initial = harness.audit().count_events(&realm).expect("initial count");

    for _ in 0..3 {
        harness
            .audit()
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: uuid::Uuid::new_v4().to_string(),
                metadata: None,
            })
            .expect("append");
    }

    let total = harness.audit().count_events(&realm).expect("total");
    assert_eq!(total, initial + 3);

    // Ask to prune more than exist — must cap at actual total.
    let deleted = harness
        .audit()
        .prune_oldest(&realm, 1_000_000)
        .expect("prune_oldest with n > total");
    assert_eq!(deleted, total, "must cap deletions at actual total");

    let remaining = harness
        .audit()
        .count_events(&realm)
        .expect("count after total prune");
    assert_eq!(remaining, 0, "no events must remain after prune_oldest(1M)");
}

/// Simulates the max_rows backstop: append events, then prune oldest excess.
#[tokio::test]
async fn a25_max_rows_backstop_simulation() {
    use hearth::audit::{AuditAction, CreateAuditEvent};

    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness.create_realm();
    let initial = harness.audit().count_events(&realm).expect("initial count");

    const APPENDED: u64 = 20;
    const MAX_ROWS: u64 = 10;

    for _ in 0..APPENDED {
        harness
            .audit()
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::SessionCreated,
                resource_type: "session".to_string(),
                resource_id: uuid::Uuid::new_v4().to_string(),
                metadata: None,
            })
            .expect("append");
    }

    let count = harness.audit().count_events(&realm).expect("count");
    assert_eq!(count, initial + APPENDED);

    if count > MAX_ROWS {
        let excess = count - MAX_ROWS;
        harness
            .audit()
            .prune_oldest(&realm, excess)
            .expect("prune_oldest excess");
    }

    let remaining = harness
        .audit()
        .count_events(&realm)
        .expect("count after prune");
    assert_eq!(
        remaining, MAX_ROWS,
        "after backstop: count must equal max_rows"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: exact boundary and quota metadata
// ─────────────────────────────────────────────────────────────────────────────

/// The error carries the correct limit and current values so callers can
/// surface them to operators.
#[tokio::test]
async fn a24_quota_error_carries_metadata() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_users: Some(1),
            ..RealmQuotaConfig::default()
        },
    );

    create_user(&harness, &realm, 1);

    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: unique_email("overflow-meta"),
                display_name: "Overflow".to_string(),
                ..Default::default()
            },
        )
        .expect_err("must fail at quota=1");

    match err {
        IdentityError::QuotaExceeded {
            resource,
            limit,
            current,
        } => {
            assert_eq!(resource, "users");
            assert_eq!(limit, 1);
            assert_eq!(current, 1, "current count must equal limit (1)");
        }
        other => panic!("expected QuotaExceeded, got: {other:?}"),
    }
}

/// Zero quota (limit=0) blocks all creates immediately.
#[tokio::test]
async fn a24_adversarial_zero_quota_blocks_all() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_users: Some(0),
            ..RealmQuotaConfig::default()
        },
    );

    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: unique_email("zero-quota"),
                display_name: "Nobody".to_string(),
                ..Default::default()
            },
        )
        .expect_err("create must fail with max_users=0");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "users",
                limit: 0,
                current: 0
            }
        ),
        "expected QuotaExceeded(users,0,0), got: {err:?}"
    );
}

/// Quota on one resource does not block creates of a different resource.
#[tokio::test]
async fn a24_quota_isolation_across_resources() {
    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &harness,
        RealmQuotaConfig {
            max_orgs: Some(0), // orgs blocked
            max_users: None,   // users unlimited
            ..RealmQuotaConfig::default()
        },
    );

    // Users can still be created.
    create_user(&harness, &realm, 1);

    // Orgs are blocked.
    let err = harness
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Blocked Org".to_string(),
                slug: "blocked-org".to_string(),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect_err("org must be blocked when max_orgs=0");

    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "orgs",
                ..
            }
        ),
        "expected QuotaExceeded(orgs), got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression (#630): the documented quota block loads from hearth.yaml
// ─────────────────────────────────────────────────────────────────────────────

/// A production `hearth.yaml` (it passes the checked loader) with `extra`
/// appended at the top level.
fn prod_yaml(extra: &str) -> String {
    format!(
        "server:\n  trust_forwarded_proto: true\n  trusted_proxies: [\"127.0.0.1\"]\n\
         storage:\n  data_dir: \"/tmp/hearth-a24-quotas\"\n\
         security:\n  key_encryption_key: \"\
         1111111111111111111111111111111111111111111111111111111111111111\"\n\
         oidc:\n  issuer: \"https://auth.example.test\"\n\
         email:\n  allow_log_transport_in_production: true\n{extra}"
    )
}

/// Scenario "Regression — documented quota block loads": the production loader
/// accepts `realms.<name>.quotas`, every key reaches the realm config, and the
/// eleventh user create fails with `HEARTH_QUOTA_EXCEEDED`.
#[tokio::test]
async fn a24_documented_quota_block_loads_from_yaml() {
    let config = hearth::config::Config::from_yaml_str(&prod_yaml(
        "realms:\n  acme:\n    quotas:\n      max_users: 10\n      max_orgs: 2\n      \
         max_clients: 3\n      max_agents: 4\n      max_sessions: 5\n      \
         max_audit_rows: 1000\n      max_disk_bytes: 1073741824\n",
    ))
    .expect("the documented quota block must load");
    let acme = config.realms.as_ref().expect("realms block")["acme"]
        .to_realm_config("acme", &config.auth, None)
        .expect("acme realm config");
    assert_eq!(
        acme.quotas,
        Some(RealmQuotaConfig {
            max_users: Some(10),
            max_orgs: Some(2),
            max_clients: Some(3),
            max_agents: Some(4),
            max_sessions: Some(5),
            max_audit_rows: Some(1000),
            max_disk_bytes: Some(1_073_741_824),
        }),
        "every quota key in hearth.yaml must reach the realm config"
    );

    let harness = common::TestHarness::in_process().await.expect("setup");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("acme-{}", uuid::Uuid::new_v4()),
            config: Some(acme),
        })
        .expect("create realm from the YAML config")
        .id()
        .clone();
    for n in 1..=10 {
        create_user(&harness, &realm, n);
    }
    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: unique_email("eleventh"),
                display_name: "Eleventh".to_string(),
                ..Default::default()
            },
        )
        .expect_err("the eleventh create must fail when max_users=10");
    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "users",
                limit: 10,
                current: 10,
            }
        ),
        "expected QuotaExceeded(users,10,10), got: {err:?}"
    );
    assert_eq!(err.wire_error_code(), Some("HEARTH_QUOTA_EXCEEDED"));
}

/// A quota key that is not in the documented set refuses to load, as every
/// other misspelt `hearth.yaml` key does.
#[test]
fn a24_a_misspelt_quota_key_is_refused() {
    let err = hearth::config::Config::from_yaml_str(&prod_yaml(
        "realms:\n  acme:\n    quotas:\n      max_user: 10\n",
    ))
    .expect_err("a misspelt quota key must not load");
    assert!(
        err.to_string().contains("max_user"),
        "the error must name the misspelt key: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// #630: the quota count reads keys, not values
// ─────────────────────────────────────────────────────────────────────────────

/// Storage that refuses a value scan of the whole user prefix (the scan a
/// quota count does when it reads every user record) and serves key walks.
struct UserValueScanRefused {
    inner: std::sync::Arc<hearth::storage::EmbeddedStorageEngine>,
}

impl hearth::storage::StorageEngine for UserValueScanRefused {
    fn get(
        &self,
        realm_id: &hearth::core::RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, hearth::storage::StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(
        &self,
        realm_id: &hearth::core::RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(
        &self,
        realm_id: &hearth::core::RealmId,
        key: &[u8],
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &hearth::core::RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<hearth::storage::ScanEntry>, hearth::storage::StorageError> {
        if start == b"usr:id:" {
            return Err(hearth::storage::StorageError::Io(std::io::Error::other(
                "a value scan of every user record",
            )));
        }
        self.inner.scan(realm_id, start, end)
    }

    fn scan_keys(
        &self,
        realm_id: &hearth::core::RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, hearth::storage::StorageError> {
        self.inner.scan_keys(realm_id, start, end)
    }

    fn visit_keys(
        &self,
        realm_id: &hearth::core::RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> std::ops::ControlFlow<()>,
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner.visit_keys(realm_id, start, end, visit)
    }

    fn list_realms(&self) -> Result<Vec<hearth::core::RealmId>, hearth::storage::StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(
        &self,
        snapshot_id: &str,
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), hearth::storage::StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

/// The user quota counts the realm's user keys without reading a user record:
/// with a value scan of the user prefix refused, users below the limit are
/// still created, and the create at the limit still fails.
#[test]
fn a24_the_user_quota_counts_keys_without_reading_values() {
    use std::sync::Arc;

    let temp = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        hearth::storage::EmbeddedStorageEngine::open(hearth::storage::StorageConfig::dev(
            temp.path().join("data"),
        ))
        .expect("open storage"),
    );
    let storage: Arc<dyn hearth::storage::StorageEngine> = Arc::new(UserValueScanRefused { inner });
    let clock: Arc<dyn hearth::core::Clock> = Arc::new(hearth::core::SystemClock);
    let rbac: Arc<dyn hearth::rbac::RbacEngine> = Arc::new(hearth::rbac::EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit: Arc<dyn hearth::audit::AuditEngine> = Arc::new(
        hearth::audit::EmbeddedAuditEngine::new(Arc::clone(&storage), Arc::clone(&clock)),
    );
    let identity = hearth::identity::EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        hearth::identity::IdentityConfig {
            credential: hearth::identity::CredentialConfig::fast_for_testing(),
            ..hearth::identity::IdentityConfig::default()
        },
        rbac,
        audit,
    )
    .expect("identity engine");
    let realm = hearth::identity::IdentityEngine::create_realm(
        &identity,
        &CreateRealmRequest {
            name: "quota-keys".to_string(),
            config: Some(RealmConfig {
                quotas: Some(RealmQuotaConfig {
                    max_users: Some(2),
                    ..RealmQuotaConfig::default()
                }),
                ..RealmConfig::default()
            }),
        },
    )
    .expect("create realm")
    .id()
    .clone();

    let create = |n: u32| {
        hearth::identity::IdentityEngine::create_user(
            &identity,
            &realm,
            &CreateUserRequest {
                email: unique_email(&format!("k{n}")),
                display_name: format!("User {n}"),
                ..Default::default()
            },
        )
    };
    for n in 1..=2 {
        if let Err(err) = create(n) {
            panic!("create {n} is below max_users=2 and must not read user records: {err:?}");
        }
    }
    let err = create(3).expect_err("the third create must fail when max_users=2");
    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "users",
                limit: 2,
                current: 2,
            }
        ),
        "expected QuotaExceeded(users,2,2), got: {err:?}"
    );
}
