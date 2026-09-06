//! Integration tests for Ed25519 signing key rotation with dual JWKS grace period.
//!
//! Covers:
//! - Rotation produces a JWKS with both active and retiring keys.
//! - Retiring key is excluded from JWKS once the grace period expires.
//! - Config `rotate_signing_key: true` triggers rotation via `apply_diff`.
//! - Snapshot flag is auto-cleared so a second startup does not re-rotate.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::config::{compute_diff, ConfigSnapshot, RealmYamlConfig};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::reconcile::{apply_diff, save_snapshot};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, SessionContext,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Helper ────────────────────────────────────────────────────────────────────

fn setup_engine_with_clock(
    initial_micros: i64,
) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
    let (dir, engine, clock, _storage) = setup_engine_with_storage(
        initial_micros,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
    );
    (dir, engine, clock)
}

/// Same as [`setup_engine_with_clock`] but also hands back the storage engine,
/// so a test can assert on the raw `realm:retiring:` blobs the engine writes.
fn setup_engine_with_storage(
    initial_micros: i64,
    identity_config: IdentityConfig,
) -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<FakeClock>,
    Arc<dyn StorageEngine>,
) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).unwrap()) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(initial_micros)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config,
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .unwrap();
    (dir, engine, clock, storage)
}

/// The nil-UUID system realm every signing-key blob is stored under.
fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Lists the raw `realm:retiring:{uuid}:*` storage keys for a realm.
///
/// Deliberately re-derives the key layout instead of reaching into the
/// `pub(crate)` encoder: the test must fail if the on-disk format changes.
fn retiring_key_blobs(storage: &Arc<dyn StorageEngine>, realm_id: &RealmId) -> Vec<Vec<u8>> {
    let start = format!("realm:retiring:{}:", realm_id.as_uuid()).into_bytes();
    let mut end = start.clone();
    // ':' + 1 — the exclusive upper bound of the prefix range.
    *end.last_mut().unwrap() += 1;
    storage
        .scan(&system_realm(), &start, &end)
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect()
}

// ── Test 1: rotate → dual JWKS ────────────────────────────────────────────────

#[test]
fn rotation_produces_dual_jwks() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // Before rotation: one key in JWKS.
    let jwks_before = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(jwks_before.keys.len(), 1, "expected 1 key before rotation");
    let original_kid = jwks_before.keys[0].kid.clone();

    // Rotate with a 24-hour grace period.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();

    // After rotation: two keys — new active + retiring old key.
    let jwks_after = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(jwks_after.keys.len(), 2, "expected 2 keys after rotation");

    let kids: Vec<&str> = jwks_after.keys.iter().map(|k| k.kid.as_str()).collect();
    assert!(
        kids.contains(&original_kid.as_str()),
        "retiring key must still appear in JWKS during grace period"
    );
}

// ── Test 2: retiring key excluded after grace period expires ─────────────────

#[test]
fn retiring_key_removed_after_grace_period() {
    // Start at t=0 (seconds = 0, but use micros epoch).
    let start_micros = 1_000_000_000_000_i64; // arbitrary fixed point
    let (_dir, engine, clock) = setup_engine_with_clock(start_micros);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "corp".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    let jwks_before = engine.realm_jwks(realm.id()).unwrap();
    let original_kid = jwks_before.keys[0].kid.clone();

    // Rotate with a 1-second grace period.
    engine.rotate_realm_signing_key(realm.id(), 1).unwrap();

    // During grace period: both keys present.
    let jwks_during = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_during.keys.len(),
        2,
        "expected 2 keys during grace period"
    );

    // Advance clock past the grace period deadline (2 seconds).
    clock.advance(2_000_000); // +2 seconds in micros
    let jwks_after = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after.keys.len(),
        1,
        "expected 1 key after grace period expires"
    );

    // The surviving key must be the new one, not the retiring one.
    assert_ne!(
        jwks_after.keys[0].kid, original_kid,
        "surviving key should be the new active key, not the old retiring key"
    );
}

// ── Test 3: second rotation produces new key, old retiring key still present ─

#[test]
fn second_rotation_adds_another_retiring_key() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "multi".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // First rotation.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    let jwks_after_first = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after_first.keys.len(),
        2,
        "2 keys after first rotation"
    );

    // Second rotation — now we should have active + 2 retiring keys.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    let jwks_after_second = engine.realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks_after_second.keys.len(),
        3,
        "3 keys after second rotation (1 active + 2 retiring)"
    );
}

// ── Test 4: snapshot flag auto-cleared by apply_diff ─────────────────────────

#[tokio::test]
async fn snapshot_rotate_flag_cleared_after_apply_diff() {
    let harness = common::TestHarness::embedded().await.unwrap();

    // Create realm in storage.
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // Build a config with rotate_signing_key: true.
    let realm_yaml = RealmYamlConfig {
        rotate_signing_key: Some(true),
        ..RealmYamlConfig::default()
    };
    let mut config = hearth::config::Config::default();
    let mut realms = std::collections::HashMap::new();
    realms.insert("tenant".to_string(), realm_yaml);
    config.realms = Some(realms);

    // Old snapshot has rotate_signing_key: false (not yet rotated).
    let old_snap = {
        let mut snap = ConfigSnapshot::from_config(&config);
        if let Some(realm_snaps) = snap.realms.as_mut() {
            if let Some(rs) = realm_snaps.get_mut("tenant") {
                rs.rotate_signing_key = false; // force old state to "not set"
            }
        }
        snap
    };

    // Compute diff: should detect RealmSigningKeyRotationRequested.
    let diffs = compute_diff(&old_snap, &config);
    let rotation_requested = diffs.iter().any(|d| {
        matches!(
            d,
            hearth::config::ConfigDiff::RealmSigningKeyRotationRequested { realm }
            if realm == "tenant"
        )
    });
    assert!(
        rotation_requested,
        "expected RealmSigningKeyRotationRequested diff; got: {diffs:?}"
    );

    // Apply diffs — rotation handler fires and returns consumed realm names.
    let consumed = apply_diff(&diffs, &config, harness.identity(), harness.rbac()).unwrap();
    assert!(
        consumed.contains(&"tenant".to_string()),
        "tenant should be in consumed_rotations"
    );

    // The realm JWKS should now have 2 keys (before saving snapshot, just check rotation happened).
    let jwks = harness.identity().realm_jwks(realm.id()).unwrap();
    assert_eq!(
        jwks.keys.len(),
        2,
        "JWKS must have 2 keys after rotation (active + retiring)"
    );

    // Save the current snapshot unchanged (rotate_signing_key stays true to match
    // YAML). This models the correct production behaviour: saving true→true means
    // the next compute_diff sees no transition and does not re-rotate.
    let snap = ConfigSnapshot::from_config(&config);
    save_snapshot(harness.storage(), &snap).unwrap();

    // Reload snapshot and re-compute diff. With the flag cleared, no rotation diff should fire.
    let saved_snap = hearth::identity::reconcile::load_snapshot(harness.storage())
        .unwrap()
        .unwrap();
    let diffs2 = compute_diff(&saved_snap, &config);
    let rotation_again = diffs2.iter().any(|d| {
        matches!(
            d,
            hearth::config::ConfigDiff::RealmSigningKeyRotationRequested { .. }
        )
    });
    assert!(
        !rotation_again,
        "rotation diff must NOT fire on second startup when flag was cleared from snapshot"
    );
}

// ── HEA-2090: grace period is two-sided (Hearth accepts old-kid tokens) ───────

/// Creates a realm + user + session and issues a token pair, returning the
/// realm id, user id, and the issued pair. Signed with the realm's active key.
fn realm_user_and_tokens(
    engine: &EmbeddedIdentityEngine,
    realm_name: &str,
) -> (RealmId, UserId, hearth::identity::TokenPair) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: realm_name.to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let user = engine
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Grace Tester".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();
    let session = engine
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .unwrap();
    let pair = engine
        .issue_tokens(realm.id(), user.id(), session.id())
        .unwrap();
    (realm.id().clone(), user.id().clone(), pair)
}

/// A token minted before rotation must still validate during the grace period —
/// otherwise every active session is logged out the instant an operator rotates
/// the realm's signing key (HEA-2090).
#[test]
fn validate_token_accepts_old_kid_during_grace_period() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "grace-accept");
    let access = pair.access_token().to_string();

    // Rotate with the default 24-hour grace period. The token is NOT validated
    // before rotation, so the token-claims cache cannot mask the retiring-key path.
    engine.rotate_realm_signing_key(&realm, 86_400).unwrap();

    let claims = engine.validate_token(&realm, &access).expect(
        "access token signed with the retiring key must still validate during the grace period",
    );
    assert_eq!(claims.tid, realm.to_string());
    assert_eq!(claims.token_type, "access");
}

/// Once the grace period elapses, a token signed with the retired key MUST be
/// rejected — the fallback is strictly time-bounded and fails closed.
#[test]
fn validate_token_rejects_old_kid_after_grace_period() {
    let (_dir, engine, clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "grace-expire");
    let access = pair.access_token().to_string();

    // Rotate with a 1-second grace period, then advance past the deadline.
    // The token is never validated inside the window, so no cache entry exists.
    engine.rotate_realm_signing_key(&realm, 1).unwrap();
    clock.advance(2_000_000); // +2 seconds in micros

    let err = engine
        .validate_token(&realm, &access)
        .expect_err("token signed with an expired retiring key must be rejected");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidToken),
        "expected InvalidToken after grace period, got {err:?}"
    );
}

/// The refresh-token grant is the call site that logged everyone out in the
/// original report: a refresh token minted before rotation must still be
/// redeemable during the grace period.
#[test]
fn refresh_grant_accepts_old_kid_during_grace_period() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "grace-refresh-ok");
    let refresh = pair.refresh_token().to_string();

    engine.rotate_realm_signing_key(&realm, 86_400).unwrap();

    let refreshed = engine
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("old-kid refresh token must be redeemable during the grace period");
    // The freshly issued pair is signed with the new active key and validates.
    engine
        .validate_token(&realm, refreshed.access_token())
        .expect("re-issued access token validates against the new active key");
}

/// After the grace period, an old-kid refresh token must be rejected.
#[test]
fn refresh_grant_rejects_old_kid_after_grace_period() {
    let (_dir, engine, clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "grace-refresh-expire");
    let refresh = pair.refresh_token().to_string();

    engine.rotate_realm_signing_key(&realm, 1).unwrap();
    clock.advance(2_000_000); // +2 seconds — past the 1-second deadline

    let err = engine
        .refresh_tokens(&realm, &refresh, None, None)
        .expect_err("old-kid refresh token must be rejected after the grace period");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidToken),
        "expected InvalidToken after grace period, got {err:?}"
    );
}

// ── HEA-2093: retiring-key lifecycle hygiene ─────────────────────────────────

/// Emergency rotation (grace 0) must cut off tokens the engine has *already*
/// validated. Without a claims-cache flush, a warm cache entry lets a token
/// minted under the compromised key keep passing until its own `exp`.
#[test]
fn emergency_rotation_flushes_already_validated_tokens() {
    let (_dir, engine, _clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "emergency-rotate");
    let access = pair.access_token().to_string();

    // Warm the token-claims cache under the (soon to be compromised) active key.
    engine
        .validate_token(&realm, &access)
        .expect("token validates before rotation");

    // Zero grace: the old key is revoked the instant rotation completes.
    engine.rotate_realm_signing_key(&realm, 0).unwrap();

    let err = engine
        .validate_token(&realm, &access)
        .expect_err("a previously-validated token must not survive a zero-grace rotation");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidToken),
        "expected InvalidToken after emergency rotation, got {err:?}"
    );
}

/// A token accepted *during* the grace period must stop being accepted once the
/// deadline passes. Caching the claims of a retiring-key-signed token would let
/// it outlive the grace window on the same engine instance.
#[test]
fn claims_cached_during_grace_do_not_outlive_the_deadline() {
    let (_dir, engine, clock) = setup_engine_with_clock(1_000_000_000_000);
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "grace-cache-expiry");
    let access = pair.access_token().to_string();

    engine.rotate_realm_signing_key(&realm, 1).unwrap();

    // Validated inside the window: accepted via the retiring key.
    engine
        .validate_token(&realm, &access)
        .expect("token validates during the grace period");

    // Past the deadline — the access token's own `exp` is still ~an hour out,
    // so only the retiring-key deadline can reject it.
    clock.advance(2_000_000);

    let err = engine
        .validate_token(&realm, &access)
        .expect_err("a token accepted during grace must be rejected once the deadline passes");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidToken),
        "expected InvalidToken after the grace deadline, got {err:?}"
    );
}

/// Every rotation appends a retiring-key blob. Rotation must purge the ones
/// whose grace window has already closed, or the set grows without bound and
/// every cache reload decrypts dead key material.
#[test]
fn rotation_purges_expired_retiring_keys() {
    let (_dir, engine, clock, storage) = setup_engine_with_storage(
        1_000_000_000_000,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
    );
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "purge".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // First rotation: one retiring key with a 1-second grace window.
    engine.rotate_realm_signing_key(realm.id(), 1).unwrap();
    assert_eq!(
        retiring_key_blobs(&storage, realm.id()).len(),
        1,
        "first rotation writes one retiring key"
    );

    // Let it expire, then rotate again.
    clock.advance(2_000_000);
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();

    let remaining = retiring_key_blobs(&storage, realm.id());
    assert_eq!(
        remaining.len(),
        1,
        "the expired retiring key must be purged, leaving only the freshly-retired one; got {:?}",
        remaining
            .iter()
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .collect::<Vec<_>>()
    );

    // A still-in-grace key must NOT be purged by a subsequent rotation.
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    assert_eq!(
        retiring_key_blobs(&storage, realm.id()).len(),
        2,
        "in-grace retiring keys must survive a later rotation"
    );
}

/// Deleting a realm must not leave wrapped private keys behind — with no KEK
/// configured those blobs are plaintext PKCS#8 (synchronous cascade path).
#[test]
fn realm_delete_purges_retiring_keys_sync_path() {
    let (_dir, engine, _clock, storage) = setup_engine_with_storage(
        1_000_000_000_000,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
    );
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "delete-sync".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    engine.rotate_realm_signing_key(realm.id(), 86_400).unwrap();
    assert_eq!(retiring_key_blobs(&storage, realm.id()).len(), 1);

    engine.delete_realm(realm.id()).unwrap();

    assert!(
        retiring_key_blobs(&storage, realm.id()).is_empty(),
        "retiring signing keys must not outlive the realm"
    );
}

/// Same guarantee on the background cascade path, which a large realm takes.
#[tokio::test]
async fn realm_delete_purges_retiring_keys_background_path() {
    let (_dir, engine, _clock, storage) = setup_engine_with_storage(
        1_000_000_000_000,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            // Force the Tokio background cascade for any non-empty realm.
            cascade_background_threshold: 0,
            ..IdentityConfig::default()
        },
    );
    let (realm, _user, _pair) = realm_user_and_tokens(&engine, "delete-bg");
    engine.rotate_realm_signing_key(&realm, 86_400).unwrap();
    assert_eq!(retiring_key_blobs(&storage, &realm).len(), 1);

    engine.delete_realm(&realm).unwrap();

    // The cascade runs on a spawned task; poll for completion.
    for _ in 0..200 {
        if retiring_key_blobs(&storage, &realm).is_empty() {
            return;
        }
        // AUDIT: justified-sleep: backoff in a bounded poll for a spawned cascade task with no completion handle — no timer for tokio::time::advance to drive.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("background cascade left retiring signing keys in storage");
}

// ── B9 (audit 2026-08-28): rotation is the remedy for a leaked key ────────────

/// Builds the admin REST router over a harness.
fn build_admin_app(h: &common::TestHarness) -> axum::Router {
    hearth::protocol::http::router(Arc::new(hearth::protocol::http::AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// Creates an admin user in `realm` with `realm.admin` and returns an access
/// token signed by that realm's active signing key.
fn admin_access_token(h: &common::TestHarness, realm: &RealmId, suffix: &str) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("rotate-{suffix}@test.example"),
                display_name: "Rotation Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin role exists after seed");
    h.rbac()
        .assign_role(
            realm,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user.id().clone()),
                role_id: role.id,
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

async fn admin_get(app: &axum::Router, uri: &str, token: &str, realm: &RealmId) -> u16 {
    let resp = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", realm.as_uuid().to_string())
            .body(axum::body::Body::empty())
            .expect("build request"),
    )
    .await
    .expect("response");
    resp.status().as_u16()
}

/// B9 — rotating a realm's signing key must revoke it.
///
/// Rotation is the documented remedy for a leaked signing key. While the
/// retired key stays valid, whoever holds it keeps minting **new**
/// administrative credentials: the grace window protects the attacker as
/// faithfully as it protects a legitimate session. `POST
/// /admin/realms/{id}/rotate-signing-key` therefore revokes by default.
#[tokio::test]
async fn admin_rotate_signing_key_revokes_the_retired_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let app = build_admin_app(&h);
    let token = admin_access_token(&h, &realm, "revoke");

    // Baseline: the credential works before rotation.
    assert_eq!(
        admin_get(&app, "/admin/users", &token, &realm).await,
        200,
        "the admin token must work before rotation"
    );

    let rotate = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/admin/realms/{}/rotate-signing-key",
                realm.as_uuid()
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", realm.as_uuid().to_string())
            .body(axum::body::Body::empty())
            .expect("build rotate request"),
    )
    .await
    .expect("rotate response");
    assert_eq!(rotate.status().as_u16(), 200, "rotation must succeed");

    // Every route the critic reached with a retired-key credential.
    for uri in ["/admin/users", "/admin/realms", "/admin/audit"] {
        assert_eq!(
            admin_get(&app, uri, &token, &realm).await,
            401,
            "a credential signed with the retired key must be refused on {uri}"
        );
    }
}

/// A planned rotation can still ask for a grace window explicitly, which is
/// what keeps live sessions alive across routine key hygiene (HEA-2090).
/// The operator opts in; it is never the default.
#[tokio::test]
async fn admin_rotate_signing_key_honours_an_explicit_grace_period() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let app = build_admin_app(&h);
    let token = admin_access_token(&h, &realm, "grace");

    let rotate = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/admin/realms/{}/rotate-signing-key?grace_period_secs=3600",
                realm.as_uuid()
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", realm.as_uuid().to_string())
            .body(axum::body::Body::empty())
            .expect("build rotate request"),
    )
    .await
    .expect("rotate response");
    assert_eq!(rotate.status().as_u16(), 200, "rotation must succeed");

    assert_eq!(
        admin_get(&app, "/admin/users", &token, &realm).await,
        200,
        "an explicit grace window must keep pre-rotation credentials working"
    );
}

/// A revoking rotation must clear keys retired by an *earlier* rotation too.
///
/// Purging only expired keys would leave the previous key live inside its own
/// window: the operator is told the realm has been re-keyed while the key they
/// are running from an incident for still validates tokens.
#[test]
fn revoking_rotation_purges_an_earlier_rotations_live_retiring_key() {
    let (_dir, engine, _clock, storage) = setup_engine_with_storage(
        1_000_000_000_000,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
    );
    let (realm, _user, pair) = realm_user_and_tokens(&engine, "revoke-earlier");
    let access = pair.access_token().to_string();

    // A planned rotation with a 24-hour window.
    engine.rotate_realm_signing_key(&realm, 86_400).unwrap();
    assert_eq!(
        retiring_key_blobs(&storage, &realm).len(),
        1,
        "a grace rotation stores the retired key"
    );
    engine
        .validate_token(&realm, &access)
        .expect("the pre-rotation token is inside the grace window");

    // Now the incident: revoke.
    engine.rotate_realm_signing_key(&realm, 0).unwrap();
    assert!(
        retiring_key_blobs(&storage, &realm).is_empty(),
        "a revoking rotation must leave no retiring key material behind"
    );
    let err = engine
        .validate_token(&realm, &access)
        .expect_err("a revoking rotation must refuse tokens from every retired key");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidToken),
        "expected InvalidToken after a revoking rotation, got {err:?}"
    );
}
