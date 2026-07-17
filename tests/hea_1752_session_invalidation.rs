//! HEA-1752 regression tests: session invalidation on password change (D2)
//! and atomic single-use MFA nonce redemption (M1a).
//!
//! * D2 — `change_password` must revoke all existing sessions (default config),
//!   so a stolen session cookie cannot outlive the credential. This is enforced
//!   via `set_password`'s A-42 credential-change revocation; the test guards the
//!   end-to-end invariant so a future refactor cannot silently drop it.
//! * M1a — `redeem_mfa_nonce` must serialize the check-then-burn sequence so a
//!   single nonce can be redeemed at most once even under concurrency.

use std::sync::Arc;

use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext, UpdateUserRequest,
    UserStatus,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Builds a standalone embedded identity engine backed by a temp WAL dir.
fn build_identity() -> Arc<dyn IdentityEngine> {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;

    Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit,
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>
}

// ===========================================================================
// D2: change_password revokes existing sessions
// ===========================================================================

#[tokio::test]
async fn change_password_revokes_existing_sessions() {
    let identity = build_identity();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let old = CleartextPassword::from_string("original-pass!".to_string());
    identity
        .set_password(realm.id(), user.id(), &old)
        .expect("set password");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");

    // Establish two live sessions.
    let s1 = identity
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("session 1");
    let s2 = identity
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("session 2");
    assert!(
        identity
            .get_session(realm.id(), s1.id())
            .expect("get s1")
            .is_some(),
        "session 1 must exist before change_password"
    );

    // Change the password.
    let old = CleartextPassword::from_string("original-pass!".to_string());
    let new = CleartextPassword::from_string("updated-pass!".to_string());
    identity
        .change_password(realm.id(), user.id(), &old, &new)
        .expect("change password");

    // Both prior sessions must now be gone.
    assert!(
        identity
            .get_session(realm.id(), s1.id())
            .expect("get s1")
            .is_none(),
        "session 1 must be revoked after change_password"
    );
    assert!(
        identity
            .get_session(realm.id(), s2.id())
            .expect("get s2")
            .is_none(),
        "session 2 must be revoked after change_password"
    );
}

// ===========================================================================
// M1a: concurrent MFA nonce redemption succeeds at most once
// ===========================================================================

#[tokio::test]
async fn concurrent_mfa_nonce_redemption_succeeds_once() {
    let identity = build_identity();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let nonce = "shared-mfa-nonce-abc123";
    let exp_secs = 4_000_000_000u64;

    // Fire many concurrent redemptions of the SAME nonce, maximizing overlap
    // with a barrier so the check-then-burn windows race.
    let threads = 16;
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let identity = Arc::clone(&identity);
        let realm_id = realm_id.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            identity
                .redeem_mfa_nonce(&realm_id, nonce, exp_secs)
                .expect("redeem_mfa_nonce")
        }));
    }

    let successes = handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .filter(|&redeemed| redeemed)
        .count();

    assert_eq!(
        successes, 1,
        "exactly one concurrent redemption of a single MFA nonce may succeed"
    );

    // A subsequent redemption also fails (idempotent burn).
    assert!(
        !identity
            .redeem_mfa_nonce(&realm_id, nonce, exp_secs)
            .expect("redeem again"),
        "already-burned nonce must not be redeemable again"
    );
}
