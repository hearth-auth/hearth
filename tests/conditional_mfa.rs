//! Integration tests for conditional MFA enforcement (HEA-1330).
//!
//! Covers:
//! - `mfa_required: true` on a registered client is stored and retrieved correctly.
//! - `update_client` with `mfa_required` updates the stored value.
//! - `RealmConfig::mfa_required_roles` is persisted and reloaded correctly.
//! - Realm-wide `mfa_required: true` blocks engine-level `create_session`.
//! - `mfa_required_roles` is a web-layer-only gate (requires `required_action_check`
//!   via a full HTTP WebState); it does NOT gate engine `create_session` directly.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, RegisterClientRequest, UpdateClientRequest,
    UpdateRealmRequest,
};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};

// ─── helpers ────────────────────────────────────────────────────────────────

fn create_realm(harness: &common::TestHarness) -> hearth::identity::Realm {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("cond-mfa-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
}

fn create_user(harness: &common::TestHarness, realm: &RealmId) -> hearth::identity::User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ─── client mfa_required field round-trip ───────────────────────────────────

/// Registers a client with `mfa_required = true` and verifies the field
/// survives a round-trip through storage.
#[tokio::test]
async fn client_mfa_required_true_persists() {
    let harness = common::TestHarness::embedded().await.expect("test harness");
    let realm = create_realm(&harness);

    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "MFA App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                mfa_required: Some(true),
                ..Default::default()
            },
        )
        .expect("register_client");

    assert_eq!(
        client.mfa_required(),
        Some(true),
        "mfa_required must be stored on registration"
    );

    let loaded = harness
        .identity()
        .get_client(realm.id(), client.client_id())
        .expect("get_client")
        .expect("client must exist");

    assert_eq!(
        loaded.mfa_required(),
        Some(true),
        "mfa_required must survive a storage round-trip"
    );
}

/// Registers a client without `mfa_required`, then updates it to `true`, and
/// verifies the update is persisted.
#[tokio::test]
async fn client_mfa_required_update_persists() {
    let harness = common::TestHarness::embedded().await.expect("test harness");
    let realm = create_realm(&harness);

    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Plain App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                ..Default::default()
            },
        )
        .expect("register_client");

    assert_eq!(
        client.mfa_required(),
        None,
        "mfa_required must default to None"
    );

    // Update to enable conditional MFA on this client.
    let updated = harness
        .identity()
        .update_client(
            realm.id(),
            client.client_id(),
            &UpdateClientRequest {
                mfa_required: Some(Some(true)),
                ..Default::default()
            },
        )
        .expect("update_client");

    assert_eq!(
        updated.mfa_required(),
        Some(true),
        "mfa_required must be updatable to true"
    );

    // Disable it again.
    let disabled = harness
        .identity()
        .update_client(
            realm.id(),
            client.client_id(),
            &UpdateClientRequest {
                mfa_required: Some(Some(false)),
                ..Default::default()
            },
        )
        .expect("update_client disable");

    assert_eq!(
        disabled.mfa_required(),
        Some(false),
        "mfa_required must be updatable to false"
    );
}

// ─── realm mfa_required_roles round-trip ────────────────────────────────────

/// Creates a realm with `mfa_required_roles` set and verifies it survives a
/// storage round-trip via `get_realm`.
#[tokio::test]
async fn realm_mfa_required_roles_persists() {
    let harness = common::TestHarness::embedded().await.expect("test harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("roles-mfa-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required_roles: Some(vec!["realm.admin".to_string()]),
                ..Default::default()
            }),
        })
        .expect("create realm with mfa_required_roles");

    assert_eq!(
        realm.config().mfa_required_roles,
        Some(vec!["realm.admin".to_string()]),
        "mfa_required_roles must be stored on realm creation"
    );

    let loaded = harness
        .identity()
        .get_realm(realm.id())
        .expect("get_realm")
        .expect("realm must exist");

    assert_eq!(
        loaded.config().mfa_required_roles,
        Some(vec!["realm.admin".to_string()]),
        "mfa_required_roles must survive a storage round-trip"
    );
}

/// Updates a realm to set `mfa_required_roles` and verifies the update.
#[tokio::test]
async fn realm_mfa_required_roles_update_persists() {
    let harness = common::TestHarness::embedded().await.expect("test harness");
    let realm = create_realm(&harness);

    assert!(
        realm.config().mfa_required_roles.is_none(),
        "mfa_required_roles must default to None"
    );

    let updated = harness
        .identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    mfa_required_roles: Some(vec!["admin".to_string(), "finance".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update_realm");

    assert_eq!(
        updated.config().mfa_required_roles,
        Some(vec!["admin".to_string(), "finance".to_string()]),
        "mfa_required_roles update must persist"
    );
}

// ─── realm-wide mfa_required vs. role-scoped mfa_required_roles ─────────────

/// Realm-wide `mfa_required: true` blocks session creation for any user
/// without MFA enrolled, regardless of their roles.
///
/// **Why this test was renamed:** the prior version was titled
/// `realm_mfa_required_roles_blocks_session_for_matching_role_user`, but it
/// configured the realm with `mfa_required: true` (the realm-wide flag), not
/// `mfa_required_roles`. The role seeding and assignment were dead setup —
/// they did not affect the outcome. The engine's `create_session` only checks
/// `mfa_required: true`; the role-scoped gate lives in the web layer
/// (`src/protocol/web/required_action.rs` `required_action_check`) and is
/// covered by the web-layer integration tests there.
#[tokio::test]
async fn realm_wide_mfa_required_blocks_session_for_any_user_without_mfa() {
    let harness = common::TestHarness::embedded().await.expect("test harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-mfa-block-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..Default::default()
            }),
        })
        .expect("create realm");

    let user = create_user(&harness, realm.id());

    // Engine gate: MfaRequired is returned for any user when mfa_required=true.
    let err = harness
        .identity()
        .create_session(
            realm.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect_err("create_session must fail when mfa_required is true and user has no MFA");
    assert!(
        matches!(err, hearth::identity::IdentityError::MfaRequired),
        "expected MfaRequired, got: {err:?}"
    );
}

/// `mfa_required_roles` does NOT gate engine-level `create_session` — it is
/// enforced by the web layer only. A user with a matching role can still
/// create a session via the engine directly, while a user in a realm with
/// `mfa_required: true` cannot.
///
/// This test draws the line between the two controls: `mfa_required_roles`
/// is a web-layer injection gate (it pushes `EnrollMfa` into `RequiredAction`
/// on the login flow), whereas `mfa_required` is an engine-level hard block.
#[tokio::test]
async fn mfa_required_roles_does_not_block_engine_create_session() {
    let harness = common::TestHarness::embedded().await.expect("test harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("role-gate-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                // Role-gate only — no realm-wide mfa_required flag.
                mfa_required_roles: Some(vec!["realm.admin".to_string()]),
                mfa_required: None,
                ..Default::default()
            }),
        })
        .expect("create realm");

    // Seed standard roles and assign admin to the user.
    harness.rbac().seed_realm(realm.id()).expect("seed_realm");
    let user = create_user(&harness, realm.id());
    let admin_role = harness
        .rbac()
        .get_role_by_name(realm.id(), "realm.admin")
        .expect("get_role_by_name")
        .expect("realm.admin must exist after seed");
    harness
        .rbac()
        .assign_role(
            realm.id(),
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign_role");

    // The engine does NOT enforce mfa_required_roles — session creation
    // succeeds even for a user with the matching role and no MFA enrolled.
    // The web layer (`required_action_check`) injects EnrollMfa on the
    // login flow; that path requires a full HTTP WebState harness and is
    // tested in the web-layer integration suite.
    harness
        .identity()
        .create_session(
            realm.id(),
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect(
            "create_session must succeed via the engine when only mfa_required_roles is set \
             (role-gate is enforced by the web layer, not the engine)",
        );
}
