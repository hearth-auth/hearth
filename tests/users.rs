//! Integration tests for user CRUD operations.
//!
//! Black box tests via `TestHarness` — exercises the identity engine
//! through the public `IdentityEngine` trait.

mod common;

use hearth::identity::{CreateUserRequest, UpdateUserRequest, UserStatus};

// ===== P0 fast: Full CRUD lifecycle =====

#[tokio::test]
async fn create_and_read_user_by_id() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    let created = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice Smith".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let fetched = harness
        .identity()
        .get_user(&realm, created.id())
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.email(), "alice@example.com");
    assert_eq!(fetched.display_name(), "Alice Smith");
    assert_eq!(fetched.status(), UserStatus::Active);
}

#[tokio::test]
async fn create_and_read_user_by_email() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    let created = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "Bob@Example.COM".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    // Lookup by original casing — should still find via normalization
    let fetched = harness
        .identity()
        .get_user_by_email(&realm, "BOB@EXAMPLE.COM")
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.id(), created.id());
    assert_eq!(fetched.email(), "bob@example.com");
}

#[tokio::test]
async fn update_user_fields() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    let created = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    let updated = harness
        .identity()
        .update_user(
            &realm,
            created.id(),
            &UpdateUserRequest {
                display_name: Some("Alice Smith".to_string()),
                status: Some(UserStatus::Disabled),
                ..UpdateUserRequest::default()
            },
        )
        .expect("update");

    assert_eq!(updated.display_name(), "Alice Smith");
    assert_eq!(updated.status(), UserStatus::Disabled);
    assert_eq!(updated.email(), "alice@example.com"); // unchanged
    assert!(updated.updated_at() >= created.updated_at());
}

#[tokio::test]
async fn delete_user_removes_from_both_indexes() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    let created = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    harness
        .identity()
        .delete_user(&realm, created.id())
        .expect("delete");

    assert!(harness
        .identity()
        .get_user(&realm, created.id())
        .expect("get")
        .is_none());
    assert!(harness
        .identity()
        .get_user_by_email(&realm, "alice@example.com")
        .expect("get")
        .is_none());
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("first create");

    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "Alice@Example.COM".to_string(),
                display_name: "Other".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect_err("should fail");

    assert!(
        format!("{err}").contains("already exists"),
        "error should indicate duplicate: {err}"
    );
}

// ===== P0 fast: Delete cascade (partial — user only) =====

#[tokio::test]
async fn delete_frees_email_for_reuse() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = harness.create_realm();

    let first = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice 1".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create");

    harness
        .identity()
        .delete_user(&realm, first.id())
        .expect("delete");

    // A-20: email is reserved for 90 days after deletion.
    // Verify the reservation is active.
    let err = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice 2".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect_err("email must be reserved after delete");
    assert!(
        matches!(err, hearth::identity::IdentityError::EmailReserved),
        "expected EmailReserved, got {err:?}"
    );
    // A different email can be used immediately.
    let second = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice2@example.com".to_string(),
                display_name: "Alice 2".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("re-create with different email should succeed");

    assert_ne!(first.id(), second.id());
}

// ===== Cross-realm isolation =====

#[tokio::test]
async fn cross_realm_isolation() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_a = harness.create_realm();
    let realm_b = harness.create_realm();

    let alice_a = harness
        .identity()
        .create_user(
            &realm_a,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice A".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create in realm A");

    // Same email in different realm should succeed
    let alice_b = harness
        .identity()
        .create_user(
            &realm_b,
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice B".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create in realm B should succeed");

    assert_ne!(alice_a.id(), alice_b.id());

    // Can't see realm A's user from realm B
    assert!(harness
        .identity()
        .get_user(&realm_b, alice_a.id())
        .expect("get")
        .is_none());
}

// ===== Zero-PII residual checks (HEA-1270) =====

/// After `delete_user`, the ONLY remaining key for the deleted identity is the
/// A-20 90-day email tombstone (`email:reserved:{email}`).  All PII-bearing
/// key families must be empty.
#[tokio::test]
async fn delete_user_leaves_no_residual_pii() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let identity = harness.identity();
    let storage = harness.storage();

    let realm = harness.create_realm();

    let user = identity
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "pii-test@example.com".to_string(),
                display_name: "PII Test User".to_string(),
                first_name: "PII".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let user_id = user.id().clone();
    let user_email = user.email().to_string();

    identity.delete_user(&realm, &user_id).expect("delete user");

    // Helper: assert a prefix is empty in the realm's storage namespace.
    let assert_empty = |prefix: &str, label: &str| {
        let start = prefix.as_bytes().to_vec();
        let mut end = start.clone();
        *end.last_mut().expect("non-empty prefix") += 1;
        let entries = storage.scan(&realm, &start, &end).unwrap_or_default();
        assert!(
            entries.is_empty(),
            "residual PII after delete_user: prefix '{}' must be empty, found {} entries",
            label,
            entries.len()
        );
    };

    // All PII-bearing key families must be completely gone.
    assert_empty("usr:id:", "user primary record");
    assert_empty("usr:email:", "user email index");
    assert_empty("cred:user:", "credentials");
    assert_empty("mfa:totp:", "TOTP secrets");
    assert_empty("webauthn:cred:", "WebAuthn credentials");
    assert_empty("webauthn:disc:", "WebAuthn discoverable index");
    assert_empty("ses:id:", "sessions");
    assert_empty("ses:user:", "session user index");
    assert_empty("orgm:user:", "org memberships (user→org side)");
    assert_empty("dfp:user:", "device fingerprints");
    assert_empty("email:change:", "pending email-change tokens");
    assert_empty("fed:ext_fwd:", "federated identity forward index");
    assert_empty("scim:ext_user_fwd:", "SCIM user forward mapping");
    assert_empty("oauth:consent:", "OAuth consent records");

    // The A-20 tombstone MUST survive for 90 days so re-registration is blocked.
    let reserved_key = format!("email:reserved:{user_email}");
    let start = reserved_key.as_bytes().to_vec();
    let mut end = start.clone();
    *end.last_mut().expect("non-empty key") += 1;
    let tombstones = storage.scan(&realm, &start, &end).unwrap_or_default();
    assert_eq!(
        tombstones.len(),
        1,
        "A-20 tombstone must be present at email:reserved:{{email}} after delete_user"
    );
}

/// After `delete_realm`, ALL key families in the deleted realm's namespace
/// must be empty — including the A-20 email tombstone, org-slug reservation
/// tombstones, and device fingerprint entries.  No PII should outlive its realm.
#[tokio::test]
async fn delete_realm_leaves_no_residual_pii() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let identity = harness.identity();
    let storage = harness.storage();

    let realm_id = harness.create_realm();

    // Create a user so that delete_user plants the A-20 tombstone.
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "realm-pii-test@example.com".to_string(),
                display_name: "Realm PII Test".to_string(),
                first_name: "Realm".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let user_email = user.email().to_string();

    // Delete the user — this writes the email:reserved: tombstone.
    identity
        .delete_user(&realm_id, user.id())
        .expect("delete user");

    // Confirm tombstone exists before realm deletion.
    let reserved_key = format!("email:reserved:{user_email}");
    let ts_start = reserved_key.as_bytes().to_vec();
    let mut ts_end = ts_start.clone();
    *ts_end.last_mut().expect("non-empty key") += 1;
    let tombstones_before = storage
        .scan(&realm_id, &ts_start, &ts_end)
        .unwrap_or_default();
    assert_eq!(
        tombstones_before.len(),
        1,
        "tombstone must exist before realm delete (test pre-condition)"
    );

    // Delete the realm — cascade must clean up the tombstone too.
    identity.delete_realm(&realm_id).expect("delete realm");

    // Helper: assert a prefix is empty in the (now-deleted) realm's namespace.
    let assert_empty = |prefix: &str, label: &str| {
        let start = prefix.as_bytes().to_vec();
        let mut end = start.clone();
        *end.last_mut().expect("non-empty prefix") += 1;
        let entries = storage.scan(&realm_id, &start, &end).unwrap_or_default();
        assert!(
            entries.is_empty(),
            "residual PII after delete_realm: prefix '{}' must be empty, found {} entries",
            label,
            entries.len()
        );
    };

    // The A-20 tombstone must be gone — it must not outlive the realm.
    assert_empty("email:reserved:", "A-20 email tombstones");

    // All other key families must also be wiped.
    assert_empty("usr:id:", "user records");
    assert_empty("usr:email:", "user email index");
    assert_empty("cred:user:", "credentials");
    assert_empty("ses:id:", "sessions");
    assert_empty("mfa:totp:", "TOTP secrets");
    assert_empty("webauthn:cred:", "WebAuthn credentials");
    assert_empty("org:id:", "org records");
    assert_empty("slug:org:", "org slug reservation tombstones");
    assert_empty("dfp:user:", "device fingerprints");
    assert_empty("email:change:", "pending email-change tokens");
    assert_empty("orgm:org:", "org memberships (org→user side)");
    assert_empty("orgm:user:", "user memberships (user→org side)");
    assert_empty("oauth:client:", "OAuth clients");
    assert_empty("rel:", "RBAC relation tuples");
}
