//! Audit 2026-08-28 §4.20#10: delete preconditions living in the adapters.
//!
//! Two preconditions guard permanent deletion, and both were hand-rolled by
//! each protocol adapter rather than enforced where the deletion happens:
//!
//! - the **archival gate** — a realm must be archived before it can be
//!   permanently deleted. REST and the `/ui` tree each carried their own copy;
//!   gRPC `DeleteRealm` carried none, so a gRPC admin could destroy a live
//!   tenant that REST would have refused.
//! - the **YAML-managed gate** — an application declared in `hearth.yaml` is
//!   config-managed and must not be deleted at runtime. Only the `/ui` tree
//!   checked it; REST and gRPC application delete did not.
//!
//! Both now live in the identity engine, so every adapter gets them.

#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, IdentityError, ImportClientRequest, RealmStatus,
    RegisterClientRequest, UpdateRealmRequest,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn create_realm(h: &common::TestHarness, name: &str) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn archive(h: &common::TestHarness, realm: &RealmId) {
    h.identity()
        .update_realm(
            realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive realm");
}

// ─── The archival gate ────────────────────────────────────────────────────────

/// The engine refuses to permanently delete a live realm, whatever adapter
/// asked. Before this, only REST and the `/ui` tree refused; gRPC did not.
#[tokio::test]
async fn deleting_an_active_realm_is_refused_by_the_engine() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h, "gate-active");

    let err = h
        .identity()
        .delete_realm(&realm)
        .expect_err("an active realm must not be permanently deletable");
    assert!(
        matches!(err, IdentityError::RealmNotArchived),
        "expected RealmNotArchived, got {err:?}"
    );

    assert!(
        h.identity().get_realm(&realm).expect("get realm").is_some(),
        "the refused delete must leave the realm intact"
    );
}

/// A suspended realm is frozen, not retired. It is still not deletable.
#[tokio::test]
async fn deleting_a_suspended_realm_is_refused_by_the_engine() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h, "gate-suspended");
    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Suspended),
                ..Default::default()
            },
        )
        .expect("suspend realm");

    let err = h
        .identity()
        .delete_realm(&realm)
        .expect_err("a suspended realm must not be permanently deletable");
    assert!(
        matches!(err, IdentityError::RealmNotArchived),
        "expected RealmNotArchived, got {err:?}"
    );
}

/// An archived realm is what the gate exists to admit.
#[tokio::test]
async fn deleting_an_archived_realm_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h, "gate-archived");
    archive(&h, &realm);

    h.identity()
        .delete_realm(&realm)
        .expect("an archived realm must be deletable");

    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        h.identity().get_realm(&realm).expect("get realm").is_none(),
        "the cascade must remove the realm record"
    );
}

/// A realm whose record a previous cascade already removed stays deletable, so
/// the retry that converges an interrupted cascade is not blocked by the gate.
#[tokio::test]
async fn the_gate_does_not_block_a_retry_on_a_realm_with_no_record() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let err = h
        .identity()
        .delete_realm(&RealmId::generate())
        .expect_err("a realm that never existed is not found");
    assert!(
        matches!(err, IdentityError::RealmNotFound),
        "a missing realm must read as RealmNotFound, never as the archival gate, \
         or a half-finished cascade can never be retried; got {err:?}"
    );
}

// ─── The YAML-managed gate ────────────────────────────────────────────────────

/// An application declared in `hearth.yaml` is config-managed. Deleting it at
/// runtime would leave the next reconcile to re-create it, so the engine
/// refuses — for every adapter, not just the `/ui` tree.
#[tokio::test]
async fn deleting_a_yaml_managed_application_is_refused_by_the_engine() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h, "gate-yaml-app");

    // `reconcile_applications` derives a YAML app's `ClientId` as a UUID v5 from
    // realm name + app key, and `is_yaml_managed()` reads exactly that version
    // number. Importing under a v5 ID is the same thing reconciliation does.
    let managed_id = ClientId::new(uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        b"gate-yaml-app/managed",
    ));
    let client = h
        .identity()
        .import_client(
            &realm,
            &ImportClientRequest {
                id: Some(managed_id),
                client_name: "Managed App".to_string(),
                redirect_uris: vec!["https://app.test/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                slug: None,
                trust_level: ClientTrustLevel::default(),
                declared_scopes: Vec::new(),
                consent_spans_orgs: false,
            },
        )
        .expect("import client under a YAML-shaped ID");
    assert!(
        client.is_yaml_managed(),
        "precondition: the imported client must read as YAML-managed"
    );

    let err = h
        .identity()
        .delete_client(&realm, client.client_id())
        .expect_err("a YAML-managed application must not be deletable at runtime");
    assert!(
        matches!(err, IdentityError::YamlManagedResource { .. }),
        "expected YamlManagedResource, got {err:?}"
    );

    assert!(
        h.identity()
            .get_client(&realm, client.client_id())
            .expect("get client")
            .is_some(),
        "the refused delete must leave the application intact"
    );
}

/// A runtime-registered application is still deletable.
#[tokio::test]
async fn deleting_a_runtime_application_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h, "gate-runtime-app");

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Runtime App".to_string(),
                redirect_uris: vec!["https://app.test/callback".to_string()],
                ..Default::default()
            },
        )
        .expect("register client");

    h.identity()
        .delete_client(&realm, client.client_id())
        .expect("a runtime-registered application must be deletable");
}
