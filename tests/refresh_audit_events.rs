//! #448 — a refresh-token rotation appends exactly one audit event.
//!
//! Redeeming a refresh token rotates the grant family and slides the session's
//! expiry. No session is created, yet every rotation also appended a
//! `SessionCreated` event next to `TokenRefreshed`: one extra audit write per
//! refresh and an audit log that over-reported session creation.

mod common;

use std::collections::HashSet;

use hearth::audit::{AuditAction, AuditEvent, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest};

fn realm_events(harness: &common::TestHarness, realm: &RealmId) -> Vec<AuditEvent> {
    harness
        .audit()
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("query audit")
}

#[tokio::test]
async fn refresh_appends_one_token_refreshed_event_and_no_session_created() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("refresh-audit-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("refresh-audit-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Refresh Audit".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let pair = common::user_token_pair(harness.identity(), &realm, user.id());

    let before: HashSet<uuid::Uuid> = realm_events(&harness, &realm)
        .iter()
        .map(|e| *e.id.as_uuid())
        .collect();

    harness
        .identity()
        .refresh_tokens(&realm, pair.refresh_token(), None, None)
        .expect("refresh");

    let appended: Vec<AuditAction> = realm_events(&harness, &realm)
        .into_iter()
        .filter(|e| !before.contains(e.id.as_uuid()))
        .map(|e| e.action)
        .collect();
    assert_eq!(
        appended,
        vec![AuditAction::TokenRefreshed],
        "one refresh must append exactly one TokenRefreshed event and no SessionCreated"
    );
}
