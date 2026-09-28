//! GA audit 2026-09-28 L11 — any confidential client could introspect any
//! user token that carries no `azp`, and an Introspection/Decision-mode caller
//! got the user's live roles and permissions back.
//!
//! A session-bound token without `azp` is now introspectable only by:
//! - a client its `aud` names,
//! - the client its grant family was issued to, or
//! - a declared resource server (a client whose `access_token_authorization`
//!   is `introspection` or `decision` — an admin-registered setting; dynamic
//!   registration always yields `embedded`).
//!
//! Any other caller gets `{"active": false}`. Tokens that do carry `azp`, and
//! sessionless (machine) tokens, keep their existing, narrower rules.

#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AccessTokenAuthorization, ClientTrustLevel, CreateUserRequest, RegisterClientRequest,
    SessionContext, TokenIntrospectionRequest, TokenIssuanceContext,
};

fn client(h: &common::TestHarness, realm: &RealmId, mode: AccessTokenAuthorization) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("rs-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some("ga-introspect-secret-0123!".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                access_token_authorization: mode,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap()
        .client_id()
        .clone()
}

/// A user access token; `issued_to` is the OAuth client the grant family
/// belongs to (`None`: a Hearth first-party session token).
fn user_token(h: &common::TestHarness, realm: &RealmId, issued_to: Option<&ClientId>) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("l11-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "L11".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .unwrap();
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: issued_to.cloned(),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
        .access_token()
        .to_string()
}

fn active_for(h: &common::TestHarness, realm: &RealmId, token: &str, caller: &ClientId) -> bool {
    h.identity()
        .introspect_token(
            realm,
            &TokenIntrospectionRequest {
                token: token.to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(caller.clone()),
            },
        )
        .unwrap()
        .active
}

#[tokio::test]
async fn an_unrelated_client_cannot_introspect_another_clients_user_token() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let owner = client(&h, &realm, AccessTokenAuthorization::Embedded);
    let stranger = client(&h, &realm, AccessTokenAuthorization::Embedded);
    let token = user_token(&h, &realm, Some(&owner));

    assert!(
        active_for(&h, &realm, &token, &owner),
        "the client the token was issued to may introspect it"
    );
    assert!(
        !active_for(&h, &realm, &token, &stranger),
        "an unrelated client must get active=false"
    );
}

#[tokio::test]
async fn an_unrelated_client_cannot_introspect_a_first_party_session_token() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let stranger = client(&h, &realm, AccessTokenAuthorization::Embedded);
    let token = user_token(&h, &realm, None);
    assert!(!active_for(&h, &realm, &token, &stranger));
}

#[tokio::test]
async fn a_declared_resource_server_can_introspect_user_tokens() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let owner = client(&h, &realm, AccessTokenAuthorization::Embedded);
    let rs = client(&h, &realm, AccessTokenAuthorization::Introspection);
    let decision_rs = client(&h, &realm, AccessTokenAuthorization::Decision);

    let issued = user_token(&h, &realm, Some(&owner));
    let first_party = user_token(&h, &realm, None);
    for token in [&issued, &first_party] {
        assert!(active_for(&h, &realm, token, &rs), "introspection-mode RS");
        assert!(
            active_for(&h, &realm, token, &decision_rs),
            "decision-mode RS"
        );
    }
}
