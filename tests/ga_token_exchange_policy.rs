//! GA audit 2026-09-28 M8 — RFC 8693 token exchange had no per-client policy.
//!
//! - A public client exchanged tokens on its `client_id` alone.
//! - Any client could exchange, whatever its registered `grant_types`.
//! - The requested `audience` replaced `aud` verbatim (and `resource` was
//!   appended verbatim), so a holder of a token for one resource server could
//!   mint one accepted by another.
//!
//! The policy now: the exchanging client must be an Active, confidential
//! client whose `grant_types` include the token-exchange grant, and
//! `audience` / `resource` must name a protected resource registered in the
//! realm (RFC 8693 §2.2.2 `invalid_target` otherwise).

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ApplicationStatus, ClientTrustLevel, CreateUserRequest, IdentityError, RegisterClientRequest,
    RegisterProtectedResourceRequest, Rfc8693Request, SessionContext, TokenIssuanceContext,
    UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const TE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SECRET: &str = "ga-token-exchange-secret-0123!";
const RS: &str = "https://rs.example.com/api";

fn client(h: &common::TestHarness, realm: &RealmId, secret: bool, grants: &[&str]) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("te-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: secret.then(|| SECRET.to_string()),
                grant_types: grants.iter().map(|g| (*g).to_string()).collect(),
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap()
        .client_id()
        .clone()
}

fn subject_token(h: &common::TestHarness, realm: &RealmId) -> String {
    // The scope registry refuses a scope the realm does not define.
    h.declare_scopes(realm, &["read"]);
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("te-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TE".into(),
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
                granted_scopes: std::iter::once("read".to_string()).collect(),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
        .access_token()
        .to_string()
}

fn exchange(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    audience: Option<&str>,
    resource: Option<&str>,
) -> Result<String, IdentityError> {
    h.identity()
        .rfc8693_token_exchange(
            realm,
            &Rfc8693Request {
                client_id: client.clone(),
                subject_token: subject_token(h, realm),
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource: resource.map(str::to_string),
                audience: audience.map(str::to_string),
                dpop_jkt: None,
            },
        )
        .map(|r| r.access_token)
}

fn oauth_error(err: &IdentityError) -> &'static str {
    match err {
        IdentityError::TokenExchangeRejected { oauth_error, .. } => oauth_error,
        IdentityError::InvalidClient => "invalid_client",
        other => panic!("unexpected error {other:?}"),
    }
}

fn register_rs(h: &common::TestHarness, realm: &RealmId) {
    h.identity()
        .register_protected_resource(
            realm,
            &RegisterProtectedResourceRequest {
                resource_uri: RS.to_string(),
                display_name: "RS".to_string(),
                scopes: vec!["read".to_string()],
                required_claims: Vec::new(),
                introspection_client_id: None,
            },
        )
        .unwrap();
}

#[tokio::test]
async fn a_confidential_client_with_the_grant_may_exchange() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &[TE]);
    exchange(&h, &realm, &c, None, None).expect("the policy admits this client");
}

#[tokio::test]
async fn a_public_client_may_not_exchange() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, false, &[TE]);
    let err = exchange(&h, &realm, &c, None, None).unwrap_err();
    assert_eq!(oauth_error(&err), "unauthorized_client");
}

#[tokio::test]
async fn a_client_without_the_token_exchange_grant_may_not_exchange() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &["client_credentials"]);
    let err = exchange(&h, &realm, &c, None, None).unwrap_err();
    assert_eq!(oauth_error(&err), "unauthorized_client");
}

#[tokio::test]
async fn an_archived_or_unknown_client_may_not_exchange() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &[TE]);
    h.identity()
        .update_client(
            &realm,
            &c,
            &UpdateClientRequest {
                status: Some(ApplicationStatus::Archived),
                ..Default::default()
            },
        )
        .unwrap();
    let err = exchange(&h, &realm, &c, None, None).unwrap_err();
    assert_eq!(oauth_error(&err), "invalid_client");

    let unknown = ClientId::new(uuid::Uuid::new_v4());
    let err = exchange(&h, &realm, &unknown, None, None).unwrap_err();
    assert_eq!(oauth_error(&err), "invalid_client");
}

#[tokio::test]
async fn audience_must_name_a_registered_protected_resource() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &[TE]);
    let err = exchange(&h, &realm, &c, Some("https://evil.example.com"), None).unwrap_err();
    assert_eq!(oauth_error(&err), "invalid_target");

    register_rs(&h, &realm);
    let token = exchange(&h, &realm, &c, Some(RS), None).expect("a registered audience");
    let claims = hearth::identity::tokens::decode_claims_unverified(&token).unwrap();
    assert!(claims.aud.contains(RS), "aud names the registered resource");
}

/// Narrowing to an audience the subject token already carries widens nothing,
/// so it needs no registration.
#[tokio::test]
async fn audience_already_in_the_subject_token_is_allowed() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &[TE]);
    // The harness issues user tokens for the default Hearth audience.
    let subject_aud = "hearth";
    let subject =
        hearth::identity::tokens::decode_claims_unverified(&subject_token(&h, &realm)).unwrap();
    assert!(subject.aud.contains(subject_aud), "precondition");
    exchange(&h, &realm, &c, Some(subject_aud), None).expect("the subject's own audience");
}

#[tokio::test]
async fn resource_must_name_a_registered_protected_resource() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, true, &[TE]);
    let err = exchange(&h, &realm, &c, None, Some("https://evil.example.com")).unwrap_err();
    assert_eq!(oauth_error(&err), "invalid_target");

    register_rs(&h, &realm);
    exchange(&h, &realm, &c, None, Some(RS)).expect("a registered resource");
}

/// Black box: a public client at `POST /token` is refused before anything is
/// minted.
#[tokio::test]
async fn public_client_token_exchange_over_http_is_refused() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let c = client(&h, &realm, false, &[TE]);
    let form = format!(
        "grant_type={TE}&client_id={}&subject_token={}\
         &subject_token_type=urn:ietf:params:oauth:token-type:access_token",
        c.as_uuid(),
        subject_token(&h, &realm)
    );
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client", "{body}");
}
