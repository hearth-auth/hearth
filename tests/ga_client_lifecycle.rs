//! GA audit 2026-09-28 — OAuth client lifecycle.
//!
//! - **B9**: a client archived by removal from `hearth.yaml` (status
//!   `Archived`) kept working on every grant except `/authorize`. Every grant,
//!   client authentication and PAR must refuse it, and archival must revoke
//!   its outstanding refresh tokens (grant families).
//! - **L5**: a `client_credentials` access token stayed valid after its client
//!   was archived or deleted, because validation only consults the revoked-JTI
//!   projection. Archival and deletion now project a client-wide cutoff into
//!   that same projection.
//! - **L10**: a public client's refresh token could be redeemed under a
//!   different `client_id`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ApplicationStatus, ClientCredentialsRequest, ClientTrustLevel, CodeChallengeMethod,
    CreateUserRequest, DeviceAuthorizationRequest, IdentityError, PushedAuthorizationRequest,
    RefreshBindContext, RegisterClientRequest, SessionContext, TokenIssuanceContext,
    UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const SECRET: &str = "ga-lifecycle-secret-0123456789!";
const REDIRECT_URI: &str = "https://app.example.com/cb";

/// Registers a client — confidential when `secret` is `Some`, public otherwise.
fn register(h: &common::TestHarness, realm: &RealmId, secret: Option<&str>) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("ga-client-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "client_credentials".to_string(),
                    "refresh_token".to_string(),
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

fn set_status(h: &common::TestHarness, realm: &RealmId, client: &ClientId, s: ApplicationStatus) {
    h.identity()
        .update_client(
            realm,
            client,
            &UpdateClientRequest {
                status: Some(s),
                ..Default::default()
            },
        )
        .expect("update client status");
}

fn archive(h: &common::TestHarness, realm: &RealmId, client: &ClientId) {
    set_status(h, realm, client, ApplicationStatus::Archived);
}

/// A refresh token whose grant family is bound to `client`.
fn client_refresh(h: &common::TestHarness, realm: &RealmId, client: &ClientId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("ga-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "GA".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.clone()),
                ..TokenIssuanceContext::default()
            },
        )
        .expect("issue tokens")
        .refresh_token()
        .to_string()
}

fn bind(client: &ClientId) -> RefreshBindContext {
    RefreshBindContext {
        authenticated_client_id: Some(client.clone()),
    }
}

fn cc_request(client: &ClientId) -> ClientCredentialsRequest {
    ClientCredentialsRequest {
        client_id: client.clone(),
        client_secret: Some(SECRET.to_string()),
        scope: None,
        dpop_jkt: None,
        client_assertion_type: None,
        client_assertion: None,
        resource: None,
    }
}

fn par_request(client: &ClientId) -> PushedAuthorizationRequest {
    use base64::Engine as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, b"ga-lifecycle-verifier-0123456789");
    PushedAuthorizationRequest {
        organization: None,
        client_id: client.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "st".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()),
        ),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: None,
        request: None,
        response_mode: None,
        prompt: None,
    }
}

// ─── B9: every grant refuses an archived client ─────────────────────────────

#[tokio::test]
async fn archived_client_cannot_use_client_credentials() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    h.identity()
        .client_credentials_token(&realm, &cc_request(&client))
        .expect("control: an active client gets a token");

    archive(&h, &realm, &client);
    let err = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&client))
        .expect_err("an archived client must not obtain a client_credentials token");
    assert!(
        matches!(err, IdentityError::InvalidClientSecret),
        "expected the uniform invalid_client refusal, got {err:?}"
    );
}

#[tokio::test]
async fn archived_client_cannot_authenticate_at_the_endpoint() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let confidential = register(&h, &realm, Some(SECRET));
    let public = register(&h, &realm, None);
    h.identity()
        .authenticate_client(&realm, &confidential, Some(SECRET))
        .expect("control: confidential authenticates");
    h.identity()
        .authenticate_client(&realm, &public, None)
        .expect("control: public authenticates");
    h.identity()
        .authenticate_confidential_client(&realm, &confidential, Some(SECRET))
        .expect("control: confidential-only authenticates");

    archive(&h, &realm, &confidential);
    archive(&h, &realm, &public);
    assert!(matches!(
        h.identity()
            .authenticate_client(&realm, &confidential, Some(SECRET)),
        Err(IdentityError::InvalidClientSecret)
    ));
    assert!(matches!(
        h.identity().authenticate_client(&realm, &public, None),
        Err(IdentityError::InvalidClientSecret)
    ));
    assert!(matches!(
        h.identity()
            .authenticate_confidential_client(&realm, &confidential, Some(SECRET)),
        Err(IdentityError::InvalidClientSecret)
    ));
}

#[tokio::test]
async fn archived_client_cannot_refresh() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    let refresh = client_refresh(&h, &realm, &client);

    archive(&h, &realm, &client);
    let err = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, Some(&bind(&client)))
        .expect_err("an archived client's refresh token must not rotate");
    assert!(
        matches!(
            err,
            IdentityError::TokenRevoked | IdentityError::InvalidClient
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn archival_revokes_the_clients_refresh_tokens() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    let refresh = client_refresh(&h, &realm, &client);

    // Archive, then restore. A status gate alone would let the old refresh
    // token work again after the restore; archival must have revoked it.
    archive(&h, &realm, &client);
    set_status(&h, &realm, &client, ApplicationStatus::Active);
    let err = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, Some(&bind(&client)))
        .expect_err("a refresh token issued before archival must stay revoked");
    assert!(matches!(err, IdentityError::TokenRevoked), "got {err:?}");

    // Control: a family issued after the restore works.
    let fresh = client_refresh(&h, &realm, &client);
    h.identity()
        .refresh_tokens(&realm, &fresh, None, Some(&bind(&client)))
        .expect("a refresh token issued after the restore rotates");
}

#[tokio::test]
async fn archived_client_cannot_start_device_authorization() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, None);
    let req = DeviceAuthorizationRequest {
        client_id: client.clone(),
        scope: Some("openid".to_string()),
    };
    h.identity()
        .device_authorize(&realm, &req)
        .expect("control: an active client starts the device flow");

    archive(&h, &realm, &client);
    let err = h
        .identity()
        .device_authorize(&realm, &req)
        .expect_err("an archived client must not start the device flow");
    assert!(matches!(err, IdentityError::InvalidClient), "got {err:?}");
}

#[tokio::test]
async fn archived_client_cannot_push_a_par_request() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, None);
    h.identity()
        .push_authorization_request(&realm, &par_request(&client))
        .expect("control: an active client pushes a PAR request");

    archive(&h, &realm, &client);
    let err = h
        .identity()
        .push_authorization_request(&realm, &par_request(&client))
        .expect_err("an archived client must not push a PAR request");
    assert!(matches!(err, IdentityError::InvalidClient), "got {err:?}");
}

async fn post_token(state: &Arc<AppState>, realm: &RealmId, form: &str) -> StatusCode {
    let resp = router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    status
}

/// Black box: `POST /token grant_type=client_credentials` for an archived
/// client answers 401, as for an unknown one.
#[tokio::test]
async fn archived_client_credentials_over_http_is_401() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={SECRET}",
        client.as_uuid()
    );
    assert_eq!(post_token(&state, &realm, &form).await, StatusCode::OK);

    archive(&h, &realm, &client);
    assert_eq!(
        post_token(&state, &realm, &form).await,
        StatusCode::UNAUTHORIZED
    );
}

// ─── L5: outstanding client_credentials tokens die with their client ───────

#[tokio::test]
async fn archival_invalidates_outstanding_client_credentials_tokens() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    let token = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&client))
        .expect("cc token")
        .access_token()
        .to_string();
    h.identity()
        .validate_token(&realm, &token)
        .expect("control: the token validates while the client is active");

    archive(&h, &realm, &client);
    assert!(
        h.identity().validate_token(&realm, &token).is_err(),
        "a client_credentials token must stop validating once its client is archived"
    );

    // Restoring the client does not resurrect the pre-archival token.
    set_status(&h, &realm, &client, ApplicationStatus::Active);
    assert!(
        h.identity().validate_token(&realm, &token).is_err(),
        "restoring the client must not resurrect a token cut off by archival"
    );
}

#[tokio::test]
async fn deletion_invalidates_outstanding_client_credentials_tokens() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let client = register(&h, &realm, Some(SECRET));
    let other = register(&h, &realm, Some(SECRET));
    let token = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&client))
        .expect("cc token")
        .access_token()
        .to_string();
    let other_token = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&other))
        .expect("cc token")
        .access_token()
        .to_string();

    h.identity()
        .delete_client(&realm, &client)
        .expect("delete client");
    assert!(
        h.identity().validate_token(&realm, &token).is_err(),
        "a client_credentials token must stop validating once its client is deleted"
    );
    h.identity()
        .validate_token(&realm, &other_token)
        .expect("another client's token is unaffected");
}

// ─── L10: a public client's refresh token is bound to that client ───────────

#[tokio::test]
async fn public_refresh_token_cannot_be_redeemed_under_another_client_id() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h.create_realm();
    let owner = register(&h, &realm, None);
    let other = register(&h, &realm, None);
    let refresh = client_refresh(&h, &realm, &owner);

    let err = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, Some(&bind(&other)))
        .expect_err("another public client must not redeem the refresh token");
    assert!(matches!(err, IdentityError::InvalidClient), "got {err:?}");

    // The refused attempt must not have burned the token for its owner.
    h.identity()
        .refresh_tokens(&realm, &refresh, None, Some(&bind(&owner)))
        .expect("the owning public client still redeems it");
}
