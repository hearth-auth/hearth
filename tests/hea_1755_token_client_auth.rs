//! HEA-1755 R6 — Token-endpoint confidential-client authentication.
//!
//! Two remediations, each with regression coverage that fails against the
//! pre-fix code and passes after:
//!
//! - **O2**: the `authorization_code` exchange never verified `client_secret`.
//!   A confidential client's code could be redeemed without proving possession
//!   of the secret. Fixed at the token endpoint (`enforce_confidential_client_auth`).
//! - **O1**: the `refresh_token` grant had no client authentication and no
//!   token↔client binding. A refresh token issued to one confidential client
//!   could be redeemed unauthenticated or by a different client. Fixed by
//!   binding the grant family to the authenticated client in
//!   `rotate_grant_family`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    IdentityError, RefreshBindContext, RegisterClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://app.example.com/cb";

/// A fixed PKCE verifier/challenge (S256) pair used across the exchange flows.
fn pkce_pair() -> (String, String) {
    let verifier = "hea1755-verifier-abcdefghijklmnopqrstuvwxyz-012345".to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());
    (verifier, challenge)
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> hearth::core::UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@hea1755.test", uuid::Uuid::new_v4()),
                display_name: "HEA-1755 User".to_string(),
                first_name: "H".to_string(),
                last_name: "U".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap()
        .id()
        .clone()
}

fn register_client(
    h: &common::TestHarness,
    realm: &RealmId,
    secret: Option<&str>,
) -> hearth::identity::OAuthClient {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("hea1755-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap()
}

/// Runs `authorize` (PKCE) and returns the freshly minted authorization code.
fn mint_code(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &hearth::identity::OAuthClient,
    user_id: &hearth::core::UserId,
    challenge: &str,
) -> String {
    h.identity()
        .grant_consent(
            realm,
            &hearth::identity::ConsentGrant {
                key: hearth::identity::ConsentKey {
                    user_id: user_id.clone(),
                    client_id: client.client_id().clone(),
                    org_id: None,
                    resource: None,
                },
                scopes: vec!["openid".to_string()],
                via: hearth::identity::ConsentSurface::Web,
            },
        )
        .expect("consent");
    h.identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                organization: None,
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: Some(challenge.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize")
        .code()
        .to_string()
}

async fn post_token(
    state: &Arc<AppState>,
    realm_id: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ─── O2: authorization_code exchange requires client_secret ──────────────────

/// A confidential client cannot redeem its code without a client_secret.
#[tokio::test]
async fn o2_code_exchange_confidential_without_secret_rejected() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let client = register_client(&h, realm.id(), Some("o2-secret-abcdefgh!"));
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let (status, _json) = post_token(
        &state,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id().as_uuid().to_string(),
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            // no client_secret
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "confidential code exchange without client_secret must be 401"
    );
}

/// A confidential client cannot redeem its code with the wrong client_secret.
#[tokio::test]
async fn o2_code_exchange_confidential_wrong_secret_rejected() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let client = register_client(&h, realm.id(), Some("o2-secret-abcdefgh!"));
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let (status, _json) = post_token(
        &state,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id().as_uuid().to_string(),
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_secret": "totally-wrong-secret",
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "confidential code exchange with wrong client_secret must be 401"
    );
}

/// A confidential client redeems its code with the correct client_secret.
#[tokio::test]
async fn o2_code_exchange_confidential_correct_secret_succeeds() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let secret = "o2-secret-abcdefgh!";
    let client = register_client(&h, realm.id(), Some(secret));
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let (status, json) = post_token(
        &state,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id().as_uuid().to_string(),
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_secret": secret,
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "correct secret must succeed: {json}"
    );
    assert!(json["access_token"].as_str().is_some_and(|t| !t.is_empty()));
}

/// Public clients (PKCE, no secret) are unaffected by the O2 fix.
#[tokio::test]
async fn o2_code_exchange_public_client_unaffected() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let client = register_client(&h, realm.id(), None); // public
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let (status, json) = post_token(
        &state,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id().as_uuid().to_string(),
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "public client PKCE exchange must still succeed: {json}"
    );
    assert!(json["access_token"].as_str().is_some_and(|t| !t.is_empty()));
}

// ─── O1: refresh_token grant binds to its confidential client ────────────────

/// Exchanges a confidential client's code (with the correct secret) and returns
/// the issued refresh token.
async fn issue_confidential_refresh(
    h: &common::TestHarness,
    state: &Arc<AppState>,
    realm_id_str: &str,
    client: &hearth::identity::OAuthClient,
    user_id: &hearth::core::UserId,
    secret: &str,
) -> String {
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(
        h,
        &RealmId::new(uuid::Uuid::parse_str(realm_id_str).unwrap()),
        client,
        user_id,
        &challenge,
    );
    let (status, json) = post_token(
        state,
        realm_id_str,
        serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client.client_id().as_uuid().to_string(),
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_secret": secret,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed exchange must succeed: {json}");
    json["refresh_token"].as_str().unwrap().to_string()
}

/// A confidential client's refresh token cannot be redeemed without client auth.
#[tokio::test]
async fn o1_refresh_confidential_without_client_auth_rejected() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let secret = "o1-secret-abcdefgh!";
    let client = register_client(&h, realm.id(), Some(secret));
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let refresh =
        issue_confidential_refresh(&h, &state, &realm_id_str, &client, &user, secret).await;

    // Refresh with NO client_secret → 401 (verify_endpoint_client rejects the
    // confidential client without a secret).
    let (status, _json) = post_token(
        &state,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": client.client_id().as_uuid().to_string(),
            "refresh_token": refresh,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "confidential refresh without client auth must be 401"
    );
}

/// A confidential client's refresh token cannot be redeemed by a different client.
#[tokio::test]
async fn o1_refresh_token_bound_to_issuing_client() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();
    let user = make_user(&h, &realm_id);
    let secret_a = "o1-secret-a-abcdefgh!";
    let client_a = register_client(&h, &realm_id, Some(secret_a));
    let client_b = register_client(&h, &realm_id, Some("o1-secret-b-abcdefgh!"));
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let refresh =
        issue_confidential_refresh(&h, &state, &realm_id_str, &client_a, &user, secret_a).await;

    // Engine-level assertion: authenticating as a *different* client (client_b)
    // must not be able to redeem client_a's refresh token.
    let bind = RefreshBindContext {
        authenticated_client_id: Some(client_b.client_id().clone()),
        dpop_jti: None,
    };
    let cross = h
        .identity()
        .refresh_tokens(&realm_id, &refresh, None, Some(&bind));
    // RFC 6749 §5.2: client_b authenticated; the grant was issued to another
    // client, so the answer is `invalid_grant` (#639).
    assert!(
        matches!(cross, Err(IdentityError::InvalidGrant { .. })),
        "refresh token issued to client_a must be rejected with InvalidGrant when \
         redeemed by client_b, got: {cross:?}"
    );

    // Sanity: authenticating as the correct client succeeds.
    let bind_ok = RefreshBindContext {
        authenticated_client_id: Some(client_a.client_id().clone()),
        dpop_jti: None,
    };
    let ok = h
        .identity()
        .refresh_tokens(&realm_id, &refresh, None, Some(&bind_ok))
        .expect("refresh by the issuing client must succeed");
    assert!(
        !ok.access_token().is_empty(),
        "issuing-client refresh must return a non-empty access token"
    );
}

/// Engine-level: a confidential grant family cannot be refreshed with no
/// authenticated client in the bind context.
#[tokio::test]
async fn o1_refresh_confidential_engine_requires_authenticated_client() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea1755-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();
    let user = make_user(&h, &realm_id);
    let secret = "o1-secret-abcdefgh!";
    let client = register_client(&h, &realm_id, Some(secret));
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let refresh =
        issue_confidential_refresh(&h, &state, &realm_id_str, &client, &user, secret).await;

    // No authenticated client → rejected.
    let none = h.identity().refresh_tokens(&realm_id, &refresh, None, None);
    assert!(
        matches!(none, Err(IdentityError::InvalidClient)),
        "confidential grant family must reject refresh with InvalidClient when no \
         authenticated client is present, got: {none:?}"
    );
}

// ─── RFC 6749 §5: token-endpoint error codes and caching (#639) ─────────────
//
// The OpenID Foundation Basic OP plan found three token-endpoint answers that
// RFC 6749 §5 does not allow: a reused authorization code answered
// `"invalid authorization code"` instead of `invalid_grant`; a refresh token
// presented by another (authenticated) client answered `401 invalid_client`
// instead of `400 invalid_grant` (§5.2: "issued to another client"); and no
// token response carried `Cache-Control: no-store` (§5.1).

/// `POST {uri}` with a JSON body. Returns the status, the response headers and
/// the JSON body.
async fn post_token_at(
    state: &Arc<AppState>,
    uri: &str,
    realm_id: &str,
    body: serde_json::Value,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let resp = router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("X-Realm-ID", realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, headers, json)
}

/// RFC 6749 §5.1: the token response is never cached.
fn assert_not_cached(headers: &axum::http::HeaderMap, what: &str) {
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "{what}: Cache-Control"
    );
    assert_eq!(
        headers.get("pragma").and_then(|v| v.to_str().ok()),
        Some("no-cache"),
        "{what}: Pragma"
    );
}

#[tokio::test]
async fn reused_authorization_code_is_refused_with_invalid_grant() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("rfc6749-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let secret = "rfc6749-secret-abcdefgh!";
    let client = register_client(&h, realm.id(), Some(secret));
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let exchange = serde_json::json!({
        "grant_type": "authorization_code",
        "client_id": client.client_id().as_uuid().to_string(),
        "client_secret": secret,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    });

    let (status, headers, body) =
        post_token_at(&state, "/token", &realm_id_str, exchange.clone()).await;
    assert_eq!(status, StatusCode::OK, "first exchange: {body}");
    assert_not_cached(&headers, "code exchange");

    let (status, headers, body) = post_token_at(&state, "/token", &realm_id_str, exchange).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reused code: {body}");
    assert_eq!(body["error"], "invalid_grant", "reused code: {body}");
    assert_not_cached(&headers, "token error");
}

#[tokio::test]
async fn refresh_token_of_another_client_is_refused_with_invalid_grant() {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm_name = format!("rfc6749-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap();
    let realm_id_str = realm.id().as_uuid().to_string();
    let user = make_user(&h, realm.id());
    let secret_a = "rfc6749-secret-a-abcdefgh!";
    let secret_b = "rfc6749-secret-b-abcdefgh!";
    let client_a = register_client(&h, realm.id(), Some(secret_a));
    let client_b = register_client(&h, realm.id(), Some(secret_b));
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let refresh =
        issue_confidential_refresh(&h, &state, &realm_id_str, &client_a, &user, secret_a).await;
    let realm_token = format!("/realms/{realm_name}/token");

    let (status, _, body) = post_token_at(
        &state,
        &realm_token,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_b.client_id().as_uuid().to_string(),
            "client_secret": secret_b,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "another client: {body}");
    assert_eq!(body["error"], "invalid_grant", "another client: {body}");

    // The refused attempt does not burn the token for its own client.
    let (status, headers, body) = post_token_at(
        &state,
        &realm_token,
        &realm_id_str,
        serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_a.client_id().as_uuid().to_string(),
            "client_secret": secret_a,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the issuing client: {body}");
    assert_not_cached(&headers, "refresh");
}
