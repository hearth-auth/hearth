//! The UserInfo endpoint and the profile claims, as OIDC Core 1.0 states them
//! (#639). The OpenID Foundation Basic OP plan found two defects:
//!
//! - §5.3.1: "The UserInfo Endpoint MUST support the use of the HTTP GET and
//!   HTTP POST methods". `POST /userinfo` answered `405`
//!   (`oidcc-userinfo-post-header`).
//! - §5.3.2: a claim with no value is omitted, not sent as an empty string. A
//!   user with no first or last name got `"given_name": ""` and
//!   `"family_name": ""` in the ID token and the UserInfo response
//!   (`oidcc-scope-profile`).

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    IdentityEngine, OidcTokenResponse, RegisterClientRequest, TokenExchangeRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://rp.example.com/cb";
const PKCE_VERIFIER: &str = "userinfo-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";

struct Rig {
    _harness: common::TestHarness,
    state: Arc<AppState>,
    realm: RealmId,
    realm_name: String,
    client: ClientId,
}

async fn rig() -> Rig {
    {
        let h = common::TestHarness::in_process().await.unwrap();
        let realm_name = format!("userinfo-{}", uuid::Uuid::new_v4());
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: realm_name.clone(),
                config: None,
            })
            .unwrap()
            .id()
            .clone();
        let client = h
            .identity()
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "UserInfo RP".to_string(),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    ..Default::default()
                },
            )
            .unwrap()
            .client_id()
            .clone();
        let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
        Rig {
            _harness: h,
            state,
            realm,
            realm_name,
            client,
        }
    }
}

/// A user with a display name and no first or last name, as a seeded or
/// self-registered user often is.
fn user_without_names(engine: &dyn IdentityEngine, realm: &RealmId) -> hearth::core::UserId {
    engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@userinfo.test", uuid::Uuid::new_v4()),
                display_name: "Uma Info".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap()
        .id()
        .clone()
}

/// An authorization-code + PKCE flow through the engine (the path `/token`
/// takes) for `scope`.
fn code_flow(rig: &Rig, scope: &str) -> OidcTokenResponse {
    let engine = rig.state.identity.as_ref();
    let user = user_without_names(engine, &rig.realm);
    let digest = ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes());
    let code = engine
        .authorize(
            &rig.realm,
            &AuthorizationRequest {
                organization: None,
                client_id: rig.client.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: scope.to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user,
                code_challenge: Some(URL_SAFE_NO_PAD.encode(digest.as_ref())),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize")
        .code()
        .to_string();
    engine
        .exchange_authorization_code(
            &rig.realm,
            &TokenExchangeRequest {
                client_id: rig.client.clone(),
                code,
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("exchange authorization code")
}

async fn userinfo(
    rig: &Rig,
    method: &str,
    uri: &str,
    access_token: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = router(Arc::clone(&rig.state))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-Realm-ID", rig.realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn id_token_claims(tokens: &OidcTokenResponse) -> serde_json::Value {
    let payload = tokens.id_token().split('.').nth(1).expect("JWS payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// OIDC Core §5.3.1: GET and POST, on both UserInfo routes.
#[tokio::test]
async fn userinfo_answers_get_and_post_on_both_routes() {
    let rig = rig().await;
    let tokens = code_flow(&rig, "openid");
    let realm_route = format!("/realms/{}/userinfo", rig.realm_name);
    for method in ["GET", "POST"] {
        for uri in ["/userinfo", realm_route.as_str()] {
            let (status, body) = userinfo(&rig, method, uri, tokens.access_token()).await;
            assert_eq!(status, StatusCode::OK, "{method} {uri}: {body}");
            assert!(
                body["sub"].as_str().is_some_and(|s| !s.is_empty()),
                "{method} {uri}: no sub in {body}"
            );
        }
    }
}

/// OIDC Core §5.3.2: a profile claim with no value is left out of the ID
/// token and the UserInfo response; one with a value is there.
#[tokio::test]
async fn empty_profile_claims_are_omitted() {
    let rig = rig().await;
    let tokens = code_flow(&rig, "openid profile");
    let realm_route = format!("/realms/{}/userinfo", rig.realm_name);
    let (status, info) = userinfo(&rig, "GET", &realm_route, tokens.access_token()).await;
    assert_eq!(status, StatusCode::OK, "{info}");

    for (what, claims) in [("ID token", id_token_claims(&tokens)), ("UserInfo", info)] {
        assert_eq!(claims["name"], "Uma Info", "{what}: name in {claims}");
        for empty in ["given_name", "family_name"] {
            assert!(
                claims.get(empty).is_none(),
                "{what}: {empty} has no value and must be omitted; got {claims}"
            );
        }
    }
}
