#![allow(clippy::unwrap_used)]
//! GA audit 3 round 6 — what a standard relying party matches.
//!
//! * OIDC Core §3.1.3.7 step 2 / Discovery §4.3: an ID token's `iss` equals
//!   the `issuer` of the discovery document the RP used — for a realm, the
//!   realm document (`{base}/realms/{name}`), which is also the access
//!   tokens' issuer. The same identifier is the RFC 9207 `iss` authorization
//!   response parameter. ID tokens carried the
//!   bare base URL instead.
//! * OIDC Back-Channel Logout §2.4 / §2.6: a logout token's `iss`, `sub` and
//!   `sid` are compared with the ID tokens the RP holds for that session, so
//!   they must be the same strings. Logout tokens carried bare UUIDs where
//!   the ID token carries `user_<uuid>` / `session_<uuid>`, and the base
//!   issuer. Front-Channel Logout §2 has the same rule for the `iss` / `sid`
//!   query parameters.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{RealmId, UserId};
use hearth::identity::oidc::RpLogoutRequest;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, OAuthClient,
    OidcTokenResponse, RegisterClientRequest, ResponseMode, TokenExchangeRequest,
    UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://rp.example.com/callback";
const BCL_URI: &str = "https://rp.example.com/backchannel-logout";
const FCL_URI: &str = "https://rp.example.com/frontchannel-logout";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    client: OAuthClient,
}

async fn env() -> Env {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("rp-match-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("rp-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RP User".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "standard-rp".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .expect("client");
    h.identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                backchannel_logout_uri: Some(Some(BCL_URI.into())),
                frontchannel_logout_uri: Some(Some(FCL_URI.into())),
                ..UpdateClientRequest::default()
            },
        )
        .expect("logout uris");
    Env {
        h,
        realm,
        user,
        client,
    }
}

fn claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("a JWT");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

impl Env {
    fn realm_issuer(&self) -> String {
        self.h
            .identity()
            .realm_oidc_discovery(&self.realm)
            .expect("realm discovery")
            .issuer
    }

    fn authorize(
        &self,
        response_mode: Option<ResponseMode>,
    ) -> hearth::identity::AuthorizationResponse {
        use data_encoding::BASE64URL_NOPAD;
        let challenge = BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes()).as_ref());
        self.h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    client_id: self.client.client_id().clone(),
                    redirect_uri: REDIRECT_URI.into(),
                    scope: "openid".into(),
                    state: "st".into(),
                    response_type: "code".into(),
                    user_id: self.user.clone(),
                    code_challenge: Some(challenge),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: Some(uuid::Uuid::new_v4().to_string()),
                    resource: None,
                    amr_values: Vec::new(),
                    response_mode,
                    request: None,
                },
            )
            .expect("authorize")
    }

    fn code_exchange(&self) -> OidcTokenResponse {
        let code = self.authorize(None).code().to_string();
        self.h
            .identity()
            .exchange_authorization_code(
                &self.realm,
                &TokenExchangeRequest {
                    client_id: self.client.client_id().clone(),
                    code,
                    redirect_uri: REDIRECT_URI.into(),
                    code_verifier: Some(VERIFIER.into()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("code exchange")
    }
}

#[tokio::test]
async fn id_token_iss_is_the_realm_discovery_issuer() {
    let env = env().await;
    let issuer = env.realm_issuer();
    let tokens = env.code_exchange();

    assert_eq!(
        claims(tokens.id_token())["iss"],
        issuer.as_str(),
        "OIDC Core §3.1.3.7 step 2: ID token iss == the realm discovery issuer"
    );
    assert_eq!(
        claims(tokens.access_token())["iss"],
        issuer.as_str(),
        "control: access tokens already carry the realm issuer"
    );

    let response = env.authorize(None);
    assert_eq!(
        response.iss(),
        issuer,
        "RFC 9207 iss == the realm discovery issuer"
    );
}

#[tokio::test]
async fn logout_token_iss_sub_and_sid_match_the_id_token() {
    let env = env().await;
    let tokens = env.code_exchange();
    let id = claims(tokens.id_token());

    let result = env
        .h
        .identity()
        .initiate_logout(
            &env.realm,
            &RpLogoutRequest {
                id_token_hint: Some(tokens.id_token().to_string()),
                session_id: None,
                post_logout_redirect_uri: None,
                client_id: Some(env.client.client_id().clone()),
                state: None,
            },
        )
        .expect("logout");
    let target = result
        .backchannel_targets
        .iter()
        .find(|t| t.uri == BCL_URI)
        .expect("a back-channel target for the RP");
    let logout = claims(&target.logout_token);
    for claim in ["iss", "sub", "sid"] {
        assert_eq!(
            logout[claim], id[claim],
            "BCL §2.6: the logout token's {claim} must equal the ID token's; \
             logout token {logout}, ID token {id}"
        );
    }
}

#[tokio::test]
async fn frontchannel_logout_iss_and_sid_match_the_id_token() {
    let env = env().await;
    let tokens = env.code_exchange();
    let id = claims(tokens.id_token());

    let app = router(Arc::new(AppState::new(
        env.h.identity_arc(),
        env.h.rbac_arc(),
        env.h.audit_arc(),
    )));
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", tokens.id_token())
        .append_pair("client_id", &env.client.client_id().as_uuid().to_string())
        .finish();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/end_session?{query}"))
                .header("x-realm-id", env.realm.as_uuid().to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    let src_start = html.find(FCL_URI).expect("the RP's front-channel iframe");
    let src = &html[src_start..html[src_start..].find('"').unwrap() + src_start];
    let params: std::collections::HashMap<String, String> =
        form_urlencoded::parse(src.split_once('?').unwrap().1.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        params.get("iss").map(String::as_str),
        id["iss"].as_str(),
        "FCL §2: iss parameter == the ID token's iss; iframe src {src}"
    );
    assert_eq!(
        params.get("sid").map(String::as_str),
        id["sid"].as_str(),
        "FCL §2: sid parameter == the ID token's sid; iframe src {src}"
    );
}
