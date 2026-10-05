#![allow(clippy::unwrap_used)]
//! GA audit 3 round 5 — every token field that names a client carries the
//! `client_id` exactly as registration issued it (the bare UUID).
//!
//! OIDC Core §2 / §3.1.3.7: an ID token's `aud` contains the relying party's
//! `client_id` and `azp`, when present, equals it. RFC 9068 §2.2: an access
//! token's `client_id` claim is the client identifier. RFC 7662 §2.2: the
//! introspection `client_id` is the client identifier. Hearth wrote its
//! internal display form `client_<uuid>` into all of them, so a standard
//! relying party comparing `aud` with its own client_id refused every Hearth
//! ID token.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{RealmId, UserId};
use hearth::identity::oidc::TokenIntrospectionRequest;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, OAuthClient,
    OidcTokenResponse, RegisterClientRequest, ResponseMode, TokenExchangeRequest,
};

const REDIRECT_URI: &str = "https://app.example.com/callback";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    client: OAuthClient,
}

async fn env() -> Env {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("token-cid-{}", uuid::Uuid::new_v4()),
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
                display_name: "Relying Party User".into(),
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

/// What the client was issued at registration, and what it configures as
/// its `client_id` — the admin API and dynamic registration return this.
fn issued(client: &OAuthClient) -> String {
    client.client_id().as_uuid().to_string()
}

/// OIDC Core §3.1.3.7 steps 3–5, as a relying party library performs them.
fn assert_audience_is_the_client(label: &str, claims: &serde_json::Value, client_id: &str) {
    let aud_contains = match &claims["aud"] {
        serde_json::Value::String(s) => s == client_id,
        serde_json::Value::Array(list) => list.iter().any(|a| a == client_id),
        _ => false,
    };
    assert!(
        aud_contains,
        "{label}: aud must contain the client_id {client_id}; claims {claims}"
    );
    if let Some(azp) = claims.get("azp") {
        assert_eq!(azp, client_id, "{label}: azp must equal the client_id");
    }
}

impl Env {
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
                    scope: "openid profile".into(),
                    state: "st".into(),
                    response_type: "code".into(),
                    user_id: self.user.clone(),
                    code_challenge: Some(challenge),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: Some("n-0S6_WzA2Mj".into()),
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
                    resource: None,
                },
            )
            .expect("code exchange")
    }
}

#[tokio::test]
async fn id_token_aud_and_azp_are_the_issued_client_id() {
    let env = env().await;
    let tokens = env.code_exchange();
    let id = claims(tokens.id_token());
    assert_audience_is_the_client("code-exchange ID token", &id, &issued(&env.client));
}

#[tokio::test]
async fn access_token_and_introspection_client_id_are_the_issued_client_id() {
    let env = env().await;
    let tokens = env.code_exchange();
    let access = claims(tokens.access_token());
    assert_eq!(
        access["client_id"],
        issued(&env.client),
        "RFC 9068 §2.2: the access token's client_id claim; claims {access}"
    );

    let introspection = env
        .h
        .identity()
        .introspect_token(
            &env.realm,
            &TokenIntrospectionRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(env.client.client_id().clone()),
            },
        )
        .expect("introspect");
    assert!(
        introspection.active,
        "the issuing client introspects its own token"
    );
    assert_eq!(
        introspection.client_id.as_deref(),
        Some(issued(&env.client).as_str()),
        "RFC 7662 §2.2: introspection names the client the token was issued to"
    );
}

/// OIDC RP-Initiated Logout §2: when `client_id` accompanies an
/// `id_token_hint`, the hint must have been issued to that client (its `aud`
/// holds the issued client_id). A hint for another client is refused before
/// any session is revoked.
#[tokio::test]
async fn end_session_refuses_an_id_token_hint_issued_to_another_client() {
    use hearth::identity::oidc::RpLogoutRequest;
    use hearth::identity::IdentityError;

    let env = env().await;
    let other = env
        .h
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "other-rp".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into()],
                ..RegisterClientRequest::default()
            },
        )
        .expect("other client");
    let tokens = env.code_exchange();
    let logout = |client: &OAuthClient| {
        env.h.identity().initiate_logout(
            &env.realm,
            &RpLogoutRequest {
                id_token_hint: Some(tokens.id_token().to_string()),
                session_id: None,
                post_logout_redirect_uri: None,
                client_id: Some(client.client_id().clone()),
                state: None,
            },
        )
    };

    let refused = logout(&other);
    assert!(
        matches!(refused, Err(IdentityError::ClientMismatch)),
        "a hint issued to another client must be refused, got {:?}",
        refused.map(|_| ())
    );
    assert!(
        env.h
            .identity()
            .validate_token(&env.realm, tokens.access_token())
            .is_ok(),
        "the refused logout revoked nothing"
    );
    logout(&env.client).expect("the hint's own client logs out");
}
