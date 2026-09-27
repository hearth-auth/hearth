#![allow(clippy::unwrap_used)]
//! The per-client token rate limit covers every endpoint that authenticates
//! a client, and is checked BEFORE the client is verified.
//!
//! - `POST /as/par` and `POST /realms/{name}/as/par` had no rate limit at all,
//!   unlike `/token`: a client could push without bound, and each push of an
//!   Argon2id secret costs a KDF permit.
//! - `/introspect` and `/revoke` checked the limit only AFTER verifying the
//!   client, so a flood of wrong secrets was never limited and every one of
//!   them was hashed. `/token` limits first, keyed on the claimed client (body
//!   `client_id` or Basic username) or, with none, the client IP; the others
//!   now do the same.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{ClientTrustLevel, CreateRealmRequest, RegisterClientRequest};
use hearth::protocol::admin_auth::TokenRateLimiter;
use hearth::protocol::http::{router, AppState};

const LIMIT: u32 = 2;
const REDIRECT_URI: &str = "https://app.example.com/cb";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Env {
    _h: common::TestHarness,
    base: String,
    realm_id: RealmId,
    realm_name: String,
    identity: Arc<dyn hearth::identity::IdentityEngine>,
}

/// A server whose token rate limit is [`LIMIT`] requests per client.
async fn env() -> Env {
    let h = common::TestHarness::embedded().await.expect("harness");
    let identity = h.identity_arc();
    let mut state = AppState::new_dev(Arc::clone(&identity), h.rbac_arc(), h.audit_arc());
    state.token_rate_limiter = Arc::new(TokenRateLimiter::with_limit(LIMIT));
    let app = router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });
    let realm_name = format!("rate-{}", uuid::Uuid::new_v4());
    let realm_id = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap()
        .id()
        .clone();
    Env {
        _h: h,
        base,
        realm_id,
        realm_name,
        identity,
    }
}

impl Env {
    fn client(&self, secret: Option<&str>) -> ClientId {
        self.identity
            .register_client(
                &self.realm_id,
                &RegisterClientRequest {
                    client_name: format!("rate-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    client_secret: secret.map(str::to_string),
                    grant_types: vec!["authorization_code".to_string()],
                    trust_level: ClientTrustLevel::FirstParty,
                    ..Default::default()
                },
            )
            .unwrap()
            .client_id()
            .clone()
    }

    async fn post(
        &self,
        path: &str,
        header_realm: bool,
        form: &[(&str, String)],
        basic: Option<(&ClientId, &str)>,
    ) -> u16 {
        let mut req = reqwest::Client::new()
            .post(format!("{}{path}", self.base))
            .form(form);
        if header_realm {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        if let Some((id, secret)) = basic {
            req = req.header(
                "Authorization",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{secret}", id.as_uuid()))
                ),
            );
        }
        req.send().await.unwrap().status().as_u16()
    }
}

fn par_form(client_id: String) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", "openid".to_string()),
        ("state", "s".to_string()),
        ("response_type", "code".to_string()),
        ("code_challenge", PKCE_CHALLENGE.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

/// PAR, on both routes, answers `429` once a client exceeds its limit.
#[tokio::test]
async fn pushed_authorization_requests_are_rate_limited_per_client() {
    let env = env().await;
    for (path, header_realm) in [
        ("/as/par".to_string(), true),
        (format!("/realms/{}/as/par", env.realm_name), false),
    ] {
        let client = env.client(None);
        let form = par_form(client.as_uuid().to_string());
        for n in 0..LIMIT {
            let status = env.post(&path, header_realm, &form, None).await;
            assert_eq!(status, 201, "{path}: push {n} is within the limit");
        }
        let status = env.post(&path, header_realm, &form, None).await;
        assert_eq!(status, 429, "{path}: a push past the limit is refused");
    }
}

/// A push naming no parseable client is bucketed by client IP, as `/token`
/// buckets its clientless requests.
#[tokio::test]
async fn a_clientless_push_is_rate_limited_by_ip() {
    let env = env().await;
    let form = par_form("not-a-client".to_string());
    for _ in 0..LIMIT {
        let status = env.post("/as/par", true, &form, None).await;
        assert_eq!(status, 401, "an unparseable client_id is refused");
    }
    let status = env.post("/as/par", true, &form, None).await;
    assert_eq!(status, 429, "past the limit, the IP bucket refuses");
}

/// `/introspect` and `/revoke` limit the claimed client BEFORE verifying it:
/// a flood of wrong secrets is refused with `429` once past the limit instead
/// of being verified (and hashed) one by one.
#[tokio::test]
async fn introspection_and_revocation_are_limited_before_the_client_is_verified() {
    let env = env().await;
    for (path, header_realm) in [
        ("/introspect".to_string(), true),
        (format!("/realms/{}/introspect", env.realm_name), false),
        ("/revoke".to_string(), true),
        (format!("/realms/{}/revoke", env.realm_name), false),
    ] {
        let client = env.client(Some("the-real-secret-0123456789abcdef!"));
        let form = [("token", "not-a-token".to_string())];
        for n in 0..LIMIT {
            let status = env
                .post(&path, header_realm, &form, Some((&client, "wrong")))
                .await;
            assert_eq!(status, 401, "{path}: wrong secret {n} is refused");
        }
        let status = env
            .post(&path, header_realm, &form, Some((&client, "wrong")))
            .await;
        assert_eq!(
            status, 429,
            "{path}: past the limit the request is refused before the secret is checked"
        );
    }
}
