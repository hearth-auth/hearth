//! #624 — the token endpoint spends a DPoP proof's `jti` only after the grant's
//! key-binding check passes (OpenSpec `dpop`, "A proof with the wrong key does
//! not burn the jti"; RFC 9449 §11.1).
//!
//! The endpoint recorded the `jti` before the refresh grant compared the proof
//! key with the grant family's key, and before the token-exchange grant
//! compared it with the subject token's `cnf.jkt`. A proof that failed that
//! check still spent its `jti`, so a later proof from the right key with the
//! same `jti` was refused as a replay.
//!
//! Each test runs on both token routes (`/token` with `X-Realm-ID`, and
//! `/realms/{name}/token`) and shows three things:
//! - a proof from the wrong key is refused by the binding check;
//! - a proof from the right key with the same `jti` then succeeds;
//! - that `jti` is then spent: the next proof that carries it is a replay.

#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, CreateUserRequest, RegisterClientRequest, SessionContext,
    TokenIssuanceContext,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const CLIENT_SECRET: &str = "jti-order-client-secret!";

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// An Ed25519 DPoP key.
struct DpopKey(Ed25519KeyPair);

impl DpopKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn x(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
    }

    /// RFC 7638 thumbprint, computed by the server's own function.
    fn thumbprint(&self) -> String {
        hearth::identity::dpop::compute_jwk_thumbprint(&hearth::identity::dpop::DPopJwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(self.x()),
            y: None,
            n: None,
            e: None,
        })
        .unwrap()
    }

    /// A proof for `POST htu` that carries `jti` and the server `nonce`.
    fn proof(&self, htu: &str, nonce: &str, jti: &str) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA", "typ": "dpop+jwt",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": self.x()},
        });
        let claims = serde_json::json!({
            "htm": "POST", "htu": htu, "iat": now_secs(), "jti": jti, "nonce": nonce,
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

struct Fx {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    client: ClientId,
    user: UserId,
}

/// A server, a realm, a user, and a confidential first-party client that holds
/// the refresh-token and token-exchange grants.
async fn fixture() -> Fx {
    let h = common::TestHarness::server().await.unwrap();
    let realm_name = format!("jti-order-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: format!("jti-order-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: Some(CLIENT_SECRET.to_string()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                    TOKEN_EXCHANGE.to_string(),
                ],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("jti-order-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "JTI order user".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    Fx {
        h,
        realm,
        realm_name,
        client,
        user,
    }
}

impl Fx {
    /// A token pair bound to `key`: the access token carries `cnf.jkt`, and the
    /// refresh token's grant family is bound to the same key.
    fn bound_pair(&self, key: &DpopKey) -> (String, String) {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &self.user, &SessionContext::default())
            .expect("create session");
        let pair = self
            .h
            .identity()
            .issue_tokens_with_context(
                &self.realm,
                &self.user,
                session.id(),
                &TokenIssuanceContext {
                    client_id: Some(self.client.clone()),
                    granted_scopes: BTreeSet::from(["openid".to_string()]),
                    oid: None,
                    resource: None,
                    dpop_jkt: Some(key.thumbprint()),
                },
            )
            .expect("issue bound pair");
        (
            pair.access_token().to_string(),
            pair.refresh_token().to_string(),
        )
    }

    fn token_url(&self, route: Route) -> String {
        let base = self.h.base_url().expect("server harness");
        match route {
            Route::Header => format!("{base}/token"),
            Route::Realm => format!("{base}/realms/{}/token", self.realm_name),
        }
    }

    fn token_htu(&self, route: Route) -> String {
        let doc = self.h.identity().oidc_discovery();
        match route {
            Route::Header => doc.token_endpoint,
            Route::Realm => format!("{}/realms/{}/token", doc.issuer, self.realm_name),
        }
    }

    fn request(&self, route: Route, http: &reqwest::Client) -> reqwest::RequestBuilder {
        let req = http.post(self.token_url(route));
        match route {
            Route::Header => req.header("X-Realm-ID", self.realm.as_uuid().to_string()),
            Route::Realm => req,
        }
    }

    /// POSTs `form` with a proof from `key` that carries `jti`.
    async fn post(
        &self,
        route: Route,
        form: &[(&str, String)],
        key: &DpopKey,
        jti: &str,
    ) -> (u16, serde_json::Value) {
        let http = reqwest::Client::new();
        let probe = self
            .request(route, &http)
            .form(&[("grant_type", "nonce-probe")])
            .send()
            .await
            .expect("nonce probe");
        let nonce = probe
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .expect("token responses carry DPoP-Nonce")
            .to_string();
        let resp = self
            .request(route, &http)
            .form(form)
            .header("DPoP", key.proof(&self.token_htu(route), &nonce, jti))
            .send()
            .await
            .expect("token request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }

    fn refresh_form(&self, refresh_token: &str) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", self.client.as_uuid().to_string()),
            ("client_secret", CLIENT_SECRET.to_string()),
        ]
    }

    fn exchange_form(&self, subject_token: &str) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", TOKEN_EXCHANGE.to_string()),
            ("subject_token", subject_token.to_string()),
            ("subject_token_type", ACCESS_TOKEN_TYPE.to_string()),
            ("client_id", self.client.as_uuid().to_string()),
            ("client_secret", CLIENT_SECRET.to_string()),
        ]
    }
}

fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[tokio::test]
async fn a_refresh_proof_from_the_wrong_key_does_not_spend_its_jti() {
    let fx = fixture().await;
    for route in ROUTES {
        let right = DpopKey::new();
        let wrong = DpopKey::new();
        let (_, refresh) = fx.bound_pair(&right);

        // Control: the bound refresh token rotates with the right key.
        let (status, body) = fx
            .post(route, &fx.refresh_form(&refresh), &right, &new_jti())
            .await;
        assert_eq!(status, 200, "{route:?}: control refresh: {body}");
        let refresh = body["refresh_token"].as_str().unwrap().to_string();

        let jti = new_jti();
        let (status, body) = fx
            .post(route, &fx.refresh_form(&refresh), &wrong, &jti)
            .await;
        assert_eq!(status, 401, "{route:?}: wrong key: {body}");
        assert_eq!(
            body["error"], "invalid_token",
            "{route:?}: wrong key: {body}"
        );

        let (status, body) = fx
            .post(route, &fx.refresh_form(&refresh), &right, &jti)
            .await;
        assert_eq!(
            status, 200,
            "{route:?}: the right key with the jti of the refused proof: {body}"
        );
        let rotated = body["refresh_token"].as_str().unwrap().to_string();

        let (_, body) = fx
            .post(route, &fx.refresh_form(&rotated), &right, &jti)
            .await;
        assert_eq!(
            body["error"], "use_dpop_nonce",
            "{route:?}: the jti is spent after a success: {body}"
        );
        assert!(body.get("access_token").is_none(), "{route:?}: {body}");
    }
}

#[tokio::test]
async fn a_token_exchange_proof_from_the_wrong_key_does_not_spend_its_jti() {
    let fx = fixture().await;
    for route in ROUTES {
        let right = DpopKey::new();
        let wrong = DpopKey::new();
        let (access, _) = fx.bound_pair(&right);
        let form = fx.exchange_form(&access);

        // Control: the bound subject token is exchanged with the right key.
        let (status, body) = fx.post(route, &form, &right, &new_jti()).await;
        assert_eq!(status, 200, "{route:?}: control exchange: {body}");

        let jti = new_jti();
        let (status, body) = fx.post(route, &form, &wrong, &jti).await;
        assert_eq!(status, 400, "{route:?}: wrong key: {body}");
        assert_eq!(
            body["error"], "invalid_grant",
            "{route:?}: wrong key: {body}"
        );

        let (status, body) = fx.post(route, &form, &right, &jti).await;
        assert_eq!(
            status, 200,
            "{route:?}: the right key with the jti of the refused proof: {body}"
        );

        let (_, body) = fx.post(route, &form, &right, &jti).await;
        assert_eq!(
            body["error"], "use_dpop_nonce",
            "{route:?}: the jti is spent after a success: {body}"
        );
        assert!(body.get("access_token").is_none(), "{route:?}: {body}");
    }
}
