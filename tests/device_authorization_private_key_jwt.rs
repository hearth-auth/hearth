#![allow(clippy::unwrap_used)]
//! `private_key_jwt` clients can use the device flow (RFC 8628 §3.1).
//!
//! `/device_authorization` authenticated a client with a secret or, for a
//! public client, its `client_id` alone — but read no assertion fields: the
//! header route rejected a `client_assertion` as an unknown field (`400`) and
//! the realm route ignored it and answered `401`, because a client with keys
//! and no secret is not public. A FAPI 2.0 client (JWKS, no secret) could
//! therefore never start a device flow. Both routes (form and JSON) now
//! accept and verify `client_assertion_type` +
//! `client_assertion`; the poll at `/token` (`device_code` grant) takes the
//! assertion too.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{ClientTrustLevel, CreateRealmRequest, RegisterClientRequest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct ClientKey(Ed25519KeyPair);

impl ClientKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn jwks(&self) -> String {
        serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref()),
        }]})
        .to_string()
    }

    fn assertion(&self, client: &ClientId, aud: &str) -> String {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::json!({"alg": "EdDSA", "kid": "k1", "typ": "JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "iss": client.as_uuid().to_string(), "sub": client.as_uuid().to_string(), "aud": aud,
                    "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
                })
                .to_string()
            ),
        );
        let sig = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

struct Env {
    /// Keeps the engines behind the spawned server alive.
    _h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    issuer: String,
    key: ClientKey,
    /// JWKS only: no secret, no separate assertion key.
    client: ClientId,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("device-pkjwt-{}", uuid::Uuid::new_v4());
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let issuer = format!(
        "{}/realms/{realm_name}",
        h.identity().oidc_discovery().issuer
    );
    let key = ClientKey::new();
    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Key-holding TV".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec![DEVICE_GRANT.to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                jwks: Some(key.jwks()),
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone();
    Env {
        _h: h,
        base,
        realm_name,
        realm_id,
        issuer,
        key,
        client,
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

#[derive(Clone, Copy, Debug)]
enum Encoding {
    Form,
    Json,
}

impl Env {
    fn id(&self) -> String {
        self.client.as_uuid().to_string()
    }

    async fn post(
        &self,
        route: Route,
        encoding: Encoding,
        endpoint: &str,
        fields: &[(&str, String)],
    ) -> (u16, serde_json::Value) {
        let url = match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        };
        let client = reqwest::Client::new();
        let mut req = match encoding {
            Encoding::Form => client.post(&url).form(fields),
            Encoding::Json => {
                let body: serde_json::Map<String, serde_json::Value> = fields
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), serde_json::json!(v)))
                    .collect();
                client.post(&url).json(&body)
            }
        };
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }

    fn with_assertion(
        &self,
        mut fields: Vec<(&'static str, String)>,
    ) -> Vec<(&'static str, String)> {
        fields.push(("client_assertion_type", JWT_BEARER.to_string()));
        fields.push((
            "client_assertion",
            self.key.assertion(&self.client, &self.issuer),
        ));
        fields
    }
}

#[tokio::test]
async fn a_private_key_jwt_client_starts_and_polls_a_device_flow() {
    let env = env().await;
    for route in [Route::Header, Route::Realm] {
        for encoding in [Encoding::Form, Encoding::Json] {
            let what = format!("{route:?} {encoding:?}");

            // Without an assertion: refused (it is not a public client).
            let (status, body) = env
                .post(
                    route,
                    encoding,
                    "device_authorization",
                    &[("client_id", env.id())],
                )
                .await;
            assert_eq!(status, 401, "{what} client_id only: {body}");
            assert_eq!(body["error"], "invalid_client", "{what}: {body}");

            // With its assertion: a device code.
            let (status, body) = env
                .post(
                    route,
                    encoding,
                    "device_authorization",
                    &env.with_assertion(vec![("client_id", env.id())]),
                )
                .await;
            assert_eq!(status, 200, "{what} with assertion: {body}");
            let device_code = body["device_code"].as_str().unwrap().to_string();

            // The poll authenticates with an assertion too; the code is not
            // approved yet, so client authentication passing shows as
            // `authorization_pending`.
            let (status, body) = env
                .post(
                    route,
                    encoding,
                    "token",
                    &env.with_assertion(vec![
                        ("grant_type", DEVICE_GRANT.to_string()),
                        ("client_id", env.id()),
                        ("device_code", device_code.clone()),
                    ]),
                )
                .await;
            assert_eq!(status, 400, "{what} poll with assertion: {body}");
            assert_eq!(body["error"], "authorization_pending", "{what}: {body}");

            let (status, body) = env
                .post(
                    route,
                    encoding,
                    "token",
                    &[
                        ("grant_type", DEVICE_GRANT.to_string()),
                        ("client_id", env.id()),
                        ("device_code", device_code),
                    ],
                )
                .await;
            assert_eq!(status, 401, "{what} poll without assertion: {body}");
        }
    }
}

/// A forged assertion at `/device_authorization` is refused like everywhere
/// else (`client_assertion_presence.rs` covers every other surface).
#[tokio::test]
async fn a_forged_assertion_is_refused() {
    let env = env().await;
    let stranger = ClientKey::new();
    for route in [Route::Header, Route::Realm] {
        for (label, fields) in [
            (
                "junk, no type",
                vec![("client_assertion", "junk".to_string())],
            ),
            (
                "wrong type",
                vec![
                    ("client_assertion_type", "urn:x".to_string()),
                    ("client_assertion", "junk".to_string()),
                ],
            ),
            (
                "malformed JWT",
                vec![
                    ("client_assertion_type", JWT_BEARER.to_string()),
                    ("client_assertion", "a.b.c".to_string()),
                ],
            ),
            (
                "foreign key",
                vec![
                    ("client_assertion_type", JWT_BEARER.to_string()),
                    (
                        "client_assertion",
                        stranger.assertion(&env.client, &env.issuer),
                    ),
                ],
            ),
        ] {
            let mut body = vec![("client_id", env.id())];
            body.extend(fields);
            let (status, answer) = env
                .post(route, Encoding::Form, "device_authorization", &body)
                .await;
            assert_eq!(status, 401, "{route:?} {label}: {answer}");
            assert_eq!(
                answer["error"], "invalid_client",
                "{route:?} {label}: {answer}"
            );
        }
        let mut body = env.with_assertion(vec![("client_id", env.id())]);
        body.push(("client_secret", "also-a-secret".to_string()));
        let (status, answer) = env
            .post(route, Encoding::Form, "device_authorization", &body)
            .await;
        assert_eq!(status, 400, "{route:?} assertion + secret: {answer}");
    }
}
