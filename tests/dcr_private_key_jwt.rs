#![allow(clippy::unwrap_used)]
//! Dynamic Client Registration (RFC 7591) registers clients that can
//! authenticate — including `private_key_jwt` clients and clients of a FAPI
//! 2.0 Advanced realm.
//!
//! `POST /register` always minted a secret and answered
//! `token_endpoint_auth_method: client_secret_basic`, and both DCR routes
//! dropped `jwks`: in a FAPI 2.0 Advanced realm, which refuses every secret
//! and every public client, DCR handed out clients that could never
//! authenticate. Now both routes read `jwks` (RFC 7591 §2, validated) and
//! `token_endpoint_auth_method`; a client registering keys defaults to
//! `private_key_jwt` (no secret), the response states the method that works,
//! and an Advanced realm refuses anything else with `invalid_client_metadata`.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{CreateRealmRequest, DcrPolicy, FapiProfile, RealmConfig};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

struct ClientKey(Ed25519KeyPair);

impl ClientKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn jwks(&self) -> serde_json::Value {
        serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref()),
        }]})
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
    _h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    issuer: String,
}

async fn env(fapi: Option<FapiProfile>) -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("dcr-pkjwt-{}", uuid::Uuid::new_v4());
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Open),
                fapi_profile: fapi,
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();
    let issuer = format!(
        "{}/realms/{realm_name}",
        h.identity().oidc_discovery().issuer
    );
    Env {
        _h: h,
        base,
        realm_name,
        realm_id,
        issuer,
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

impl Env {
    async fn post_json(
        &self,
        route: Route,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let url = match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        };
        let mut req = reqwest::Client::new().post(&url).json(body);
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }

    async fn register(&self, route: Route, extra: serde_json::Value) -> (u16, serde_json::Value) {
        let mut body = serde_json::json!({
            "client_name": "DCR RP",
            "redirect_uris": ["https://rp.example.com/cb"],
            "grant_types": ["authorization_code"],
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        self.post_json(route, "register", &body).await
    }

    /// Introspects a junk token authenticating with `key`'s assertion: `200`
    /// means the registered client authenticated.
    async fn introspect_with_assertion(
        &self,
        route: Route,
        client_id: &str,
        key: &ClientKey,
    ) -> u16 {
        let client = ClientId::new(client_id.parse().unwrap());
        self.post_json(
            route,
            "introspect",
            &serde_json::json!({
                "token": "not-a-token",
                "client_id": client_id,
                "client_assertion_type": JWT_BEARER,
                "client_assertion": key.assertion(&client, &self.issuer),
            }),
        )
        .await
        .0
    }
}

fn assert_invalid_metadata(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(status, 400, "{what}: {body}");
    assert_eq!(body["error"], "invalid_client_metadata", "{what}: {body}");
}

/// A client that registers its JWKS gets `private_key_jwt`, no secret, and
/// authenticates with an assertion.
#[tokio::test]
async fn dcr_registers_a_private_key_jwt_client() {
    let env = env(None).await;
    for route in ROUTES {
        for explicit in [false, true] {
            let what = format!("{route:?} explicit={explicit}");
            let key = ClientKey::new();
            let mut extra = serde_json::json!({ "jwks": key.jwks() });
            if explicit {
                extra["token_endpoint_auth_method"] = serde_json::json!("private_key_jwt");
            }
            let (status, body) = env.register(route, extra).await;
            assert_eq!(status, 201, "{what}: {body}");
            assert_eq!(
                body["token_endpoint_auth_method"], "private_key_jwt",
                "{what}: {body}"
            );
            assert!(
                body.get("client_secret").is_none(),
                "{what}: no secret: {body}"
            );
            assert_eq!(
                body["jwks"]["keys"][0]["kid"], "k1",
                "{what}: jwks echoed: {body}"
            );
            let client_id = body["client_id"].as_str().unwrap();
            assert_eq!(
                env.introspect_with_assertion(route, client_id, &key).await,
                200,
                "{what}: the registered client authenticates with its assertion"
            );
        }
    }
}

/// A secret-based registration still works outside FAPI Advanced and says so.
#[tokio::test]
async fn dcr_secret_registration_states_its_method() {
    let env = env(None).await;
    for route in ROUTES {
        for method in ["client_secret_basic", "client_secret_post"] {
            let (status, body) = env
                .register(
                    route,
                    serde_json::json!({ "token_endpoint_auth_method": method }),
                )
                .await;
            assert_eq!(status, 201, "{route:?} {method}: {body}");
            assert_eq!(
                body["token_endpoint_auth_method"], method,
                "{route:?}: {body}"
            );
            assert!(
                body["client_secret"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
                "{route:?} {method}: a secret is minted: {body}"
            );
        }
    }
}

/// Invalid key metadata is refused as `invalid_client_metadata`.
#[tokio::test]
async fn dcr_refuses_unusable_keys() {
    let env = env(None).await;
    let key = ClientKey::new();
    let mut private = key.jwks();
    private["keys"][0]["d"] = serde_json::json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    for route in ROUTES {
        for (what, extra) in [
            (
                "private key material",
                serde_json::json!({ "jwks": private }),
            ),
            (
                "private_key_jwt with jwks_uri only (never fetched)",
                serde_json::json!({
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks_uri": "https://rp.example.com/jwks",
                }),
            ),
            (
                "private_key_jwt without keys",
                serde_json::json!({ "token_endpoint_auth_method": "private_key_jwt" }),
            ),
            (
                "jwks and jwks_uri together (RFC 7591 §2)",
                serde_json::json!({ "jwks": key.jwks(), "jwks_uri": "https://rp.example.com/jwks" }),
            ),
            (
                "an unsupported method",
                serde_json::json!({ "token_endpoint_auth_method": "tls_client_auth" }),
            ),
        ] {
            let (status, body) = env.register(route, extra).await;
            assert_invalid_metadata(status, &body, &format!("{route:?} {what}"));
        }
    }
}

/// A FAPI 2.0 Advanced realm accepts `private_key_jwt` registrations only.
#[tokio::test]
async fn dcr_in_a_fapi_advanced_realm_requires_private_key_jwt() {
    let env = env(Some(FapiProfile::Advanced)).await;
    for route in ROUTES {
        for (what, extra) in [
            ("no keys (default method)", serde_json::json!({})),
            (
                "client_secret_basic",
                serde_json::json!({ "token_endpoint_auth_method": "client_secret_basic" }),
            ),
            (
                "none",
                serde_json::json!({ "token_endpoint_auth_method": "none" }),
            ),
        ] {
            let (status, body) = env.register(route, extra).await;
            assert_invalid_metadata(status, &body, &format!("{route:?} {what}"));
        }
        let key = ClientKey::new();
        let (status, body) = env
            .register(route, serde_json::json!({ "jwks": key.jwks() }))
            .await;
        assert_eq!(status, 201, "{route:?} with jwks: {body}");
        assert_eq!(body["token_endpoint_auth_method"], "private_key_jwt");
        let client_id = body["client_id"].as_str().unwrap();
        assert_eq!(
            env.introspect_with_assertion(route, client_id, &key).await,
            200,
            "{route:?}: the Advanced-realm client authenticates"
        );
    }
}
