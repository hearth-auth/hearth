#![allow(clippy::unwrap_used)]
//! `private_key_jwt` against a client's registered JWKS: algorithm and key
//! selection (FAPI review L-FAPI-3).
//!
//! FAPI 2.0 Security Profile §5.4 permits PS256, ES256 and EdDSA for client
//! authentication, so RS256 (PKCS#1 v1.5) is refused even from a registered
//! RSA key; a key registered for one algorithm never verifies another; a
//! header without `kid` selects nothing when the set holds several keys; a
//! client registered with only a `jwks_uri` cannot authenticate (key sets are
//! not fetched); and the token-exchange grant accepts an assertion. (The
//! `device_code` grant with an assertion is pinned by
//! `device_authorization_private_key_jwt.rs`.)

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, CreateUserRequest, RegisterClientRequest,
    RsaIdTokenSigningKey, SessionContext, TokenIssuanceContext,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, RsaKeyPair};

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Something that signs a JWS signing input.
enum Signer {
    Ed(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

impl Signer {
    fn ed() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn rsa() -> (Self, serde_json::Value) {
        let key = RsaIdTokenSigningKey::generate().unwrap();
        let jwk = key.to_jwk().unwrap();
        let pair = RsaKeyPair::from_pkcs8(key.pkcs8_bytes()).unwrap();
        // The public key without `alg`, so each test chooses what it registers.
        let public = serde_json::json!({"kty": "RSA", "use": "sig", "n": jwk.n, "e": jwk.e});
        (Self::Rsa(pair), public)
    }

    fn ed_jwk(&self, kid: &str) -> serde_json::Value {
        let Self::Ed(k) = self else {
            panic!("not an Ed25519 key")
        };
        serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(k.public_key().as_ref()),
        })
    }

    fn sign(&self, alg: &str, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed(k) => k.sign(input).as_ref().to_vec(),
            Self::Rsa(k) => {
                let padding: &dyn ring::signature::RsaEncoding = match alg {
                    "PS256" => &ring::signature::RSA_PSS_SHA256,
                    _ => &ring::signature::RSA_PKCS1_SHA256,
                };
                let mut sig = vec![0; k.public().modulus_len()];
                k.sign(padding, &SystemRandom::new(), input, &mut sig)
                    .unwrap();
                sig
            }
        }
    }

    /// A `private_key_jwt` assertion for `client` with header `alg` and, when
    /// given, `kid`.
    fn assertion(&self, alg: &str, kid: Option<&str>, client: &ClientId, aud: &str) -> String {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let mut header = serde_json::json!({"alg": alg, "typ": "JWT"});
        if let Some(kid) = kid {
            header["kid"] = serde_json::json!(kid);
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "iss": client.as_uuid().to_string(), "sub": client.as_uuid().to_string(), "aud": aud,
                    "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
                })
                .to_string()
            ),
        );
        let sig = self.sign(alg, input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

struct Env {
    h: common::TestHarness,
    base: String,
    realm_id: RealmId,
    issuer: String,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("pkjwt-alg-{}", uuid::Uuid::new_v4());
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
    Env {
        h,
        base,
        realm_id,
        issuer,
    }
}

impl Env {
    fn register(&self, jwks: Option<serde_json::Value>, jwks_uri: Option<&str>) -> ClientId {
        self.h
            .identity()
            .register_client(
                &self.realm_id,
                &RegisterClientRequest {
                    client_name: format!("pkjwt-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec!["https://rp.example.com/cb".to_string()],
                    grant_types: vec!["client_credentials".to_string(), TOKEN_EXCHANGE.to_string()],
                    trust_level: ClientTrustLevel::FirstParty,
                    require_consent: false,
                    jwks: jwks.map(|j| j.to_string()),
                    jwks_uri: jwks_uri.map(str::to_string),
                    ..Default::default()
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    }

    async fn token(&self, form: &[(&str, String)]) -> (u16, serde_json::Value) {
        let resp = reqwest::Client::new()
            .post(format!("{}/token", self.base))
            .header("X-Realm-ID", self.realm_id.as_uuid().to_string())
            .form(form)
            .send()
            .await
            .expect("request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }

    /// `client_credentials` authenticated by `assertion`.
    async fn cc(&self, client: &ClientId, assertion: String) -> (u16, serde_json::Value) {
        self.token(&[
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client.as_uuid().to_string()),
            ("client_assertion_type", JWT_BEARER.to_string()),
            ("client_assertion", assertion),
        ])
        .await
    }
}

#[tokio::test]
async fn ps256_is_accepted_and_rs256_refused_from_the_same_rsa_key() {
    let env = env().await;
    let (rsa, mut jwk) = Signer::rsa();
    jwk["kid"] = serde_json::json!("rsa");
    let client = env.register(Some(serde_json::json!({ "keys": [jwk] })), None);

    let (status, body) = env
        .cc(
            &client,
            rsa.assertion("PS256", Some("rsa"), &client, &env.issuer),
        )
        .await;
    assert_eq!(status, 200, "PS256 (FAPI 2.0 §5.4): {body}");

    let (status, body) = env
        .cc(
            &client,
            rsa.assertion("RS256", Some("rsa"), &client, &env.issuer),
        )
        .await;
    assert_eq!(
        status, 401,
        "RS256 is not accepted for client authentication: {body}"
    );
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn a_key_registered_for_one_algorithm_does_not_verify_another() {
    let env = env().await;
    let (rsa, mut jwk) = Signer::rsa();
    jwk["kid"] = serde_json::json!("rsa");
    jwk["alg"] = serde_json::json!("RS256");
    let client = env.register(Some(serde_json::json!({ "keys": [jwk] })), None);
    // A correct PSS signature, from the key registered for RS256 only.
    let (status, body) = env
        .cc(
            &client,
            rsa.assertion("PS256", Some("rsa"), &client, &env.issuer),
        )
        .await;
    assert_eq!(status, 401, "key alg RS256 vs header alg PS256: {body}");
}

#[tokio::test]
async fn a_header_without_kid_selects_nothing_among_several_keys() {
    let env = env().await;
    let (k1, k2) = (Signer::ed(), Signer::ed());
    let client = env.register(
        Some(serde_json::json!({ "keys": [k1.ed_jwk("k1"), k2.ed_jwk("k2")] })),
        None,
    );
    let (status, body) = env
        .cc(
            &client,
            k1.assertion("EdDSA", Some("k1"), &client, &env.issuer),
        )
        .await;
    assert_eq!(status, 200, "control: kid k1 selects its key: {body}");
    let (status, body) = env
        .cc(&client, k1.assertion("EdDSA", None, &client, &env.issuer))
        .await;
    assert_eq!(status, 401, "no kid among two keys: {body}");
}

#[tokio::test]
async fn a_jwks_uri_only_client_cannot_authenticate() {
    let env = env().await;
    let key = Signer::ed();
    let client = env.register(None, Some("https://rp.example.com/jwks.json"));
    let (status, body) = env
        .cc(
            &client,
            key.assertion("EdDSA", Some("k1"), &client, &env.issuer),
        )
        .await;
    assert_eq!(status, 401, "jwks_uri is never fetched: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn token_exchange_accepts_an_assertion() {
    let env = env().await;
    let key = Signer::ed();
    let client = env.register(
        Some(serde_json::json!({ "keys": [key.ed_jwk("k1")] })),
        None,
    );
    let user = env
        .h
        .identity()
        .create_user(
            &env.realm_id,
            &CreateUserRequest {
                email: format!("u-{}@pkjwt.test", uuid::Uuid::new_v4()),
                display_name: "Subject".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    let session = env
        .h
        .identity()
        .create_session(&env.realm_id, user.id(), &SessionContext::default())
        .unwrap();
    let subject = env
        .h
        .identity()
        .issue_tokens_with_context(
            &env.realm_id,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes: std::collections::BTreeSet::from(["openid".to_string()]),
                oid: None,
                resource: None,
            },
        )
        .unwrap()
        .access_token()
        .to_string();
    let form = |assertion: Option<String>| {
        let mut form = vec![
            ("grant_type", TOKEN_EXCHANGE.to_string()),
            ("client_id", client.as_uuid().to_string()),
            ("subject_token", subject.clone()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token".to_string(),
            ),
        ];
        if let Some(a) = assertion {
            form.push(("client_assertion_type", JWT_BEARER.to_string()));
            form.push(("client_assertion", a));
        }
        form
    };

    let (status, body) = env.token(&form(None)).await;
    assert_eq!(
        status, 401,
        "a key-holding client presenting nothing: {body}"
    );

    let (status, body) = env
        .token(&form(Some(key.assertion(
            "EdDSA",
            Some("k1"),
            &client,
            &env.issuer,
        ))))
        .await;
    assert_eq!(status, 200, "token exchange with an assertion: {body}");
    let access = body["access_token"].as_str().unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["act"]["sub"],
        client.as_uuid().to_string(),
        "the actor is the assertion-authenticated client"
    );
}
