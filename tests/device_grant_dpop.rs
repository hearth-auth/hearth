//! Device authorization grant (RFC 8628) and DPoP (RFC 9449) — GA audit 3 B-6.
//!
//! The device grant validated a DPoP proof at the token endpoint, burned its
//! `jti`, and then minted plain Bearer tokens: no `cnf` on the access token,
//! no key on the grant family, `token_type: Bearer`. In a realm with a
//! `fapi_profile`, or for a FAPI 2.0 client, it minted them with no proof at
//! all, although every other user grant requires sender-constrained tokens
//! there (OIDC.md §2.1/§2.2).
//!
//! These tests pin the device grant to the authorization-code grant's rules:
//! - a proof binds the access token (`cnf.jkt`), the refresh token and the
//!   grant family, and the response says `token_type: DPoP`;
//! - the bound refresh token rotates only with the same key;
//! - a FAPI realm or a FAPI 2.0 client gets no tokens without a proof, and
//!   the refusal leaves the approved code redeemable with one;
//! - the tokens carry the approved `scope`.

#![allow(clippy::unwrap_used)]

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    ClientProfile, CreateRealmRequest, CreateUserRequest, DeviceAuthorizationRequest, FapiProfile,
    IdentityError, RegisterClientRequest, UpdateRealmRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const JKT: &str = "device-grant-thumbprint-A";
const OTHER_JKT: &str = "device-grant-thumbprint-B";
const SCOPE: &str = "openid profile";

// ── engine fixture ───────────────────────────────────────────────────────────

struct Fx {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    user: UserId,
}

async fn fixture(h: common::TestHarness, fapi: Option<FapiProfile>) -> Fx {
    let realm_name = format!("device-dpop-{}", uuid::Uuid::new_v4());
    let rec = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm");
    let realm = rec.id().clone();
    if let Some(profile) = fapi {
        let mut config = rec.config().clone();
        config.fapi_profile = Some(profile);
        h.identity()
            .update_realm(
                &realm,
                &UpdateRealmRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .expect("set fapi profile");
    }
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("device-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Device user".to_string(),
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
        user,
    }
}

impl Fx {
    /// A public device client with the refresh grant.
    fn device_client(&self, profile: ClientProfile) -> ClientId {
        self.h
            .identity()
            .register_client(
                &self.realm,
                &RegisterClientRequest {
                    client_name: format!("device-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![],
                    client_secret: None,
                    grant_types: vec![DEVICE_GRANT.to_string(), "refresh_token".to_string()],
                    require_consent: false,
                    // A FAPI 2.0 client must register its keys inline.
                    jwks: (profile == ClientProfile::Fapi2).then(|| DpopKey::new().jwks()),
                    profile,
                    ..Default::default()
                },
            )
            .expect("register device client")
            .client_id()
            .clone()
    }

    /// Starts a device flow for `client` and approves it; returns the
    /// device code.
    fn approved_device_code(&self, client: &ClientId) -> String {
        let started = self
            .h
            .identity()
            .device_authorize(
                &self.realm,
                &DeviceAuthorizationRequest {
                    client_id: client.clone(),
                    scope: Some(SCOPE.to_string()),
                },
            )
            .expect("device authorize");
        self.h
            .identity()
            .approve_device(&self.realm, &started.user_code, &self.user)
            .expect("approve device");
        started.device_code
    }
}

// ── engine: binding ──────────────────────────────────────────────────────────

/// A proof on the poll binds the access token, the refresh token and the
/// response's `token_type`, and the tokens carry the approved scope.
#[tokio::test]
async fn device_poll_with_dpop_binds_the_token_pair() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let client = fx.device_client(ClientProfile::Standard);
    let code = fx.approved_device_code(&client);

    let resp =
        fx.h.identity()
            .poll_device_token(&fx.realm, &code, &client, Some(JKT))
            .expect("poll with DPoP");

    assert_eq!(resp.token_type(), "DPoP", "a bound pair is a DPoP pair");
    let access =
        fx.h.identity()
            .validate_token(&fx.realm, resp.access_token())
            .expect("access token validates");
    assert_eq!(
        access.cnf.as_ref().map(|c| c.jkt.as_str()),
        Some(JKT),
        "access token must carry cnf.jkt of the proof key"
    );
    assert_eq!(access.scope.as_deref(), Some(SCOPE), "approved scope");

    let refresh = decode_claims(resp.refresh_token());
    assert_eq!(
        refresh["cnf"]["jkt"].as_str(),
        Some(JKT),
        "refresh token must carry cnf.jkt, as the code grant's does"
    );
    assert_eq!(refresh["scope"].as_str(), Some(SCOPE));
}

/// The grant family is bound: the refresh token rotates only with the key
/// that was proven at the poll.
#[tokio::test]
async fn device_bound_refresh_token_rotates_only_with_the_same_key() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let client = fx.device_client(ClientProfile::Standard);
    let code = fx.approved_device_code(&client);
    let resp =
        fx.h.identity()
            .poll_device_token(&fx.realm, &code, &client, Some(JKT))
            .expect("poll with DPoP");

    for (jkt, what) in [(None, "no proof"), (Some(OTHER_JKT), "another key")] {
        let err =
            fx.h.identity()
                .refresh_tokens(&fx.realm, resp.refresh_token(), jkt, None)
                .expect_err(what);
        assert!(
            matches!(err, IdentityError::DPopBindingMismatch),
            "refresh with {what}: expected DPopBindingMismatch, got {err:?}"
        );
    }

    let rotated =
        fx.h.identity()
            .refresh_tokens(&fx.realm, resp.refresh_token(), Some(JKT), None)
            .expect("refresh with the bound key");
    let claims =
        fx.h.identity()
            .validate_token(&fx.realm, rotated.access_token())
            .expect("rotated access token validates");
    assert_eq!(claims.cnf.as_ref().map(|c| c.jkt.as_str()), Some(JKT));
}

/// Without a proof, a standard realm still issues Bearer tokens.
#[tokio::test]
async fn device_poll_without_dpop_in_a_standard_realm_stays_bearer() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let client = fx.device_client(ClientProfile::Standard);
    let code = fx.approved_device_code(&client);
    let resp =
        fx.h.identity()
            .poll_device_token(&fx.realm, &code, &client, None)
            .expect("poll without DPoP");
    assert_eq!(resp.token_type(), "Bearer");
    let access =
        fx.h.identity()
            .validate_token(&fx.realm, resp.access_token())
            .expect("validates");
    assert!(access.cnf.is_none(), "no proof, no binding");
    assert_eq!(access.scope.as_deref(), Some(SCOPE));
}

// ── engine: FAPI gate ────────────────────────────────────────────────────────

/// A FAPI realm (either profile) refuses the device grant without a proof;
/// the refusal does not consume the code, so the device can retry with one.
#[tokio::test]
async fn fapi_realm_requires_dpop_on_the_device_grant() {
    for profile in [FapiProfile::Baseline, FapiProfile::Advanced] {
        let fx = fixture(
            common::TestHarness::embedded().await.unwrap(),
            Some(profile),
        )
        .await;
        let client = fx.device_client(ClientProfile::Standard);
        let code = fx.approved_device_code(&client);

        let err =
            fx.h.identity()
                .poll_device_token(&fx.realm, &code, &client, None)
                .expect_err("FAPI realm must refuse an unbound device grant");
        assert!(
            matches!(err, IdentityError::FapiViolation { .. }),
            "{profile:?}: expected FapiViolation, got {err:?}"
        );

        let resp =
            fx.h.identity()
                .poll_device_token(&fx.realm, &code, &client, Some(JKT))
                .expect("the same code redeems with a proof");
        assert_eq!(resp.token_type(), "DPoP", "{profile:?}");
    }
}

/// A FAPI 2.0 client is held to the same rule in a standard realm.
#[tokio::test]
async fn fapi2_client_requires_dpop_on_the_device_grant() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let client = fx.device_client(ClientProfile::Fapi2);
    let code = fx.approved_device_code(&client);
    let err =
        fx.h.identity()
            .poll_device_token(&fx.realm, &code, &client, None)
            .expect_err("a FAPI 2.0 client must not get unbound tokens");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got {err:?}"
    );
}

// ── HTTP: /token device arm, both routes ─────────────────────────────────────

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn decode_claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("json")
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

    /// A one-key JWKS for client registration.
    fn jwks(&self) -> String {
        serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "x": self.x(),
            "kid": "device-key", "alg": "EdDSA", "use": "sig",
        }]})
        .to_string()
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

    fn proof(&self, htu: &str, nonce: &str) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA", "typ": "dpop+jwt",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": self.x()},
        });
        let claims = serde_json::json!({
            "htm": "POST", "htu": htu, "iat": now_secs(),
            "jti": uuid::Uuid::new_v4().to_string(), "nonce": nonce,
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

impl Fx {
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

    /// POSTs the device-code grant; `dpop` adds a fresh proof.
    async fn poll(
        &self,
        route: Route,
        client: &ClientId,
        code: &str,
        dpop: Option<&DpopKey>,
    ) -> (u16, serde_json::Value) {
        let http = reqwest::Client::new();
        let url = self.token_url(route);
        let with_realm = |r: reqwest::RequestBuilder| match route {
            Route::Header => r.header("X-Realm-ID", self.realm.as_uuid().to_string()),
            Route::Realm => r,
        };
        let mut req = with_realm(http.post(&url).form(&[
            ("grant_type", DEVICE_GRANT.to_string()),
            ("device_code", code.to_string()),
            ("client_id", client.as_uuid().to_string()),
        ]));
        if let Some(key) = dpop {
            let probe = with_realm(http.post(&url).form(&[("grant_type", "nonce-probe")]))
                .send()
                .await
                .expect("nonce probe");
            let nonce = probe
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .expect("token responses carry DPoP-Nonce")
                .to_string();
            req = req.header("DPoP", key.proof(&self.token_htu(route), &nonce));
        }
        let resp = req.send().await.expect("token request");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }
}

/// Over HTTP, a proof on the device-code poll yields a DPoP-bound pair on
/// both token routes.
#[tokio::test]
async fn http_device_poll_with_dpop_returns_a_bound_pair() {
    let fx = fixture(common::TestHarness::server().await.unwrap(), None).await;
    for route in [Route::Header, Route::Realm] {
        let client = fx.device_client(ClientProfile::Standard);
        let code = fx.approved_device_code(&client);
        let key = DpopKey::new();
        let (status, body) = fx.poll(route, &client, &code, Some(&key)).await;
        assert_eq!(status, 200, "{route:?}: {body}");
        assert_eq!(body["token_type"], "DPoP", "{route:?}: {body}");
        let access = decode_claims(body["access_token"].as_str().unwrap());
        assert_eq!(
            access["cnf"]["jkt"].as_str(),
            Some(key.thumbprint().as_str()),
            "{route:?}: access token bound to the proof key"
        );
        assert_eq!(access["scope"].as_str(), Some(SCOPE), "{route:?}");
    }
}

/// Over HTTP, a FAPI realm refuses the device grant without a proof and
/// honours it with one.
#[tokio::test]
async fn http_fapi_realm_requires_dpop_on_the_device_grant() {
    let fx = fixture(
        common::TestHarness::server().await.unwrap(),
        Some(FapiProfile::Baseline),
    )
    .await;
    for route in [Route::Header, Route::Realm] {
        let client = fx.device_client(ClientProfile::Standard);
        let code = fx.approved_device_code(&client);
        let (status, body) = fx.poll(route, &client, &code, None).await;
        assert_eq!(status, 400, "{route:?}: unbound device grant: {body}");
        assert_eq!(body["error"], "invalid_request", "{route:?}: {body}");
        assert!(body.get("access_token").is_none(), "{route:?}: {body}");

        let key = DpopKey::new();
        let (status, body) = fx.poll(route, &client, &code, Some(&key)).await;
        assert_eq!(status, 200, "{route:?}: bound retry: {body}");
        assert_eq!(body["token_type"], "DPoP", "{route:?}");
    }
}
