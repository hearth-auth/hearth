#![allow(clippy::unwrap_used)]
//! HEA-2039 — DPoP sender-constraint MUST be enforced at the session-version
//! feed endpoints that consume the raw access token directly (same defect
//! class as HEA-2031):
//!
//!   * `GET /oauth/session-versions`          (`oauth_sv_delta_feed`)
//!   * `GET /oauth/session-versions/snapshot` (`oauth_sv_snapshot`)
//!
//! Before this fix both handlers called `validate_token` on the raw bearer and
//! gated on the `hearth.sv_feed`/`hearth.admin` JWT permission WITHOUT checking
//! `cnf` or requiring a DPoP proof, so a DPoP-bound access token (`cnf.jkt`
//! present) stolen from a log/referrer/proxy and replayed as a plain `Bearer`
//! silently succeeded — a downgrade of the RFC 9449 §7.2 sender-constraint.
//!
//! Regression contract (proves the sender-constraint end to end):
//!   * bound token replayed as plain `Bearer` (NO DPoP proof) → 401
//!     `invalid_token` with an `error_description` naming DPoP. This is the
//!     regression differentiator: on the pre-fix tree the raw `validate_token`
//!     succeeds and the request falls through to the permission gate (403), so
//!     a `401`-DPoP here can only come from the new enforcement.
//!   * bound token presented WITH a valid DPoP proof → the guard passes the
//!     request through to the permission gate, which denies it 403 (the fixture
//!     token deliberately lacks `hearth.sv_feed`). A non-401 here proves the fix
//!     is a targeted sender-constraint check, not a blanket reject of bound
//!     tokens.
//!
//! Why 403 rather than 200/204 on the positive arm: the `hearth.*` namespace is
//! reserved and reserved permissions are not embedded into issued access tokens,
//! so a token that both (a) is DPoP-bound and (b) carries `hearth.sv_feed` is
//! not mintable through the public issuance path. The 403 still exercises the
//! full guard: it only fires *after* DPoP verification has accepted the proof.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, RealmConfig,
    RegisterClientRequest, SessionVersionConfig, TokenExchangeRequest,
};
use hearth::protocol::http::{router, AppState};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";

// ── DPoP key + proof helpers (mirrors tests/hea_2031_dpop_userinfo_bypass.rs) ─

struct DPopKey {
    key_pair: EcdsaKeyPair,
    /// Public key bytes: `0x04 || x(32) || y(32)`
    pub_bytes: Vec<u8>,
}

impl DPopKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            pub_bytes,
        }
    }

    /// Public key as a JWK JSON object (RFC 7638 canonical member order).
    fn public_jwk_json(&self) -> serde_json::Value {
        let x = &self.pub_bytes[1..33];
        let y = &self.pub_bytes[33..65];
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
        serde_json::json!({"crv":"P-256","kty":"EC","x":x_b64,"y":y_b64})
    }

    /// RFC 7638 JWK thumbprint (base64url(SHA-256(canonical JWK))).
    fn thumbprint(&self) -> String {
        let jwk_str = serde_json::to_string(&self.public_jwk_json()).unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, jwk_str.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        self.key_pair.sign(&rng, data).unwrap().as_ref().to_vec()
    }
}

/// Builds a resource-server DPoP proof including the `ath` claim
/// (`base64url(SHA-256(access_token))`) required by RFC 9449 §4.2.
#[allow(clippy::similar_names)]
fn make_resource_dpop_proof(key: &DPopKey, htm: &str, htu: &str, access_token: &str) -> String {
    let jwk = key.public_jwk_json();
    let header = serde_json::json!({"alg": "ES256", "jwk": jwk, "typ": "dpop+jwt"});
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let jti = uuid::Uuid::new_v4().to_string();
    let ath_bytes = ring::digest::digest(&ring::digest::SHA256, access_token.as_bytes());
    let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ath_bytes.as_ref());
    let claims = serde_json::json!({"htm": htm, "htu": htu, "iat": iat, "jti": jti, "ath": ath});

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let claims_b64 = b64.encode(serde_json::to_string(&claims).unwrap().as_bytes());
    let msg = format!("{header_b64}.{claims_b64}");
    let sig = key.sign(msg.as_bytes());
    format!("{header_b64}.{claims_b64}.{}", b64.encode(&sig))
}

// ── Fixture ───────────────────────────────────────────────────────────────────

fn pkce_challenge() -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

fn decode_claims_json(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "token must be a 3-part JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64-decode claims");
    serde_json::from_slice(&payload).expect("parse claims JSON")
}

struct Fixture {
    harness: common::TestHarness,
    realm: RealmId,
    /// A DPoP-bound USER access token (`cnf.jkt` present, real `sub`).
    access_token: String,
    dpop_key: DPopKey,
}

/// Mints a genuine user access token sender-constrained to `dpop_key`
/// (`cnf.jkt` present) via the authorization-code + DPoP exchange path, so a
/// valid resource-server proof is constructible. The token intentionally does
/// NOT carry `hearth.sv_feed` (reserved perms are not embedded), so the
/// permission gate denies it 403 once DPoP has accepted the proof.
async fn setup() -> Fixture {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_name = format!("hea2039-{}", uuid::Uuid::new_v4());
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name,
            // Session versioning MUST be enabled or the feed returns 404
            // regardless of DPoP, making the positive assertion vacuous.
            config: Some(RealmConfig {
                session_version: SessionVersionConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();
    harness.rbac().seed_realm(&realm).expect("seed realm");

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("victim-{}@hea2039.test", uuid::Uuid::new_v4()),
                display_name: "Victim".to_string(),
                first_name: "Victim".to_string(),
                last_name: "User".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "hea2039-client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let dpop_key = DPopKey::generate();
    let jkt = dpop_key.thumbprint();

    let access_token = mint_bound_user_token(&harness, &realm, user.id(), client.client_id(), &jkt);

    // Precondition: the token must actually carry the cnf.jkt binding, otherwise
    // the negative test would pass vacuously (no cnf ⇒ no DPoP requirement).
    let claims = decode_claims_json(&access_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(jkt.as_str()),
        "fixture must mint a DPoP-bound access token; got claims: {claims}"
    );

    Fixture {
        harness,
        realm,
        access_token,
        dpop_key,
    }
}

fn mint_bound_user_token(
    h: &common::TestHarness,
    realm: &RealmId,
    user_id: &UserId,
    client_id: &ClientId,
    jkt: &str,
) -> String {
    let auth = h
        .identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: uuid::Uuid::new_v4().to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: user_id.clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    h.identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: Some(jkt.to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange auth code")
        .access_token()
        .to_string()
}

fn app(f: &Fixture) -> axum::Router {
    router(Arc::new(AppState::new(
        f.harness.identity_arc(),
        f.harness.rbac_arc(),
        f.harness.audit_arc(),
    )))
}

/// Asserts a 401 whose body is `invalid_token` and whose `error_description`
/// names DPoP — i.e. the request was rejected by DPoP enforcement, not by the
/// permission gate (which would be a 403) or an unrelated failure.
async fn assert_dpop_rejected(resp: axum::response::Response) {
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "bound token replayed as plain Bearer must be 401"
    );
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"].as_str(),
        Some("invalid_token"),
        "error body must be invalid_token; got {json}"
    );
    assert!(
        json["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("DPoP")),
        "error_description must name the DPoP requirement (proves it was DPoP enforcement, \
         not the permission gate or a lookup failure); got: {json}"
    );
}

// ── GET /oauth/session-versions (delta feed) ──────────────────────────────────

#[tokio::test]
async fn sv_delta_feed_rejects_bound_token_replayed_as_plain_bearer() {
    let f = setup().await;
    let resp = app(&f)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/session-versions?since=0")
                .header("Authorization", format!("Bearer {}", f.access_token))
                .header("X-Realm-ID", f.realm.as_uuid().to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_dpop_rejected(resp).await;
}

#[tokio::test]
async fn sv_delta_feed_accepts_bound_token_with_valid_dpop_proof() {
    let f = setup().await;
    // htu is issuer + path only (no query), matching the handler's construction.
    let proof = make_resource_dpop_proof(
        &f.dpop_key,
        "GET",
        "https://hearth.local/oauth/session-versions",
        &f.access_token,
    );
    let resp = app(&f)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/session-versions?since=0")
                .header("Authorization", format!("Bearer {}", f.access_token))
                .header("X-Realm-ID", f.realm.as_uuid().to_string())
                .header("DPoP", proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // A valid proof passes DPoP enforcement; the request then reaches the
    // permission gate, which denies the (sv_feed-less) token 403. The key
    // property is that it is NOT the 401 DPoP rejection — the guard is a
    // targeted sender-constraint check, not a blanket reject.
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a valid DPoP proof must pass enforcement (must not be blanket-rejected)"
    );
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "past DPoP, the sv_feed-less token must be denied by the permission gate"
    );
}

// ── GET /oauth/session-versions/snapshot ──────────────────────────────────────

#[tokio::test]
async fn sv_snapshot_rejects_bound_token_replayed_as_plain_bearer() {
    let f = setup().await;
    let resp = app(&f)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/session-versions/snapshot")
                .header("Authorization", format!("Bearer {}", f.access_token))
                .header("X-Realm-ID", f.realm.as_uuid().to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_dpop_rejected(resp).await;
}

#[tokio::test]
async fn sv_snapshot_accepts_bound_token_with_valid_dpop_proof() {
    let f = setup().await;
    let proof = make_resource_dpop_proof(
        &f.dpop_key,
        "GET",
        "https://hearth.local/oauth/session-versions/snapshot",
        &f.access_token,
    );
    let resp = app(&f)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/session-versions/snapshot")
                .header("Authorization", format!("Bearer {}", f.access_token))
                .header("X-Realm-ID", f.realm.as_uuid().to_string())
                .header("DPoP", proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a valid DPoP proof must pass enforcement (must not be blanket-rejected)"
    );
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "past DPoP, the sv_feed-less token must be denied by the permission gate"
    );
}
