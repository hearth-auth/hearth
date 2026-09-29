#![allow(clippy::unwrap_used)]
//! GA audit 3 round 4 — a client-authored JWT names the client by the
//! `client_id` the client was issued.
//!
//! RFC 7523 §3 (and OIDC Core §9 for `private_key_jwt`) say `iss` and `sub`
//! of a client assertion are the client's `client_id`; RFC 9101 §4 says the
//! same of a request object's `iss` and `client_id`. Registration hands the
//! client a bare UUID, which is also what it sends as the `client_id`
//! parameter. Hearth compared these claims against its internal display form
//! `client_<uuid>` instead, so every standards-compliant client library was
//! refused, and only the internal form was accepted. The issued `client_id`
//! is now the one accepted form, on all three surfaces:
//!
//! * `private_key_jwt` client authentication (token, PAR, introspection …);
//! * the RFC 7523 JWT-bearer authorization grant;
//! * signed request objects (JAR) at PAR and `/authorize`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::oidc::{CodeChallengeMethod, PushedAuthorizationRequest};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, IdentityError, JwtBearerRequest, RegisterClientRequest,
    UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt as _;

const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const REDIRECT_URI: &str = "https://rp.example.com/cb";
/// A valid S256 challenge (RFC 7636 Appendix B).
const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    issuer: String,
    key: Ed25519KeyPair,
    client: ClientId,
}

/// A realm and one client whose Ed25519 key is registered both as its
/// `jwks` (private_key_jwt, JAR) and as its `assertion_public_key`
/// (JWT-bearer grant).
async fn env() -> Env {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_name = format!("issued-cid-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    let issuer = format!(
        "{}/realms/{realm_name}",
        h.identity().oidc_discovery().issuer
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
    let jwks = serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig", "x": public,
    }]});
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "issued-client-id".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec![
                    "authorization_code".into(),
                    "client_credentials".into(),
                    JWT_BEARER_GRANT.into(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                jwks: Some(jwks.to_string()),
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone();
    h.identity()
        .update_client(
            &realm,
            &client,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(public)),
                ..UpdateClientRequest::default()
            },
        )
        .expect("assertion key");
    Env {
        h,
        realm,
        realm_name,
        issuer,
        key,
        client,
    }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

impl Env {
    /// The `client_id` exactly as registration returned it — the bare UUID.
    fn issued(&self) -> String {
        self.client.as_uuid().to_string()
    }

    /// An EdDSA JWS over `claims`.
    fn sign(&self, claims: &serde_json::Value) -> String {
        // `kid` names the registered JWK; the raw `assertion_public_key`
        // path also insists on a `kid` header member.
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "k1"});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let sig = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    /// A client assertion (RFC 7523 §3) naming the client as `iss` / `sub`.
    fn assertion(&self, iss: &str, sub: &str) -> String {
        let now = now();
        self.sign(&serde_json::json!({
            "iss": iss, "sub": sub, "aud": self.issuer,
            "iat": now, "exp": now + 60, "jti": uuid::Uuid::new_v4().to_string(),
        }))
    }

    /// A signed request object (RFC 9101) with `iss` and `client_id` claims.
    fn request_object(&self, iss: &str, client_id: &str) -> String {
        let now = now();
        self.sign(&serde_json::json!({
            "iss": iss, "client_id": client_id, "aud": self.issuer,
            "iat": now, "exp": now + 60, "jti": uuid::Uuid::new_v4().to_string(),
            "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid",
            "state": "st", "code_challenge": CODE_CHALLENGE, "code_challenge_method": "S256",
        }))
    }

    fn push(&self, request_object: String) -> Result<(), IdentityError> {
        self.h
            .identity()
            .push_authorization_request(
                &self.realm,
                &PushedAuthorizationRequest {
                    client_id: self.client.clone(),
                    redirect_uri: REDIRECT_URI.into(),
                    scope: "openid".into(),
                    state: "st".into(),
                    resource: None,
                    response_type: "code".into(),
                    code_challenge: Some(CODE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    request: Some(request_object),
                    response_mode: None,
                    prompt: None,
                },
            )
            .map(|_| ())
    }

    /// The forms a client assertion must NOT be accepted under.
    fn other_forms(&self) -> Vec<(&'static str, String, String)> {
        let issued = self.issued();
        let prefixed = format!("client_{issued}");
        let other = uuid::Uuid::new_v4().to_string();
        vec![
            (
                "internal client_<uuid> form",
                prefixed.clone(),
                prefixed.clone(),
            ),
            (
                "upper-case UUID",
                issued.to_uppercase(),
                issued.to_uppercase(),
            ),
            ("another client's id", other.clone(), other),
            ("sub differs from iss", issued, prefixed),
        ]
    }
}

#[tokio::test]
async fn private_key_jwt_accepts_the_client_id_as_issued() {
    let env = env().await;
    let issued = env.issued();

    env.h
        .identity()
        .verify_client_assertion(&env.realm, &env.client, &env.assertion(&issued, &issued))
        .expect("a standard assertion (iss = sub = issued client_id) authenticates");

    // Black box: the realm token endpoint, as a standard client library calls it.
    let app = router(Arc::new(AppState::new(
        env.h.identity_arc(),
        env.h.rbac_arc(),
        env.h.audit_arc(),
    )));
    let form = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("scope", "openid")
        .append_pair("client_id", &issued)
        .append_pair("client_assertion_type", JWT_BEARER_ASSERTION)
        .append_pair("client_assertion", &env.assertion(&issued, &issued))
        .finish();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/realms/{}/token", env.realm_name))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials with a standard assertion; body {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn private_key_jwt_refuses_every_other_form_of_the_client_id() {
    let env = env().await;
    for (label, iss, sub) in env.other_forms() {
        let result = env.h.identity().verify_client_assertion(
            &env.realm,
            &env.client,
            &env.assertion(&iss, &sub),
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidClientAssertion { .. })),
            "{label}: must be refused, got {result:?}"
        );
    }
}

#[tokio::test]
async fn jwt_bearer_grant_accepts_only_the_client_id_as_issued() {
    let env = env().await;
    let issued = env.issued();
    let grant = |assertion: String| {
        env.h.identity().jwt_bearer_token(
            &env.realm,
            &JwtBearerRequest {
                client_id: env.client.clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
    };

    let token = grant(env.assertion(&issued, &issued))
        .expect("a standard JWT-bearer assertion yields an access token");
    let payload = token.access_token().split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        claims["sub"],
        env.client.to_string(),
        "the minted token keeps Hearth's client subject form, as client_credentials does"
    );
    for (label, iss, sub) in env.other_forms() {
        let result = grant(env.assertion(&iss, &sub));
        assert!(
            matches!(result, Err(IdentityError::JwtBearerAssertionInvalid { .. })),
            "{label}: must be refused, got {:?}",
            result.map(|_| ())
        );
    }
}

#[tokio::test]
async fn request_object_accepts_only_the_client_id_as_issued() {
    let env = env().await;
    let issued = env.issued();
    let prefixed = format!("client_{issued}");

    let claims = env
        .h
        .identity()
        .verify_jar(
            &env.realm,
            &env.client,
            &env.request_object(&issued, &issued),
        )
        .expect("a standard request object (iss = issued client_id) verifies");
    assert_eq!(claims.iss, issued);
    env.push(env.request_object(&issued, &issued))
        .expect("PAR accepts a standard request object");

    for (label, iss, client_id) in [
        ("iss in the internal form", prefixed.clone(), issued.clone()),
        (
            "client_id claim in the internal form",
            issued.clone(),
            prefixed,
        ),
        (
            "client_id claim names another client",
            issued,
            uuid::Uuid::new_v4().to_string(),
        ),
    ] {
        let result = env.push(env.request_object(&iss, &client_id));
        assert!(
            matches!(result, Err(IdentityError::InvalidJar { .. })),
            "{label}: must be refused, got {result:?}"
        );
    }
}

/// `aud` stays the realm issuer: RFC 7523 §3 lets an AS take its token
/// endpoint URL too, but the audience-injection guidance of
/// draft-ietf-oauth-rfc7523bis and FAPI 2.0 §5.3.2.1 make the issuer the one
/// value to accept. Pins that decision alongside the `iss`/`sub` change.
#[tokio::test]
async fn private_key_jwt_audience_is_the_issuer_not_the_token_endpoint() {
    let env = env().await;
    let issued = env.issued();
    let now = now();
    for (label, aud, accepted) in [
        ("the realm issuer", serde_json::json!(env.issuer), true),
        (
            "the token endpoint",
            serde_json::json!(format!("{}/token", env.issuer)),
            false,
        ),
    ] {
        let assertion = env.sign(&serde_json::json!({
            "iss": issued, "sub": issued, "aud": aud,
            "iat": now, "exp": now + 60, "jti": uuid::Uuid::new_v4().to_string(),
        }));
        let result = env
            .h
            .identity()
            .verify_client_assertion(&env.realm, &env.client, &assertion);
        assert_eq!(result.is_ok(), accepted, "aud = {label}: got {result:?}");
    }
}
