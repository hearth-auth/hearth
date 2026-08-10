//! HEA-2112 — `client_secret_basic` advertisement + Basic-auth hardening.
//!
//! The external audit claimed HTTP Basic client authentication was not
//! implemented. That was a misdiagnosis — `parse_basic_auth` has handled it
//! since HEA-1755 — but verifying the claim surfaced real defects:
//!
//! 1. Discovery omitted `client_secret_basic` from
//!    `token_endpoint_auth_methods_supported`, contradicting the auth method
//!    DCR hands to every registered client
//!    (`basic_auth_discovery_advertises_client_secret_basic`).
//! 2. `parse_basic_auth` did not percent-decode credentials per RFC 6749
//!    §2.3.1, so strict clients whose secrets contain reserved characters
//!    could never authenticate via Basic
//!    (`basic_auth_percent_encoded_credentials_authenticate`).
//! 3. A request carrying both Basic and body credentials that disagree was
//!    silently resolved in favor of the Basic header instead of being
//!    rejected — RFC 6749 §2.3.1 forbids more than one client
//!    authentication mechanism per request, and §5.2 prescribes
//!    `invalid_request` for it
//!    (`basic_auth_vs_body_secret_disagreement_rejected`,
//!    `basic_auth_vs_body_client_id_disagreement_rejected`,
//!    `basic_auth_vs_body_disagreement_rejected_at_introspect`).
//! 4. Body `client_id` was a required deserialization field, so a strictly
//!    compliant `client_secret_basic` client — which per RFC 6749 §3.2.1
//!    carries its identity only in the Authorization header — was rejected
//!    before reaching any handler, contradicting the newly advertised
//!    discovery metadata
//!    (`basic_only_code_exchange_without_body_client_id_succeeds`,
//!    `basic_only_code_exchange_succeeds_on_realm_path`,
//!    `basic_auth_with_explicitly_empty_body_client_id_succeeds`).
//!
//! The related timing oracle (unknown client ids failed without an Argon2
//! verification) is covered by unit tests in `src/identity/engine/mod.rs`
//! because it asserts the code path, not a wall-clock duration.
//!
//! `basic_auth_code_exchange_succeeds` and
//! `basic_auth_unencoded_legacy_secret_still_authenticates` are regression
//! fences: they passed before this change and must keep passing.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    RegisterClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://app.example.com/cb";

/// A fixed PKCE verifier/challenge (S256) pair used across the exchange flows.
fn pkce_pair() -> (String, String) {
    let verifier = "hea2112-verifier-abcdefghijklmnopqrstuvwxyz-012345".to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());
    (verifier, challenge)
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> hearth::core::UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@hea2112.test", uuid::Uuid::new_v4()),
                display_name: "HEA-2112 User".to_string(),
                first_name: "H".to_string(),
                last_name: "U".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap()
        .id()
        .clone()
}

fn register_client(
    h: &common::TestHarness,
    realm: &RealmId,
    secret: Option<&str>,
) -> hearth::identity::OAuthClient {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("hea2112-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap()
}

/// Runs `authorize` (PKCE) and returns the freshly minted authorization code.
fn mint_code(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &hearth::identity::OAuthClient,
    user_id: &hearth::core::UserId,
    challenge: &str,
) -> String {
    h.identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: Some(challenge.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize")
        .code()
        .to_string()
}

fn basic_header(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

/// POSTs `body` to `path` with an optional `Authorization` header value.
async fn post_json(
    state: &Arc<AppState>,
    path: &str,
    realm_id: &str,
    authorization: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("X-Realm-ID", realm_id)
        .header("Content-Type", "application/json");
    if let Some(auth) = authorization {
        builder = builder.header("Authorization", auth);
    }
    let resp = router(Arc::clone(state))
        .oneshot(
            builder
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Everything a code-exchange test needs, minted through the domain API.
struct Fixture {
    state: Arc<AppState>,
    realm_id_str: String,
    realm_name: String,
    client_id: String,
    code: String,
    verifier: String,
}

async fn fixture_with_secret(secret: &str) -> Fixture {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_name = format!("hea2112-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap();
    let user = make_user(&h, realm.id());
    let client = register_client(&h, realm.id(), Some(secret));
    let (verifier, challenge) = pkce_pair();
    let code = mint_code(&h, realm.id(), &client, &user, &challenge);
    Fixture {
        state: Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())),
        realm_id_str: realm.id().as_uuid().to_string(),
        realm_name,
        client_id: client.client_id().as_uuid().to_string(),
        code,
        verifier,
    }
}

fn exchange_body(f: &Fixture) -> serde_json::Value {
    serde_json::json!({
        "grant_type": "authorization_code",
        "client_id": f.client_id,
        "code": f.code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": f.verifier,
    })
}

/// The same exchange body a strict `client_secret_basic` client sends:
/// per RFC 6749 §3.2.1, `client_id` stays out of the body because the
/// client authenticates via the Authorization header.
fn exchange_body_without_client_id(f: &Fixture) -> serde_json::Value {
    let mut body = exchange_body(f);
    body.as_object_mut().unwrap().remove("client_id");
    body
}

/// Regression fence for the misdiagnosed audit finding: a confidential
/// client's full authorization-code exchange authenticated purely via
/// `Authorization: Basic` (no body `client_secret`) already worked.
#[tokio::test]
async fn basic_auth_code_exchange_succeeds() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        exchange_body(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Basic-auth code exchange must succeed: {json}"
    );
    assert!(
        json["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "exchange must mint an access token"
    );
}

/// RFC 6749 §3.2.1: body `client_id` is REQUIRED only "if the client is not
/// authenticating with the authorization server". A strictly compliant
/// `client_secret_basic` client therefore omits it — the exchange must still
/// succeed with the identity taken from the Authorization header.
#[tokio::test]
async fn basic_only_code_exchange_without_body_client_id_succeeds() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        exchange_body_without_client_id(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Basic-only exchange (no body client_id) must succeed: {json}"
    );
    assert!(
        json["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "exchange must mint an access token"
    );
}

/// Same strict Basic-only exchange through the realm-scoped
/// `/realms/{{name}}/token` handler, which has its own dispatch path.
#[tokio::test]
async fn basic_only_code_exchange_succeeds_on_realm_path() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let (status, json) = post_json(
        &f.state,
        &format!("/realms/{}/token", f.realm_name),
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        exchange_body_without_client_id(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "realm-path Basic-only exchange must succeed: {json}"
    );
    assert!(
        json["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "exchange must mint an access token"
    );
}

/// An explicitly empty `client_id=` next to Basic auth is an absent
/// identifier, not a disagreeing credential — it must not trip the RFC 6749
/// §2.3.1 mismatch rejection.
#[tokio::test]
async fn basic_auth_with_explicitly_empty_body_client_id_succeeds() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let mut body = exchange_body(&f);
    body["client_id"] = serde_json::json!("");
    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        body,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "empty body client_id must read as absent, not as a mismatch: {json}"
    );
}

/// RFC 6749 §2.3.1 / §5.2: Basic and body secrets that disagree must be
/// rejected as `invalid_request`, not silently resolved in Basic's favor.
#[tokio::test]
async fn basic_auth_vs_body_secret_disagreement_rejected() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let mut body = exchange_body(&f);
    body["client_secret"] = serde_json::json!("a-different-secret");
    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        body,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "disagreeing Basic/body secrets must be rejected: {json}"
    );
    assert_eq!(
        json["error"].as_str(),
        Some("invalid_request"),
        "RFC 6749 §5.2 prescribes invalid_request for multiple auth mechanisms"
    );
}

/// A Basic username that names a different client than the body `client_id`
/// must be rejected — previously the Basic secret was verified against the
/// body's client, so a cross-client credential mix-up passed.
#[tokio::test]
async fn basic_auth_vs_body_client_id_disagreement_rejected() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let other_id = uuid::Uuid::new_v4().to_string();
    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&other_id, secret)),
        exchange_body(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Basic username disagreeing with body client_id must be rejected: {json}"
    );
    assert_eq!(json["error"].as_str(), Some("invalid_request"));
}

/// The same disagreement rejection must hold on the `verify_endpoint_client`
/// path (introspection), not just the code-exchange arm.
#[tokio::test]
async fn basic_auth_vs_body_disagreement_rejected_at_introspect() {
    let secret = "hea2112-basic-secret!";
    let f = fixture_with_secret(secret).await;

    let (status, json) = post_json(
        &f.state,
        "/introspect",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        serde_json::json!({
            "token": "some.fake.token",
            "client_id": f.client_id,
            "client_secret": "a-different-secret",
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "disagreeing Basic/body credentials at /introspect must be rejected: {json}"
    );
    assert_eq!(json["error"].as_str(), Some("invalid_request"));
}

/// RFC 6749 §2.3.1: Basic credentials are form-urlencoded before base64.
/// A strict client whose secret contains reserved characters
/// (space, `%`, `+`, `:`, `&`, `=`) percent-encodes them — the server must
/// decode before verifying.
#[tokio::test]
async fn basic_auth_percent_encoded_credentials_authenticate() {
    // Raw secret registered with the client.
    let secret = "sec ret%+:&=";
    // What a strict RFC 6749 client sends: form-urlencoded value encoding.
    let encoded_secret = "sec+ret%25%2B%3A%26%3D";
    let f = fixture_with_secret(secret).await;

    // Over-encode one unreserved character of the client_id too — legal
    // per the encoding, and proves the userid is decoded as well.
    let first = &f.client_id[..1];
    let encoded_id = format!("%{:02X}{}", first.as_bytes()[0], &f.client_id[1..]);

    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&encoded_id, encoded_secret)),
        exchange_body(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "form-urlencoded Basic credentials must authenticate: {json}"
    );
    assert!(json["access_token"].as_str().is_some_and(|t| !t.is_empty()));
}

/// Regression fence: a legacy client sending its secret raw (unencoded, with
/// a `%` that is not a valid escape) must keep authenticating — the decoder
/// is lenient and passes malformed escapes through unchanged.
#[tokio::test]
async fn basic_auth_unencoded_legacy_secret_still_authenticates() {
    let secret = "100%legit-secret";
    let f = fixture_with_secret(secret).await;

    let (status, json) = post_json(
        &f.state,
        "/token",
        &f.realm_id_str,
        Some(&basic_header(&f.client_id, secret)),
        exchange_body(&f),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "raw legacy secret with a non-escape % must keep working: {json}"
    );
}

/// Discovery must advertise `client_secret_basic` — the very method DCR
/// returns for every dynamically registered client — alongside the other
/// supported methods.
#[tokio::test]
async fn basic_auth_discovery_advertises_client_secret_basic() {
    let harness = common::TestHarness::embedded().await.unwrap();
    let doc = harness.identity().oidc_discovery();

    // The method DCR hands out (`token_endpoint_auth_method` in DcrResponse)
    // must be present, plus the previously advertised set.
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "none",
    ] {
        assert!(
            doc.token_endpoint_auth_methods_supported
                .contains(&method.to_string()),
            "discovery must advertise {method}, got: {:?}",
            doc.token_endpoint_auth_methods_supported
        );
    }
}
