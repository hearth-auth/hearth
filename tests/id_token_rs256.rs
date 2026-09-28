//! Task 26.55 — RS256 ID tokens, selected per client with
//! `id_token_signed_response_alg` (OpenID Connect Dynamic Client Registration
//! 1.0 §2).
//!
//! OIDC Discovery 1.0 §3 and Core §15.1 each make RS256 mandatory for ID
//! tokens, so an OP that signs them with EdDSA alone cannot pass any OpenID
//! certification profile. Hearth keeps Ed25519 for everything it issues and
//! validates, and signs an ID token with RS256 only for a client that asked
//! for it. These tests pin both halves of that:
//!
//! - **the interop half** — discovery advertises RS256; a dynamically
//!   registered client that omits the parameter gets RS256, as the spec says;
//!   the ID token verifies against the RSA key published in the realm JWKS;
//! - **the containment half** — access tokens stay EdDSA, and no Hearth path
//!   that validates an access token ever accepts an RS256 token.
//!
//! Rotation, cluster-epoch, KEK and realm-delete behaviour of the RSA key is
//! covered here too; the backup round-trip lives in `tests/backup.rs`.

#![allow(clippy::unwrap_used)]

mod common;

use std::str::FromStr as _;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{ClientId, Clock, FakeClock, RealmId, SessionId, Timestamp};
use hearth::identity::oidc::RpLogoutRequest;
use hearth::identity::{
    AuthorizationRequest, ClientProfile, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, CredentialConfig, DcrPolicy, EmbeddedIdentityEngine, FapiProfile,
    IdTokenSigningAlg, IdentityConfig, IdentityEngine, IdentityError, OidcTokenResponse,
    RealmConfig, RegisterClientRequest, TokenExchangeRequest, TokenIntrospectionRequest,
    TokenRevocationRequest, UpdateClientRequest, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://rp.example.com/cb";
const PKCE_VERIFIER: &str = "rs256-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A realm that allows open Dynamic Client Registration, plus an HTTP router
/// over the same engines.
struct DcrRealm {
    state: Arc<AppState>,
    name: String,
    id: RealmId,
}

fn dcr_realm(h: &common::TestHarness) -> DcrRealm {
    let name = format!("rs256-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Open),
                ..Default::default()
            }),
        })
        .unwrap();
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    DcrRealm {
        state,
        name,
        id: realm.id().clone(),
    }
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = router(Arc::clone(state)).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get_json(state: &Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
    send(
        state,
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// `POST /realms/{realm}/register` — the registration endpoint the realm's
/// discovery document advertises.
async fn realm_register(
    realm: &DcrRealm,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        &realm.state,
        Request::builder()
            .method("POST")
            .uri(format!("/realms/{}/register", realm.name))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

/// `POST /register` with `X-Realm-ID` — the global registration endpoint.
async fn global_register(
    realm: &DcrRealm,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        &realm.state,
        Request::builder()
            .method("POST")
            .uri("/register")
            .header("Content-Type", "application/json")
            .header("X-Realm-ID", realm.id.as_uuid().to_string())
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

fn registration(extra: serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({
        "client_name": "RS256 Relying Party",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code"],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn client_id_of(body: &serde_json::Value) -> ClientId {
    ClientId::from_str(body["client_id"].as_str().expect("client_id")).expect("uuid client_id")
}

/// Registers a client through the administrative engine API.
fn admin_register(
    engine: &dyn IdentityEngine,
    realm: &RealmId,
    alg: Option<&str>,
) -> Result<ClientId, IdentityError> {
    engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Admin RP".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                id_token_signed_response_alg: alg.map(str::to_string),
                ..Default::default()
            },
        )
        .map(|c| c.client_id().clone())
}

fn new_user(engine: &dyn IdentityEngine, realm: &RealmId) -> hearth::core::UserId {
    engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@rs256.test", uuid::Uuid::new_v4()),
                display_name: "RS256 User".to_string(),
                first_name: "R".to_string(),
                last_name: "S".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap()
        .id()
        .clone()
}

/// Runs a real authorization-code + PKCE flow through the engine and returns
/// the token response — the same path `/token` takes.
fn code_flow(engine: &dyn IdentityEngine, realm: &RealmId, client: &ClientId) -> OidcTokenResponse {
    let user = new_user(engine, realm);
    let digest = ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest.as_ref());
    let code = engine
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user,
                code_challenge: Some(challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(format!("n-{}", uuid::Uuid::new_v4())),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize")
        .code()
        .to_string();
    engine
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client.clone(),
                code,
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange authorization code")
}

fn jws_part(token: &str, index: usize) -> serde_json::Value {
    let segment = token.split('.').nth(index).expect("jws segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("b64")).expect("json")
}

fn header_alg(token: &str) -> String {
    jws_part(token, 0)["alg"].as_str().expect("alg").to_string()
}

fn header_kid(token: &str) -> String {
    jws_part(token, 0)["kid"].as_str().expect("kid").to_string()
}

/// Verifies `token` the way a relying party does: pick the JWK by `kid` from
/// the published JWKS and check the signature with the algorithm the JWK
/// names. Returns the matched JWK.
fn verify_against_jwks(token: &str, jwks: &serde_json::Value) -> serde_json::Value {
    let kid = header_kid(token);
    let jwk = jwks["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .unwrap_or_else(|| panic!("kid {kid} is not published in the JWKS: {jwks}"))
        .clone();
    let (signing_input, sig_b64) = token.rsplit_once('.').expect("jws");
    let sig = URL_SAFE_NO_PAD.decode(sig_b64).expect("sig");
    match jwk["kty"].as_str() {
        Some("RSA") => {
            assert_eq!(jwk["alg"], "RS256");
            let n = URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap();
            let e = URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap();
            ring::signature::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    signing_input.as_bytes(),
                    &sig,
                )
                .expect("RS256 signature must verify against the published RSA JWK");
        }
        Some("OKP") => {
            assert_eq!(jwk["alg"], "EdDSA");
            let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &x)
                .verify(signing_input.as_bytes(), &sig)
                .expect("EdDSA signature must verify against the published OKP JWK");
        }
        other => panic!("unexpected kty {other:?}"),
    }
    jwk
}

fn rsa_kids(jwks: &hearth::identity::JwksDocument) -> Vec<String> {
    jwks.keys
        .iter()
        .filter(|k| k.kty == "RSA")
        .map(|k| k.kid.clone())
        .collect()
}

fn session_of(token: &str) -> SessionId {
    let sid = jws_part(token, 1)["sid"].as_str().expect("sid").to_string();
    SessionId::new(uuid::Uuid::parse_str(sid.strip_prefix("session_").unwrap()).unwrap())
}

/// An engine over its own storage with a controllable clock — for grace
/// windows — and the handles a test needs to inspect raw storage.
fn engine_with_clock(
    kek: Option<[u8; 32]>,
) -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<FakeClock>,
    Arc<dyn StorageEngine>,
) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).unwrap(),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_800_000_000 * 1_000_000,
    )));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            key_encryption_key: kek.map(hearth::identity::key_encryption::StorageKek::new),
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .unwrap();
    (dir, engine, clock, storage)
}

fn plain_realm(engine: &dyn IdentityEngine) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("rs256-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone()
}

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Raw storage key of a realm's active RSA ID-token key. Re-derived rather
/// than imported, so a change to the on-disk layout fails this test.
fn rsa_key_storage_key(realm: &RealmId) -> Vec<u8> {
    format!("realm:idtoken_rsa:{}", realm.as_uuid()).into_bytes()
}

fn rsa_retiring_blobs(storage: &Arc<dyn StorageEngine>, realm: &RealmId) -> usize {
    let start = format!("realm:idtoken_rsa_retiring:{}:", realm.as_uuid()).into_bytes();
    let mut end = start.clone();
    *end.last_mut().unwrap() += 1;
    storage.scan(&system_realm(), &start, &end).unwrap().len()
}

// ── Discovery ─────────────────────────────────────────────────────────────────

/// OIDC Discovery 1.0 §3: "The algorithm RS256 MUST be included." Both the
/// global and the realm-scoped document — the OpenID Foundation suite ran
/// against each and failed both on exactly this (reports/conformance-suite-
/// run-2026-09-21.md §4.1).
#[tokio::test]
async fn discovery_advertises_rs256_and_eddsa_for_id_tokens() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);

    for uri in [
        "/.well-known/openid-configuration".to_string(),
        format!("/realms/{}/.well-known/openid-configuration", realm.name),
    ] {
        let (status, doc) = get_json(&realm.state, &uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {doc}");
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            serde_json::json!(["RS256", "EdDSA"]),
            "{uri} must advertise RS256 (and never none/HS*)"
        );
    }
}

// ── Registration ──────────────────────────────────────────────────────────────

/// OIDC Registration §2: when `id_token_signed_response_alg` is omitted "the
/// default … is RS256". A client that registers the way a certification suite
/// does must get exactly that, and the response must say so (RFC 7591 §3.2.1
/// returns registered metadata, defaults included).
#[tokio::test]
async fn dynamic_registration_without_the_parameter_gets_rs256() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);

    let (status, body) = realm_register(&realm, registration(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["id_token_signed_response_alg"], "RS256");
    let client = h
        .identity()
        .get_client(&realm.id, &client_id_of(&body))
        .unwrap()
        .unwrap();
    assert_eq!(
        client.id_token_signed_response_alg(),
        IdTokenSigningAlg::Rs256
    );

    // The global endpoint applies the same default.
    let (status, body) = global_register(&realm, registration(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["id_token_signed_response_alg"], "RS256");
}

#[tokio::test]
async fn dynamic_registration_honours_an_explicit_rs256_or_eddsa() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);

    for (requested, expected) in [
        ("RS256", IdTokenSigningAlg::Rs256),
        ("EdDSA", IdTokenSigningAlg::EdDsa),
    ] {
        for global in [false, true] {
            let body =
                registration(serde_json::json!({ "id_token_signed_response_alg": requested }));
            let (status, resp) = if global {
                global_register(&realm, body).await
            } else {
                realm_register(&realm, body).await
            };
            assert_eq!(
                status,
                StatusCode::CREATED,
                "{requested} global={global}: {resp}"
            );
            assert_eq!(resp["id_token_signed_response_alg"], requested);
            let client = h
                .identity()
                .get_client(&realm.id, &client_id_of(&resp))
                .unwrap()
                .unwrap();
            assert_eq!(client.id_token_signed_response_alg(), expected);
        }
    }
}

/// Anything but RS256/EdDSA is refused with RFC 7591 §3.2.2
/// `invalid_client_metadata` — never narrowed to a default. `none` and the
/// symmetric `HS*` family in particular: an HMAC key the client also holds
/// would let it forge its own ID tokens.
#[tokio::test]
async fn dynamic_registration_refuses_unsupported_algorithms() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);

    for bad in [
        serde_json::json!("HS256"),
        serde_json::json!("none"),
        serde_json::json!("rs256"),
        serde_json::json!("ES256"),
        serde_json::json!("PS256"),
        serde_json::json!(""),
        serde_json::json!(256),
        serde_json::json!(["RS256"]),
    ] {
        let body = registration(serde_json::json!({ "id_token_signed_response_alg": bad }));
        let (status, resp) = realm_register(&realm, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "realm DCR accepted {bad}: {resp}"
        );
        assert_eq!(resp["error"], "invalid_client_metadata", "{bad}");
    }
    for bad in ["HS256", "none", "HS512", "RS512"] {
        let body = registration(serde_json::json!({ "id_token_signed_response_alg": bad }));
        let (status, resp) = global_register(&realm, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "global DCR accepted {bad}: {resp}"
        );
        assert_eq!(resp["error"], "invalid_client_metadata", "{bad}");
    }

    // Nothing was registered along the way, and no RSA key was provisioned.
    let page = h
        .identity()
        .list_clients(&realm.id, &hearth::core::PageRequest::new(0, 100))
        .unwrap();
    assert_eq!(
        page.total, 0,
        "a refused registration must not leave a client"
    );
    assert!(rsa_kids(&h.identity().realm_jwks(&realm.id).unwrap()).is_empty());
}

/// Administrative surfaces keep Hearth's native algorithm when the parameter
/// is omitted, persist it explicitly, and validate an explicit value exactly
/// as dynamic registration does.
#[tokio::test]
async fn admin_registration_defaults_to_eddsa_and_validates_the_parameter() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();

    let default = admin_register(h.identity(), &realm, None).unwrap();
    let client = h.identity().get_client(&realm, &default).unwrap().unwrap();
    assert_eq!(
        client.id_token_signed_response_alg(),
        IdTokenSigningAlg::EdDsa
    );
    assert!(
        rsa_kids(&h.identity().realm_jwks(&realm).unwrap()).is_empty(),
        "an EdDSA registration must not provision an RSA key"
    );

    let rs = admin_register(h.identity(), &realm, Some("RS256")).unwrap();
    let client = h.identity().get_client(&realm, &rs).unwrap().unwrap();
    assert_eq!(
        client.id_token_signed_response_alg(),
        IdTokenSigningAlg::Rs256
    );

    for bad in ["HS256", "none", "rs256"] {
        assert!(
            matches!(
                admin_register(h.identity(), &realm, Some(bad)),
                Err(IdentityError::InvalidInput { .. })
            ),
            "{bad} must be refused by the engine"
        );
    }
}

/// Issues a realm-admin access token for the admin REST API.
fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    use hearth::rbac::{AssignRoleRequest, Scope, Subject};
    h.rbac().seed_realm(realm).expect("seed rbac");
    let user = new_user(h.identity(), realm);
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin");
    let session = h
        .identity()
        .create_session(realm, &user, &hearth::identity::SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, &user, session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn admin_call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    token: &str,
    realm: &RealmId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        state,
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

/// The admin REST API — `POST` and `PATCH /admin/applications` — accepts,
/// validates and reports the algorithm. `PATCH` used a hand-rolled body that
/// silently dropped unknown keys, so without an explicit field an operator's
/// switch to RS256 would have been ignored with a `200`.
#[tokio::test]
async fn admin_rest_api_sets_and_validates_id_token_signed_response_alg() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let token = admin_token(&h, &realm);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let (status, created) = admin_call(
        &state,
        "POST",
        "/admin/applications",
        &token,
        &realm,
        registration(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["id_token_signed_response_alg"], "EdDSA",
        "the admin surface defaults to EdDSA and says so"
    );
    let id = created["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    let (status, body) = admin_call(
        &state,
        "PATCH",
        &format!("/admin/applications/{id}"),
        &token,
        &realm,
        serde_json::json!({ "id_token_signed_response_alg": "RS256" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id_token_signed_response_alg"], "RS256");
    assert_eq!(
        h.identity()
            .get_client(&realm, &ClientId::from_str(&id).unwrap())
            .unwrap()
            .unwrap()
            .id_token_signed_response_alg(),
        IdTokenSigningAlg::Rs256
    );

    let (status, body) = admin_call(
        &state,
        "PATCH",
        &format!("/admin/applications/{id}"),
        &token,
        &realm,
        serde_json::json!({ "id_token_signed_response_alg": "HS256" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "HS256 must be refused: {body}"
    );

    let (status, created) = admin_call(
        &state,
        "POST",
        "/admin/applications",
        &token,
        &realm,
        registration(serde_json::json!({ "id_token_signed_response_alg": "none" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "none must be refused: {created}"
    );
}

// ── Issuance ──────────────────────────────────────────────────────────────────

/// The core interop property, end to end over HTTP: a client registered
/// without the parameter receives an RS256 ID token, whose `kid` is published
/// in the realm JWKS as an RSA key with `alg: RS256`, `use: sig`, `n`, `e` —
/// and the signature verifies against it. The access token from the same
/// grant is still EdDSA and verifies against the Ed25519 key.
#[tokio::test]
async fn rs256_client_receives_an_id_token_that_verifies_against_the_realm_jwks() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);
    let (status, body) = realm_register(&realm, registration(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let client = client_id_of(&body);

    let tokens = code_flow(h.identity(), &realm.id, &client);
    assert_eq!(header_alg(tokens.id_token()), "RS256");
    assert_eq!(
        jws_part(tokens.id_token(), 1)["token_type"],
        "id_token",
        "only an ID token is ever RS256"
    );

    let (status, jwks) = get_json(
        &realm.state,
        &format!("/realms/{}/.well-known/jwks.json", realm.name),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{jwks}");
    let jwk = verify_against_jwks(tokens.id_token(), &jwks);
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["use"], "sig");
    assert!(jwk["n"].as_str().is_some_and(|n| !n.is_empty()));
    assert_eq!(jwk["e"], "AQAB");
    assert!(
        jwk.get("x").is_none() && jwk.get("crv").is_none(),
        "an RSA JWK carries no OKP fields: {jwk}"
    );

    // Access token: EdDSA, verifiable against the same JWKS, and valid for Hearth.
    assert_eq!(header_alg(tokens.access_token()), "EdDSA");
    let access_jwk = verify_against_jwks(tokens.access_token(), &jwks);
    assert_eq!(access_jwk["kty"], "OKP");
    let access = h
        .identity()
        .validate_token(&realm.id, tokens.access_token())
        .expect("the EdDSA access token must still validate");
    assert_eq!(access.token_type, "access");
    assert_eq!(
        access.sub,
        jws_part(tokens.id_token(), 1)["sub"].as_str().expect("sub"),
        "the access token and the RS256 ID token describe the same user"
    );
}

/// An EdDSA client — including every client created before this change,
/// which reads as EdDSA — keeps EdDSA ID tokens, and a realm with no RS256
/// client publishes no RSA key.
#[tokio::test]
async fn eddsa_client_keeps_eddsa_id_tokens() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let client = admin_register(h.identity(), &realm, None).unwrap();

    let tokens = code_flow(h.identity(), &realm, &client);
    assert_eq!(header_alg(tokens.id_token()), "EdDSA");
    assert_eq!(header_alg(tokens.access_token()), "EdDSA");
    let jwks = h.identity().realm_jwks(&realm).unwrap();
    assert!(rsa_kids(&jwks).is_empty(), "no RS256 client, no RSA key");
    assert!(jwks.keys.iter().all(|k| k.kty == "OKP"));
}

/// Switching an existing client to RS256 provisions the key and takes effect
/// on the next grant; an unsupported value is refused and changes nothing.
#[tokio::test]
async fn updating_a_client_switches_its_id_token_algorithm() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let client = admin_register(h.identity(), &realm, None).unwrap();

    let update = |alg: &str| {
        h.identity().update_client(
            &realm,
            &client,
            &UpdateClientRequest {
                id_token_signed_response_alg: Some(alg.to_string()),
                ..Default::default()
            },
        )
    };
    assert!(matches!(
        update("HS256"),
        Err(IdentityError::InvalidInput { .. })
    ));
    assert_eq!(
        h.identity()
            .get_client(&realm, &client)
            .unwrap()
            .unwrap()
            .id_token_signed_response_alg(),
        IdTokenSigningAlg::EdDsa,
        "a refused update must change nothing"
    );

    let updated = update("RS256").expect("switch to RS256");
    assert_eq!(
        updated.id_token_signed_response_alg(),
        IdTokenSigningAlg::Rs256
    );
    let tokens = code_flow(h.identity(), &realm, &client);
    assert_eq!(header_alg(tokens.id_token()), "RS256");

    update("EdDSA").expect("switch back");
    let tokens = code_flow(h.identity(), &realm, &client);
    assert_eq!(header_alg(tokens.id_token()), "EdDSA");
}

/// The device grant also returns an ID token, and signs it with the client's
/// algorithm too.
#[tokio::test]
async fn device_grant_signs_the_id_token_with_the_clients_algorithm() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Device RP".to_string(),
                redirect_uris: Vec::new(),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                id_token_signed_response_alg: Some("RS256".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .client_id()
        .clone();
    let user = new_user(h.identity(), &realm);
    let auth = h
        .identity()
        .device_authorize(
            &realm,
            &hearth::identity::DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: Some("openid".to_string()),
            },
        )
        .unwrap();
    h.identity()
        .approve_device(&realm, &auth.user_code, &user)
        .unwrap();
    let tokens = h
        .identity()
        .poll_device_token(&realm, &auth.device_code, &client)
        .unwrap();
    assert_eq!(header_alg(tokens.id_token()), "RS256");
    assert_eq!(header_alg(tokens.access_token()), "EdDSA");
    let jwks = serde_json::to_value(h.identity().realm_jwks(&realm).unwrap()).unwrap();
    verify_against_jwks(tokens.id_token(), &jwks);
}

// ── Containment: Hearth never accepts RS256 where it validates access ─────────

/// A genuine RS256 ID token, signed by the realm's own RSA key, is refused by
/// every path that validates an access token: `validate_token` (the hot path),
/// introspection, and `userinfo`.
#[tokio::test]
async fn an_rs256_id_token_is_never_accepted_as_an_access_token() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = dcr_realm(&h);
    let (_, body) = realm_register(&realm, registration(serde_json::json!({}))).await;
    let tokens = code_flow(h.identity(), &realm.id, &client_id_of(&body));
    let id_token = tokens.id_token();
    assert_eq!(header_alg(id_token), "RS256");

    assert!(matches!(
        h.identity().validate_token(&realm.id, id_token),
        Err(IdentityError::InvalidToken)
    ));

    let introspection = h
        .identity()
        .introspect_token(
            &realm.id,
            &TokenIntrospectionRequest {
                token: id_token.to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .unwrap();
    assert!(
        !introspection.active,
        "an RS256 ID token must introspect inactive"
    );

    let (status, body) = send(
        &realm.state,
        Request::builder()
            .method("GET")
            .uri(format!("/realms/{}/userinfo", realm.name))
            .header("Authorization", format!("Bearer {id_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "userinfo accepted an RS256 token: {body}"
    );

    // Control: the EdDSA access token from the same grant is accepted.
    let control = h
        .identity()
        .validate_token(&realm.id, tokens.access_token())
        .expect("control: the access token validates");
    assert_eq!(
        control.token_type, "access",
        "control: the EdDSA access token from the same grant is accepted as an access token"
    );
}

/// RP-Initiated Logout: an RS256 ID token is exactly what an RS256 client
/// holds, so it must work as `id_token_hint` — and a tampered one must not.
#[tokio::test]
async fn an_rs256_id_token_hint_ends_the_session_and_a_forged_one_does_not() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let client = admin_register(h.identity(), &realm, Some("RS256")).unwrap();
    let tokens = code_flow(h.identity(), &realm, &client);
    assert_eq!(
        header_alg(tokens.id_token()),
        "RS256",
        "precondition: the hint under test is an RS256 ID token"
    );
    let session = session_of(tokens.id_token());
    assert!(h
        .identity()
        .get_session(&realm, &session)
        .unwrap()
        .is_some());

    // Forged: same header and signature over a different subject.
    let mut parts: Vec<String> = tokens.id_token().split('.').map(str::to_string).collect();
    let mut claims = jws_part(tokens.id_token(), 1);
    claims["sub"] = serde_json::json!("user_00000000-0000-0000-0000-000000000000");
    parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
    let forged = parts.join(".");
    let refused = h.identity().initiate_logout(
        &realm,
        &RpLogoutRequest {
            id_token_hint: Some(forged),
            ..Default::default()
        },
    );
    assert!(
        matches!(refused, Err(IdentityError::InvalidToken)),
        "a forged RS256 hint must fail signature verification, got {refused:?}"
    );
    assert!(
        h.identity()
            .get_session(&realm, &session)
            .unwrap()
            .is_some(),
        "a forged hint must revoke nothing"
    );

    let result = h
        .identity()
        .initiate_logout(
            &realm,
            &RpLogoutRequest {
                id_token_hint: Some(tokens.id_token().to_string()),
                ..Default::default()
            },
        )
        .expect("a genuine RS256 id_token_hint must be accepted");
    assert_eq!(result.session_id, session);
    assert!(h
        .identity()
        .get_session(&realm, &session)
        .unwrap()
        .is_none());
}

/// Revocation parity: a client may end its session by revoking its ID token,
/// whichever algorithm signed it (RFC 7009 answers 200 either way, so a
/// silently ignored RS256 token would report a revocation that never happened).
#[tokio::test]
async fn revoking_an_rs256_id_token_ends_its_session() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let client = admin_register(h.identity(), &realm, Some("RS256")).unwrap();
    let tokens = code_flow(h.identity(), &realm, &client);
    assert_eq!(
        header_alg(tokens.id_token()),
        "RS256",
        "precondition: the token under test is an RS256 ID token"
    );
    let session = session_of(tokens.id_token());
    assert!(h
        .identity()
        .get_session(&realm, &session)
        .unwrap()
        .is_some());

    h.identity()
        .revoke_token(
            &realm,
            &TokenRevocationRequest {
                token: tokens.id_token().to_string(),
                token_type_hint: None,
                // As the `/revoke` wire surfaces do: the ID token was issued to
                // `client`, so the RFC 7009 §2.1 ownership check must pass.
                revoking_client_id: Some(client.clone()),
            },
        )
        .unwrap();
    assert!(h
        .identity()
        .get_session(&realm, &session)
        .unwrap()
        .is_none());
}

// ── Key lifecycle ─────────────────────────────────────────────────────────────

/// Rotation replaces the RSA key with the same grace semantics as the Ed25519
/// key: the old `kid` stays published — and stays usable as an
/// `id_token_hint` — until its deadline, new ID tokens use the new key, and
/// after the deadline the old key is gone from the JWKS and refused.
#[test]
fn rotation_keeps_the_old_rsa_kid_valid_through_its_grace_period() {
    let (_dir, engine, clock, storage) = engine_with_clock(None);
    let realm = plain_realm(&engine);
    let client = admin_register(&engine, &realm, Some("RS256")).unwrap();

    let before = code_flow(&engine, &realm, &client);
    let old_kid = header_kid(before.id_token());
    assert_eq!(
        rsa_kids(&engine.realm_jwks(&realm).unwrap()),
        vec![old_kid.clone()]
    );

    engine.rotate_realm_signing_key(&realm, 3_600).unwrap();

    let after = code_flow(&engine, &realm, &client);
    let new_kid = header_kid(after.id_token());
    assert_ne!(new_kid, old_kid, "new ID tokens must use the new RSA key");
    let jwks = serde_json::to_value(engine.realm_jwks(&realm).unwrap()).unwrap();
    verify_against_jwks(before.id_token(), &jwks);
    verify_against_jwks(after.id_token(), &jwks);
    assert_eq!(rsa_retiring_blobs(&storage, &realm), 1);

    // Inside the grace window the pre-rotation ID token still ends its session.
    engine
        .initiate_logout(
            &realm,
            &RpLogoutRequest {
                id_token_hint: Some(before.id_token().to_string()),
                ..Default::default()
            },
        )
        .expect("an in-grace RS256 hint must be accepted");

    // Past the deadline the old key is neither published nor accepted.
    clock.advance(3_601 * 1_000_000);
    let kids = rsa_kids(&engine.realm_jwks(&realm).unwrap());
    assert_eq!(
        kids,
        vec![new_kid],
        "the retired RSA kid must leave the JWKS"
    );
    let refused = engine.initiate_logout(
        &realm,
        &RpLogoutRequest {
            id_token_hint: Some(before.id_token().to_string()),
            ..Default::default()
        },
    );
    assert!(
        matches!(refused, Err(IdentityError::InvalidToken)),
        "a hint signed by an RSA key past its grace deadline must be refused, got {refused:?}"
    );
}

/// A revoking rotation (grace 0) — the response to a leaked key — cuts the old
/// RSA key off at once and leaves no retiring copy of it in storage.
#[test]
fn revoking_rotation_drops_the_old_rsa_key_immediately() {
    let (_dir, engine, _clock, storage) = engine_with_clock(None);
    let realm = plain_realm(&engine);
    let client = admin_register(&engine, &realm, Some("RS256")).unwrap();
    let before = code_flow(&engine, &realm, &client);
    assert_eq!(
        header_alg(before.id_token()),
        "RS256",
        "precondition: the token under test is an RS256 ID token, so `old_kid` is an RSA kid"
    );
    let old_kid = header_kid(before.id_token());
    assert_eq!(
        rsa_kids(&engine.realm_jwks(&realm).unwrap()),
        vec![old_kid.clone()]
    );

    // A graceful rotation first leaves a retiring key; the revoking one must
    // purge it along with the key it retires.
    engine.rotate_realm_signing_key(&realm, 3_600).unwrap();
    engine.rotate_realm_signing_key(&realm, 0).unwrap();

    let kids = rsa_kids(&engine.realm_jwks(&realm).unwrap());
    assert_eq!(kids.len(), 1);
    assert!(!kids.contains(&old_kid));
    assert_eq!(rsa_retiring_blobs(&storage, &realm), 0);
    let refused = engine.initiate_logout(
        &realm,
        &RpLogoutRequest {
            id_token_hint: Some(before.id_token().to_string()),
            ..Default::default()
        },
    );
    assert!(
        matches!(refused, Err(IdentityError::InvalidToken)),
        "a hint signed by a revoked RSA key must be refused, got {refused:?}"
    );
}

/// Rotation never provisions RS256 for a realm no client asked it of.
#[test]
fn rotation_does_not_create_an_rsa_key() {
    let (_dir, engine, _clock, storage) = engine_with_clock(None);
    let realm = plain_realm(&engine);
    engine.rotate_realm_signing_key(&realm, 3_600).unwrap();
    assert!(rsa_kids(&engine.realm_jwks(&realm).unwrap()).is_empty());
    assert!(storage
        .get(&system_realm(), &rsa_key_storage_key(&realm))
        .unwrap()
        .is_none());
}

/// The RSA private key is sealed under the KEK like every other signing key.
#[test]
fn rsa_key_is_stored_enveloped_under_the_kek() {
    let (_dir, engine, _clock, storage) = engine_with_clock(Some([7u8; 32]));
    let realm = plain_realm(&engine);
    admin_register(&engine, &realm, Some("RS256")).unwrap();
    let raw = storage
        .get(&system_realm(), &rsa_key_storage_key(&realm))
        .unwrap()
        .expect("an RS256 registration provisions the key");
    assert!(
        raw.starts_with(b"HKEY"),
        "the RSA key must be HKEY-enveloped at rest"
    );
}

/// Deleting a realm deletes its RSA keys — active and retiring — like its
/// Ed25519 ones.
#[test]
fn realm_delete_removes_the_rsa_keys() {
    let (_dir, engine, _clock, storage) = engine_with_clock(None);
    let realm = plain_realm(&engine);
    admin_register(&engine, &realm, Some("RS256")).unwrap();
    engine.rotate_realm_signing_key(&realm, 3_600).unwrap();
    assert_eq!(rsa_retiring_blobs(&storage, &realm), 1);

    engine
        .update_realm(
            &realm,
            &hearth::identity::UpdateRealmRequest {
                status: Some(hearth::identity::RealmStatus::Archived),
                ..Default::default()
            },
        )
        .unwrap();
    engine.delete_realm(&realm).unwrap();
    assert!(storage
        .get(&system_realm(), &rsa_key_storage_key(&realm))
        .unwrap()
        .is_none());
    assert_eq!(rsa_retiring_blobs(&storage, &realm), 0);
}

/// Many clients selecting RS256 at once in a fresh realm must converge on ONE
/// key: every ID token any of them receives verifies against the single RSA
/// key the JWKS publishes. A losing candidate key that signed anything would
/// leave that token unverifiable.
#[tokio::test]
async fn concurrent_rs256_registrations_converge_on_one_rsa_key() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let identity = h.identity_arc();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let identity = Arc::clone(&identity);
            let realm = realm.clone();
            std::thread::spawn(move || {
                let client = admin_register(identity.as_ref(), &realm, Some("RS256")).unwrap();
                code_flow(identity.as_ref(), &realm, &client)
                    .id_token()
                    .to_string()
            })
        })
        .collect();
    let id_tokens: Vec<String> = handles.into_iter().map(|t| t.join().unwrap()).collect();

    let jwks = h.identity().realm_jwks(&realm).unwrap();
    assert_eq!(
        rsa_kids(&jwks).len(),
        1,
        "exactly one RSA key: {:?}",
        rsa_kids(&jwks)
    );
    let jwks = serde_json::to_value(jwks).unwrap();
    for token in &id_tokens {
        assert_eq!(
            header_alg(token),
            "RS256",
            "every client here registered RS256, so every ID token must be RS256"
        );
        let jwk = verify_against_jwks(token, &jwks);
        assert_eq!(
            jwk["kty"], "RSA",
            "each ID token must verify against the single published RSA key"
        );
    }
}

// ── FAPI 2.0: RS256 is not an allowed algorithm ───────────────────────────────
//
// FAPI 2.0 Security Profile §5.4.1 lets authorization servers, clients and
// resource servers use only PS256, ES256 and EdDSA (Ed25519). RS256
// (RSASSA-PKCS1-v1_5) is not among them, so wherever FAPI applies — a client
// registered with the FAPI 2.0 profile, or any client of a realm with a
// `fapi_profile` — Hearth must neither accept RS256 nor default to it.

/// A JWKS a FAPI 2.0 client must register for `private_key_jwt`.
fn fapi_client_jwks() -> String {
    // A complete public JWK: registration validates the set (the key is never
    // used to verify anything here).
    r#"{"keys":[{"kty":"OKP","use":"sig","alg":"EdDSA","crv":"Ed25519","kid":"fapi2-rp","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#
        .to_string()
}

fn register_fapi2_client(
    engine: &dyn IdentityEngine,
    realm: &RealmId,
    alg: Option<&str>,
) -> Result<hearth::identity::OAuthClient, IdentityError> {
    engine.register_client(
        realm,
        &RegisterClientRequest {
            client_name: "FAPI 2.0 RP".to_string(),
            redirect_uris: vec![REDIRECT_URI.to_string()],
            grant_types: vec!["authorization_code".to_string()],
            jwks: Some(fapi_client_jwks()),
            profile: ClientProfile::Fapi2,
            id_token_signed_response_alg: alg.map(str::to_string),
            ..Default::default()
        },
    )
}

fn fapi_realm(engine: &dyn IdentityEngine, dcr_policy: Option<DcrPolicy>) -> (RealmId, String) {
    let name = format!("rs256-fapi-{}", uuid::Uuid::new_v4());
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: Some(RealmConfig {
                fapi_profile: Some(FapiProfile::Baseline),
                dcr_policy,
                ..Default::default()
            }),
        })
        .unwrap();
    (realm.id().clone(), name)
}

fn is_rs256_fapi_refusal(result: &Result<impl std::fmt::Debug, IdentityError>) -> bool {
    matches!(result, Err(IdentityError::FapiViolation { reason }) if reason.contains("RS256"))
}

/// Registration refuses RS256 for a FAPI 2.0 client and for any client of a
/// FAPI realm — and, refused, provisions no RSA key. Omitting the parameter on
/// these administrative paths still yields EdDSA.
#[tokio::test]
async fn fapi_clients_and_fapi_realms_cannot_register_rs256() {
    let h = common::TestHarness::embedded().await.unwrap();

    let realm = h.create_realm();
    let refused = register_fapi2_client(h.identity(), &realm, Some("RS256"));
    assert!(
        is_rs256_fapi_refusal(&refused),
        "a FAPI 2.0 client must not register RS256, got {refused:?}"
    );
    let fapi_client = register_fapi2_client(h.identity(), &realm, None)
        .expect("a FAPI 2.0 client registers without the parameter");
    assert_eq!(
        fapi_client.id_token_signed_response_alg(),
        IdTokenSigningAlg::EdDsa
    );

    let (fapi_realm, _) = fapi_realm(h.identity(), None);
    let refused = admin_register(h.identity(), &fapi_realm, Some("RS256"));
    assert!(
        is_rs256_fapi_refusal(&refused),
        "no client of a FAPI realm may register RS256, got {refused:?}"
    );

    for realm in [&realm, &fapi_realm] {
        assert!(
            rsa_kids(&h.identity().realm_jwks(realm).unwrap()).is_empty(),
            "a refused RS256 registration must not provision an RSA key"
        );
    }
}

/// Dynamic registration in a FAPI realm: the OIDC Registration default
/// (RS256) is one FAPI 2.0 forbids, so an omitted parameter resolves to EdDSA
/// there, and an explicit RS256 is `invalid_client_metadata` on both endpoints.
#[tokio::test]
async fn dynamic_registration_in_a_fapi_realm_defaults_to_eddsa_and_refuses_rs256() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (id, name) = fapi_realm(h.identity(), Some(DcrPolicy::Open));
    let realm = DcrRealm {
        state: Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())),
        name,
        id,
    };

    for global in [false, true] {
        let body = registration(serde_json::json!({}));
        let (status, resp) = if global {
            global_register(&realm, body).await
        } else {
            realm_register(&realm, body).await
        };
        assert_eq!(status, StatusCode::CREATED, "global={global}: {resp}");
        assert_eq!(
            resp["id_token_signed_response_alg"], "EdDSA",
            "global={global}: a FAPI realm must not default to RS256"
        );

        let body = registration(serde_json::json!({ "id_token_signed_response_alg": "RS256" }));
        let (status, resp) = if global {
            global_register(&realm, body).await
        } else {
            realm_register(&realm, body).await
        };
        assert_eq!(status, StatusCode::BAD_REQUEST, "global={global}: {resp}");
        assert_eq!(resp["error"], "invalid_client_metadata", "global={global}");
    }
    assert!(rsa_kids(&h.identity().realm_jwks(&realm.id).unwrap()).is_empty());
}

/// An update may not produce an RS256 client under FAPI either way round:
/// selecting RS256 for a FAPI 2.0 client, or moving an RS256 client to the
/// FAPI 2.0 profile. Both refusals leave the client unchanged.
#[tokio::test]
async fn an_update_cannot_combine_rs256_with_fapi() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();

    let fapi_client = register_fapi2_client(h.identity(), &realm, None)
        .unwrap()
        .client_id()
        .clone();
    let refused = h.identity().update_client(
        &realm,
        &fapi_client,
        &UpdateClientRequest {
            id_token_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        },
    );
    assert!(
        is_rs256_fapi_refusal(&refused),
        "a FAPI 2.0 client must not switch to RS256, got {refused:?}"
    );
    assert_eq!(
        h.identity()
            .get_client(&realm, &fapi_client)
            .unwrap()
            .unwrap()
            .id_token_signed_response_alg(),
        IdTokenSigningAlg::EdDsa
    );

    let rs_client = admin_register(h.identity(), &realm, Some("RS256")).unwrap();
    let refused = h.identity().update_client(
        &realm,
        &rs_client,
        &UpdateClientRequest {
            profile: Some(ClientProfile::Fapi2),
            // Keys, so the only thing wrong with the move is RS256 (a FAPI 2.0
            // client without keys is refused on its own account).
            jwks: Some(Some(fapi_client_jwks())),
            ..Default::default()
        },
    );
    assert!(
        is_rs256_fapi_refusal(&refused),
        "an RS256 client must not move to the FAPI 2.0 profile, got {refused:?}"
    );
    assert_eq!(
        h.identity()
            .get_client(&realm, &rs_client)
            .unwrap()
            .unwrap()
            .profile(),
        ClientProfile::Standard
    );
}

/// A realm that turns FAPI on after an RS256 client registered must stop
/// signing that client's ID tokens with RS256: the grant is refused rather
/// than answered with a token FAPI 2.0 forbids.
#[test]
fn enabling_fapi_on_a_realm_stops_rs256_id_token_issuance() {
    let (_dir, engine, _clock, _storage) = engine_with_clock(None);
    let realm = plain_realm(&engine);
    let client = admin_register(&engine, &realm, Some("RS256")).unwrap();
    assert_eq!(
        header_alg(code_flow(&engine, &realm, &client).id_token()),
        "RS256",
        "precondition: before FAPI the client receives RS256 ID tokens"
    );

    engine
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    fapi_profile: Some(FapiProfile::Baseline),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();

    // A grant that satisfies FAPI 2.0 Baseline — PAR, PKCE S256 and a DPoP
    // binding — so the only thing left to refuse is the RS256 ID token.
    let user = new_user(&engine, &realm);
    let challenge = URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref());
    let code = engine
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user,
                code_challenge: Some(challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("n-fapi".to_string()),
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: true,
            },
        )
        .expect("a PAR + PKCE request satisfies FAPI 2.0 Baseline")
        .code()
        .to_string();
    let refused = engine.exchange_authorization_code(
        &realm,
        &TokenExchangeRequest {
            client_id: client,
            code,
            redirect_uri: REDIRECT_URI.to_string(),
            code_verifier: Some(PKCE_VERIFIER.to_string()),
            dpop_jkt: Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".to_string()),
            client_assertion_type: None,
            client_assertion: None,
        },
    );
    assert!(
        is_rs256_fapi_refusal(&refused),
        "a FAPI realm must not issue an RS256 ID token, got {refused:?}"
    );
}
