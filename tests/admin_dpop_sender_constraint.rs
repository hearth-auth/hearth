#![allow(clippy::unwrap_used)]
//! Task 18.18 (audit 2026-08-28 §4.19#8) — the DPoP sender-constraint
//! (RFC 9449 §7.2) MUST be enforced on the administrative surface.
//!
//! `extract_admin_auth`, SCIM's `authenticate` and the gRPC `authenticate_admin`
//! all validated the bearer token's signature, realm and permissions and never
//! looked at `cnf`. A DPoP-bound admin token — one whose holder proved
//! possession of a private key at issuance — was therefore replayable as a
//! plain `Bearer` for every admin read and write, which is precisely the attack
//! the binding exists to stop. The resource endpoints under `/oauth` have
//! enforced it since HEA-2031 through `enforce_dpop_binding`; the admin surface
//! simply never called it.
//!
//! Regression contract:
//!   * `/admin/*` — bound token, no proof → 401 `invalid_token` naming DPoP;
//!     bound token **with** a valid proof → passes the layer (the fix is not a
//!     blanket reject); an unbound admin token is untouched.
//!   * `/scim/v2/*` — same rejection.
//!   * gRPC admin — a bound token is refused with `UNAUTHENTICATED`, because
//!     that transport has no proof channel to validate against.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, RegisterClientRequest,
    SessionContext, TokenExchangeRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";

// ── DPoP key + proof helpers (mirrors tests/dpop.rs) ────────────────────────

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

/// Builds a resource-server DPoP proof including the `ath` claim required by
/// RFC 9449 §4.2.
#[allow(clippy::similar_names)]
fn make_resource_dpop_proof(key: &DPopKey, htm: &str, htu: &str, access_token: &str) -> String {
    let jwk = key.public_jwk_json();
    let header = serde_json::json!({"alg": "ES256", "jwk": jwk, "typ": "dpop+jwt"});
    #[allow(clippy::cast_possible_wrap)]
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

// ── Fixture ─────────────────────────────────────────────────────────────────

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
    /// A DPoP-bound access token (`cnf.jkt` present).
    bound_token: String,
    /// An ordinary, unbound admin token — must keep working.
    unbound_admin_token: String,
    dpop_key: DPopKey,
    issuer: String,
}

async fn setup() -> Fixture {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness.create_realm();
    harness.rbac().seed_realm(&realm).expect("seed realm");

    let user = create_user(&harness, &realm, "bound");
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "admin-dpop-client".to_string(),
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
    let bound_token = mint_bound_token(&harness, &realm, user.id(), client.client_id(), &jkt);

    // Precondition: without a real cnf.jkt the negative tests pass vacuously.
    let claims = decode_claims_json(&bound_token);
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(jkt.as_str()),
        "fixture must mint a DPoP-bound access token; got claims: {claims}"
    );

    let unbound_admin_token = mint_admin_token(&harness, &realm);
    assert!(
        decode_claims_json(&unbound_admin_token)
            .get("cnf")
            .is_none(),
        "the control token must NOT be sender-constrained"
    );

    let issuer = harness.identity().oidc_discovery().issuer;

    Fixture {
        harness,
        realm,
        bound_token,
        unbound_admin_token,
        dpop_key,
        issuer,
    }
}

fn create_user(h: &common::TestHarness, realm: &RealmId, label: &str) -> hearth::identity::User {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("{label}-{}@admin-dpop.test", uuid::Uuid::new_v4()),
                display_name: "DPoP Subject".to_string(),
                first_name: "DPoP".to_string(),
                last_name: "Subject".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("create user")
}

fn mint_bound_token(
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

/// An ordinary session-issued token for a user holding the seeded
/// `hearth.admin` role — the control that proves the new layer does not break
/// unbound admin auth.
fn mint_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    use hearth::rbac::{AssignRoleRequest, Scope, Subject};

    let user = create_user(h, realm, "admin");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
        .expect("seeded realm.admin role");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
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

/// Asserts the response is the DPoP layer's rejection, not an unrelated 401.
async fn assert_dpop_rejected(resp: axum::response::Response, what: &str) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{what}: a cnf-bound token replayed as a plain Bearer must be 401; body {json}"
    );
    assert!(
        json["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("DPoP")),
        "{what}: the rejection must name the DPoP requirement, proving it came from \
         sender-constraint enforcement rather than an unrelated auth failure; got {json}"
    );
}

fn get(uri: &str, token: &str, realm: &RealmId, proof: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", realm.as_uuid().to_string());
    if let Some(proof) = proof {
        builder = builder.header("dpop", proof);
    }
    builder.body(Body::empty()).unwrap()
}

// ── /admin ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_rejects_bound_token_replayed_as_plain_bearer() {
    let f = setup().await;
    let resp = app(&f)
        .oneshot(get("/admin/users", &f.bound_token, &f.realm, None))
        .await
        .unwrap();
    assert_dpop_rejected(resp, "GET /admin/users").await;
}

#[tokio::test]
async fn admin_accepts_bound_token_with_a_valid_proof() {
    let f = setup().await;
    let htu = format!("{}/admin/users", f.issuer);
    let proof = make_resource_dpop_proof(&f.dpop_key, "GET", &htu, &f.bound_token);
    let resp = app(&f)
        .oneshot(get("/admin/users", &f.bound_token, &f.realm, Some(&proof)))
        .await
        .unwrap();

    // The subject is not an admin, so the handler answers 403 — which is the
    // point: the request got *past* the sender-constraint layer. A blanket
    // reject would have produced the 401 the previous test asserts.
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a bound token presented with a valid DPoP proof must not be rejected \
         by the sender-constraint layer"
    );
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the proof was accepted, so the outcome must come from the permission gate"
    );
}

#[tokio::test]
async fn admin_still_accepts_an_unbound_admin_token() {
    let f = setup().await;
    let resp = app(&f)
        .oneshot(get("/admin/users", &f.unbound_admin_token, &f.realm, None))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a token with no cnf claim carries no sender-constraint; the layer must \
         leave it alone"
    );
}

// ── SCIM ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scim_rejects_bound_token_replayed_as_plain_bearer() {
    let f = setup().await;
    let resp = app(&f)
        .oneshot(get("/scim/v2/Users", &f.bound_token, &f.realm, None))
        .await
        .unwrap();
    assert_dpop_rejected(resp, "GET /scim/v2/Users").await;
}

// ── gRPC admin ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_admin_refuses_a_sender_constrained_token() {
    use hearth::protocol::grpc::auth::authenticate_admin;

    let f = setup().await;
    let state = GrpcState::new(
        f.harness.identity_arc(),
        f.harness.rbac_arc(),
        f.harness.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );

    let mut md = tonic::metadata::MetadataMap::new();
    md.insert(
        "authorization",
        format!("Bearer {}", f.bound_token).parse().unwrap(),
    );
    md.insert("x-realm-id", f.realm.as_uuid().to_string().parse().unwrap());

    let err = authenticate_admin(&md, &state)
        .expect_err("a cnf-bound token must not authenticate on the gRPC admin API");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "gRPC has no DPoP proof channel, so a sender-constrained token must be \
         refused rather than accepted unbound; got {err:?}"
    );

    // Control: the same call with an unbound admin token authenticates, so the
    // refusal is the cnf check and not a broken fixture.
    let mut ok_md = tonic::metadata::MetadataMap::new();
    ok_md.insert(
        "authorization",
        format!("Bearer {}", f.unbound_admin_token).parse().unwrap(),
    );
    ok_md.insert("x-realm-id", f.realm.as_uuid().to_string().parse().unwrap());
    authenticate_admin(&ok_md, &state).expect("an unbound admin token must still authenticate");
}

// ── Task 25.17 — the admin surface outside the `/admin` and `/scim/v2` nests ──
//
// 18.18 mounted `enforce_admin_dpop` with `route_layer` on exactly two routers:
// the `/admin` nest and the `/scim/v2` nest. Every *other* handler that
// authenticates through `extract_admin_auth` was left behind, and there are
// five files' worth of them merged at the router root rather than nested:
// `users.rs` (`POST /users`), `oauth.rs` (`POST /clients`), `agents.rs`,
// `approval.rs` and `advanced.rs`. A stolen `cnf`-bound admin token was still
// replayable as a plain `Bearer` against all of them — the same defect 18.18
// closed one nest at a time.
//
// `tool_invocation.rs` is deliberately NOT in this list. It reaches the same
// token through `extract_bearer_token` and already calls `validate_dpop_if_bound`
// itself, so layering the guard over it would validate the proof twice and the
// second call would burn the first's `jti` in the replay cache — turning a
// correct request into a false `invalid_token`.

/// Every route outside the two nests whose handler calls `extract_admin_auth`,
/// as `(method, uri, body)`.
const NON_NESTED_ADMIN_ROUTES: &[(&str, &str)] = &[
    ("POST", "/users"),
    ("POST", "/clients"),
    ("GET", "/v1/agents"),
    ("GET", "/v1/approval-requests"),
    ("POST", "/v1/aats"),
];

/// Builds the router with the three agent capabilities on, so the `agents.rs`,
/// `approval.rs` and `advanced.rs` routers are actually registered. With the
/// defaults they are absent from the table and every assertion below would
/// measure a 404 instead of the guard.
fn app_with_agent_capabilities(f: &Fixture) -> axum::Router {
    router(Arc::new(
        AppState::new(
            f.harness.identity_arc(),
            f.harness.rbac_arc(),
            f.harness.audit_arc(),
        )
        .with_agent_identity(true)
        .with_agent_approval(true)
        .with_agent_advanced(true),
    ))
}

fn admin_req(
    method: &str,
    uri: &str,
    token: &str,
    realm: &RealmId,
    proof: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("x-realm-id", realm.as_uuid().to_string());
    if let Some(proof) = proof {
        builder = builder.header("dpop", proof);
    }
    builder.body(Body::from("{}")).unwrap()
}

/// Asserts the response is *not* the DPoP layer's rejection.
///
/// Deliberately weaker than asserting a specific success status: these handlers
/// answer 403 (no permission) or 422 (empty body) once past the layer, and the
/// only thing under test is that the sender-constraint guard let the request
/// through.
async fn assert_not_dpop_rejected(resp: axum::response::Response, what: &str) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let dpop_rejection = status == StatusCode::UNAUTHORIZED
        && json["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("DPoP"));
    assert!(
        !dpop_rejection,
        "{what}: the sender-constraint layer must not reject this request; got {status} {json}"
    );
}

#[tokio::test]
async fn non_nested_admin_routes_reject_a_bound_token_replayed_as_plain_bearer() {
    let f = setup().await;
    for (method, uri) in NON_NESTED_ADMIN_ROUTES {
        let resp = app_with_agent_capabilities(&f)
            .oneshot(admin_req(method, uri, &f.bound_token, &f.realm, None))
            .await
            .unwrap();
        assert_dpop_rejected(resp, &format!("{method} {uri}")).await;
    }
}

#[tokio::test]
async fn non_nested_admin_routes_accept_a_bound_token_with_a_valid_proof() {
    let f = setup().await;
    for (method, uri) in NON_NESTED_ADMIN_ROUTES {
        let htu = format!("{}{uri}", f.issuer);
        let proof = make_resource_dpop_proof(&f.dpop_key, method, &htu, &f.bound_token);
        let resp = app_with_agent_capabilities(&f)
            .oneshot(admin_req(
                method,
                uri,
                &f.bound_token,
                &f.realm,
                Some(&proof),
            ))
            .await
            .unwrap();
        assert_not_dpop_rejected(resp, &format!("{method} {uri} with a valid proof")).await;
    }
}

#[tokio::test]
async fn non_nested_admin_routes_still_accept_an_unbound_admin_token() {
    let f = setup().await;
    for (method, uri) in NON_NESTED_ADMIN_ROUTES {
        let resp = app_with_agent_capabilities(&f)
            .oneshot(admin_req(
                method,
                uri,
                &f.unbound_admin_token,
                &f.realm,
                None,
            ))
            .await
            .unwrap();
        assert_not_dpop_rejected(resp, &format!("{method} {uri} with an unbound token")).await;
    }
}
