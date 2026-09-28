#![allow(clippy::unwrap_used)]
//! Task 26.43 — token introspection accepts CONFIDENTIAL clients only.
//!
//! `client_id` values are public by construction: they travel in every browser
//! authorization request and dynamic registration hands them out. Before this
//! change `/introspect` authenticated a public client on `client_id` alone, so
//! anyone who had read a client identifier off a login URL could ask the
//! server about any user-session token — RFC 7662 §4 calls the endpoint a
//! token-information oracle for exactly this reason, and §2.1 requires it to
//! demand authorization. A public client is now refused with
//! `401 invalid_client` (RFC 6749 §5.2) on the header-form route, the
//! realm-scoped twin and the gRPC `Introspect` RPC.
//!
//! A `private_key_jwt` client has no stored secret either, so the old code
//! treated it as public and let its `client_id` alone through. It is
//! confidential, so it now authenticates at `/introspect` the way it does at
//! `/token`: with a signed `client_assertion` (RFC 7523 §2.2).
//!
//! `/revoke` keeps accepting public clients: RFC 7009 §2.1 lets a public
//! client revoke the tokens issued to it, and the regression guard below keeps
//! that working. That a client can revoke ONLY its own tokens is covered by
//! `tests/revoke_client_ownership.rs`.

mod common;

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest, CreateUserRequest,
    RegisterClientRequest, SessionContext, SigningKey, TokenIntrospectionRequest,
    TokenIssuanceContext, UpdateClientRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use tonic::{Code, Request as TonicRequest};

const SECRET: &str = "introspect-confidential-secret-1!";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

struct Env {
    h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
}

async fn server_env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("introspect-conf-{}", uuid::Uuid::new_v4());
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    Env {
        h,
        base,
        realm_name,
        realm_id,
    }
}

/// Registers a client — confidential when `secret` is `Some`, public otherwise.
fn register(h: &common::TestHarness, realm: &RealmId, secret: Option<&str>) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("client-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "client_credentials".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                // A declared resource server: since GA audit L11 only such a
                // client (or the token's own client) may introspect a
                // user-session token that carries no `azp`.
                access_token_authorization:
                    hearth::identity::AccessTokenAuthorization::Introspection,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

/// Mints an ordinary user-session access token — the `azp`-absent,
/// `sid != "none"` shape the audience gate lets a declared resource server
/// read (GA audit L11).
fn user_session_token(h: &common::TestHarness, realm: &RealmId) -> (String, String) {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("victim-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Victim".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = h
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens");
    (
        pair.access_token().to_string(),
        user.id().as_uuid().to_string(),
    )
}

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

/// POSTs to the header-form `/introspect`.
async fn introspect_header_form(
    env: &Env,
    body: serde_json::Value,
    authorization: Option<String>,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(format!("{}/introspect", env.base))
        .header("X-Realm-ID", env.realm_id.as_uuid().to_string())
        .json(&body);
    if let Some(a) = authorization {
        req = req.header("Authorization", a);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// POSTs to the realm-scoped `/realms/{realm}/introspect`.
async fn introspect_realm_form(env: &Env, body: serde_json::Value) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{}/realms/{}/introspect", env.base, env.realm_name))
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn assert_invalid_client(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(status, 401, "{what}: expected 401, got {status} {body}");
    assert_eq!(
        body["error"], "invalid_client",
        "{what}: RFC 6749 §5.2 requires error=invalid_client, got {body}"
    );
    assert!(
        body.get("sub").is_none() && body.get("active").is_none(),
        "{what}: a refused caller must learn nothing about the token, got {body}"
    );
}

// ===== Public clients are refused =====

#[tokio::test]
async fn header_form_introspect_refuses_a_public_client() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let (token, _) = user_session_token(&env.h, &env.realm_id);

    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token, "client_id": public.as_uuid().to_string() }),
        None,
    )
    .await;
    assert_invalid_client(status, &body, "public client_id alone on /introspect");
}

#[tokio::test]
async fn realm_introspect_refuses_a_public_client() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let (token, _) = user_session_token(&env.h, &env.realm_id);

    let (status, body) = introspect_realm_form(
        &env,
        serde_json::json!({ "token": token, "client_id": public.as_uuid().to_string() }),
    )
    .await;
    assert_invalid_client(
        status,
        &body,
        "public client_id alone on /realms/{realm}/introspect",
    );
}

/// A public client that tacks on an arbitrary secret is still public: the
/// secret authenticates nothing, because there is nothing stored to match.
#[tokio::test]
async fn introspect_refuses_a_public_client_presenting_a_made_up_secret() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let (token, _) = user_session_token(&env.h, &env.realm_id);
    let id = public.as_uuid().to_string();

    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token, "client_id": id, "client_secret": "anything" }),
        None,
    )
    .await;
    assert_invalid_client(status, &body, "public client + body secret");

    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token }),
        Some(basic(&id, "anything")),
    )
    .await;
    assert_invalid_client(status, &body, "public client + Basic secret");
}

// ===== Confidential clients =====

#[tokio::test]
async fn introspect_refuses_a_confidential_client_with_a_wrong_secret() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let (token, _) = user_session_token(&env.h, &env.realm_id);
    let id = conf.as_uuid().to_string();

    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token, "client_id": id, "client_secret": "wrong-secret" }),
        None,
    )
    .await;
    assert_invalid_client(status, &body, "confidential + wrong body secret");

    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token }),
        Some(basic(&id, "nope")),
    )
    .await;
    assert_invalid_client(status, &body, "confidential + wrong Basic secret");

    let (status, body) =
        introspect_realm_form(&env, serde_json::json!({ "token": token, "client_id": id })).await;
    assert_invalid_client(status, &body, "confidential + no secret");
}

#[tokio::test]
async fn introspect_serves_a_confidential_client_with_its_secret() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let (token, user_id) = user_session_token(&env.h, &env.realm_id);
    let id = conf.as_uuid().to_string();

    // client_secret_post
    let (status, body) = introspect_header_form(
        &env,
        serde_json::json!({ "token": token, "client_id": id, "client_secret": SECRET }),
        None,
    )
    .await;
    assert_eq!(status, 200, "client_secret_post must be served, got {body}");
    assert_eq!(body["active"], true, "got {body}");
    assert!(
        body["sub"].as_str().is_some_and(|s| s.contains(&user_id)),
        "an authenticated resource server gets the subject, got {body}"
    );

    // client_secret_basic, realm-scoped route
    let resp = reqwest::Client::new()
        .post(format!("{}/realms/{}/introspect", env.base, env.realm_name))
        .header("Authorization", basic(&id, SECRET))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["active"], true,
        "client_secret_basic must be served, got {body}"
    );
}

// ===== private_key_jwt =====

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("secs")
}

/// Signs a `private_key_jwt` assertion. `iss`/`sub` carry the typed
/// `client_<uuid>` form, as at the token endpoint.
fn assertion(key: &SigningKey, client_id: &ClientId, audience: &str) -> String {
    let now = now_secs();
    key.issue_assertion_jwt(&JwtAssertionClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: Audience::single(audience.to_string()),
        exp: now + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: Some(now),
    })
    .expect("sign assertion")
}

/// Registers a secretless client that authenticates with `private_key_jwt`.
fn register_pkjwt(h: &common::TestHarness, realm: &RealmId) -> (ClientId, SigningKey) {
    let key = SigningKey::generate().expect("key");
    let client_id = register(h, realm, None);
    h.identity()
        .update_client(
            realm,
            &client_id,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("install assertion key");
    (client_id, key)
}

#[tokio::test]
async fn introspect_refuses_a_private_key_jwt_client_without_its_assertion() {
    let env = server_env().await;
    let (client_id, _key) = register_pkjwt(&env.h, &env.realm_id);
    let (token, _) = user_session_token(&env.h, &env.realm_id);

    let (status, body) = introspect_realm_form(
        &env,
        serde_json::json!({ "token": token, "client_id": client_id.as_uuid().to_string() }),
    )
    .await;
    assert_invalid_client(status, &body, "private_key_jwt client_id alone");
}

#[tokio::test]
async fn introspect_serves_a_private_key_jwt_client_with_a_valid_assertion() {
    let env = server_env().await;
    let (client_id, key) = register_pkjwt(&env.h, &env.realm_id);
    let (token, _) = user_session_token(&env.h, &env.realm_id);
    let id = client_id.as_uuid().to_string();
    let issuer = env.h.identity().oidc_discovery().issuer;
    let aud = format!("{issuer}/realms/{}", env.realm_name);

    let (status, body) = introspect_realm_form(
        &env,
        serde_json::json!({
            "token": token,
            "client_id": id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&key, &client_id, &aud),
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "a valid assertion must authenticate, got {body}"
    );
    assert_eq!(body["active"], true, "got {body}");

    // An assertion signed by some other key is refused.
    let stranger = SigningKey::generate().expect("key");
    let (status, body) = introspect_realm_form(
        &env,
        serde_json::json!({
            "token": token,
            "client_id": id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&stranger, &client_id, &aud),
        }),
    )
    .await;
    assert_invalid_client(status, &body, "assertion signed by the wrong key");
}

/// RFC 6749 §2.3: a client MUST NOT use more than one authentication method
/// in a request, so an assertion alongside a secret is refused — with
/// `invalid_request`, the code §5.2 assigns to that case.
#[tokio::test]
async fn introspect_refuses_an_assertion_combined_with_a_secret() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let key = SigningKey::generate().expect("key");
    let id = conf.as_uuid().to_string();
    env.h
        .identity()
        .update_client(
            &env.realm_id,
            &conf,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("install assertion key");
    let (token, _) = user_session_token(&env.h, &env.realm_id);
    let issuer = env.h.identity().oidc_discovery().issuer;
    let aud = format!("{issuer}/realms/{}", env.realm_name);

    let (status, body) = introspect_realm_form(
        &env,
        serde_json::json!({
            "token": token,
            "client_id": id,
            "client_secret": SECRET,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&key, &conf, &aud),
        }),
    )
    .await;
    assert_eq!(status, 400, "assertion + secret together, got {body}");
    assert_eq!(body["error"], "invalid_request", "got {body}");
    assert!(body.get("active").is_none(), "got {body}");
}

// ===== Revocation keeps accepting public clients (RFC 7009 §2.1) =====

#[tokio::test]
async fn revoke_still_accepts_a_public_client() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    // A token issued TO the public client: RFC 7009 §2.1 lets a client revoke
    // only its own tokens (tests/revoke_client_ownership.rs).
    let user = env
        .h
        .identity()
        .create_user(
            &env.realm_id,
            &CreateUserRequest {
                email: format!("owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = env
        .h
        .identity()
        .create_session(&env.realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let token = env
        .h
        .identity()
        .issue_tokens_with_context(
            &env.realm_id,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(public.clone()),
                ..TokenIssuanceContext::default()
            },
        )
        .expect("issue tokens")
        .access_token()
        .to_string();

    let resp = reqwest::Client::new()
        .post(format!("{}/realms/{}/revoke", env.base, env.realm_name))
        .json(&serde_json::json!({
            "token": token,
            "client_id": public.as_uuid().to_string(),
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "RFC 7009 §2.1 lets a public client revoke; this change must not break it"
    );
    let still = env
        .h
        .identity()
        .introspect_token(
            &env.realm_id,
            &TokenIntrospectionRequest {
                token,
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect");
    assert!(
        !still.active,
        "the public client's own token must actually be revoked"
    );
}

// ===== Discovery =====

#[tokio::test]
async fn discovery_does_not_advertise_none_for_introspection() {
    let env = server_env().await;
    for url in [
        format!("{}/.well-known/openid-configuration", env.base),
        format!(
            "{}/realms/{}/.well-known/openid-configuration",
            env.base, env.realm_name
        ),
    ] {
        let doc: serde_json::Value = reqwest::get(&url)
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        let methods: Vec<&str> = doc["introspection_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap_or_else(|| panic!("{url}: introspection auth methods must be advertised"))
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(!methods.contains(&"none"), "{url}: got {methods:?}");
        for m in [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ] {
            assert!(methods.contains(&m), "{url}: {m} missing from {methods:?}");
        }
        let revocation: Vec<&str> = doc["revocation_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap_or_else(|| panic!("{url}: revocation auth methods must be advertised"))
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(
            revocation.contains(&"none"),
            "{url}: RFC 7009 public-client revocation stays advertised, got {revocation:?}"
        );
    }
}

// ===== gRPC Introspect =====

fn grpc_state(h: &common::TestHarness) -> GrpcState {
    GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    )
}

fn grpc_introspect_request(
    realm: &RealmId,
    token: &str,
    client: &ClientId,
    secret: Option<&str>,
) -> TonicRequest<id_pb::TokenIntrospectionRequest> {
    let mut r = TonicRequest::new(id_pb::TokenIntrospectionRequest {
        token: token.to_string(),
        token_type_hint: None,
    });
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r.metadata_mut().insert(
        "x-hearth-client-id",
        client.as_uuid().to_string().parse().expect("client meta"),
    );
    if let Some(s) = secret {
        r.metadata_mut()
            .insert("x-hearth-client-secret", s.parse().expect("secret meta"));
    }
    r
}

#[tokio::test]
async fn grpc_introspect_refuses_a_public_client() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let public = register(&h, &realm, None);
    let (token, _) = user_session_token(&h, &realm);
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .introspect(grpc_introspect_request(&realm, &token, &public, None))
        .await
        .expect_err("a public client must not introspect over gRPC");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = svc
        .introspect(grpc_introspect_request(
            &realm,
            &token,
            &public,
            Some("made-up"),
        ))
        .await
        .expect_err("a made-up secret does not make a public client confidential");
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn grpc_introspect_serves_a_confidential_client_and_applies_the_audience_gate() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let a = register(&h, &realm, Some(SECRET));
    let b = register(&h, &realm, Some(SECRET));
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .introspect(grpc_introspect_request(&realm, "x", &a, Some("wrong")))
        .await
        .expect_err("a wrong secret must be refused");
    assert_eq!(err.code(), Code::Unauthenticated);

    let (user_token, _) = user_session_token(&h, &realm);
    let ok = svc
        .introspect(grpc_introspect_request(
            &realm,
            &user_token,
            &a,
            Some(SECRET),
        ))
        .await
        .expect("confidential client with its secret")
        .into_inner();
    assert!(ok.active, "an authenticated confidential client is served");

    // Client A's machine token must not be readable by client B: the gRPC
    // path used to pass no introspecting client, which skipped the RFC 7662
    // audience restriction the HTTP routes apply.
    let a_token = h
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: a.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: None,
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint A's token")
        .access_token()
        .to_string();
    let by_b = svc
        .introspect(grpc_introspect_request(&realm, &a_token, &b, Some(SECRET)))
        .await
        .expect("B authenticates")
        .into_inner();
    assert!(
        !by_b.active,
        "client B must not read client A's machine token over gRPC"
    );
    let by_a = svc
        .introspect(grpc_introspect_request(&realm, &a_token, &a, Some(SECRET)))
        .await
        .expect("A authenticates")
        .into_inner();
    assert!(by_a.active, "the owning client reads its own token");
}
