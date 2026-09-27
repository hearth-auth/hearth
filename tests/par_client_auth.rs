#![allow(clippy::unwrap_used)]
//! Pushed Authorization Requests authenticate the client (RFC 9126 §2).
//!
//! RFC 9126 §2: "The client MUST authenticate itself using the same method it
//! uses at the token endpoint" when it is confidential; a public client
//! identifies itself with `client_id` alone. `POST /as/par` and its realm twin
//! used to read `client_id` from the body and push the request with no client
//! authentication at all, so anyone could push scopes, a `resource`, a choice
//! among the registered redirect URIs, a request object and a `prompt` in the
//! name of a confidential client — and FAPI 2.0 makes PAR, with client
//! authentication, the only way into `/authorize`.
//!
//! Pinned here, on both routes:
//! - a confidential client with no credentials, a wrong secret, or a
//!   `private_key_jwt` client with no (or a foreign) assertion gets
//!   `401 invalid_client` (RFC 6749 §5.2) with `WWW-Authenticate: Basic`;
//! - `client_secret_basic` (with or without a body `client_id`),
//!   `client_secret_post` and `private_key_jwt` push successfully (`201`);
//! - a public client pushes on `client_id` alone, and presenting a secret it
//!   cannot hold is refused rather than ignored;
//! - the authenticated client must be the one the body and the request object
//!   name; combining an assertion with a secret is `400 invalid_request`;
//! - a FAPI 2.0 client (assertion key, no secret) cannot push on its
//!   `client_id` alone, and a confidential client in a FAPI realm must
//!   authenticate;
//! - an Argon2id secret whose verification the saturated KDF gate sheds is
//!   `503` + `Retry-After`, as at the token endpoint.

mod common;

use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    ClientProfile, CreateRealmRequest, FapiProfile, KdfGateConfig, RegisterClientRequest,
    SigningKey, UpdateClientRequest, UpdateRealmRequest,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

const SECRET: &str = "par-client-auth-secret-0123456789!";
const REDIRECT_URI: &str = "https://app.example.com/cb";
/// S256 of the RFC 7636 Appendix B verifier.
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const JAR_KID: &str = "par-client-auth-jar";

struct Env {
    h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    /// The realm issuer — the `aud` of client assertions and request objects.
    issuer: String,
}

async fn server_env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("par-auth-{}", uuid::Uuid::new_v4());
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
        realm_name,
        realm_id,
        issuer,
    }
}

/// Switches the realm to a FAPI 2.0 profile.
fn set_fapi(env: &Env, profile: FapiProfile) {
    let realm = env
        .h
        .identity()
        .get_realm(&env.realm_id)
        .expect("get realm")
        .expect("realm exists");
    let mut config = realm.config().clone();
    config.fapi_profile = Some(profile);
    env.h
        .identity()
        .update_realm(
            &env.realm_id,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("set fapi profile");
}

fn register_with(env: &Env, req: RegisterClientRequest) -> ClientId {
    env.h
        .identity()
        .register_client(
            &env.realm_id,
            &RegisterClientRequest {
                client_name: format!("par-client-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                ..req
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

/// Registers a client — confidential when `secret` is `Some`, public otherwise.
fn register(env: &Env, secret: Option<&str>) -> ClientId {
    register_with(
        env,
        RegisterClientRequest {
            client_secret: secret.map(str::to_string),
            ..Default::default()
        },
    )
}

/// Installs a `private_key_jwt` assertion key on a client.
fn install_assertion_key(env: &Env, client: &ClientId) -> SigningKey {
    let key = SigningKey::generate().expect("key");
    env.h
        .identity()
        .update_client(
            &env.realm_id,
            client,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("install assertion key");
    key
}

/// A secretless client that authenticates with `private_key_jwt`.
fn register_pkjwt(env: &Env) -> (ClientId, SigningKey) {
    let client = register(env, None);
    let key = install_assertion_key(env, &client);
    (client, key)
}

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("secs")
}

/// Signs a `private_key_jwt` assertion naming `client` as `iss`/`sub`.
fn assertion(key: &SigningKey, client: &ClientId, audience: &str) -> String {
    let now = now_secs();
    key.issue_assertion_jwt(&JwtAssertionClaims {
        iss: client.to_string(),
        sub: client.to_string(),
        aud: Audience::single(audience.to_string()),
        exp: now + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: Some(now),
    })
    .expect("sign assertion")
}

/// An Ed25519 request-object signing key and its one-key JWKS.
struct JarKey {
    pkcs8: Vec<u8>,
    jwks: String,
}

fn jar_key() -> JarKey {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pair");
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    JarKey {
        pkcs8: pkcs8.as_ref().to_vec(),
        jwks: format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{JAR_KID}","x":"{x}"}}]}}"#
        ),
    }
}

/// Signs a request object (RFC 9101) with the given `iss` and `client_id`.
fn request_object(key: &JarKey, iss: &ClientId, client_id: &ClientId, aud: &str) -> String {
    let now = now_secs();
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": "EdDSA", "kid": JAR_KID}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": iss.to_string(),
            "aud": aud,
            "exp": now + 300,
            "iat": now,
            "jti": uuid::Uuid::new_v4().to_string(),
            "client_id": client_id.to_string(),
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "jar-state",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
        })
        .to_string(),
    );
    let signing_input = format!("{header}.{claims}");
    let sig = Ed25519KeyPair::from_pkcs8(&key.pkcs8)
        .expect("pair")
        .sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
}

fn basic(client: &ClientId, secret: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{secret}", client.as_uuid()))
    )
}

/// A valid pushed request body; `client_id` is omitted when `None`.
fn par_body(client: Option<&ClientId>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "par-state",
        "response_type": "code",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    });
    if let Some(c) = client {
        body["client_id"] = serde_json::json!(c.as_uuid().to_string());
    }
    body
}

/// Adds fields to a JSON body.
fn with(mut body: serde_json::Value, fields: &[(&str, &str)]) -> serde_json::Value {
    for (k, v) in fields {
        body[*k] = serde_json::json!(v);
    }
    body
}

#[derive(Clone, Copy, Debug)]
enum Route {
    /// `POST /as/par` with `X-Realm-ID`.
    Header,
    /// `POST /realms/{name}/as/par`.
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

struct Pushed {
    status: u16,
    body: serde_json::Value,
    www_authenticate: Option<String>,
    retry_after: bool,
}

/// POSTs a form-encoded pushed request (RFC 9126 §2.1).
async fn push(
    env: &Env,
    route: Route,
    body: &serde_json::Value,
    authorization: Option<String>,
) -> Pushed {
    let form: Vec<(String, String)> = body
        .as_object()
        .expect("object body")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("string field").to_string()))
        .collect();
    let url = match route {
        Route::Header => format!("{}/as/par", env.base),
        Route::Realm => format!("{}/realms/{}/as/par", env.base, env.realm_name),
    };
    let mut req = reqwest::Client::new().post(url).form(&form);
    if matches!(route, Route::Header) {
        req = req.header("X-Realm-ID", env.realm_id.as_uuid().to_string());
    }
    if let Some(a) = authorization {
        req = req.header("Authorization", a);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let www_authenticate = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let retry_after = resp.headers().contains_key("retry-after");
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    Pushed {
        status,
        body,
        www_authenticate,
        retry_after,
    }
}

fn assert_invalid_client(p: &Pushed, what: &str) {
    assert_eq!(
        p.status, 401,
        "{what}: expected 401 invalid_client, got {} {}",
        p.status, p.body
    );
    assert_eq!(
        p.body["error"], "invalid_client",
        "{what}: RFC 6749 §5.2 requires error=invalid_client, got {}",
        p.body
    );
    assert!(
        p.body.get("request_uri").is_none(),
        "{what}: a refused push must not mint a request_uri, got {}",
        p.body
    );
}

fn assert_pushed(p: &Pushed, what: &str) {
    assert_eq!(
        p.status, 201,
        "{what}: expected 201 Created, got {} {}",
        p.status, p.body
    );
    let uri = p.body["request_uri"].as_str().unwrap_or_default();
    assert!(
        uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "{what}: expected an RFC 9126 request_uri, got {}",
        p.body
    );
}

// ===== Confidential clients (client_secret_basic / client_secret_post) =====

#[tokio::test]
async fn confidential_client_without_credentials_is_refused() {
    let env = server_env().await;
    let client = register(&env, Some(SECRET));
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&client)), None).await;
        assert_invalid_client(&p, &format!("{route:?}: no credentials"));
        assert!(
            p.www_authenticate
                .as_deref()
                .is_some_and(|v| v.starts_with("Basic")),
            "{route:?}: a 401 invalid_client must carry WWW-Authenticate: Basic (RFC 6749 §5.2), \
             got {:?}",
            p.www_authenticate
        );
    }
}

#[tokio::test]
async fn confidential_client_with_a_wrong_secret_is_refused() {
    let env = server_env().await;
    let client = register(&env, Some(SECRET));
    for route in ROUTES {
        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, "not-the-secret")),
        )
        .await;
        assert_invalid_client(&p, &format!("{route:?}: wrong Basic secret"));

        let body = with(
            par_body(Some(&client)),
            &[("client_secret", "not-the-secret")],
        );
        let p = push(&env, route, &body, None).await;
        assert_invalid_client(&p, &format!("{route:?}: wrong body secret"));
    }
}

#[tokio::test]
async fn confidential_client_with_its_secret_is_accepted() {
    let env = server_env().await;
    let client = register(&env, Some(SECRET));
    for route in ROUTES {
        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, SECRET)),
        )
        .await;
        assert_pushed(&p, &format!("{route:?}: client_secret_basic"));

        // RFC 6749 §3.2.1: a client_secret_basic client need not repeat its
        // client_id in the body.
        let p = push(&env, route, &par_body(None), Some(basic(&client, SECRET))).await;
        assert_pushed(
            &p,
            &format!("{route:?}: client_secret_basic, no body client_id"),
        );

        let body = with(par_body(Some(&client)), &[("client_secret", SECRET)]);
        let p = push(&env, route, &body, None).await;
        assert_pushed(&p, &format!("{route:?}: client_secret_post"));
    }
}

#[tokio::test]
async fn unknown_client_is_refused() {
    let env = server_env().await;
    let stranger = ClientId::new(uuid::Uuid::new_v4());
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&stranger)), None).await;
        assert_invalid_client(&p, &format!("{route:?}: unknown client, no secret"));
        let p = push(
            &env,
            route,
            &par_body(Some(&stranger)),
            Some(basic(&stranger, SECRET)),
        )
        .await;
        assert_invalid_client(&p, &format!("{route:?}: unknown client, with secret"));
    }
}

// ===== Public clients =====

#[tokio::test]
async fn public_client_pushes_on_its_client_id_alone() {
    let env = server_env().await;
    let client = register(&env, None);
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&client)), None).await;
        assert_pushed(&p, &format!("{route:?}: public client"));
    }
}

#[tokio::test]
async fn public_client_presenting_a_secret_is_refused() {
    let env = server_env().await;
    let client = register(&env, None);
    for route in ROUTES {
        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, "made-up-secret")),
        )
        .await;
        assert_invalid_client(&p, &format!("{route:?}: public client + Basic secret"));

        let body = with(par_body(Some(&client)), &[("client_secret", "made-up")]);
        let p = push(&env, route, &body, None).await;
        assert_invalid_client(&p, &format!("{route:?}: public client + body secret"));
    }
}

// ===== private_key_jwt =====

#[tokio::test]
async fn private_key_jwt_client_with_a_valid_assertion_is_accepted() {
    let env = server_env().await;
    let (client, key) = register_pkjwt(&env);
    for route in ROUTES {
        let body = with(
            par_body(Some(&client)),
            &[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &assertion(&key, &client, &env.issuer)),
            ],
        );
        let p = push(&env, route, &body, None).await;
        assert_pushed(&p, &format!("{route:?}: private_key_jwt"));
    }
}

#[tokio::test]
async fn private_key_jwt_client_without_its_assertion_is_refused() {
    let env = server_env().await;
    let (client, _key) = register_pkjwt(&env);
    let stranger_key = SigningKey::generate().expect("key");
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&client)), None).await;
        assert_invalid_client(
            &p,
            &format!("{route:?}: private_key_jwt client, client_id only"),
        );

        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, "made-up-secret")),
        )
        .await;
        assert_invalid_client(
            &p,
            &format!("{route:?}: private_key_jwt client, made-up secret"),
        );

        let body = with(
            par_body(Some(&client)),
            &[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                (
                    "client_assertion",
                    &assertion(&stranger_key, &client, &env.issuer),
                ),
            ],
        );
        let p = push(&env, route, &body, None).await;
        assert_invalid_client(&p, &format!("{route:?}: assertion signed by a foreign key"));
    }
}

#[tokio::test]
async fn an_assertion_combined_with_a_secret_is_refused() {
    let env = server_env().await;
    let client = register(&env, Some(SECRET));
    let key = install_assertion_key(&env, &client);
    for route in ROUTES {
        let body = with(
            par_body(Some(&client)),
            &[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &assertion(&key, &client, &env.issuer)),
                ("client_secret", SECRET),
            ],
        );
        let p = push(&env, route, &body, None).await;
        assert_eq!(
            p.status, 400,
            "{route:?}: two authentication methods in one request must be 400 (RFC 6749 §2.3), \
             got {} {}",
            p.status, p.body
        );
        assert_eq!(p.body["error"], "invalid_request", "{route:?}: {}", p.body);
    }
}

// ===== The authenticated client is the client the request names =====

#[tokio::test]
async fn basic_credentials_for_another_client_are_refused() {
    let env = server_env().await;
    let victim = register(&env, Some(SECRET));
    let attacker = register(&env, Some("attacker-secret-0123456789abcdef!"));
    for route in ROUTES {
        let p = push(
            &env,
            route,
            &par_body(Some(&victim)),
            Some(basic(&attacker, "attacker-secret-0123456789abcdef!")),
        )
        .await;
        assert_eq!(
            p.status, 400,
            "{route:?}: Basic credentials for one client and a body client_id naming another \
             must be refused, got {} {}",
            p.status, p.body
        );
        assert!(p.body.get("request_uri").is_none(), "{route:?}: {}", p.body);
    }
}

#[tokio::test]
async fn an_assertion_for_another_client_is_refused() {
    let env = server_env().await;
    let (attacker, attacker_key) = register_pkjwt(&env);
    let (victim, _victim_key) = register_pkjwt(&env);
    for route in ROUTES {
        // The attacker's own, valid assertion — presented for the victim.
        let body = with(
            par_body(Some(&victim)),
            &[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                (
                    "client_assertion",
                    &assertion(&attacker_key, &attacker, &env.issuer),
                ),
            ],
        );
        let p = push(&env, route, &body, None).await;
        assert_invalid_client(&p, &format!("{route:?}: assertion for another client"));
    }
}

#[tokio::test]
async fn a_request_object_naming_another_client_is_refused() {
    let env = server_env().await;
    let jar = jar_key();
    let client = register_with(
        &env,
        RegisterClientRequest {
            client_secret: Some(SECRET.to_string()),
            jwks: Some(jar.jwks.clone()),
            ..Default::default()
        },
    );
    let other = register(&env, None);
    for route in ROUTES {
        // Control: the authenticated client's own request object is accepted,
        // so the refusals below are about the client it names.
        let own = request_object(&jar, &client, &client, &env.issuer);
        let body = with(par_body(Some(&client)), &[("request", &own)]);
        let p = push(&env, route, &body, Some(basic(&client, SECRET))).await;
        assert_pushed(&p, &format!("{route:?}: own request object"));

        let foreign_client_id = request_object(&jar, &client, &other, &env.issuer);
        let body = with(par_body(Some(&client)), &[("request", &foreign_client_id)]);
        let p = push(&env, route, &body, Some(basic(&client, SECRET))).await;
        assert_eq!(
            p.status, 400,
            "{route:?}: a request object whose client_id names another client must be refused, \
             got {} {}",
            p.status, p.body
        );

        let foreign_iss = request_object(&jar, &other, &other, &env.issuer);
        let body = with(par_body(Some(&client)), &[("request", &foreign_iss)]);
        let p = push(&env, route, &body, Some(basic(&client, SECRET))).await;
        assert_eq!(
            p.status, 400,
            "{route:?}: a request object issued by another client must be refused, got {} {}",
            p.status, p.body
        );
    }
}

// ===== FAPI 2.0 =====

#[tokio::test]
async fn fapi2_client_must_push_with_its_assertion() {
    let env = server_env().await;
    let jar = jar_key();
    // FAPI 2.0 clients hold no secret and register a JWKS; they authenticate
    // with private_key_jwt.
    let client = register_with(
        &env,
        RegisterClientRequest {
            jwks: Some(jar.jwks.clone()),
            profile: ClientProfile::Fapi2,
            ..Default::default()
        },
    );
    let key = install_assertion_key(&env, &client);
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&client)), None).await;
        assert_invalid_client(&p, &format!("{route:?}: FAPI 2.0 client, client_id only"));

        let body = with(
            par_body(Some(&client)),
            &[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &assertion(&key, &client, &env.issuer)),
            ],
        );
        let p = push(&env, route, &body, None).await;
        assert_pushed(&p, &format!("{route:?}: FAPI 2.0 client, private_key_jwt"));
    }
}

#[tokio::test]
async fn confidential_client_in_a_fapi_realm_must_authenticate() {
    let env = server_env().await;
    set_fapi(&env, FapiProfile::Baseline);
    let client = register(&env, Some(SECRET));
    for route in ROUTES {
        let p = push(&env, route, &par_body(Some(&client)), None).await;
        assert_invalid_client(&p, &format!("{route:?}: FAPI Baseline, no credentials"));

        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, SECRET)),
        )
        .await;
        assert_pushed(&p, &format!("{route:?}: FAPI Baseline, authenticated"));
    }
}

// ===== KDF admission gate =====

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_argon2id_secret_is_verified_behind_the_kdf_gate() {
    // A 1-permit gate, installed before anything touches `gate()`. nextest
    // runs this test in its own process, so it wins the OnceLock.
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: Duration::from_millis(40),
        retry_after: Duration::from_secs(2),
    });
    assert!(installed, "init_gate must win the process-global OnceLock");

    let env = server_env().await;
    // A caller-chosen secret is stored as Argon2id.
    let client = register(&env, Some(SECRET));

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    for route in ROUTES {
        let p = push(
            &env,
            route,
            &par_body(Some(&client)),
            Some(basic(&client, SECRET)),
        )
        .await;
        assert_eq!(
            p.status, 503,
            "{route:?}: a shed Argon2id verification must be 503, got {} {}",
            p.status, p.body
        );
        assert!(
            p.retry_after,
            "{route:?}: a shed response must carry Retry-After"
        );
    }

    release_tx.send(()).expect("release the permit");
    holder.await.expect("holder joins");
    let p = push(
        &env,
        Route::Header,
        &par_body(Some(&client)),
        Some(basic(&client, SECRET)),
    )
    .await;
    assert_pushed(&p, "with a free permit the Argon2id client authenticates");
}
