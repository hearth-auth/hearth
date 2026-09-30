#![allow(clippy::unwrap_used)]
//! FAPI 2.0 client authentication at the token and PAR endpoints.
//!
//! Two defects, pinned on every route (header-realm and `/realms/{name}/…`):
//!
//! 1. **A FAPI 2.0 client that registered only a JWKS counted as PUBLIC.**
//!    FAPI 2.0 registration requires a JWKS and forbids a secret, but
//!    `private_key_jwt` assertions were verified only against the separate
//!    `assertion_public_key`, and "public" meant "no stored secret". So such a
//!    client could not authenticate with its registered keys at all, and every
//!    surface that accepts a public client on its `client_id` alone — `/as/par`,
//!    the `authorization_code` and `refresh_token` arms of `/token` — accepted
//!    it with nothing. Now an assertion verifies against the client's JWKS
//!    (PS256 / ES256 / EdDSA, key chosen by `kid`) and a client holding a JWKS
//!    is never public.
//! 2. **FAPI 2.0 Advanced realms did not require `private_key_jwt`.**
//!    `docs/specs/OIDC.md` §2.1.2 item 6: `client_secret_basic`,
//!    `client_secret_post` and `none` are rejected. They were accepted at
//!    `/token`, `/as/par`, `/introspect` and `/revoke`. Now each answers `401
//!    invalid_client` with a description naming `private_key_jwt`.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AuthorizationRequest, ClientProfile, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, FapiProfile, RegisterClientRequest, UpdateRealmRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

const REDIRECT_URI: &str = "https://app.example.com/cb";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// S256 of [`PKCE_VERIFIER`] (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const SECRET: &str = "fapi-client-auth-secret-0123456789!";

// ── keys ─────────────────────────────────────────────────────────────────────

/// A client signing key registered in the client's JWKS.
enum ClientKey {
    Es256(EcdsaKeyPair),
    EdDsa(Ed25519KeyPair),
}

impl ClientKey {
    fn es256() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Self::Es256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        )
    }

    fn eddsa() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self::EdDsa(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn alg(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::EdDsa(_) => "EdDSA",
        }
    }

    fn kid(&self) -> &'static str {
        match self {
            Self::Es256(_) => "client-es256",
            Self::EdDsa(_) => "client-eddsa",
        }
    }

    /// The public key as a JWK (no `kid`/`alg`).
    fn public_jwk(&self) -> serde_json::Value {
        match self {
            Self::Es256(k) => {
                let p = k.public_key().as_ref();
                serde_json::json!({
                    "crv": "P-256", "kty": "EC",
                    "x": URL_SAFE_NO_PAD.encode(&p[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&p[33..65]),
                })
            }
            Self::EdDsa(k) => serde_json::json!({
                "crv": "Ed25519", "kty": "OKP",
                "x": URL_SAFE_NO_PAD.encode(k.public_key().as_ref()),
            }),
        }
    }

    /// A one-key JWKS for registration.
    fn jwks(&self) -> String {
        let mut jwk = self.public_jwk();
        jwk["kid"] = serde_json::json!(self.kid());
        jwk["alg"] = serde_json::json!(self.alg());
        jwk["use"] = serde_json::json!("sig");
        serde_json::json!({ "keys": [jwk] }).to_string()
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256(k) => k
                .sign(&SystemRandom::new(), data)
                .unwrap()
                .as_ref()
                .to_vec(),
            Self::EdDsa(k) => k.sign(data).as_ref().to_vec(),
        }
    }

    fn jws(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// A `private_key_jwt` client assertion (RFC 7523 §2.2).
    fn assertion(&self, client: &ClientId, aud: &str) -> String {
        let now = now_secs();
        self.jws(
            &serde_json::json!({"alg": self.alg(), "kid": self.kid(), "typ": "JWT"}),
            &serde_json::json!({
                "iss": client.as_uuid().to_string(),
                "sub": client.as_uuid().to_string(),
                "aud": aud,
                "exp": now + 60,
                "iat": now,
                "jti": uuid::Uuid::new_v4().to_string(),
            }),
        )
    }

    /// A DPoP proof (RFC 9449) for `POST htu`.
    fn dpop(&self, htu: &str, nonce: &str) -> String {
        self.jws(
            &serde_json::json!({"alg": self.alg(), "typ": "dpop+jwt", "jwk": self.public_jwk()}),
            &serde_json::json!({
                "htm": "POST",
                "htu": htu,
                "iat": now_secs(),
                "jti": uuid::Uuid::new_v4().to_string(),
                "nonce": nonce,
            }),
        )
    }
}

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ── environment ──────────────────────────────────────────────────────────────

struct Env {
    h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    /// The realm issuer: the `aud` of client assertions.
    issuer: String,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("fapi-auth-{}", uuid::Uuid::new_v4());
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

impl Env {
    fn set_fapi(&self, profile: FapiProfile) {
        let realm = self
            .h
            .identity()
            .get_realm(&self.realm_id)
            .unwrap()
            .unwrap();
        let mut config = realm.config().clone();
        config.fapi_profile = Some(profile);
        self.h
            .identity()
            .update_realm(
                &self.realm_id,
                &UpdateRealmRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .expect("set fapi profile");
    }

    fn register(&self, req: RegisterClientRequest) -> ClientId {
        self.h
            .identity()
            .register_client(
                &self.realm_id,
                &RegisterClientRequest {
                    client_name: format!("fapi-client-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    require_consent: false,
                    // First-party: `client_credentials` without a scope.
                    trust_level: ClientTrustLevel::FirstParty,
                    ..req
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    }

    /// A FAPI 2.0 client that registered only a JWKS — no secret, no
    /// separate assertion key.
    fn fapi2_client(&self, key: &ClientKey) -> ClientId {
        self.register(RegisterClientRequest {
            jwks: Some(key.jwks()),
            profile: ClientProfile::Fapi2,
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            ..Default::default()
        })
    }

    fn secret_client(&self) -> ClientId {
        self.register(RegisterClientRequest {
            client_secret: Some(SECRET.to_string()),
            grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
            ],
            ..Default::default()
        })
    }

    fn public_client(&self) -> ClientId {
        self.register(RegisterClientRequest {
            grant_types: vec!["authorization_code".to_string()],
            ..Default::default()
        })
    }

    fn url(&self, route: Route, endpoint: &str) -> String {
        match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        }
    }

    /// The `htu` the server expects in a token-endpoint DPoP proof.
    fn token_htu(&self, route: Route) -> String {
        match route {
            Route::Header => self.h.identity().oidc_discovery().token_endpoint,
            Route::Realm => format!("{}/token", self.issuer),
        }
    }

    /// An authorization code for `client`, issued as after a PAR.
    async fn code(&self, client: &ClientId) -> String {
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm_id,
                &CreateUserRequest {
                    email: format!("fapi-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "FAPI user".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user")
            .id()
            .clone();
        self.h
            .identity()
            .authorize(
                &self.realm_id,
                &AuthorizationRequest {
                    client_id: client.clone(),
                    redirect_uri: REDIRECT_URI.to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    state: "fapi-state".to_string(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.to_string()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    user_id: user,
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                    via_par: true,
                },
            )
            .expect("authorize")
            .code()
            .to_string()
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    /// `POST /{endpoint}` with `X-Realm-ID`.
    Header,
    /// `POST /realms/{name}/{endpoint}`.
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

struct Answer {
    status: u16,
    body: serde_json::Value,
}

/// POSTs a form to `url`; `basic` adds `client_secret_basic` credentials and
/// `dpop` a `DPoP` header.
async fn post(
    env: &Env,
    route: Route,
    endpoint: &str,
    form: &[(&str, String)],
    basic: Option<(&ClientId, &str)>,
    dpop: Option<&ClientKey>,
) -> Answer {
    let client = reqwest::Client::new();
    let url = env.url(route, endpoint);
    let mut nonce = String::new();
    if dpop.is_some() {
        // Every token response carries the current DPoP-Nonce (RFC 9449 §9).
        let mut probe = client.post(&url).form(&[("grant_type", "nonce-probe")]);
        if matches!(route, Route::Header) {
            probe = probe.header("X-Realm-ID", env.realm_id.as_uuid().to_string());
        }
        let resp = probe.send().await.expect("nonce probe");
        nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .expect("token responses carry DPoP-Nonce")
            .to_string();
    }
    let mut req = client.post(&url).form(form);
    if matches!(route, Route::Header) {
        req = req.header("X-Realm-ID", env.realm_id.as_uuid().to_string());
    }
    if let Some((id, secret)) = basic {
        req = req.header(
            "Authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{secret}", id.as_uuid()))
            ),
        );
    }
    if let Some(key) = dpop {
        req = req.header("DPoP", key.dpop(&env.token_htu(route), &nonce));
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    Answer { status, body }
}

fn assert_invalid_client(a: &Answer, what: &str) {
    assert_eq!(
        a.status, 401,
        "{what}: expected 401 invalid_client, got {} {}",
        a.status, a.body
    );
    assert_eq!(a.body["error"], "invalid_client", "{what}: {}", a.body);
}

fn assert_requires_private_key_jwt(a: &Answer, what: &str) {
    assert_invalid_client(a, what);
    let description = a.body["error_description"].as_str().unwrap_or_default();
    assert!(
        description.contains("private_key_jwt"),
        "{what}: the refusal must say private_key_jwt is required, got {}",
        a.body
    );
}

/// The `private_key_jwt` fields (the caller adds `client_id` when its form
/// has none).
fn assertion_form(key: &ClientKey, client: &ClientId, aud: &str) -> Vec<(&'static str, String)> {
    vec![
        ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()),
        ("client_assertion", key.assertion(client, aud)),
    ]
}

/// A client id as a form field: the bare UUID.
fn id(client: &ClientId) -> String {
    client.as_uuid().to_string()
}

fn par_form(client: &ClientId) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", id(client)),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", "openid".to_string()),
        ("state", "par-state".to_string()),
        ("response_type", "code".to_string()),
        ("code_challenge", PKCE_CHALLENGE.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

fn code_form(client: &ClientId, code: String) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", id(client)),
        ("code", code),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("code_verifier", PKCE_VERIFIER.to_string()),
    ]
}

// ── 1. JWKS-only FAPI 2.0 clients ────────────────────────────────────────────

/// Presenting nothing but its `client_id`, a JWKS-only FAPI 2.0 client is
/// refused at PAR and at every token-endpoint arm that used to take it for a
/// public client.
#[tokio::test]
async fn a_jwks_only_fapi2_client_presenting_nothing_is_refused() {
    let env = env().await;
    let key = ClientKey::es256();
    let client = env.fapi2_client(&key);
    for route in ROUTES {
        let a = post(&env, route, "as/par", &par_form(&client), None, None).await;
        assert_invalid_client(&a, &format!("{route:?} /as/par, client_id only"));

        let code = env.code(&client).await;
        let a = post(
            &env,
            route,
            "token",
            &code_form(&client, code),
            None,
            Some(&key),
        )
        .await;
        assert_invalid_client(
            &a,
            &format!("{route:?} /token authorization_code, client_id only"),
        );

        let a = post(
            &env,
            route,
            "token",
            &[
                ("grant_type", "client_credentials".to_string()),
                ("client_id", id(&client)),
            ],
            None,
            Some(&key),
        )
        .await;
        assert_invalid_client(
            &a,
            &format!("{route:?} /token client_credentials, client_id only"),
        );
    }
}

/// With an assertion signed by a key from its registered JWKS — ES256 or
/// EdDSA, chosen by `kid` — the same client authenticates at PAR and at the
/// token endpoint, and can refresh with an assertion but not without one.
#[tokio::test]
async fn a_jwks_only_fapi2_client_authenticates_with_its_jwks() {
    for key in [ClientKey::es256(), ClientKey::eddsa()] {
        let env = env().await;
        let client = env.fapi2_client(&key);
        for route in ROUTES {
            let what = format!("{route:?} {}", key.alg());
            let mut form = par_form(&client);
            form.extend(assertion_form(&key, &client, &env.issuer));
            let a = post(&env, route, "as/par", &form, None, None).await;
            assert_eq!(a.status, 201, "{what} /as/par with assertion: {}", a.body);

            let code = env.code(&client).await;
            let mut form = code_form(&client, code);
            form.extend(assertion_form(&key, &client, &env.issuer));
            let a = post(&env, route, "token", &form, None, Some(&key)).await;
            assert_eq!(
                a.status, 200,
                "{what} /token authorization_code with assertion: {}",
                a.body
            );
            let refresh = a.body["refresh_token"].as_str().unwrap().to_string();

            let a = post(
                &env,
                route,
                "token",
                &[
                    ("grant_type", "refresh_token".to_string()),
                    ("client_id", id(&client)),
                    ("refresh_token", refresh.clone()),
                ],
                None,
                Some(&key),
            )
            .await;
            assert_invalid_client(&a, &format!("{what} /token refresh_token, client_id only"));

            let mut form = vec![
                ("grant_type", "refresh_token".to_string()),
                ("client_id", id(&client)),
                ("refresh_token", refresh),
            ];
            form.extend(assertion_form(&key, &client, &env.issuer));
            let a = post(&env, route, "token", &form, None, Some(&key)).await;
            assert_eq!(
                a.status, 200,
                "{what} /token refresh_token with assertion: {}",
                a.body
            );

            let mut form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", id(&client)),
            ];
            form.extend(assertion_form(&key, &client, &env.issuer));
            let a = post(&env, route, "token", &form, None, Some(&key)).await;
            assert_eq!(
                a.status, 200,
                "{what} /token client_credentials with assertion: {}",
                a.body
            );
        }
    }
}

/// An assertion signed by a key the client did not register is refused.
#[tokio::test]
async fn an_assertion_signed_by_an_unregistered_key_is_refused() {
    let env = env().await;
    let key = ClientKey::es256();
    let client = env.fapi2_client(&key);
    let stranger = ClientKey::es256();
    for route in ROUTES {
        let mut form = par_form(&client);
        form.extend(assertion_form(&stranger, &client, &env.issuer));
        let a = post(&env, route, "as/par", &form, None, None).await;
        assert_invalid_client(&a, &format!("{route:?} /as/par, foreign key"));
    }
}

// ── 2. FAPI 2.0 Advanced realms require private_key_jwt ──────────────────────

/// A client secret — Basic or body — is refused at every client-auth surface
/// of a FAPI 2.0 Advanced realm, with a description naming `private_key_jwt`.
#[tokio::test]
async fn a_fapi_advanced_realm_refuses_client_secrets() {
    let env = env().await;
    let client = env.secret_client();
    // Issue the codes before the realm turns Advanced (authorize would then
    // demand PAR + JAR + JARM, which is not what this test is about).
    let codes = [env.code(&client).await, env.code(&client).await];
    env.set_fapi(FapiProfile::Advanced);
    for (route, code) in ROUTES.into_iter().zip(codes) {
        let cc = [("grant_type", "client_credentials".to_string())];
        let a = post(&env, route, "token", &cc, Some((&client, SECRET)), None).await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /token, client_secret_basic"));

        let a = post(
            &env,
            route,
            "token",
            &[
                ("grant_type", "client_credentials".to_string()),
                ("client_id", id(&client)),
                ("client_secret", SECRET.to_string()),
            ],
            None,
            None,
        )
        .await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /token, client_secret_post"));

        let a = post(
            &env,
            route,
            "token",
            &code_form(&client, code),
            Some((&client, SECRET)),
            None,
        )
        .await;
        assert_requires_private_key_jwt(
            &a,
            &format!("{route:?} /token authorization_code, client_secret_basic"),
        );

        let a = post(
            &env,
            route,
            "as/par",
            &par_form(&client),
            Some((&client, SECRET)),
            None,
        )
        .await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /as/par, client_secret_basic"));

        let token = [("token", "not-a-token".to_string())];
        let a = post(
            &env,
            route,
            "introspect",
            &token,
            Some((&client, SECRET)),
            None,
        )
        .await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /introspect, client_secret_basic"));

        let a = post(&env, route, "revoke", &token, Some((&client, SECRET)), None).await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /revoke, client_secret_basic"));
    }
}

/// `none` is refused too: a public client cannot push or redeem a code on its
/// `client_id` alone in a FAPI 2.0 Advanced realm.
#[tokio::test]
async fn a_fapi_advanced_realm_refuses_public_clients() {
    let env = env().await;
    let client = env.public_client();
    // Issue the code before the realm turns Advanced (authorize would then
    // demand PAR + JAR + JARM, which is not what this test is about).
    let codes = [env.code(&client).await, env.code(&client).await];
    env.set_fapi(FapiProfile::Advanced);
    for (route, code) in ROUTES.into_iter().zip(codes) {
        let a = post(&env, route, "as/par", &par_form(&client), None, None).await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /as/par, none"));

        let a = post(&env, route, "token", &code_form(&client, code), None, None).await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /token authorization_code, none"));

        let token = [
            ("token", "not-a-token".to_string()),
            ("client_id", id(&client)),
        ];
        let a = post(&env, route, "revoke", &token, None, None).await;
        assert_requires_private_key_jwt(&a, &format!("{route:?} /revoke, none"));
    }
}

/// `private_key_jwt` still works in a FAPI 2.0 Advanced realm.
#[tokio::test]
async fn a_fapi_advanced_realm_accepts_private_key_jwt() {
    let env = env().await;
    env.set_fapi(FapiProfile::Advanced);
    let key = ClientKey::eddsa();
    let client = env.fapi2_client(&key);
    for route in ROUTES {
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", id(&client)),
        ];
        form.extend(assertion_form(&key, &client, &env.issuer));
        let a = post(&env, route, "token", &form, None, Some(&key)).await;
        assert_eq!(a.status, 200, "{route:?} /token with assertion: {}", a.body);
        let access = a.body["access_token"].as_str().unwrap().to_string();

        let mut form = vec![("token", access), ("client_id", id(&client))];
        form.extend(assertion_form(&key, &client, &env.issuer));
        let a = post(&env, route, "introspect", &form, None, None).await;
        assert_eq!(
            a.status, 200,
            "{route:?} /introspect with assertion: {}",
            a.body
        );
    }
}
