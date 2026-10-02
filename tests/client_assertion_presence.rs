#![allow(clippy::unwrap_used)]
//! A request that carries `client_assertion` or `client_assertion_type` has
//! attempted `private_key_jwt`, on every surface that reads those fields.
//!
//! The defect (introduced with FAPI 2.0 client authentication): at the
//! `authorization_code` exchange the protocol layer waved through ANY
//! non-empty assertion field, deferring to the engine, and the engine verified
//! only when `client_assertion_type` was exactly the jwt-bearer URN — so a
//! client that holds a SECRET could redeem its code with
//! `client_assertion=junk` (no type, or a wrong one) and no secret at all, and
//! got tokens.
//!
//! The rule now, pinned on the header-realm and `/realms/{name}/…` twin of
//! every surface: a presented assertion field means `private_key_jwt`. The
//! type must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, the
//! assertion must be present and must verify for THIS client, else `401
//! invalid_client`; combined with a secret it is `400 invalid_request` (RFC
//! 6749 §2.3: one method per request). It never falls through to another
//! method, and never to success.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, DeviceAuthorizationRequest, RegisterClientRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const REDIRECT_URI: &str = "https://app.example.com/cb";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// S256 of [`PKCE_VERIFIER`] (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const SECRET: &str = "assertion-presence-secret-0123456789!";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

// ── keys ─────────────────────────────────────────────────────────────────────

/// An Ed25519 client key registered in a client's JWKS.
struct ClientKey(Ed25519KeyPair);

impl ClientKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn jwks(&self) -> String {
        serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref()),
        }]})
        .to_string()
    }

    /// A well-formed `private_key_jwt` assertion naming `iss`/`sub`.
    fn assertion(&self, iss_sub: &ClientId, aud: &str) -> String {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::json!({"alg": "EdDSA", "kid": "k1", "typ": "JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "iss": iss_sub.to_string(), "sub": iss_sub.to_string(), "aud": aud,
                    "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
                })
                .to_string()
            ),
        );
        let sig = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

// ── environment ──────────────────────────────────────────────────────────────

struct Env {
    h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    issuer: String,
    /// Holds a secret; the victim of every forged-assertion case.
    secret_client: ClientId,
    /// Holds a JWKS; the source of well-formed assertions for another client.
    key_client: ClientId,
    key: ClientKey,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("assertion-presence-{}", uuid::Uuid::new_v4());
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
    let grant_types = vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
        "client_credentials".to_string(),
        DEVICE_GRANT.to_string(),
        TOKEN_EXCHANGE_GRANT.to_string(),
    ];
    let register = |secret: Option<String>, jwks: Option<String>| {
        h.identity()
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: format!("presence-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    require_consent: false,
                    trust_level: ClientTrustLevel::FirstParty,
                    grant_types: grant_types.clone(),
                    client_secret: secret,
                    jwks,
                    ..Default::default()
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    };
    let key = ClientKey::new();
    let secret_client = register(Some(SECRET.to_string()), None);
    let key_client = register(None, Some(key.jwks()));
    Env {
        h,
        base,
        realm_name,
        realm_id,
        issuer,
        secret_client,
        key_client,
        key,
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

struct Answer {
    status: u16,
    body: serde_json::Value,
}

impl Env {
    fn id(&self) -> String {
        self.secret_client.as_uuid().to_string()
    }

    async fn post(
        &self,
        route: Route,
        endpoint: &str,
        form: &[(&str, String)],
        basic: bool,
    ) -> Answer {
        let url = match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        };
        let mut req = reqwest::Client::new().post(&url).form(form);
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        if basic {
            req = req.header(
                "Authorization",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{SECRET}", self.id()))
                ),
            );
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        Answer { status, body }
    }

    /// A fresh authorization code for the secret client.
    fn code(&self) -> String {
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm_id,
                &CreateUserRequest {
                    email: format!("presence-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Presence user".to_string(),
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
                    client_id: self.secret_client.clone(),
                    redirect_uri: REDIRECT_URI.to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    state: "presence-state".to_string(),
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

    /// The secret client's refresh token, from a secret-authenticated
    /// code exchange.
    async fn refresh_token(&self) -> String {
        let mut form = code_form(&self.id(), self.code());
        form.push(("client_secret", SECRET.to_string()));
        let a = self.post(Route::Header, "token", &form, false).await;
        assert_eq!(a.status, 200, "refresh-token setup: {}", a.body);
        a.body["refresh_token"].as_str().unwrap().to_string()
    }

    fn device_code(&self) -> String {
        self.h
            .identity()
            .device_authorize(
                &self.realm_id,
                &DeviceAuthorizationRequest {
                    client_id: self.secret_client.clone(),
                    scope: None,
                },
            )
            .expect("device authorize")
            .device_code
    }
}

fn code_form(client_id: &str, code: String) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", client_id.to_string()),
        ("code", code),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("code_verifier", PKCE_VERIFIER.to_string()),
    ]
}

// ── the cases ────────────────────────────────────────────────────────────────

/// A way of presenting (or not presenting) credentials for the secret client.
#[derive(Clone, Copy, Debug)]
enum Case {
    /// Control: the secret, as `client_secret_post`.
    Secret,
    /// Control: no credential at all.
    Nothing,
    /// `client_assertion=junk`, no type.
    JunkNoType,
    /// `client_assertion_type=urn:x`, `client_assertion=junk`.
    WrongType,
    /// A type but no assertion.
    TypeOnly,
    /// The jwt-bearer type with a garbage assertion.
    RightTypeGarbage,
    /// A valid assertion — for ANOTHER client (`iss`/`sub` = that client).
    OtherClientsAssertion,
    /// A valid-shaped assertion naming this client, signed by another
    /// client's key.
    SignedByAnotherClient,
    /// A junk assertion AND the correct secret (two methods).
    SecretPlusJunk,
}

const FORGED: [Case; 6] = [
    Case::JunkNoType,
    Case::WrongType,
    Case::TypeOnly,
    Case::RightTypeGarbage,
    Case::OtherClientsAssertion,
    Case::SignedByAnotherClient,
];

impl Env {
    fn credentials(&self, case: Case) -> Vec<(&'static str, String)> {
        let junk = ("client_assertion", "junk".to_string());
        match case {
            Case::Secret => vec![("client_secret", SECRET.to_string())],
            Case::Nothing => vec![],
            Case::JunkNoType => vec![junk],
            Case::WrongType => vec![("client_assertion_type", "urn:x".to_string()), junk],
            Case::TypeOnly => vec![("client_assertion_type", JWT_BEARER.to_string())],
            Case::RightTypeGarbage => vec![
                ("client_assertion_type", JWT_BEARER.to_string()),
                ("client_assertion", "a.b.c".to_string()),
            ],
            Case::OtherClientsAssertion => vec![
                ("client_assertion_type", JWT_BEARER.to_string()),
                (
                    "client_assertion",
                    self.key.assertion(&self.key_client, &self.issuer),
                ),
            ],
            Case::SignedByAnotherClient => vec![
                ("client_assertion_type", JWT_BEARER.to_string()),
                (
                    "client_assertion",
                    self.key.assertion(&self.secret_client, &self.issuer),
                ),
            ],
            Case::SecretPlusJunk => vec![("client_secret", SECRET.to_string()), junk],
        }
    }
}

/// Posts `form` + the case's credentials to every route and checks the
/// answer: `success` for the secret control, `401 invalid_client` for every
/// forged assertion, `400 invalid_request` for a secret plus an assertion, and
/// — when `authenticates` — `401 invalid_client` with no credential at all.
///
/// `success` is `None` for a grant whose request body here is deliberately
/// invalid: there the controls only prove the refusal is `invalid_client`
/// (client authentication) and not the grant's own error.
async fn check_surface<F, Fut>(
    env: &Env,
    what: &str,
    endpoint: &str,
    success: Option<u16>,
    authenticates: bool,
    form: F,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Vec<(&'static str, String)>>,
{
    for route in ROUTES {
        let mut cases = vec![Case::Secret, Case::SecretPlusJunk];
        if authenticates {
            cases.push(Case::Nothing);
        }
        cases.extend(FORGED);
        for case in cases {
            let mut body = form().await;
            body.extend(env.credentials(case));
            let a = env.post(route, endpoint, &body, false).await;
            let label = format!("{what} {route:?} {case:?}");
            match case {
                Case::Secret => match success {
                    Some(status) => assert_eq!(a.status, status, "{label}: {}", a.body),
                    None => assert_ne!(
                        a.body["error"], "invalid_client",
                        "{label}: the control must pass client authentication: {}",
                        a.body
                    ),
                },
                Case::SecretPlusJunk => {
                    assert_eq!(a.status, 400, "{label}: {}", a.body);
                    assert_eq!(a.body["error"], "invalid_request", "{label}: {}", a.body);
                }
                _ => {
                    assert_eq!(a.status, 401, "{label}: {}", a.body);
                    assert_eq!(a.body["error"], "invalid_client", "{label}: {}", a.body);
                }
            }
        }
        // The Basic form of the two-method case.
        let mut body = form().await;
        body.push(("client_assertion", "junk".to_string()));
        let a = env.post(route, endpoint, &body, true).await;
        assert_eq!(
            a.status, 400,
            "{what} {route:?} Basic + junk assertion: {}",
            a.body
        );
    }
}

// ── /token ───────────────────────────────────────────────────────────────────

/// The reported bypass: a secret-holding client redeemed its code with a junk
/// assertion and no secret.
#[tokio::test]
async fn token_authorization_code() {
    let env = env().await;
    let id = env.id();
    check_surface(
        &env,
        "/token authorization_code",
        "token",
        Some(200),
        true,
        || {
            let form = code_form(&id, env.code());
            async move { form }
        },
    )
    .await;
}

#[tokio::test]
async fn token_client_credentials() {
    let env = env().await;
    let id = env.id();
    check_surface(
        &env,
        "/token client_credentials",
        "token",
        Some(200),
        true,
        || {
            let form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", id.clone()),
            ];
            async move { form }
        },
    )
    .await;
}

#[tokio::test]
async fn token_refresh_token() {
    let env = env().await;
    let id = env.id();
    check_surface(
        &env,
        "/token refresh_token",
        "token",
        Some(200),
        true,
        || async {
            vec![
                ("grant_type", "refresh_token".to_string()),
                ("client_id", id.clone()),
                ("refresh_token", env.refresh_token().await),
            ]
        },
    )
    .await;
}

/// No `client_id`: the clientless session-refresh shape must not become an
/// unauthenticated refresh because only `client_assertion_type` was sent.
#[tokio::test]
async fn token_refresh_token_without_client_id() {
    let env = env().await;
    for route in ROUTES {
        let a = env
            .post(
                route,
                "token",
                &[
                    ("grant_type", "refresh_token".to_string()),
                    ("refresh_token", env.refresh_token().await),
                    ("client_assertion_type", "urn:x".to_string()),
                ],
                false,
            )
            .await;
        assert_eq!(a.status, 401, "{route:?}: {}", a.body);
        assert_eq!(a.body["error"], "invalid_client", "{route:?}: {}", a.body);
    }
}

/// The device grant: the control answers `authorization_pending` (the code
/// is never approved), which proves client authentication passed.
#[tokio::test]
async fn token_device_code() {
    let env = env().await;
    let id = env.id();
    check_surface(&env, "/token device_code", "token", Some(400), true, || {
        let form = vec![
            ("grant_type", DEVICE_GRANT.to_string()),
            ("client_id", id.clone()),
            ("device_code", env.device_code()),
        ];
        async move { form }
    })
    .await;
}

#[tokio::test]
async fn token_token_exchange() {
    let env = env().await;
    let id = env.id();
    check_surface(&env, "/token token-exchange", "token", None, true, || {
        let form = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT.to_string()),
            ("client_id", id.clone()),
            ("subject_token", "not-a-token".to_string()),
        ];
        async move { form }
    })
    .await;
}

/// Grants that do not authenticate the client still refuse a presented,
/// unverifiable assertion rather than ignoring it.
#[tokio::test]
async fn token_grants_without_client_authentication() {
    let env = env().await;
    let id = env.id();
    for (grant, extra) in [
        (
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            vec![("assertion", "not-a-jwt".to_string())],
        ),
        (
            "urn:hearth:grant-type:magic-link",
            vec![("token", "not-a-magic-link".to_string())],
        ),
    ] {
        check_surface(
            &env,
            &format!("/token {grant}"),
            "token",
            None,
            false,
            || {
                let mut form = vec![("grant_type", grant.to_string()), ("client_id", id.clone())];
                form.extend(extra.clone());
                async move { form }
            },
        )
        .await;
    }
}

// ── /as/par, /introspect, /revoke ────────────────────────────────────────────

#[tokio::test]
async fn pushed_authorization_request() {
    let env = env().await;
    let id = env.id();
    check_surface(&env, "/as/par", "as/par", Some(201), true, || {
        let form = vec![
            ("client_id", id.clone()),
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("scope", "openid".to_string()),
            ("state", "par-state".to_string()),
            ("response_type", "code".to_string()),
            ("code_challenge", PKCE_CHALLENGE.to_string()),
            ("code_challenge_method", "S256".to_string()),
        ];
        async move { form }
    })
    .await;
}

#[tokio::test]
async fn introspect() {
    let env = env().await;
    let id = env.id();
    check_surface(&env, "/introspect", "introspect", Some(200), true, || {
        let form = vec![
            ("token", "not-a-token".to_string()),
            ("client_id", id.clone()),
        ];
        async move { form }
    })
    .await;
}

#[tokio::test]
async fn revoke() {
    let env = env().await;
    let id = env.id();
    check_surface(&env, "/revoke", "revoke", Some(200), true, || {
        let form = vec![
            ("token", "not-a-token".to_string()),
            ("client_id", id.clone()),
        ];
        async move { form }
    })
    .await;
}

#[tokio::test]
async fn device_authorization() {
    let env = env().await;
    let id = env.id();
    check_surface(
        &env,
        "/device_authorization",
        "device_authorization",
        Some(200),
        true,
        || {
            let form = vec![("client_id", id.clone())];
            async move { form }
        },
    )
    .await;
}
