#![allow(clippy::unwrap_used)]
//! A `private_key_jwt` client can omit `client_id` (#785).
//!
//! RFC 7521 §4.2 and RFC 7523 §3: when a client authenticates with an
//! assertion, `client_id` is optional. The client is the assertion's `sub`,
//! which must equal its `iss`. Hearth refused such a request with `400` and
//! the free-text `error` "invalid client_id UUID". Now every surface that
//! reads `client_assertion` takes the client from the assertion when the body
//! has no `client_id`, and then verifies the assertion in full, as before.
//!
//! A request whose client Hearth cannot identify gets `401 invalid_client`
//! (RFC 6749 §5.2), not a free-text `error`.
//!
//! Every case runs on the header-realm route and on its `/realms/{name}/…`
//! twin.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

// ── keys ─────────────────────────────────────────────────────────────────────

/// An Ed25519 client key, registered in a client's JWKS with `alg` EdDSA.
struct ClientKey(Ed25519KeyPair);

/// The claims of one assertion.
struct Claims<'a> {
    iss: &'a ClientId,
    sub: &'a ClientId,
    aud: &'a str,
    /// Seconds from now.
    exp_in: i64,
}

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

    fn sign(&self, c: &Claims<'_>) -> String {
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
                    "iss": c.iss.as_uuid().to_string(),
                    "sub": c.sub.as_uuid().to_string(),
                    "aud": c.aud,
                    "exp": now + c.exp_in,
                    "iat": now,
                    "jti": uuid::Uuid::new_v4().to_string(),
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
    /// A `private_key_jwt` client: it holds a JWKS and no secret.
    client: ClientId,
    key: ClientKey,
    /// A second `private_key_jwt` client with its own key.
    other: ClientId,
    other_key: ClientKey,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("assertion-no-client-id-{}", uuid::Uuid::new_v4());
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
    let register = |jwks: String| {
        h.identity()
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: format!("no-client-id-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    require_consent: false,
                    trust_level: ClientTrustLevel::FirstParty,
                    grant_types: vec![
                        "authorization_code".to_string(),
                        "refresh_token".to_string(),
                        "client_credentials".to_string(),
                        DEVICE_GRANT.to_string(),
                    ],
                    jwks: Some(jwks),
                    ..Default::default()
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    };
    let key = ClientKey::new();
    let other_key = ClientKey::new();
    let client = register(key.jwks());
    let other = register(other_key.jwks());
    Env {
        h,
        base,
        realm_name,
        realm_id,
        issuer,
        client,
        key,
        other,
        other_key,
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
    async fn post(&self, route: Route, endpoint: &str, form: &[(&str, String)]) -> Answer {
        let url = match route {
            Route::Header => format!("{}/{endpoint}", self.base),
            Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
        };
        let mut req = reqwest::Client::new().post(&url).form(form);
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        Answer { status, body }
    }

    /// A valid assertion for [`Env::client`], signed with its key.
    fn assertion(&self) -> String {
        self.key.sign(&Claims {
            iss: &self.client,
            sub: &self.client,
            aud: &self.issuer,
            exp_in: 60,
        })
    }

    /// The assertion fields, with no `client_id`.
    fn credentials(assertion: String) -> Vec<(&'static str, String)> {
        vec![
            ("client_assertion_type", JWT_BEARER.to_string()),
            ("client_assertion", assertion),
        ]
    }

    /// A fresh authorization code for [`Env::client`].
    fn code(&self) -> String {
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm_id,
                &CreateUserRequest {
                    email: format!("no-client-id-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "No client_id user".to_string(),
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
                    organization: None,
                    client_id: self.client.clone(),
                    redirect_uri: REDIRECT_URI.to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    state: "no-client-id-state".to_string(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.to_string()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    user_id: user,
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .expect("authorize")
            .code()
            .to_string()
    }

    fn device_code(&self) -> String {
        self.h
            .identity()
            .device_authorize(
                &self.realm_id,
                &DeviceAuthorizationRequest {
                    client_id: self.client.clone(),
                    scope: None,
                },
            )
            .expect("device authorize")
            .device_code
    }
}

/// A request form.
type Form = Vec<(&'static str, String)>;

fn code_form(code: String) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("code_verifier", PKCE_VERIFIER.to_string()),
    ]
}

fn assert_invalid_client(a: &Answer, label: &str) {
    assert_eq!(a.status, 401, "{label}: {}", a.body);
    assert_eq!(a.body["error"], "invalid_client", "{label}: {}", a.body);
}

// ── the client comes from the assertion ──────────────────────────────────────

/// The OIDF suite's shape: code exchange, refresh, client credentials and
/// the device grant, each with an assertion and no `client_id`.
#[tokio::test]
async fn token_grants_take_the_client_from_the_assertion() {
    let env = env().await;
    for route in ROUTES {
        let mut form = code_form(env.code());
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "token", &form).await;
        assert_eq!(a.status, 200, "{route:?} authorization_code: {}", a.body);
        assert!(
            a.body["access_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "{route:?} authorization_code: no access_token: {}",
            a.body
        );
        let refresh_token = a.body["refresh_token"].as_str().unwrap().to_string();

        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token),
        ];
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "token", &form).await;
        assert_eq!(a.status, 200, "{route:?} refresh_token: {}", a.body);
        assert!(
            a.body["access_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "{route:?} refresh_token: no access_token: {}",
            a.body
        );

        let mut form = vec![("grant_type", "client_credentials".to_string())];
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "token", &form).await;
        assert_eq!(a.status, 200, "{route:?} client_credentials: {}", a.body);
        assert!(
            a.body["access_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "{route:?} client_credentials: no access_token: {}",
            a.body
        );

        // The code is never approved: `authorization_pending` proves that
        // client authentication passed.
        let mut form = vec![
            ("grant_type", DEVICE_GRANT.to_string()),
            ("device_code", env.device_code()),
        ];
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "token", &form).await;
        assert_eq!(a.status, 400, "{route:?} device_code: {}", a.body);
        assert_eq!(
            a.body["error"], "authorization_pending",
            "{route:?} device_code: {}",
            a.body
        );
    }
}

/// `/device_authorization`, `/as/par`, `/introspect` and `/revoke` read the
/// same fields and take the client from the assertion the same way.
#[tokio::test]
async fn other_endpoints_take_the_client_from_the_assertion() {
    let env = env().await;
    for route in ROUTES {
        let a = env
            .post(
                route,
                "device_authorization",
                &Env::credentials(env.assertion()),
            )
            .await;
        assert_eq!(a.status, 200, "{route:?} device_authorization: {}", a.body);
        assert!(
            a.body["device_code"]
                .as_str()
                .is_some_and(|c| !c.is_empty()),
            "{route:?} device_authorization: no device_code: {}",
            a.body
        );

        let mut form = vec![
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("scope", "openid".to_string()),
            ("state", "par-state".to_string()),
            ("response_type", "code".to_string()),
            ("code_challenge", PKCE_CHALLENGE.to_string()),
            ("code_challenge_method", "S256".to_string()),
        ];
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "as/par", &form).await;
        assert_eq!(a.status, 201, "{route:?} as/par: {}", a.body);
        assert!(
            a.body["request_uri"]
                .as_str()
                .is_some_and(|u| !u.is_empty()),
            "{route:?} as/par: no request_uri: {}",
            a.body
        );

        for endpoint in ["introspect", "revoke"] {
            let mut form = vec![("token", uuid::Uuid::new_v4().to_string())];
            form.extend(Env::credentials(env.assertion()));
            let a = env.post(route, endpoint, &form).await;
            assert_eq!(a.status, 200, "{route:?} {endpoint}: {}", a.body);
        }
        // An unknown token introspects as inactive.
        let mut form = vec![("token", uuid::Uuid::new_v4().to_string())];
        form.extend(Env::credentials(env.assertion()));
        let a = env.post(route, "introspect", &form).await;
        assert_eq!(a.body["active"], false, "{route:?} introspect: {}", a.body);
    }
}

// ── the assertion is still verified in full ──────────────────────────────────

/// With no `client_id`, the assertion only names which client's keys verify
/// it. Every other check still applies.
#[tokio::test]
async fn an_assertion_without_client_id_is_still_verified() {
    let env = env().await;
    let replayed = env.assertion();
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        (
            "iss differs from sub",
            Env::credentials(env.key.sign(&Claims {
                iss: &env.other,
                sub: &env.client,
                aud: &env.issuer,
                exp_in: 60,
            })),
        ),
        (
            "signed by another client's key",
            Env::credentials(env.other_key.sign(&Claims {
                iss: &env.client,
                sub: &env.client,
                aud: &env.issuer,
                exp_in: 60,
            })),
        ),
        (
            "wrong audience",
            Env::credentials(env.key.sign(&Claims {
                iss: &env.client,
                sub: &env.client,
                aud: "https://elsewhere.example.com",
                exp_in: 60,
            })),
        ),
        (
            "expired",
            Env::credentials(env.key.sign(&Claims {
                iss: &env.client,
                sub: &env.client,
                aud: &env.issuer,
                exp_in: -120,
            })),
        ),
        ("not a JWT", Env::credentials("a.b.c".to_string())),
        ("replayed", Env::credentials(replayed.clone())),
        (
            "client_id names another client",
            vec![
                ("client_id", env.other.as_uuid().to_string()),
                ("client_assertion_type", JWT_BEARER.to_string()),
                ("client_assertion", env.assertion()),
            ],
        ),
    ];

    // Spend the assertion that the "replayed" case presents again.
    let mut first = vec![("grant_type", "client_credentials".to_string())];
    first.extend(Env::credentials(replayed));
    let a = env.post(Route::Header, "token", &first).await;
    assert_eq!(
        a.status, 200,
        "first use of the replayed assertion: {}",
        a.body
    );

    for route in ROUTES {
        for (what, creds) in &cases {
            let mut form = vec![("grant_type", "client_credentials".to_string())];
            form.extend(creds.clone());
            let a = env.post(route, "token", &form).await;
            assert_invalid_client(&a, &format!("{route:?} token {what}"));

            let mut form = vec![("token", uuid::Uuid::new_v4().to_string())];
            form.extend(creds.clone());
            let a = env.post(route, "introspect", &form).await;
            assert_invalid_client(&a, &format!("{route:?} introspect {what}"));

            let a = env.post(route, "device_authorization", creds).await;
            assert_invalid_client(&a, &format!("{route:?} device_authorization {what}"));
        }
    }
}

// ── a client that cannot be identified ───────────────────────────────────────

/// No credential names a client, or `client_id` is not a client id: `401
/// invalid_client`, never `400` with a free-text `error`.
#[tokio::test]
async fn an_unidentified_client_gets_invalid_client() {
    let env = env().await;
    let bad_id = format!("not-a-client-{}", uuid::Uuid::new_v4());
    for route in ROUTES {
        let cases: Vec<(&str, &str, Form)> = vec![
            ("token", "authorization_code, bad client_id", {
                let mut f = code_form(env.code());
                f.push(("client_id", bad_id.clone()));
                f
            }),
            (
                "token",
                "client_credentials, bad client_id",
                vec![
                    ("grant_type", "client_credentials".to_string()),
                    ("client_id", bad_id.clone()),
                ],
            ),
            (
                "token",
                "device_code, bad client_id",
                vec![
                    ("grant_type", DEVICE_GRANT.to_string()),
                    ("client_id", bad_id.clone()),
                    ("device_code", env.device_code()),
                ],
            ),
            (
                "token",
                "device_code, no client_id",
                vec![
                    ("grant_type", DEVICE_GRANT.to_string()),
                    ("device_code", env.device_code()),
                ],
            ),
            (
                "token",
                "jwt-bearer, bad client_id",
                vec![
                    ("grant_type", JWT_BEARER_GRANT.to_string()),
                    ("client_id", bad_id.clone()),
                    ("assertion", "a.b.c".to_string()),
                ],
            ),
            (
                "token",
                "jwt-bearer, no client_id",
                vec![
                    ("grant_type", JWT_BEARER_GRANT.to_string()),
                    ("assertion", "a.b.c".to_string()),
                ],
            ),
            ("device_authorization", "no client_id", vec![]),
            (
                "device_authorization",
                "bad client_id",
                vec![("client_id", bad_id.clone())],
            ),
        ];
        for (endpoint, what, form) in cases {
            let a = env.post(route, endpoint, &form).await;
            assert_invalid_client(&a, &format!("{route:?} {endpoint} {what}"));
        }
    }
}
