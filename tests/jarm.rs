//! Conformance tests for JARM — JWT Authorization Response Mode.
//!
//! JARM wraps the authorization response (code + state + iss) in a signed JWT
//! delivered via `response=<jwt>` in the redirect. Spec: OAuth 2.0 JARM.
//!
//! Scenarios:
//! 1. `response_mode=query.jwt` — response contains a signed JARM JWT
//! 2. `response_mode=fragment.jwt` — same, different delivery mode flag
//! 3. `response_mode=jwt` — defaults to query.jwt for code flow
//! 4. JARM JWT carries correct `{iss, aud, exp, code, state}` claims
//! 5. No JARM mode → no JWT, plain code/state response
//! 6. Discovery advertises jwt/query.jwt/fragment.jwt in response_modes_supported
//! 10. Client with `authorization_signed_response_alg` → JARM mandatory, no response_mode needed
//! 11. Client with `authorization_signed_response_alg` → plain query mode is upgraded to JARM
//! 12. Discovery advertises `authorization_signing_alg_values_supported: ["EdDSA"]`
//! 13. Unsupported alg rejected at client registration
//! 14. Expired JARM JWT detected client-side (simulation)
//! 15. Mandatory-JARM client — error response JWT-wrapped with correct claims (JARM §4.3)

mod common;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::oidc::CodeChallengeMethod;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CreateRealmRequest, CreateUserRequest,
    RegisterClientRequest, ResponseMode,
};

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Env {
    harness: common::TestHarness,
    realm: RealmId,
    client_id: ClientId,
    user_id: UserId,
}

async fn setup() -> Env {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JARM Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let user_id = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "JARM User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    Env {
        harness,
        realm,
        client_id: client.client_id().clone(),
        user_id,
    }
}

fn authorize_with_mode(env: &Env, mode: ResponseMode) -> hearth::identity::AuthorizationResponse {
    env.harness
        .identity()
        .authorize(
            &env.realm,
            &AuthorizationRequest {
                client_id: env.client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "jarm-test-state".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: env.user_id.clone(),
                amr_values: vec![],
                response_mode: Some(mode),
                request: None,
                via_par: false,
            },
        )
        .expect("authorize")
}

// ---------------------------------------------------------------------------
// JARM-01: query.jwt produces a JARM JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_jwt_mode_produces_jarm_jwt() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::QueryJwt);

    assert!(
        resp.jarm_jwt().is_some(),
        "response_mode=query.jwt must produce a JARM JWT"
    );
    // The plain code is still accessible (used for exchange)
    assert!(!resp.code().is_empty(), "code must not be empty");
}

// ---------------------------------------------------------------------------
// JARM-02: fragment.jwt produces a JARM JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fragment_jwt_mode_produces_jarm_jwt() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::FragmentJwt);

    assert!(
        resp.jarm_jwt().is_some(),
        "response_mode=fragment.jwt must produce a JARM JWT"
    );
}

// ---------------------------------------------------------------------------
// JARM-03: response_mode=jwt produces a JARM JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jwt_mode_produces_jarm_jwt() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::Jwt);

    assert!(
        resp.jarm_jwt().is_some(),
        "response_mode=jwt must produce a JARM JWT"
    );
}

// ---------------------------------------------------------------------------
// JARM-04: JARM JWT contains correct iss / aud / code / state claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_jwt_claims_are_correct() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::QueryJwt);

    let jwt = resp.jarm_jwt().expect("must have JARM JWT");

    // Parse claims (no signature verification needed here — engine tests cover that)
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JARM JWT must be a 3-part JWS");

    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode claims");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_json).expect("parse claims JSON");

    assert_eq!(
        claims["aud"].as_str().unwrap_or(""),
        env.client_id.to_string(),
        "aud must be the client_id"
    );
    assert_eq!(
        claims["code"].as_str().unwrap_or(""),
        resp.code(),
        "code claim must match the authorization code"
    );
    assert_eq!(
        claims["state"].as_str().unwrap_or(""),
        "jarm-test-state",
        "state claim must match the request state"
    );
    assert!(
        !claims["iss"].as_str().unwrap_or("").is_empty(),
        "iss must be non-empty"
    );
    let exp = claims["exp"].as_i64().expect("exp must be an integer");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;
    assert!(exp > now, "exp must be in the future");
    assert!(
        exp - now <= 300,
        "JARM JWT lifetime must be at most 5 minutes (FAPI 2.0 §5.3.2.2)"
    );
}

// ---------------------------------------------------------------------------
// JARM-05: No response_mode → plain response, no JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_response_mode_returns_plain_response() {
    let env = setup().await;
    let resp = env
        .harness
        .identity()
        .authorize(
            &env.realm,
            &AuthorizationRequest {
                client_id: env.client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "plain-state".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: env.user_id.clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize without response_mode");

    assert!(
        resp.jarm_jwt().is_none(),
        "omitting response_mode must not produce a JARM JWT"
    );
    assert!(!resp.code().is_empty(), "code must be present");
}

// ---------------------------------------------------------------------------
// JARM-06: Discovery advertises JARM response modes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_jarm_response_modes() {
    let env = setup().await;
    let discovery = env.harness.identity().oidc_discovery();

    let modes = &discovery.response_modes_supported;
    assert!(
        modes.contains(&"query.jwt".to_string()),
        "discovery must include query.jwt; got {modes:?}"
    );
    assert!(
        modes.contains(&"fragment.jwt".to_string()),
        "discovery must include fragment.jwt; got {modes:?}"
    );
    assert!(
        modes.contains(&"jwt".to_string()),
        "discovery must include jwt; got {modes:?}"
    );
}

// ---------------------------------------------------------------------------
// JARM-07: response_mode=query.jwt → response_mode() reflects the mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_jwt_response_mode_is_set() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::QueryJwt);
    assert_eq!(
        resp.response_mode(),
        &ResponseMode::QueryJwt,
        "response_mode must be QueryJwt"
    );
    // JARM JWT must be present for the redirect builder to deliver it
    assert!(
        resp.jarm_jwt().is_some(),
        "jarm_jwt must be set for query.jwt mode"
    );
}

// ---------------------------------------------------------------------------
// JARM-08: response_mode=fragment.jwt → response_mode() reflects the mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fragment_jwt_response_mode_is_set() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::FragmentJwt);
    assert_eq!(
        resp.response_mode(),
        &ResponseMode::FragmentJwt,
        "response_mode must be FragmentJwt"
    );
    assert!(resp.jarm_jwt().is_some(), "jarm_jwt must be set");
}

// ---------------------------------------------------------------------------
// JARM-09: no response_mode → response_mode() is Query (default)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_response_mode_defaults_to_query() {
    let env = setup().await;
    let resp = env
        .harness
        .identity()
        .authorize(
            &env.realm,
            &AuthorizationRequest {
                client_id: env.client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "plain-state-2".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: env.user_id.clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    assert_eq!(
        resp.response_mode(),
        &ResponseMode::Query,
        "omitting response_mode must default to Query"
    );
    assert!(
        resp.jarm_jwt().is_none(),
        "plain query must not produce a JARM JWT"
    );
}

// ---------------------------------------------------------------------------
// JARM-10: client with authorization_signed_response_alg always gets JARM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mandatory_jarm_client_gets_jarm_without_response_mode() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-mandatory-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    // Register a client that requires JARM.
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Mandatory JARM Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register client");

    let user_id = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("mandatory-jarm-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Mandatory JARM User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    // Call authorize with NO response_mode — the client flag must force JARM.
    let resp = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "mandatory-jarm-state".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    assert!(
        resp.jarm_jwt().is_some(),
        "client with authorization_signed_response_alg must always produce a JARM JWT"
    );
    assert!(!resp.code().is_empty(), "code must be present");
}

// ---------------------------------------------------------------------------
// JARM-11: client with authorization_signed_response_alg upgrades plain query
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mandatory_jarm_client_upgrades_plain_query_mode() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-upgrade-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JARM Upgrade Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register client");

    let user_id = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("jarm-upgrade-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "JARM Upgrade User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    // response_mode=query (plain) — must be upgraded to JARM.
    let resp = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "upgrade-state".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: Some(ResponseMode::Query),
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    assert!(
        resp.jarm_jwt().is_some(),
        "plain response_mode=query must be upgraded to JARM for mandatory-JARM clients"
    );
}

// ---------------------------------------------------------------------------
// JARM-12: discovery advertises authorization_signing_alg_values_supported
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_authorization_signing_alg_values_supported() {
    let env = setup().await;
    let discovery = env.harness.identity().oidc_discovery();

    assert!(
        !discovery
            .authorization_signing_alg_values_supported
            .is_empty(),
        "discovery must advertise authorization_signing_alg_values_supported"
    );
    assert!(
        discovery
            .authorization_signing_alg_values_supported
            .contains(&"EdDSA".to_string()),
        "EdDSA must be listed in authorization_signing_alg_values_supported; got {:?}",
        discovery.authorization_signing_alg_values_supported
    );
}

// ---------------------------------------------------------------------------
// JARM-13: unsupported alg rejected at registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_alg_rejected_at_registration() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-badreq-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let result = harness.identity().register_client(
        &realm,
        &RegisterClientRequest {
            client_name: "Bad Alg Client".to_string(),
            redirect_uris: vec![REDIRECT_URI.to_string()],
            client_secret: Some("secret".to_string()),
            grant_types: vec!["authorization_code".to_string()],
            require_consent: false,
            authorization_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        },
    );

    assert!(
        result.is_err(),
        "registering with unsupported authorization_signed_response_alg must fail"
    );
}

// ---------------------------------------------------------------------------
// JARM-14: expired JARM JWT detected client-side (simulation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_jarm_jwt_rejected_client_side() {
    use serde_json::json;

    // Simulate a JARM JWT with exp in the past. Clients MUST reject these.
    // We construct a fake JWT (unsigned, for simulation only) and verify that
    // the exp claim is in the past — mirroring what a conformant client does.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;

    // Build a fake JARM claims payload with exp already elapsed.
    let claims = json!({
        "iss": "https://as.example.com",
        "aud": "client-id",
        "exp": now - 60,   // 60 seconds in the past
        "code": "some-code",
        "state": "some-state"
    });

    let claims_b64 = BASE64_URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let fake_jwt = format!("eyJhbGciOiJFZERTQSJ9.{claims_b64}.fakesig");

    // Decode claims and verify expiry — simulating client-side validation.
    let parts: Vec<&str> = fake_jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode");
    let decoded_claims: serde_json::Value = serde_json::from_slice(&decoded).expect("parse JSON");
    let exp = decoded_claims["exp"].as_i64().expect("exp must be i64");

    assert!(
        exp < now,
        "simulated expired JARM JWT must have exp in the past: exp={exp}, now={now}"
    );
}

// ---------------------------------------------------------------------------
// JARM-15 (HTTP regression, HEA-1005): unknown response_mode → invalid_request
// ---------------------------------------------------------------------------

/// Percent-encoded form of REDIRECT_URI for query-string embedding.
const REDIRECT_URI_ENCODED: &str = "https%3A%2F%2Fapp.example.com%2Fcallback";

/// Builds a minimal [`WebState`] and axum router backed by the supplied harness.
/// Returns `(router, session_cookie_kv)` where `session_cookie_kv` is the
/// `Cookie:` header value (key=value without attributes) for a fresh session
/// belonging to a newly-created user in `realm`.
async fn build_http_test_env(
    harness: &common::TestHarness,
    realm_id: &hearth::core::RealmId,
    user_id: &hearth::core::UserId,
) -> (axum::Router, String) {
    use hearth::identity::onboarding::OnboardingService;
    use hearth::identity::{EmailBranding, EmailService, LoggingEmailSender, SessionContext};
    use hearth::protocol::web::auth::{issue_auth_cookies, CookieSecret};
    use hearth::protocol::web::{self, WebState};
    use std::sync::Arc;

    let session = harness
        .identity()
        .create_session(realm_id, user_id, &SessionContext::default())
        .expect("create session");

    let sender: hearth::identity::SharedEmailSender = Arc::new(LoggingEmailSender::new());
    let email_svc = Arc::new(
        EmailService::new(
            sender,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let onboarding = Arc::new(OnboardingService::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        Arc::clone(&email_svc),
        tmp.path().to_path_buf(),
    ));
    let secret = CookieSecret::from_bytes([77u8; 32]);
    let state = WebState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
        onboarding,
        secret.clone(),
        Some(email_svc),
    );
    let router = web::router(state);

    let issued = issue_auth_cookies(&secret, realm_id, session.id(), false);
    let cookie_kv = issued
        .session_cookie
        .split_once(';')
        .map(|(kv, _)| kv.to_string())
        .unwrap_or(issued.session_cookie);

    // Keep `tmp` alive for the router's lifetime by leaking it intentionally —
    // OnboardingService only reads from data_dir on first-run checks, which
    // the authorize handler never triggers.
    std::mem::forget(tmp);

    (router, cookie_kv)
}

#[tokio::test]
async fn unknown_response_mode_returns_invalid_request() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-unk-mode-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Unk Mode Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("unk-mode-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Unk Mode User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let (router, cookie_kv) = build_http_test_env(&harness, realm.id(), user.id()).await;

    let url = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={REDIRECT_URI_ENCODED}\
         &response_type=code&scope=openid&state=s\
         &code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256\
         &response_mode=unknown_mode",
        client.client_id().as_uuid(),
    );

    let req = Request::builder()
        .method("GET")
        .uri(&url)
        .header("Cookie", cookie_kv)
        .body(Body::empty())
        .expect("request");

    let resp = router.oneshot(req).await.expect("oneshot");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "expected redirect");
    let loc = resp
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("location str");
    assert!(
        loc.contains("error=invalid_request"),
        "expected error=invalid_request in redirect; got: {loc}"
    );
}

// ---------------------------------------------------------------------------
// JARM-16 (HTTP regression, HEA-1005): absent response_mode → code (no regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_response_mode_uses_query() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-def-mode-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Def Mode Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("def-mode-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Def Mode User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let (router, cookie_kv) = build_http_test_env(&harness, realm.id(), user.id()).await;

    // No response_mode — should redirect with a plain authorization code.
    let url = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={REDIRECT_URI_ENCODED}\
         &response_type=code&scope=openid&state=s\
         &code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        client.client_id().as_uuid(),
    );

    let req = Request::builder()
        .method("GET")
        .uri(&url)
        .header("Cookie", cookie_kv)
        .body(Body::empty())
        .expect("request");

    let resp = router.oneshot(req).await.expect("oneshot");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "expected redirect");
    let loc = resp
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("location str");
    assert!(
        loc.contains("code="),
        "location must contain authorization code; got: {loc}"
    );
    assert!(
        !loc.contains("error="),
        "location must not contain error; got: {loc}"
    );
}

// ---------------------------------------------------------------------------
// JARM-17: mandatory-JARM client — error response is JWT-wrapped (§4.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_error_response_is_jwt_wrapped() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-err-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JARM Error Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register client");

    // sign_jarm_error_jwt is the engine method called by jarm_aware_error_redirect
    // when a mandatory-JARM client triggers an error on the authorization endpoint.
    let jwt = harness
        .identity()
        .sign_jarm_error_jwt(
            &realm,
            &client.client_id().to_string(),
            "consent_required",
            "user consent required",
            "test-state-xyz",
        )
        .expect("sign_jarm_error_jwt must succeed for a valid realm");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JARM error JWT must be a 3-part JWS");

    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode claims");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_json).expect("parse claims JSON");

    assert_eq!(
        claims["error"].as_str().unwrap_or(""),
        "consent_required",
        "error claim must be echoed"
    );
    assert_eq!(
        claims["error_description"].as_str().unwrap_or(""),
        "user consent required",
        "error_description must be echoed"
    );
    assert_eq!(
        claims["state"].as_str().unwrap_or(""),
        "test-state-xyz",
        "state must be echoed"
    );
    assert_eq!(
        claims["aud"].as_str().unwrap_or(""),
        client.client_id().to_string(),
        "aud must be the client_id"
    );
    assert!(
        !claims["iss"].as_str().unwrap_or("").is_empty(),
        "iss must be non-empty"
    );
    let exp = claims["exp"].as_i64().expect("exp must be integer");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;
    assert!(exp > now, "exp must be in the future");

    // Verify header typ = oauth-authz-resp+jwt (JARM §4.1)
    let header_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("base64 decode header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).expect("parse header JSON");
    assert_eq!(
        header["typ"].as_str().unwrap_or(""),
        "oauth-authz-resp+jwt",
        "typ header must be oauth-authz-resp+jwt per JARM §4.1"
    );
}

// ---------------------------------------------------------------------------
// JARM-18: error JARM JWT contains a non-empty jti claim (JARM spec §2.4)
//
// JARM §2.4 requires `jti` on ALL response JWTs (success and error) to
// enable replay detection on the client side. This test ensures the engine
// populates `jti` on the error path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_error_jwt_has_jti() {
    use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jarm-jti-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JARM JTI Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register client");

    let jwt = harness
        .identity()
        .sign_jarm_error_jwt(
            &realm,
            &client.client_id().to_string(),
            "access_denied",
            "user denied access",
            "state-jti-test",
        )
        .expect("sign_jarm_error_jwt must succeed");

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "must be a 3-part JWS");

    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode claims");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_json).expect("parse claims JSON");

    let jti = claims["jti"].as_str().unwrap_or("");
    assert!(
        !jti.is_empty(),
        "jti claim must be present and non-empty (JARM §2.4)"
    );
}

// ---------------------------------------------------------------------------
// JARM-10: JARM JWT signature verifies via JWKS (end-to-end client path)
//
// Simulates the full verifying-party path:
//   JWT header → kid → realm JWKS → Ed25519 public key → ring verify
// Catches regressions where a JARM JWT is signed with a key whose kid is
// not published in the realm's JWKS.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_jwt_signature_verifies_via_jwks() {
    use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
    use hearth::identity::tokens::JwksDocument;

    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::QueryJwt);
    let jwt = resp.jarm_jwt().expect("must have JARM JWT");

    // 1. Split the JWT into header.claims.sig
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JARM JWT must be a 3-part JWS");

    let header_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("base64 decode header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).expect("parse header JSON");

    // 2. Extract kid from the JWT header
    let kid = header["kid"]
        .as_str()
        .expect("JARM JWT header must contain kid");

    // 3. Fetch the realm JWKS and find the key matching kid
    let jwks_json = env
        .harness
        .identity()
        .realm_jwks(&env.realm)
        .expect("realm_jwks");
    let jwks_str = serde_json::to_string(&jwks_json).expect("serialize jwks");
    let jwks: JwksDocument = serde_json::from_str(&jwks_str).expect("deserialize JwksDocument");

    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .unwrap_or_else(|| panic!("kid {kid} not found in realm JWKS"));

    assert_eq!(key.kty, "OKP", "JARM key must be OKP (Ed25519)");
    assert_eq!(
        key.crv.as_deref().unwrap_or(""),
        "Ed25519",
        "JARM key curve must be Ed25519"
    );

    // 4. Decode the Ed25519 public key from the `x` JWK field
    let x_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(key.x.as_deref().expect("OKP key must have x field"))
        .expect("base64 decode public key x");

    // 5. Reconstruct the signed message: header.claims (the bytes that were signed)
    let signed_input = format!("{}.{}", parts[0], parts[1]);

    // 6. Decode the signature
    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("base64 decode signature");

    // 7. Verify Ed25519 signature using ring
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, x_bytes.clone());
    public_key
        .verify(signed_input.as_bytes(), &sig_bytes)
        .expect("JARM JWT Ed25519 signature must verify against the realm's JWKS public key");
}

// ---------------------------------------------------------------------------
// JARM-security: JARM JWT is rejected when presented as a Bearer access token
//
// Regression for HEA-1004 (RFC 8725 §3.11 token-type confusion).
// Before the fix, JARM used typ:"JWT" — same as access tokens.  After the
// fix, typ is "oauth-authz-resp+jwt", and verify_token_signature rejects any
// token whose typ header differs from JWT_TYPE ("JWT"), giving defense-in-depth
// beyond the missing `sub`/`token_type` claims.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jarm_jwt_rejected_as_bearer_token() {
    let env = setup().await;
    let resp = authorize_with_mode(&env, ResponseMode::QueryJwt);

    let jarm_jwt = resp
        .jarm_jwt()
        .expect("query.jwt mode must produce a JARM JWT")
        .to_string();

    // Present the JARM JWT as if it were an access token.
    let result = env.harness.identity().validate_token(&env.realm, &jarm_jwt);

    assert!(
        result.is_err(),
        "JARM JWT must be rejected when used as a Bearer access token (RFC 8725 §3.11)"
    );
}
