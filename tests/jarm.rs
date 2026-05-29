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

mod common;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::oidc::CodeChallengeMethod;
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, RegisterClientRequest,
    ResponseMode,
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
        .unwrap()
        .as_secs() as i64;
    assert!(exp > now, "exp must be in the future");
    assert!(
        exp - now <= 600,
        "JARM JWT lifetime must be at most 10 minutes"
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
