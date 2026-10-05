//! RFC 9449 §5.2 `dpop_bound_access_tokens`: a client registered with the
//! flag gets tokens only against a DPoP proof, on every grant.
//!
//! This replaces the FAPI 2.0 gate removed in 3.0.0 (scope-trim-trusted-core,
//! group 9): what used to be "a FAPI client or realm without DPoP is refused"
//! is now "a `dpop_bound_access_tokens` client without DPoP is refused with
//! `InvalidDPopProof`". Each grant is pinned here with its control — the same
//! client with a proof gets a token bound to that key (`cnf.jkt`):
//!
//! - authorization code;
//! - refresh token (including a family issued before the flag was set);
//! - JWT bearer (RFC 7523) — the refusal leaves the assertion unspent;
//! - device code (RFC 8628) — the refusal leaves the approved code redeemable.
//!
//! `client_credentials` is pinned in `tests/fapi_jarm_removed.rs` and
//! `tests/abuse_dpop_act.rs` (A-38a).

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::oidc::CodeChallengeMethod;
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    decode_claims_unverified, AuthorizationRequest, CreateRealmRequest, CreateUserRequest,
    DeviceAuthorizationRequest, IdentityError, JwtBearerRequest, RefreshBindContext,
    RegisterClientRequest, SigningKey, TokenExchangeRequest, UpdateClientRequest,
};

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// S256 of [`PKCE_VERIFIER`] (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SECRET: &str = "dpop-bound-client-secret-0123456789";
const JKT: &str = "dpop-bound-client-thumbprint-A";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
}

async fn env() -> Env {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-bound-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    // The scope registry refuses a scope the realm does not define.
    h.declare_scopes(&realm, &["read"]);
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("dpop-bound-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "DPoP-bound user".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    Env { h, realm, user }
}

fn assert_invalid_dpop_proof(err: &IdentityError, what: &str) {
    assert!(
        matches!(err, IdentityError::InvalidDPopProof { .. }),
        "{what}: expected InvalidDPopProof, got {err:?}"
    );
}

fn assert_bound(h: &common::TestHarness, realm: &RealmId, access_token: &str, what: &str) {
    let claims = h
        .identity()
        .validate_token(realm, access_token)
        .expect("bound access token validates");
    assert_eq!(
        claims.cnf.as_ref().map(|c| c.jkt.as_str()),
        Some(JKT),
        "{what}: the token is bound to the proof's key"
    );
}

impl Env {
    /// A confidential authorization-code client with the refresh grant.
    fn code_client(&self, dpop_bound: bool) -> ClientId {
        self.h
            .identity()
            .register_client(
                &self.realm,
                &RegisterClientRequest {
                    client_name: format!("dpop-bound-code-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                    client_secret: Some(SECRET.to_string()),
                    grant_types: vec![
                        "authorization_code".to_string(),
                        "refresh_token".to_string(),
                    ],
                    require_consent: false,
                    dpop_bound_access_tokens: dpop_bound,
                    ..Default::default()
                },
            )
            .expect("register code client")
            .client_id()
            .clone()
    }

    fn code(&self, client: &ClientId) -> String {
        self.h
            .identity()
            .grant_consent(
                &self.realm,
                &hearth::identity::ConsentGrant {
                    key: hearth::identity::ConsentKey {
                        user_id: self.user.clone(),
                        client_id: client.clone(),
                        org_id: None,
                        resource: None,
                    },
                    scopes: vec!["openid".to_string()],
                    via: hearth::identity::ConsentSurface::Web,
                },
            )
            .expect("consent");
        self.h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    organization: None,
                    client_id: client.clone(),
                    redirect_uri: REDIRECT_URI.to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    state: "dpop-bound-state".to_string(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.to_string()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .expect("authorize")
            .code()
            .to_string()
    }

    fn exchange(
        &self,
        client: &ClientId,
        code: String,
        dpop_jkt: Option<&str>,
    ) -> Result<hearth::identity::OidcTokenResponse, IdentityError> {
        self.h.identity().exchange_authorization_code(
            &self.realm,
            &TokenExchangeRequest {
                client_id: client.clone(),
                code,
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: dpop_jkt.map(str::to_string),
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
    }
}

// ── authorization code ───────────────────────────────────────────────────────

#[tokio::test]
async fn authorization_code_without_a_proof_is_refused() {
    let env = env().await;
    let client = env.code_client(true);
    let err = env
        .exchange(&client, env.code(&client), None)
        .expect_err("a dpop_bound_access_tokens client must not get an unbound token");
    assert_invalid_dpop_proof(&err, "authorization_code");
}

#[tokio::test]
async fn authorization_code_with_a_proof_gets_a_bound_token() {
    let env = env().await;
    let client = env.code_client(true);
    let resp = env
        .exchange(&client, env.code(&client), Some(JKT))
        .expect("a proof satisfies the requirement");
    assert_bound(
        &env.h,
        &env.realm,
        resp.access_token(),
        "authorization_code",
    );
}

/// Control: a client without the flag still redeems a code without a proof.
#[tokio::test]
async fn authorization_code_without_the_flag_stays_bearer() {
    let env = env().await;
    let client = env.code_client(false);
    let resp = env
        .exchange(&client, env.code(&client), None)
        .expect("bearer tokens stay available");
    let claims = decode_claims_unverified(resp.access_token()).expect("decode");
    assert!(claims.cnf.is_none(), "no proof, no binding");
}

// ── refresh token ────────────────────────────────────────────────────────────

/// A family issued as Bearer before the client was flagged no longer
/// refreshes without a proof once the flag is set; with a proof it does, and
/// the new access token is bound.
#[tokio::test]
async fn refresh_without_a_proof_is_refused_once_the_client_is_flagged() {
    let env = env().await;
    let client = env.code_client(false);
    let tokens = env
        .exchange(&client, env.code(&client), None)
        .expect("bearer exchange before the flag");
    env.h
        .identity()
        .update_client(
            &env.realm,
            &client,
            &UpdateClientRequest {
                dpop_bound_access_tokens: Some(true),
                ..Default::default()
            },
        )
        .expect("flag the client");
    assert!(
        env.h
            .identity()
            .get_client(&env.realm, &client)
            .expect("lookup")
            .expect("client exists")
            .dpop_bound_access_tokens(),
        "the update stored the flag"
    );

    let bind = RefreshBindContext {
        authenticated_client_id: Some(client.clone()),
    };
    let err = env
        .h
        .identity()
        .refresh_tokens(&env.realm, tokens.refresh_token(), None, Some(&bind))
        .expect_err("a flagged client must not refresh without a proof");
    assert_invalid_dpop_proof(&err, "refresh_token");

    let refreshed = env
        .h
        .identity()
        .refresh_tokens(&env.realm, tokens.refresh_token(), Some(JKT), Some(&bind))
        .expect("the same refresh token rotates with a proof");
    assert_bound(
        &env.h,
        &env.realm,
        refreshed.access_token(),
        "refresh_token",
    );
}

/// A family bound at issuance refreshes with the same key, and the refreshed
/// access token carries `cnf.jkt` (RFC 9449 §5, §7).
#[tokio::test]
async fn refresh_with_the_bound_proof_gets_a_bound_token() {
    let env = env().await;
    let client = env.code_client(true);
    let tokens = env
        .exchange(&client, env.code(&client), Some(JKT))
        .expect("bound exchange");
    let bind = RefreshBindContext {
        authenticated_client_id: Some(client.clone()),
    };
    env.h
        .identity()
        .refresh_tokens(&env.realm, tokens.refresh_token(), None, Some(&bind))
        .expect_err("a bound family must not refresh without a proof");
    let refreshed = env
        .h
        .identity()
        .refresh_tokens(&env.realm, tokens.refresh_token(), Some(JKT), Some(&bind))
        .expect("refresh with the bound key");
    assert_bound(
        &env.h,
        &env.realm,
        refreshed.access_token(),
        "refresh_token",
    );
}

/// Control: a client without the flag refreshes a Bearer family without a
/// proof.
#[tokio::test]
async fn refresh_without_the_flag_stays_bearer() {
    let env = env().await;
    let client = env.code_client(false);
    let tokens = env
        .exchange(&client, env.code(&client), None)
        .expect("bearer exchange");
    let refreshed = env
        .h
        .identity()
        .refresh_tokens(
            &env.realm,
            tokens.refresh_token(),
            None,
            Some(&RefreshBindContext {
                authenticated_client_id: Some(client.clone()),
            }),
        )
        .expect("an unflagged client refreshes without DPoP");
    let claims = decode_claims_unverified(refreshed.access_token()).expect("decode");
    assert!(claims.cnf.is_none(), "no proof, no binding");
}

// ── JWT bearer (RFC 7523) ────────────────────────────────────────────────────

fn realm_issuer(h: &common::TestHarness, realm: &RealmId) -> String {
    let name = h
        .identity()
        .get_realm(realm)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();
    format!("{}/realms/{name}", h.identity().oidc_discovery().issuer)
}

fn jwt_bearer_assertion(key: &SigningKey, client: &ClientId, audience: &str) -> String {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("time fits i64");
    let id = client.as_uuid().to_string();
    key.issue_assertion_jwt(&JwtAssertionClaims {
        iss: id.clone(),
        sub: id,
        aud: Audience::single(audience.to_string()),
        exp: now + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: Some(now),
    })
    .expect("sign assertion")
}

/// The flag refuses a jwt-bearer grant without a proof; the refusal leaves
/// the assertion's `jti` unspent, so the same assertion succeeds with a proof
/// and yields a bound token.
#[tokio::test]
async fn jwt_bearer_without_a_proof_is_refused_and_the_assertion_stays_usable() {
    let env = env().await;
    let key = SigningKey::generate().expect("generate key");
    let client = env
        .h
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "dpop-bound-jwt-bearer".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                dpop_bound_access_tokens: true,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone();
    env.h
        .identity()
        .update_client(
            &env.realm,
            &client,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("set assertion key");
    let assertion = jwt_bearer_assertion(&key, &client, &realm_issuer(&env.h, &env.realm));
    let request = |dpop_jkt: Option<&str>| JwtBearerRequest {
        client_id: client.clone(),
        assertion: assertion.clone(),
        scope: Some("read".to_string()),
        dpop_jkt: dpop_jkt.map(str::to_string),
    };

    let err = env
        .h
        .identity()
        .jwt_bearer_token(&env.realm, &request(None))
        .expect_err("a flagged client must not get an unbound jwt-bearer token");
    assert_invalid_dpop_proof(&err, "jwt-bearer");

    let resp = env
        .h
        .identity()
        .jwt_bearer_token(&env.realm, &request(Some(JKT)))
        .expect("the same assertion succeeds with a proof");
    assert_bound(&env.h, &env.realm, resp.access_token(), "jwt-bearer");
}

// ── device code (RFC 8628) ───────────────────────────────────────────────────

/// The flag refuses the device grant without a proof; the refusal does not
/// consume the approved code, so the device can retry with one.
#[tokio::test]
async fn device_code_without_a_proof_is_refused_and_the_code_stays_redeemable() {
    let env = env().await;
    let client = env
        .h
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "dpop-bound-device".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![DEVICE_GRANT.to_string(), "refresh_token".to_string()],
                require_consent: false,
                dpop_bound_access_tokens: true,
                ..Default::default()
            },
        )
        .expect("register device client")
        .client_id()
        .clone();
    let started = env
        .h
        .identity()
        .device_authorize(
            &env.realm,
            &DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");
    env.h
        .identity()
        .approve_device(&env.realm, &started.user_code, &env.user)
        .expect("approve device");

    let err = env
        .h
        .identity()
        .poll_device_token(&env.realm, &started.device_code, &client, None)
        .expect_err("a flagged client must not get unbound device tokens");
    assert_invalid_dpop_proof(&err, "device_code");

    let resp = env
        .h
        .identity()
        .poll_device_token(&env.realm, &started.device_code, &client, Some(JKT))
        .expect("the same code redeems with a proof");
    assert_eq!(resp.token_type(), "DPoP");
    assert_bound(&env.h, &env.realm, resp.access_token(), "device_code");
}
