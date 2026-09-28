#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 B2 / L8 — the non-interactive authorization surfaces.
//!
//! `POST /authorize`, `POST /realms/{realm}/authorize` and gRPC `Authorize`
//! mint an authorization code from a bearer token alone. They issued one for
//! ANY client and ANY scope with no consent: `authorize_inner` only re-checked
//! a consent record that already existed. Any access token of user U — one
//! leaked from an unrelated app — became a code for any client, delivered in
//! the JSON body so the registered redirect URI did not protect it.
//!
//! The browser flow runs a consent gate (`authorize_gate::consent_gate`):
//! issue only when the client does not require consent, or a recorded consent
//! covers the requested scopes. These surfaces cannot show a consent screen,
//! so they now apply that same rule and refuse with `consent_required`
//! otherwise.
//!
//! L8: `realm_authorize` built the DPoP `htu` from the nested `Uri`, whose
//! `/realms/{realm}` prefix axum strips, so no correct proof could ever match.
//!
//! gRPC `Authorize` and `Decide` ignored the DPoP `cnf` binding; they now
//! refuse a sender-constrained token as the gRPC admin surface does.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, RegisterClientRequest, SessionContext, TokenExchangeRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1::{self as pb, o_auth_service_server::OAuthService};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// ── DPoP helpers (mirrors tests/admin_dpop_sender_constraint.rs) ────────────

struct DPopKey {
    key_pair: EcdsaKeyPair,
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
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": b64.encode(&self.pub_bytes[1..33]),
            "y": b64.encode(&self.pub_bytes[33..65]),
        })
    }

    fn thumbprint(&self) -> String {
        let jwk = serde_json::to_string(&self.public_jwk_json()).unwrap();
        let digest = ring::digest::digest(&ring::digest::SHA256, jwk.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// A resource-server proof (RFC 9449 §4.2) binding `access_token` via `ath`.
    #[allow(clippy::similar_names)]
    fn resource_proof(&self, htm: &str, htu: &str, access_token: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header =
            serde_json::json!({"alg": "ES256", "jwk": self.public_jwk_json(), "typ": "dpop+jwt"});
        #[allow(clippy::cast_possible_wrap)]
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ath = b64
            .encode(ring::digest::digest(&ring::digest::SHA256, access_token.as_bytes()).as_ref());
        let claims = serde_json::json!({
            "htm": htm, "htu": htu, "iat": iat,
            "jti": uuid::Uuid::new_v4().to_string(), "ath": ath,
        });
        let msg = format!(
            "{}.{}",
            b64.encode(serde_json::to_vec(&header).unwrap()),
            b64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = self
            .key_pair
            .sign(&SystemRandom::new(), msg.as_bytes())
            .unwrap();
        format!("{msg}.{}", b64.encode(sig.as_ref()))
    }
}

// ── Fixture ─────────────────────────────────────────────────────────────────

struct Fixture {
    harness: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    user: UserId,
    /// An unbound access token for `user` (a first-party session token).
    token: String,
}

async fn setup() -> Fixture {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm_name = format!("nonint-{}", uuid::Uuid::new_v4());
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@nonint.test", uuid::Uuid::new_v4()),
                display_name: "Non-interactive".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let session = harness
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let token = harness
        .identity()
        .issue_tokens(&realm, &user, session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    Fixture {
        harness,
        realm,
        realm_name,
        user,
        token,
    }
}

impl Fixture {
    fn register(&self, trust_level: ClientTrustLevel, require_consent: bool) -> ClientId {
        self.harness
            .identity()
            .register_client(
                &self.realm,
                &RegisterClientRequest {
                    client_name: "nonint-client".into(),
                    redirect_uris: vec![REDIRECT_URI.into()],
                    grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                    require_consent,
                    trust_level,
                    declared_scopes: vec!["openid".into(), "profile".into()],
                    ..Default::default()
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    }

    fn app(&self) -> axum::Router {
        router(Arc::new(AppState::new(
            self.harness.identity_arc(),
            self.harness.rbac_arc(),
            self.harness.audit_arc(),
        )))
    }

    fn grpc(&self) -> OAuthSvc {
        OAuthSvc::new(GrpcState::new(
            self.harness.identity_arc(),
            self.harness.rbac_arc(),
            self.harness.audit_arc(),
            Arc::new(AdminRateLimiter::new()),
        ))
    }

    /// Mints a DPoP-bound (`cnf.jkt`) access token for `user` via `client`.
    fn bound_token(&self, client: &ClientId, jkt: &str) -> String {
        let auth = self
            .harness
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    client_id: client.clone(),
                    redirect_uri: REDIRECT_URI.into(),
                    response_type: "code".into(),
                    // Two scopes: a single-scope token narrows `decide` to that
                    // scope bundle, which would mask the binding under test.
                    scope: "openid profile".into(),
                    state: "s".into(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                    via_par: false,
                },
            )
            .expect("authorize");
        self.harness
            .identity()
            .exchange_authorization_code(
                &self.realm,
                &TokenExchangeRequest {
                    client_id: client.clone(),
                    code: auth.code().to_string(),
                    redirect_uri: REDIRECT_URI.into(),
                    code_verifier: Some(PKCE_VERIFIER.into()),
                    dpop_jkt: Some(jkt.to_string()),
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("exchange")
            .access_token()
            .to_string()
    }
}

fn authorize_body(client: &ClientId, scope: &str) -> String {
    serde_json::json!({
        "client_id": client.as_uuid().to_string(),
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": "st",
        "response_type": "code",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    })
    .to_string()
}

async fn post_authorize(
    f: &Fixture,
    uri: &str,
    token: &str,
    body: String,
    dpop: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", f.realm.as_uuid().to_string())
        .header("content-type", "application/json");
    if let Some(proof) = dpop {
        req = req.header("dpop", proof);
    }
    let resp = f
        .app()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn assert_consent_required(status: StatusCode, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{what}: a client that requires consent, with no recorded consent, must \
         be refused; body {body}"
    );
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_CONSENT_REQUIRED"),
        "{what}: the refusal must be the consent refusal; body {body}"
    );
    assert!(body.get("code").is_none(), "{what}: no code may be issued");
}

// ── B2: global and realm JSON /authorize ────────────────────────────────────

#[tokio::test]
async fn json_authorize_refuses_a_client_that_requires_consent_without_a_recorded_consent() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::ThirdParty, true);

    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &f.token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_consent_required(status, &body, "POST /authorize");

    let realm_uri = format!("/realms/{}/authorize", f.realm_name);
    let (status, body) = post_authorize(
        &f,
        &realm_uri,
        &f.token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_consent_required(status, &body, "POST /realms/{realm}/authorize");
}

#[tokio::test]
async fn json_authorize_issues_a_code_when_a_recorded_consent_covers_the_scopes() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::ThirdParty, true);
    f.harness
        .identity()
        .grant_consent(&f.realm, &f.user, &client, &["openid".to_string()])
        .expect("grant consent");

    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &f.token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "covered consent must issue; body {body}"
    );
    assert!(
        body["code"].as_str().is_some_and(|c| !c.is_empty()),
        "a code must be issued; body {body}"
    );

    // A scope the user never approved is not covered.
    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &f.token,
        authorize_body(&client, "openid profile"),
        None,
    )
    .await;
    assert_consent_required(status, &body, "POST /authorize with an unconsented scope");
}

#[tokio::test]
async fn json_authorize_issues_a_code_for_a_client_that_does_not_require_consent() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::FirstParty, false);

    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &f.token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "no consent needed; body {body}");
    assert!(
        body["code"].as_str().is_some_and(|c| !c.is_empty()),
        "a code must be issued; body {body}"
    );
}

// ── B2 + B5: the factor the bearer token's session PROVED ───────────────────

/// A client that sets `mfa_required` needs a session that proved a second
/// factor — the rule `authorize_gate::mfa_use_gate` applies in the browser.
/// The JSON surface has no challenge to offer, so it refuses outright when the
/// bearer token's session proved none.
#[tokio::test]
async fn json_authorize_refuses_an_mfa_required_client_for_an_unproved_session() {
    let f = setup().await;
    let client = f
        .harness
        .identity()
        .register_client(
            &f.realm,
            &RegisterClientRequest {
                client_name: "mfa-app".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                mfa_required: Some(true),
                ..Default::default()
            },
        )
        .expect("register")
        .client_id()
        .clone();

    // `f.token` belongs to a session that proved no factor.
    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &f.token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body {body}");
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_MFA_REQUIRED"),
        "the refusal must be the MFA refusal; body {body}"
    );

    // Control: a token from a session that proved a factor is issued a code.
    let proved = f
        .harness
        .identity()
        .create_session(
            &f.realm,
            &f.user,
            &SessionContext {
                mfa_proof: hearth::identity::MfaProof::Proved,
                ..SessionContext::default()
            },
        )
        .expect("proved session");
    let proved_token = f
        .harness
        .identity()
        .issue_tokens(&f.realm, &f.user, proved.id())
        .expect("issue")
        .access_token()
        .to_string();
    let (status, body) = post_authorize(
        &f,
        "/authorize",
        &proved_token,
        authorize_body(&client, "openid"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a proved session gets the code; body {body}"
    );
}

// ── L8: realm_authorize DPoP htu ─────────────────────────────────────────────

#[tokio::test]
async fn realm_authorize_accepts_a_dpop_proof_for_the_full_request_path() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::FirstParty, false);
    let key = DPopKey::generate();
    let bound = f.bound_token(&client, &key.thumbprint());

    let path = format!("/realms/{}/authorize", f.realm_name);
    let issuer = f.harness.identity().oidc_discovery().issuer;
    let proof = key.resource_proof("POST", &format!("{issuer}{path}"), &bound);
    let (status, body) = post_authorize(
        &f,
        &path,
        &bound,
        authorize_body(&client, "openid"),
        Some(&proof),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a DPoP proof signed over the path the client actually called must be \
         accepted; body {body}"
    );
}

// ── B2 + DPoP: gRPC Authorize and Decide ─────────────────────────────────────

fn grpc_request<T>(f: &Fixture, token: &str, body: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(body);
    req.metadata_mut()
        .insert("x-realm-id", f.realm.as_uuid().to_string().parse().unwrap());
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn grpc_authorize_body(client: &ClientId) -> pb::AuthorizationRequest {
    pb::AuthorizationRequest {
        client_id: client.as_uuid().to_string(),
        redirect_uri: REDIRECT_URI.into(),
        scope: "openid".into(),
        state: "st".into(),
        response_type: "code".into(),
        user_id: String::new(),
        code_challenge: Some(PKCE_CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
        nonce: None,
        request_uri: None,
    }
}

#[tokio::test]
async fn grpc_authorize_refuses_a_client_that_requires_consent_without_a_recorded_consent() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::ThirdParty, true);
    let err = f
        .grpc()
        .authorize(grpc_request(&f, &f.token, grpc_authorize_body(&client)))
        .await
        .expect_err("gRPC Authorize must not issue a code without consent");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "got {err:?}");

    // Control: once consent is recorded, the same call issues a code.
    f.harness
        .identity()
        .grant_consent(&f.realm, &f.user, &client, &["openid".to_string()])
        .expect("grant consent");
    let code = f
        .grpc()
        .authorize(grpc_request(&f, &f.token, grpc_authorize_body(&client)))
        .await
        .expect("covered consent issues a code")
        .into_inner()
        .code;
    assert!(!code.is_empty(), "a code must be issued");
}

#[tokio::test]
async fn grpc_authorize_refuses_a_dpop_bound_token() {
    let f = setup().await;
    let client = f.register(ClientTrustLevel::FirstParty, false);
    let bound = f.bound_token(&client, &DPopKey::generate().thumbprint());
    let err = f
        .grpc()
        .authorize(grpc_request(&f, &bound, grpc_authorize_body(&client)))
        .await
        .expect_err("a cnf-bound token has no proof channel on gRPC and must be refused");
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "got {err:?}");
}

#[tokio::test]
async fn grpc_decide_denies_a_dpop_bound_token() {
    use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

    let f = setup().await;
    let role = f
        .harness
        .rbac()
        .create_role(
            &f.realm,
            &CreateRoleRequest {
                name: "docs.viewer".into(),
                description: None,
                permissions: vec![Permission::new("docs.view").unwrap()],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    f.harness
        .rbac()
        .assign_role(
            &f.realm,
            &AssignRoleRequest {
                subject: Subject::User(f.user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let client = f.register(ClientTrustLevel::FirstParty, false);
    let bound = f.bound_token(&client, &DPopKey::generate().thumbprint());

    let svc = f.grpc();
    let decide = |token: &str| {
        svc.decide(grpc_request(
            &f,
            token,
            pb::TokenDecisionRequest {
                permission: "docs.view".into(),
                ..Default::default()
            },
        ))
    };

    // Control: the unbound token of the same user is allowed, so a denial
    // below is the binding and not the permission.
    let unbound = decide(&f.token).await.expect("decide").into_inner();
    assert!(unbound.allowed, "control: the user holds docs.view");

    let bound = decide(&bound).await.expect("decide").into_inner();
    assert!(
        !bound.allowed,
        "a cnf-bound token replayed without a DPoP proof must be denied, as \
         POST /oauth/authorize denies it"
    );
}
