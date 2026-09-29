//! A token session records the second factor the browser session behind it
//! proved (GA audit round 3, D-7).
//!
//! Exchanging an authorization code (or polling an approved device code)
//! opened the token's session with `MfaProof::Inherited`, whatever the browser
//! session that authorized it had proved. `Inherited` satisfies every
//! second-factor gate, so the JSON / gRPC `Authorize` check for a client or
//! role that demands a second factor never fired for a code-flow token: a
//! password-only or UV-less-passkey session was laundered into one that
//! "proved" a factor. The code and the device approval now carry the
//! authorizing session's proof into the token session.

#[path = "support/browser.rs"]
mod browser;

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use browser::{location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError, MfaProof, OAuthClient, RealmConfig, RegisterClientRequest, SessionContext,
    TokenExchangeRequest, UpdateClientRequest,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

const COOKIE_SECRET: [u8; 32] = [61u8; 32];
const CALLBACK: &str = "https://app.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    client: OAuthClient,
    user: UserId,
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    ));
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as _,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit) as _,
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("tok-proof-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Proof App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@proof.test", uuid::Uuid::new_v4().simple()),
                display_name: "Proof".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    )
    .with_dev_mode(false);
    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
        user,
    }
}

/// A browser signed in with a session whose login proved `proof`.
fn signed_in(rig: &Rig, proof: MfaProof) -> Browser {
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user,
            &SessionContext {
                mfa_proof: proof,
                ..SessionContext::default()
            },
        )
        .expect("browser session");
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        &rig.realm_id,
        session.id(),
        false,
    );
    let mut browser = Browser::new(rig.app.clone());
    browser.accept_set_cookie(&issued.session_cookie, "/ui/login");
    browser.accept_set_cookie(&issued.csrf_cookie, "/ui/login");
    browser
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ))
}

/// Runs the browser authorization and exchanges the code; returns the
/// access token.
async fn code_flow_token(rig: &Rig, browser: &mut Browser) -> String {
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s&code_challenge={}&code_challenge_method=S256",
        rig.client.client_id().as_uuid(),
        challenge()
    );
    let resp = browser.get(&uri).await;
    let next = location(&resp).expect("authorize redirects");
    assert!(next.starts_with(CALLBACK), "a code is issued: {next}");
    let code = next
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code parameter")
        .to_string();
    rig.identity
        .exchange_authorization_code(
            &rig.realm_id,
            &TokenExchangeRequest {
                client_id: rig.client.client_id().clone(),
                code,
                redirect_uri: CALLBACK.to_string(),
                code_verifier: Some(VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange")
        .access_token()
        .to_string()
}

/// The `mfa_proof` of the session an access token names.
fn token_session_proof(rig: &Rig, token: &str) -> MfaProof {
    let claims = rig
        .identity
        .validate_token(&rig.realm_id, token)
        .expect("valid token");
    let sid = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
    let session_id = hearth::core::SessionId::new(sid.parse().expect("session uuid"));
    rig.identity
        .get_session(&rig.realm_id, &session_id)
        .expect("lookup")
        .expect("token session")
        .mfa_proof()
}

#[tokio::test]
async fn a_code_carries_the_browser_sessions_proof_into_the_token_session() {
    let rig = build_rig();
    let mut browser = signed_in(&rig, MfaProof::Proved);
    let token = code_flow_token(&rig, &mut browser).await;
    assert_eq!(token_session_proof(&rig, &token), MfaProof::Proved);
}

#[tokio::test]
async fn a_code_from_an_unproved_session_opens_an_unproved_token_session() {
    let rig = build_rig();
    let mut browser = signed_in(&rig, MfaProof::None);
    let token = code_flow_token(&rig, &mut browser).await;
    assert_eq!(
        token_session_proof(&rig, &token),
        MfaProof::None,
        "the token session proved nothing its browser session did not"
    );
}

/// The gate the laundering defeated: once the client demands a second
/// factor, a code-flow token whose browser session proved none cannot mint
/// codes for it through the non-interactive `Authorize`.
#[tokio::test]
async fn an_unproved_code_flow_token_cannot_authorize_an_mfa_client() {
    let rig = build_rig();
    let mut browser = signed_in(&rig, MfaProof::None);
    let token = code_flow_token(&rig, &mut browser).await;
    rig.identity
        .update_client(
            &rig.realm_id,
            rig.client.client_id(),
            &UpdateClientRequest {
                mfa_required: Some(Some(true)),
                ..Default::default()
            },
        )
        .expect("the operator now requires MFA for the client");

    let bearer = rig
        .identity
        .validate_token(&rig.realm_id, &token)
        .expect("valid token");
    let result = rig.identity.authorize_non_interactive(
        &rig.realm_id,
        &AuthorizationRequest {
            client_id: rig.client.client_id().clone(),
            redirect_uri: CALLBACK.to_string(),
            scope: "openid".to_string(),
            state: "s2".to_string(),
            resource: None,
            response_type: "code".to_string(),
            user_id: rig.user.clone(),
            code_challenge: Some(challenge()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            nonce: None,
            amr_values: Vec::new(),
            response_mode: None,
            request: None,
            via_par: false,
        },
        &bearer,
    );
    assert!(
        matches!(result, Err(IdentityError::MfaRequired)),
        "an unproved session must not mint a code for an MFA client: {:?}",
        result.map(|_| ())
    );
}
