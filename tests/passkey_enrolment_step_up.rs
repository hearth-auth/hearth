//! Step-up authentication on passkey enrolment (audit 2026-08-28 §4.18#2).
//!
//! A session alone MUST NOT be enough to enrol a new passkey. A stolen session
//! would otherwise mint a permanent credential the account owner never sees.
//! Both enrolment surfaces share one challenge store, so both are covered here:
//!
//! * `POST /ui/account/passkeys/register-begin` — browser, session cookie.
//! * `POST /webauthn/register/begin` — REST, user access token.
//!
//! Accepted step-up proofs: the account password, a current TOTP code, or an
//! assertion from an already-enrolled passkey. An account that holds none of
//! the three has nothing to prove, so enrolment proceeds.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    AuthenticationOptions, CleartextPassword, CreateRealmRequest, CreateUserRequest,
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext,
    TokenIssuanceContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router as http_router, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];
const PASSWORD: &str = "correct-horse-battery-staple";
const WRONG_PASSWORD: &str = "not-the-password-at-all-1234";
/// `public_origin_str` falls back to the `Host` header, which `oneshot`
/// requests omit — so the pinned origin is `http://localhost` and the RP ID
/// is `localhost`.
const TEST_ORIGIN: &str = "http://localhost";
const TEST_RP_ID: &str = "localhost";

// ---------------------------------------------------------------------------
// Minimal mock authenticator — trimmed copy of the helper in `tests/webauthn.rs`.
// ---------------------------------------------------------------------------

mod webauthn_helper {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    const COSE_ALG_ES256: i64 = -7;

    pub struct TestAuthenticator {
        key_pair_pkcs8: Vec<u8>,
        pub credential_id: Vec<u8>,
        rp_id: String,
    }

    impl TestAuthenticator {
        pub fn new(rp_id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");
            let mut cred_id = vec![0u8; 32];
            rng.fill(&mut cred_id).expect("random cred id");
            Self {
                key_pair_pkcs8: pkcs8.as_ref().to_vec(),
                credential_id: cred_id,
                rp_id: rp_id.to_string(),
            }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let pub_bytes = key_pair.public_key().as_ref();
            let x = &pub_bytes[1..33];
            let y = &pub_bytes[33..65];
            let cose_map = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ),
                (
                    ciborium::Value::Integer(3.into()),
                    ciborium::Value::Integer(COSE_ALG_ES256.into()),
                ),
                (
                    ciborium::Value::Integer((-1).into()),
                    ciborium::Value::Integer(1.into()),
                ),
                (
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x.to_vec()),
                ),
                (
                    ciborium::Value::Integer((-3).into()),
                    ciborium::Value::Bytes(y.to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&cose_map, &mut buf).expect("encode COSE key");
            buf
        }

        #[allow(clippy::cast_possible_truncation)]
        fn build_auth_data(
            &self,
            sign_count: u32,
            include_credential: bool,
            user_verified: bool,
        ) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref());
            let mut flags: u8 = if include_credential { 0x41 } else { 0x01 };
            if user_verified {
                flags |= 0x04;
            }
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if include_credential {
                data.extend_from_slice(&[0u8; 16]); // AAGUID
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        fn client_data_json(ceremony_type: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "type": ceremony_type,
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": origin,
            }))
            .expect("serialize clientDataJSON")
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            key_pair.sign(&rng, data).expect("sign").as_ref().to_vec()
        }

        /// Returns `(client_data_json, attestation_object)`.
        pub fn registration(&self, challenge: &[u8], origin: &str) -> (Vec<u8>, Vec<u8>) {
            let client_data_json = Self::client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.build_auth_data(0, true, true);
            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("none".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);
            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation");
            (client_data_json, att_bytes)
        }

        /// Returns `(client_data_json, authenticator_data, signature)`.
        pub fn assertion(
            &self,
            challenge: &[u8],
            origin: &str,
            sign_count: u32,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let client_data_json = Self::client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.build_auth_data(sign_count, false, true);
            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(client_data_hash.as_ref());
            let sig = self.sign(&signed);
            (client_data_json, auth_data, sig)
        }
    }
}

use webauthn_helper::TestAuthenticator;

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes a TOTP code from a base32 secret — same algorithm as the engine.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

// ---------------------------------------------------------------------------
// Browser rig
// ---------------------------------------------------------------------------

struct WebRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
    session_id: SessionId,
}

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

/// Builds the `/ui` router with one active user. `with_password` decides
/// whether the account holds a password credential at all.
fn build_web_rig(with_password: bool) -> WebRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    if with_password {
        identity
            .set_password(
                realm.id(),
                user.id(),
                &CleartextPassword::from_string(PASSWORD.to_string()),
            )
            .expect("set password");
    }
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    let session = identity
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("create session");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    )
    .with_dev_mode(true);

    WebRig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        session_id: session.id().clone(),
    }
}

fn auth_cookie(rig: &WebRig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.session_id.as_uuid(),
        rig.realm_id.as_uuid(),
        tag,
        csrf,
    )
}

/// Posts a step-up body to the browser enrolment endpoint.
async fn web_register_begin(rig: &WebRig, body: serde_json::Value) -> (StatusCode, String) {
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/passkeys/register-begin")
                .header(header::COOKIE, auth_cookie(rig, "csrf-abc"))
                .header("x-csrf-token", "csrf-abc")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Browser surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn web_enrolment_without_a_proof_is_refused() {
    let rig = build_web_rig(true);
    let (status, body) = web_register_begin(&rig, serde_json::json!({})).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a session alone must not start a passkey enrolment; body: {body}"
    );
    assert!(
        body.contains("step_up_required"),
        "response must name the missing step-up; body: {body}"
    );
}

#[tokio::test]
async fn web_enrolment_with_a_wrong_password_is_refused() {
    let rig = build_web_rig(true);
    let (status, body) =
        web_register_begin(&rig, serde_json::json!({ "password": WRONG_PASSWORD })).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains("step_up_required"), "body: {body}");
}

#[tokio::test]
async fn web_enrolment_with_the_current_password_is_allowed() {
    let rig = build_web_rig(true);
    let (status, body) =
        web_register_begin(&rig, serde_json::json!({ "password": PASSWORD })).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert!(
        parsed.get("challenge").and_then(|c| c.as_str()).is_some(),
        "a passed step-up must return a registration challenge; body: {body}"
    );
}

#[tokio::test]
async fn web_enrolment_with_a_current_totp_code_is_allowed() {
    let rig = build_web_rig(true);
    let enrollment = rig
        .identity
        .enroll_totp(&rig.realm_id, &rig.user_id)
        .expect("enroll_totp");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    rig.identity
        .verify_totp_enrollment(&rig.realm_id, &rig.user_id, &code)
        .expect("verify_totp_enrollment");

    // A fresh code from the next time step — the enrolment code is burned.
    let next = compute_totp_code(&enrollment.secret_base32, now_secs + 30);
    let (status, body) = web_register_begin(&rig, serde_json::json!({ "totp_code": next })).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn web_enrolment_with_an_existing_passkey_assertion_is_allowed() {
    let rig = build_web_rig(true);

    // Enrol a first passkey directly through the engine.
    let authenticator = TestAuthenticator::new(TEST_RP_ID);
    let challenge = rig
        .identity
        .start_webauthn_registration(
            &rig.realm_id,
            &rig.user_id,
            &hearth::identity::RegistrationOptions {
                rp_id: TEST_RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = authenticator.registration(&challenge, TEST_ORIGIN);
    rig.identity
        .complete_webauthn_registration(&rig.realm_id, &rig.user_id, &cdj, &att, TEST_ORIGIN, true)
        .expect("complete registration");

    // Step-up assertion challenge for that credential.
    let assertion_challenge = rig
        .identity
        .start_webauthn_authentication(
            &rig.realm_id,
            Some(&rig.user_id),
            &AuthenticationOptions {
                rp_id: TEST_RP_ID.to_string(),
            },
        )
        .expect("start authentication");
    let (a_cdj, a_auth_data, a_sig) = authenticator.assertion(&assertion_challenge, TEST_ORIGIN, 1);

    let (status, body) = web_register_begin(
        &rig,
        serde_json::json!({
            "assertion": {
                "credential_id": b64(&authenticator.credential_id),
                "client_data_json": b64(&a_cdj),
                "authenticator_data": b64(&a_auth_data),
                "signature": b64(&a_sig),
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn web_enrolment_with_a_forged_assertion_is_refused() {
    let rig = build_web_rig(true);
    let (status, body) = web_register_begin(
        &rig,
        serde_json::json!({
            "assertion": {
                "credential_id": b64(b"not-a-credential"),
                "client_data_json": b64(b"{}"),
                "authenticator_data": b64(b"junk"),
                "signature": b64(b"junk"),
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains("step_up_required"), "body: {body}");
}

#[tokio::test]
async fn web_enrolment_proceeds_when_the_account_holds_no_step_up_credential() {
    // No password, no TOTP, no passkey — there is no credential to prove.
    let rig = build_web_rig(false);
    let (status, body) = web_register_begin(&rig, serde_json::json!({})).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an account with no step-up credential must still enrol; body: {body}"
    );
}

#[tokio::test]
async fn account_page_renders_the_step_up_field() {
    let rig = build_web_rig(true);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account")
                .header(header::COOKIE, auth_cookie(&rig, "csrf-abc"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("passkey-step-up-secret"),
        "the passkey card must offer the step-up field, or the button cannot enrol"
    );
}

#[tokio::test]
async fn step_up_challenge_endpoint_returns_the_accounts_credentials() {
    let rig = build_web_rig(true);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/passkeys/step-up-begin")
                .header(header::COOKIE, auth_cookie(&rig, "csrf-abc"))
                .header("x-csrf-token", "csrf-abc")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    assert!(
        parsed.get("challenge").and_then(|c| c.as_str()).is_some(),
        "step-up-begin must mint an assertion challenge; body: {parsed}"
    );
    assert!(
        parsed.get("allowCredentials").is_some(),
        "step-up-begin must list the account's credentials; body: {parsed}"
    );
}

#[tokio::test]
async fn step_up_challenge_endpoint_refuses_a_missing_csrf_token() {
    let rig = build_web_rig(true);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/passkeys/step-up-begin")
                .header(header::COOKIE, auth_cookie(&rig, "csrf-abc"))
                .header("x-csrf-token", "wrong")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn web_enrolment_no_longer_answers_a_bare_get() {
    let rig = build_web_rig(true);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/passkeys/register-begin")
                .header(header::COOKIE, auth_cookie(&rig, "csrf-abc"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "the ungated GET enrolment path must be gone"
    );
}

// ---------------------------------------------------------------------------
// REST surface — the twin that shares the same challenge store
// ---------------------------------------------------------------------------

struct RestRig {
    app: axum::Router,
    realm_id: RealmId,
    access_token: String,
}

async fn build_rest_rig() -> RestRig {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-rest-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("rest-{}@acme.test", uuid::Uuid::new_v4()),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    let session = h
        .identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("create session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            realm.id(),
            user.id(),
            session.id(),
            &TokenIssuanceContext::default(),
        )
        .expect("issue tokens");

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    RestRig {
        app: http_router(state),
        realm_id: realm.id().clone(),
        access_token: pair.access_token().to_string(),
    }
}

async fn rest_register_begin(rig: &RestRig, body: serde_json::Value) -> (StatusCode, String) {
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webauthn/register/begin")
                .header("x-realm-id", rig.realm_id.as_uuid().to_string())
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", rig.access_token),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn rest_enrolment_without_a_proof_is_refused() {
    let rig = build_rest_rig().await;
    let (status, body) = rest_register_begin(&rig, serde_json::json!({})).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stolen access token must not start a passkey enrolment; body: {body}"
    );
    assert!(body.contains("step_up_required"), "body: {body}");
}

#[tokio::test]
async fn rest_enrolment_with_the_current_password_is_allowed() {
    let rig = build_rest_rig().await;
    let (status, body) =
        rest_register_begin(&rig, serde_json::json!({ "password": PASSWORD })).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert!(
        parsed.get("challenge").and_then(|c| c.as_str()).is_some(),
        "body: {body}"
    );
}

#[tokio::test]
async fn rest_enrolment_with_a_wrong_password_is_refused() {
    let rig = build_rest_rig().await;
    let (status, body) =
        rest_register_begin(&rig, serde_json::json!({ "password": WRONG_PASSWORD })).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains("step_up_required"), "body: {body}");
}
