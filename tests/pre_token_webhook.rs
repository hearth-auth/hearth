//! Integration tests for the pre-token enrichment webhook (HEA-1324).
//!
//! Covers Gap C-3 from the 1.0 Readiness Audit: a configurable webhook
//! fired before token issuance that may inject extra claims.
//!
//! All tests use a stub transport so no real network calls are made.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::pre_token_webhook::{
    PreTokenWebhookError, PreTokenWebhookResponse, PreTokenWebhookTransport,
};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, RegisterClientRequest,
    TokenExchangeRequest, UpdateRealmRequest,
};
use hearth::identity::{PreTokenWebhookConfig, PreTokenWebhookErrorPolicy};
use serde_json::json;

// ──────────────────────────── shared helpers ──────────────────────────────

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn setup_webhook_config(url: &str, on_error: PreTokenWebhookErrorPolicy) -> PreTokenWebhookConfig {
    PreTokenWebhookConfig {
        url: url.to_string(),
        timeout_ms: 1000,
        on_error,
        hmac_secret: None,
    }
}

/// Perform a full authorization-code token exchange for a newly created user.
fn authorize_and_exchange(
    harness: &common::TestHarness,
    realm: &RealmId,
) -> hearth::identity::OidcTokenResponse {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("webhook-test-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Webhook Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Webhook Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let auth_response = harness
        .identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    harness
        .identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code")
}

// ──────────────────── stub transports ─────────────────────

/// A stub that always returns a fixed set of extra claims.
struct FixedClaimsTransport {
    claims: BTreeMap<String, serde_json::Value>,
    call_count: Arc<Mutex<u32>>,
}

impl FixedClaimsTransport {
    fn new(claims: BTreeMap<String, serde_json::Value>) -> (Self, Arc<Mutex<u32>>) {
        let counter = Arc::new(Mutex::new(0u32));
        let transport = Self {
            claims,
            call_count: Arc::clone(&counter),
        };
        (transport, counter)
    }
}

impl PreTokenWebhookTransport for FixedClaimsTransport {
    fn fire(
        &self,
        _url: &str,
        _timeout_ms: u64,
        _body: &[u8],
        _hmac_sig: Option<&str>,
    ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
        *self.call_count.lock().expect("lock") += 1;
        Ok(PreTokenWebhookResponse {
            extra_claims: self.claims.clone(),
        })
    }
}

/// A stub that always returns a transport error.
struct FailingTransport {
    call_count: Arc<Mutex<u32>>,
}

impl FailingTransport {
    fn new() -> (Self, Arc<Mutex<u32>>) {
        let counter = Arc::new(Mutex::new(0u32));
        (
            Self {
                call_count: Arc::clone(&counter),
            },
            counter,
        )
    }
}

impl PreTokenWebhookTransport for FailingTransport {
    fn fire(
        &self,
        _url: &str,
        _timeout_ms: u64,
        _body: &[u8],
        _hmac_sig: Option<&str>,
    ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
        *self.call_count.lock().expect("lock") += 1;
        Err(PreTokenWebhookError::TransportError {
            reason: "connection refused".to_string(),
        })
    }
}

// ──────────────────── tests ───────────────────────────────

/// When a realm has a pre-token webhook configured and the transport returns
/// extra claims, those claims appear in the issued access token.
#[tokio::test]
async fn webhook_extra_claims_appear_in_access_token() {
    let mut extra = BTreeMap::new();
    extra.insert("tenant_id".to_string(), json!("acme"));
    extra.insert("custom_tier".to_string(), json!("pro"));
    let (transport, _counter) = FixedClaimsTransport::new(extra);

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();

    // Configure the realm to use the webhook
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailOpen,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    let token_response = authorize_and_exchange(&harness, &realm);

    // Decode the access token claims (without verifying signature for test convenience)
    let access_token = token_response.access_token();
    let claims = decode_jwt_claims(access_token);

    assert_eq!(
        claims["tenant_id"],
        json!("acme"),
        "webhook claim tenant_id missing"
    );
    assert_eq!(
        claims["custom_tier"],
        json!("pro"),
        "webhook claim custom_tier missing"
    );
}

/// Webhook responses cannot overwrite reserved standard JWT claims.
/// Attempting to inject `sub`, `iss`, `exp` etc. must be silently dropped.
#[tokio::test]
async fn webhook_cannot_override_reserved_claims() {
    let mut evil_claims = BTreeMap::new();
    evil_claims.insert("sub".to_string(), json!("evil-actor"));
    evil_claims.insert("iss".to_string(), json!("https://evil.example.com"));
    evil_claims.insert("exp".to_string(), json!(9_999_999_999u64));
    evil_claims.insert(
        "tid".to_string(),
        json!("00000000-0000-0000-0000-000000000000"),
    );
    evil_claims.insert("legitimate_claim".to_string(), json!("ok"));
    let (transport, _counter) = FixedClaimsTransport::new(evil_claims);

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailOpen,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    let token_response = authorize_and_exchange(&harness, &realm);
    let claims = decode_jwt_claims(token_response.access_token());

    // Reserved claims must not have been overwritten
    assert_ne!(
        claims["sub"],
        json!("evil-actor"),
        "sub was overridden by webhook!"
    );
    assert_ne!(
        claims["iss"],
        json!("https://evil.example.com"),
        "iss was overridden by webhook!"
    );
    // The legitimate non-reserved claim should still be present
    assert_eq!(claims["legitimate_claim"], json!("ok"));
}

/// When the webhook transport fails and the policy is `fail_open`,
/// the token is still issued (without extra claims) and no error is returned.
#[tokio::test]
async fn webhook_fail_open_issues_token_despite_error() {
    let (transport, call_count) = FailingTransport::new();

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailOpen,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    // Token exchange must succeed despite webhook failure
    let token_response = authorize_and_exchange(&harness, &realm);
    assert!(!token_response.access_token().is_empty());
    assert_eq!(
        *call_count.lock().expect("lock"),
        1,
        "transport should have been called once"
    );
}

/// When the webhook transport fails and the policy is `fail_closed`,
/// the token request is rejected with an error.
#[tokio::test]
async fn webhook_fail_closed_rejects_token_on_error() {
    let (transport, _call_count) = FailingTransport::new();

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "failclosed@example.com".to_string(),
                display_name: "Fail Closed User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Fail Closed App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailClosed,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    let auth_response = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    // Token exchange MUST fail when webhook fails and policy is fail_closed
    let result = harness.identity().exchange_authorization_code(
        &realm,
        &TokenExchangeRequest {
            client_id: client.client_id().clone(),
            code: auth_response.code().to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );

    // Should be a webhook-specific error variant, not a generic one
    assert!(
        matches!(
            result.expect_err("expected error from fail_closed webhook failure"),
            hearth::identity::IdentityError::PreTokenWebhookFailed { .. }
        ),
        "expected PreTokenWebhookFailed error"
    );
}

/// When no pre-token webhook is configured for the realm, the transport is
/// never called and the token is issued normally.
#[tokio::test]
async fn webhook_not_called_when_not_configured() {
    let (transport, call_count) = FixedClaimsTransport::new(BTreeMap::new());

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    // No webhook config on the realm — default realm config
    let realm = harness.create_realm();

    let token_response = authorize_and_exchange(&harness, &realm);
    assert!(!token_response.access_token().is_empty());
    // Transport must not have been called
    assert_eq!(
        *call_count.lock().expect("lock"),
        0,
        "transport was called but no webhook is configured"
    );
}

/// The webhook request payload includes user_id, realm_id, grant_type, and scope.
#[tokio::test]
async fn webhook_request_contains_expected_context() {
    // CapturingTransport stores raw body bytes because PreTokenWebhookRequest
    // has `event: &'static str` which cannot be deserialized from dynamic input.
    // We check fields via serde_json::Value instead.
    struct CapturingTransport {
        last_body: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl PreTokenWebhookTransport for CapturingTransport {
        fn fire(
            &self,
            _url: &str,
            _timeout_ms: u64,
            body: &[u8],
            _hmac_sig: Option<&str>,
        ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
            *self.last_body.lock().expect("lock") = Some(body.to_vec());
            Ok(PreTokenWebhookResponse {
                extra_claims: BTreeMap::new(),
            })
        }
    }

    let captured = Arc::new(Mutex::new(None::<Vec<u8>>));
    let transport = CapturingTransport {
        last_body: Arc::clone(&captured),
    };

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailOpen,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    let _token_response = authorize_and_exchange(&harness, &realm);

    let raw_body = captured
        .lock()
        .expect("lock")
        .clone()
        .expect("transport was not called");
    let req: serde_json::Value =
        serde_json::from_slice(&raw_body).expect("body must be valid JSON");
    assert_eq!(
        req["realm_id"].as_str().unwrap_or(""),
        realm.to_string(),
        "realm_id mismatch in webhook request"
    );
    assert!(
        !req["user_id"].as_str().unwrap_or("").is_empty(),
        "user_id missing from webhook request"
    );
    assert_eq!(
        req["grant_type"].as_str().unwrap_or(""),
        "authorization_code"
    );
}

/// When `hmac_secret` is configured, the transport must receive a valid
/// `X-Hearth-Signature-256` header value (F-1 fix verification).
#[tokio::test]
async fn webhook_hmac_sig_forwarded_to_transport_when_secret_configured() {
    struct SignatureCapturingTransport {
        captured_sig: Arc<Mutex<Option<String>>>,
        captured_body: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl PreTokenWebhookTransport for SignatureCapturingTransport {
        fn fire(
            &self,
            _url: &str,
            _timeout_ms: u64,
            body: &[u8],
            hmac_sig: Option<&str>,
        ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
            *self.captured_sig.lock().expect("lock") = hmac_sig.map(str::to_string);
            *self.captured_body.lock().expect("lock") = Some(body.to_vec());
            Ok(PreTokenWebhookResponse {
                extra_claims: BTreeMap::new(),
            })
        }
    }

    let captured_sig = Arc::new(Mutex::new(None::<String>));
    let captured_body = Arc::new(Mutex::new(None::<Vec<u8>>));
    let transport = SignatureCapturingTransport {
        captured_sig: Arc::clone(&captured_sig),
        captured_body: Arc::clone(&captured_body),
    };

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();
    let secret = "test-hmac-secret-value";
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(PreTokenWebhookConfig {
                        url: "http://localhost:9999/enrich".to_string(),
                        timeout_ms: 1000,
                        on_error: PreTokenWebhookErrorPolicy::FailOpen,
                        hmac_secret: Some(secret.to_string()),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    // Trigger a token issuance to fire the webhook.
    let _ = authorize_and_exchange(&harness, &realm);

    let sig = captured_sig
        .lock()
        .expect("lock")
        .clone()
        .expect("transport must have received hmac_sig when secret is configured");

    assert!(
        sig.starts_with("sha256="),
        "signature must start with 'sha256=', got: {sig}"
    );

    let hex_part = sig.trim_start_matches("sha256=");
    assert_eq!(hex_part.len(), 64, "HMAC-SHA256 hex must be 64 chars");

    // Verify the HMAC matches: recompute over the captured body.
    let body = captured_body
        .lock()
        .expect("lock")
        .clone()
        .expect("transport must have been called with a body");
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key must be non-empty");
    mac.update(&body);
    let expected_hex = hex::encode(mac.finalize().into_bytes());
    assert_eq!(
        hex_part, expected_hex,
        "HMAC signature must be computed over the serialized request body"
    );

    // Deserialize body to confirm it's a valid request JSON payload.
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body must be valid JSON");
    assert!(
        parsed.get("realm_id").is_some(),
        "body must contain realm_id field"
    );
}

/// When `hmac_secret` is NOT configured, the transport must receive `None`
/// for `hmac_sig` (no spurious header).
#[tokio::test]
async fn webhook_no_sig_forwarded_when_no_secret() {
    struct SigCheckTransport {
        received_sig: Arc<Mutex<Option<Option<String>>>>,
    }

    impl PreTokenWebhookTransport for SigCheckTransport {
        fn fire(
            &self,
            _url: &str,
            _timeout_ms: u64,
            _body: &[u8],
            hmac_sig: Option<&str>,
        ) -> Result<PreTokenWebhookResponse, PreTokenWebhookError> {
            *self.received_sig.lock().expect("lock") = Some(hmac_sig.map(str::to_string));
            Ok(PreTokenWebhookResponse {
                extra_claims: BTreeMap::new(),
            })
        }
    }

    let received = Arc::new(Mutex::new(None::<Option<String>>));
    let transport = SigCheckTransport {
        received_sig: Arc::clone(&received),
    };

    let harness = common::TestHarness::embedded_with_pre_token_transport(Arc::new(transport))
        .await
        .expect("harness setup");

    let realm = harness.create_realm();
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(hearth::identity::RealmConfig {
                    pre_token_webhook: Some(setup_webhook_config(
                        "http://localhost:9999/enrich",
                        PreTokenWebhookErrorPolicy::FailOpen,
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm");

    let _ = authorize_and_exchange(&harness, &realm);

    let captured = received
        .lock()
        .expect("lock")
        .clone()
        .expect("transport must have been called");
    assert!(
        captured.is_none(),
        "hmac_sig must be None when no secret is configured, got: {captured:?}"
    );
}

// ──────────────────── test utility ────────────────────────

/// Decodes the payload of a JWT without verifying the signature.
/// For test use only — never use in production code.
fn decode_jwt_claims(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "expected 3-part JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode");
    serde_json::from_slice(&payload).expect("json parse")
}
