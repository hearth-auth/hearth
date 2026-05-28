//! Integration tests for RFC 7523 JWT Bearer Token Grant (HEA-908).
//!
//! Black-box tests via `TestHarness`.  Exercises:
//! - Valid assertion → access token issued
//! - Expired assertion → rejected
//! - JTI replay → rejected
//! - Wrong `iss` → rejected
//! - Wrong `aud` → rejected
//! - No assertion public key registered → rejected
//! - Tampered signature → rejected
//! - OIDC discovery includes `jwt-bearer` grant type

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::identity::tokens::Audience;
use hearth::identity::tokens::JwtAssertionClaims;
use hearth::identity::{
    CreateRealmRequest, JwtBearerRequest, RegisterClientRequest, SigningKey, UpdateClientRequest,
};

const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

fn realm_issuer(harness: &common::TestHarness, realm_id: &hearth::core::RealmId) -> String {
    let base = harness.identity().oidc_discovery().issuer;
    let realm = harness
        .identity()
        .get_realm(realm_id)
        .expect("get realm")
        .expect("realm exists");
    format!("{}/realms/{}", base, realm.name())
}

fn create_realm(h: &common::TestHarness) -> hearth::core::RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("jb-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

/// Makes a signed JWT assertion using the given signing key.
fn make_assertion(
    key: &SigningKey,
    client_id: &str,
    audience: &str,
    exp_offset_secs: i64,
    jti: Option<String>,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = JwtAssertionClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: Audience::single(audience.to_string()),
        exp: now + exp_offset_secs,
        jti,
        iat: Some(now),
    };
    key.issue_assertion_jwt(&claims).expect("sign assertion")
}

// ===== Test: valid assertion issues access token =====

#[tokio::test]
async fn jwt_bearer_valid_assertion_issues_token() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);

    // Generate a client-side Ed25519 key pair
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    // Register client with jwt-bearer grant and the assertion public key
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "JWT Bearer Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    // Get the configured issuer/audience
    let audience = realm_issuer(&harness, &realm);

    // Sign and submit assertion
    let assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        &audience,
        60,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let resp = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: Some("read".to_string()),
                dpop_jkt: None,
            },
        )
        .expect("jwt bearer token");

    assert!(!resp.access_token().is_empty(), "must return access token");
    assert_eq!(resp.token_type(), "Bearer");
    assert!(resp.expires_in() > 0);
}

// ===== Test: expired assertion is rejected =====

#[tokio::test]
async fn jwt_bearer_expired_assertion_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Expired Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let issuer = realm_issuer(&harness, &realm);
    let assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        &issuer,
        -1, // already expired
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("expired assertion must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid, got: {err:?}"
    );
}

// ===== Test: JTI replay is rejected =====

#[tokio::test]
async fn jwt_bearer_jti_replay_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Replay Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let issuer = realm_issuer(&harness, &realm);
    let jti = uuid::Uuid::new_v4().to_string();
    let assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        &issuer,
        60,
        Some(jti.clone()),
    );

    // First use — must succeed
    harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion: assertion.clone(),
                scope: Some("read".to_string()),
                dpop_jkt: None,
            },
        )
        .expect("first use must succeed");

    // Second use of the same JTI — must be rejected as replay
    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("replay must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid for replay, got: {err:?}"
    );
}

// ===== Test: wrong issuer is rejected =====

#[tokio::test]
async fn jwt_bearer_wrong_issuer_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "ISS Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let issuer = realm_issuer(&harness, &realm);
    // Use a wrong issuer (not the client_id)
    let claims = JwtAssertionClaims {
        iss: "not-the-client-id".to_string(),
        sub: client.client_id().to_string(),
        aud: Audience::single(issuer),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: None,
    };
    let assertion = assertion_key.issue_assertion_jwt(&claims).expect("sign");

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("wrong issuer must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid for wrong iss, got: {err:?}"
    );
}

// ===== Test: wrong audience is rejected =====

#[tokio::test]
async fn jwt_bearer_wrong_audience_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "AUD Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        "https://wrong-audience.example.com",
        60,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("wrong audience must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid for wrong aud, got: {err:?}"
    );
}

// ===== Test: no assertion public key registered → rejected =====

#[tokio::test]
async fn jwt_bearer_no_registered_key_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");

    // Register client WITHOUT setting an assertion_public_key
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "No Key Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let issuer = realm_issuer(&harness, &realm);
    let assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        &issuer,
        60,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("missing key must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid for missing key, got: {err:?}"
    );
}

// ===== Test: tampered signature is rejected =====

#[tokio::test]
async fn jwt_bearer_tampered_signature_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let assertion_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(assertion_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Tamper Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec![JWT_BEARER_GRANT.to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion key");

    let issuer = realm_issuer(&harness, &realm);
    let good_assertion = make_assertion(
        &assertion_key,
        &client.client_id().to_string(),
        &issuer,
        60,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    // Tamper: replace the signature with garbage
    let parts: Vec<&str> = good_assertion.split('.').collect();
    let tampered = format!("{}.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", parts[0], parts[1]);

    let err = harness
        .identity()
        .jwt_bearer_token(
            &realm,
            &JwtBearerRequest {
                client_id: client.client_id().clone(),
                assertion: tampered,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("tampered assertion must be rejected");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected JwtBearerAssertionInvalid for tampered sig, got: {err:?}"
    );
}

// ===== Test: OIDC discovery includes jwt-bearer grant type =====

#[tokio::test]
async fn jwt_bearer_grant_in_discovery() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let discovery = harness.identity().oidc_discovery();

    assert!(
        discovery
            .grant_types_supported
            .contains(&JWT_BEARER_GRANT.to_string()),
        "OIDC discovery must list jwt-bearer grant type; got: {:?}",
        discovery.grant_types_supported
    );
}
