//! HEA-SEC-29 / HEA-550: PKCE is unconditional for all OAuth 2.0 clients.
//!
//! RFC 9700 §2.1.1 mandates PKCE for all clients. The `require_pkce_for_confidential_clients`
//! opt-out config flag has been removed; confidential clients can no longer bypass PKCE.

mod common;

use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityError, OidcConfig, RegisterClientRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use std::sync::Arc;

fn build_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine) {
    use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
    use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        oidc: OidcConfig::default(),
        ..IdentityConfig::default()
    };
    let engine =
        EmbeddedIdentityEngine::with_rbac(Arc::clone(&storage), clock, config, rbac, audit)
            .expect("engine");
    (dir, engine)
}

fn setup() -> (tempfile::TempDir, EmbeddedIdentityEngine, RealmId) {
    use hearth::identity::IdentityEngine;

    let (dir, engine) = build_engine();
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "pkce-test".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    (dir, engine, realm_id)
}

fn make_user(engine: &EmbeddedIdentityEngine, realm_id: &RealmId) -> hearth::identity::User {
    use hearth::identity::IdentityEngine;
    engine
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("pkce-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "PKCE Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

fn register_confidential(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
) -> hearth::identity::OAuthClient {
    use hearth::identity::IdentityEngine;
    let client = engine
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "Confidential App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some("s3cr3t!".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    assert!(
        client.is_confidential(),
        "must be confidential for this test"
    );
    client
}

// ── HEA-SEC-29: confidential client without PKCE is unconditionally rejected ─

/// Confidential clients without PKCE must be rejected (RFC 9700 §2.1.1).
///
/// The `require_pkce_for_confidential_clients` opt-out has been removed in
/// HEA-SEC-29. There is no config escape hatch — PKCE is mandatory for all clients.
#[test]
fn confidential_client_without_pkce_always_rejected() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);
    let client = register_confidential(&engine, &realm_id);

    let result = engine.authorize(
        &realm_id,
        &AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            state: "csrf-token".to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            resource: None,
            amr_values: Vec::new(),
            response_mode: None,
            request: None,
            via_par: false,
        },
    );

    let err = result
        .expect_err("confidential client without PKCE must be rejected (RFC 9700 §2.1.1)")
        .to_string();
    assert!(err.contains("PKCE"), "error must mention PKCE, got: {err}");
}

// ── Public clients remain rejected without PKCE (no regression) ─────────────

#[test]
fn public_client_without_pkce_always_rejected() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Public App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    assert!(!client.is_confidential());

    let result = engine.authorize(
        &realm_id,
        &AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            state: "csrf-token".to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            resource: None,
            amr_values: Vec::new(),
            response_mode: None,
            request: None,
            via_par: false,
        },
    );

    assert!(
        matches!(&result, Err(IdentityError::InvalidInput { reason }) if reason.contains("PKCE")),
        "public client without PKCE must be rejected; got: {result:?}"
    );
}
