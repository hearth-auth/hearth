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
            organization: None,
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
            organization: None,
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
        },
    );

    assert!(
        matches!(&result, Err(IdentityError::InvalidInput { reason }) if reason.contains("PKCE")),
        "public client without PKCE must be rejected; got: {result:?}"
    );
}

// ── #780: a per-client `require_pkce` setting (owner decision, option 3) ────

fn authorize_request(
    client: &hearth::identity::OAuthClient,
    user: &hearth::identity::User,
    challenge: Option<&str>,
) -> AuthorizationRequest {
    AuthorizationRequest {
        organization: None,
        client_id: client.client_id().clone(),
        redirect_uri: "https://app.example.com/cb".to_string(),
        scope: "openid".to_string(),
        state: "csrf-token".to_string(),
        response_type: "code".to_string(),
        user_id: user.id().clone(),
        code_challenge: challenge.map(str::to_string),
        code_challenge_method: challenge.map(|_| hearth::identity::CodeChallengeMethod::S256),
        nonce: Some(format!("n-780-{}", uuid::Uuid::new_v4())),
        resource: None,
        amr_values: Vec::new(),
        response_mode: None,
        request: None,
    }
}

fn exchange(
    client: &hearth::identity::OAuthClient,
    code: &str,
    code_verifier: Option<&str>,
) -> hearth::identity::TokenExchangeRequest {
    hearth::identity::TokenExchangeRequest {
        client_id: client.client_id().clone(),
        code: code.to_string(),
        redirect_uri: "https://app.example.com/cb".to_string(),
        code_verifier: code_verifier.map(str::to_string),
        dpop_jkt: None,
        client_assertion_type: None,
        client_assertion: None,
        resource: None,
    }
}

fn register_with_pkce_setting(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
    secret: Option<&str>,
    require_pkce: bool,
) -> Result<hearth::identity::OAuthClient, IdentityError> {
    use hearth::identity::IdentityEngine;
    engine.register_client(
        realm_id,
        &RegisterClientRequest {
            client_name: "PKCE setting app".to_string(),
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            client_secret: secret.map(str::to_string),
            grant_types: vec!["authorization_code".to_string()],
            require_consent: false,
            require_pkce,
            ..Default::default()
        },
    )
}

/// A new client needs PKCE unless the admin says otherwise.
#[test]
fn require_pkce_defaults_to_true() {
    let (_dir, engine, realm_id) = setup();
    let client = register_confidential(&engine, &realm_id);
    assert!(client.require_pkce(), "the default is require_pkce: true");
}

/// A confidential client with `require_pkce: false` gets a code without
/// `code_challenge` and exchanges it without `code_verifier`.
#[test]
fn confidential_client_without_the_pkce_requirement_gets_and_exchanges_a_code() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);
    let client = register_with_pkce_setting(&engine, &realm_id, Some("s3cr3t!"), false)
        .expect("a confidential client may drop the PKCE requirement");
    assert!(!client.require_pkce());

    let auth = engine
        .authorize(&realm_id, &authorize_request(&client, &user, None))
        .expect("a request without code_challenge is accepted for this client");
    let tokens = engine
        .exchange_authorization_code(&realm_id, &exchange(&client, auth.code(), None))
        .expect("the code exchanges without code_verifier");
    assert_eq!(
        tokens.access_token().split('.').count(),
        3,
        "the exchange issues a signed access token"
    );
}

/// RFC 9700 §4.8.2: a `code_verifier` for a code issued without
/// `code_challenge` is refused (PKCE downgrade).
#[test]
fn a_code_verifier_for_a_code_without_a_challenge_is_invalid_grant() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);
    let client =
        register_with_pkce_setting(&engine, &realm_id, Some("s3cr3t!"), false).expect("client");
    let auth = engine
        .authorize(&realm_id, &authorize_request(&client, &user, None))
        .expect("authorize");
    let result = engine.exchange_authorization_code(
        &realm_id,
        &exchange(
            &client,
            auth.code(),
            Some("a-verifier-with-no-challenge-0123456789abc"),
        ),
    );
    assert!(
        matches!(&result, Err(IdentityError::InvalidGrant { .. })),
        "a verifier for a code without a challenge must be invalid_grant; got: {result:?}"
    );
}

/// A client without the requirement that still sends `code_challenge` gets
/// every check: the exchange needs the matching `code_verifier`.
#[test]
fn a_sent_challenge_is_checked_also_without_the_pkce_requirement() {
    use base64::Engine as _;
    use hearth::identity::IdentityEngine;
    use sha2::Digest as _;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);
    let client =
        register_with_pkce_setting(&engine, &realm_id, Some("s3cr3t!"), false).expect("client");
    let verifier = "a-pkce-verifier-for-issue-780-0123456789abcdef";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let challenge = Some(challenge.as_str());

    let auth = engine
        .authorize(&realm_id, &authorize_request(&client, &user, challenge))
        .expect("authorize");
    let result =
        engine.exchange_authorization_code(&realm_id, &exchange(&client, auth.code(), None));
    assert!(
        matches!(&result, Err(IdentityError::InvalidGrant { .. })),
        "a code with a challenge needs its verifier; got: {result:?}"
    );

    let auth = engine
        .authorize(&realm_id, &authorize_request(&client, &user, challenge))
        .expect("authorize");
    engine
        .exchange_authorization_code(&realm_id, &exchange(&client, auth.code(), Some(verifier)))
        .expect("the matching verifier exchanges");
}

/// A public client cannot drop the requirement: create and update refuse it.
#[test]
fn a_public_client_cannot_drop_the_pkce_requirement() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let result = register_with_pkce_setting(&engine, &realm_id, None, false);
    assert!(
        matches!(&result, Err(IdentityError::InvalidInput { reason }) if reason.contains("require_pkce")),
        "a public client with require_pkce: false must be refused; got: {result:?}"
    );

    let public = register_with_pkce_setting(&engine, &realm_id, None, true).expect("public");
    let result = engine.update_client(
        &realm_id,
        public.client_id(),
        &hearth::identity::UpdateClientRequest {
            require_pkce: Some(false),
            ..Default::default()
        },
    );
    assert!(
        matches!(&result, Err(IdentityError::InvalidInput { reason }) if reason.contains("require_pkce")),
        "an update of a public client to require_pkce: false must be refused; got: {result:?}"
    );
}

/// An update can turn the requirement off for a confidential client and on
/// again.
#[test]
fn an_update_sets_the_pkce_requirement_of_a_confidential_client() {
    use hearth::identity::IdentityEngine;

    let (_dir, engine, realm_id) = setup();
    let user = make_user(&engine, &realm_id);
    let client = register_confidential(&engine, &realm_id);
    for (value, accepted) in [(false, true), (true, false)] {
        engine
            .update_client(
                &realm_id,
                client.client_id(),
                &hearth::identity::UpdateClientRequest {
                    require_pkce: Some(value),
                    ..Default::default()
                },
            )
            .expect("update");
        let stored = engine
            .get_client(&realm_id, client.client_id())
            .expect("get")
            .expect("client");
        assert_eq!(stored.require_pkce(), value);
        let result = engine.authorize(&realm_id, &authorize_request(&stored, &user, None));
        assert_eq!(
            result.is_ok(),
            accepted,
            "require_pkce: {value}: {result:?}"
        );
    }
}
