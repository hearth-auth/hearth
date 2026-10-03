//! Defence in depth for `private_key_jwt`: a request that carries
//! `client_assertion` or `client_assertion_type` has attempted assertion
//! authentication, and the ENGINE refuses it unless the type is the
//! jwt-bearer URN, the assertion is present, and it verifies.
//!
//! The engine used to verify only when the type was exactly the URN and
//! otherwise fell through — to "no assertion" at the `authorization_code`
//! exchange (so a secret-holding client that sent a junk assertion and no
//! secret got tokens whenever the protocol layer deferred to the engine) and
//! to the secret check at `client_credentials` (so a junk assertion rode along
//! with a valid secret).

use super::*;

use crate::identity::oidc::{ClientCredentialsRequest, TokenExchangeRequest};
use crate::identity::AuthorizationRequest;

const REDIRECT: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// S256 of [`PKCE_VERIFIER`] (RFC 7636 Appendix B).
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Every malformed shape: `(client_assertion_type, client_assertion)`.
const MALFORMED: [(Option<&str>, Option<&str>); 4] = [
    (None, Some("junk")),
    (Some("urn:x"), Some("junk")),
    (Some("urn:x"), None),
    (
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        None,
    ),
];

fn code_for(engine: &EmbeddedIdentityEngine, realm: &RealmId, client: &ClientId) -> String {
    let user = create_test_user(engine, realm);
    engine
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "s".to_string(),
                nonce: None,
                code_challenge: Some(PKCE_CHALLENGE.to_string()),
                code_challenge_method: Some(crate::identity::CodeChallengeMethod::S256),
                resource: None,
                user_id: user.id().clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize")
        .code()
        .to_string()
}

#[test]
fn the_code_exchange_refuses_a_malformed_assertion() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    // A secret-holding client: no assertion key, no JWKS.
    let (client, _secret) = register_generated_client(&engine, &realm);
    for (assertion_type, assertion) in MALFORMED {
        let outcome = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: code_for(&engine, &realm, client.client_id()),
                redirect_uri: REDIRECT.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: assertion_type.map(str::to_string),
                client_assertion: assertion.map(str::to_string),
            },
        );
        assert!(
            matches!(outcome, Err(IdentityError::InvalidClientAssertion { .. })),
            "type={assertion_type:?} assertion={assertion:?}: a presented assertion field is a \
             private_key_jwt attempt and must be refused, got {outcome:?}"
        );
    }
}

#[test]
fn client_credentials_refuses_a_malformed_assertion_beside_a_valid_secret() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let secret = crate::identity::GeneratedClientSecret::generate();
    let client = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "cc".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                generated_client_secret: Some(secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: crate::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register");
    let request =
        |assertion_type: Option<&str>, assertion: Option<&str>| ClientCredentialsRequest {
            client_id: client.client_id().clone(),
            client_secret: Some(secret.expose().to_string()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: assertion_type.map(str::to_string),
            client_assertion: assertion.map(str::to_string),
        };
    // Control: the secret alone works.
    let issued = engine
        .client_credentials_token(&realm, &request(None, None))
        .expect("the secret alone must authenticate");
    assert_ne!(issued.access_token(), "");
    for (assertion_type, assertion) in MALFORMED {
        let outcome = engine.client_credentials_token(&realm, &request(assertion_type, assertion));
        assert!(
            matches!(outcome, Err(IdentityError::InvalidClientAssertion { .. })),
            "type={assertion_type:?} assertion={assertion:?}: must be refused, got {outcome:?}"
        );
    }
}
