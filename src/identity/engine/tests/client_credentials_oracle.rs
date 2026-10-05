//! `grant_type=client_credentials` authenticates the client before it says
//! anything about the client.
//!
//! The grant used to answer an unknown `client_id` with `InvalidClient` and a
//! client lacking the grant with `UnsupportedGrantType`, both BEFORE the secret
//! was checked — so anyone could learn, without a secret, whether a client id
//! exists and which grants it has. Every arm now performs the same work (one
//! verification of the presented secret) and a caller that has not proved the
//! secret gets one answer; only an authenticated client learns that it lacks
//! the grant.

use super::*;

use crate::identity::oidc::ClientCredentialsRequest;

fn cc_request(client_id: &ClientId, secret: &str) -> ClientCredentialsRequest {
    ClientCredentialsRequest {
        client_id: client_id.clone(),
        client_secret: Some(secret.to_string()),
        scope: None,
        dpop_jkt: None,
        client_assertion_type: None,
        client_assertion: None,
        resource: None,
    }
}

#[test]
fn client_credentials_reveals_nothing_before_the_secret_is_proved() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    // A real client that lacks the client_credentials grant.
    let (no_grant, secret) = register_generated_client(&engine, &realm);
    let unknown = ClientId::generate();

    let mut outcomes = Vec::new();
    let work = secret_work(|| {
        outcomes.push(engine.client_credentials_token(&realm, &cc_request(&unknown, "guess")));
        outcomes.push(
            engine.client_credentials_token(&realm, &cc_request(no_grant.client_id(), "guess")),
        );
    });
    for outcome in &outcomes {
        assert!(
            matches!(outcome, Err(IdentityError::InvalidClientSecret)),
            "an unauthenticated caller must get the wrong-secret answer on every arm, got \
             {outcome:?}"
        );
    }
    assert_eq!(
        work,
        (0, 2),
        "each arm must verify the presented secret exactly once"
    );

    // With the secret proved, the client may learn it lacks the grant.
    let proved =
        engine.client_credentials_token(&realm, &cc_request(no_grant.client_id(), secret.expose()));
    assert!(
        matches!(proved, Err(IdentityError::UnsupportedGrantType)),
        "an authenticated client without the grant gets unsupported_grant_type, got {proved:?}"
    );
}
