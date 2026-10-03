//! The `aud` of a `private_key_jwt` assertion (review L-FAPI-1): it must
//! name the realm's issuer, as a single string or as one value of an array
//! (RFC 7523 §3).

use super::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::identity::oidc::UpdateClientRequest;
use crate::identity::tokens::{Audience, JwtAssertionClaims};

/// A secretless client with an Ed25519 assertion key.
fn register(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
) -> (crate::core::ClientId, SigningKey) {
    let key = SigningKey::generate().expect("key");
    let client_id = engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("aud-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                ..RegisterClientRequest::default()
            },
        )
        .expect("register")
        .client_id()
        .clone();
    engine
        .update_client(
            realm,
            &client_id,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("install assertion key");
    (client_id, key)
}

fn assertion(
    clock: &FakeClock,
    client: &crate::core::ClientId,
    key: &SigningKey,
    aud: Audience,
) -> String {
    let now = clock.now().as_micros() / 1_000_000;
    key.issue_assertion_jwt(&JwtAssertionClaims {
        iss: client.as_uuid().to_string(),
        sub: client.as_uuid().to_string(),
        aud,
        exp: now + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: Some(now),
    })
    .expect("sign")
}

fn audiences(issuer: &str) -> [(Audience, &'static str); 3] {
    [
        (Audience::single(issuer), "the issuer as a string"),
        (
            Audience::Multi(vec![issuer.to_string()]),
            "a one-element array",
        ),
        (
            Audience::Multi(vec![
                issuer.to_string(),
                "https://other.example".to_string(),
            ]),
            "an array containing the issuer",
        ),
    ]
}

#[test]
fn a_standard_client_may_send_an_array_audience() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let (client, key) = register(&engine, &realm);
    for (aud, what) in audiences(&engine.realm_issuer_url(&realm)) {
        engine
            .verify_client_assertion(&realm, &client, &assertion(&clock, &client, &key, aud))
            .unwrap_or_else(|e| panic!("{what}: RFC 7523 §3 accepts it, got {e:?}"));
    }
}
