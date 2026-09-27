//! The `aud` of a `private_key_jwt` assertion (FAPI review L-FAPI-1).
//!
//! FAPI 2.0 Security Profile §5.3.2.1: the authorization server "shall only
//! accept its issuer identifier value (as defined in RFC 8414) as a string in
//! the `aud` claim". Hearth accepted any `aud` that CONTAINED the issuer,
//! arrays included. Under FAPI 2.0 — a `fapi2` client, or any client of a
//! realm with a `fapi_profile` — `aud` must now be the issuer as a single
//! string. Elsewhere RFC 7523 §3 still applies: the issuer may be one value of
//! an array.

use super::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::identity::oidc::UpdateClientRequest;
use crate::identity::tokens::{Audience, JwtAssertionClaims};
use crate::identity::{ClientProfile, FapiProfile};

/// A secretless client with an Ed25519 assertion key, optionally FAPI 2.0.
fn register(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    fapi2: bool,
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
                profile: fapi2.then_some(ClientProfile::Fapi2),
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
        iss: client.to_string(),
        sub: client.to_string(),
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
    let (client, key) = register(&engine, &realm, false);
    for (aud, what) in audiences(&engine.realm_issuer_url(&realm)) {
        engine
            .verify_client_assertion(&realm, &client, &assertion(&clock, &client, &key, aud))
            .unwrap_or_else(|e| panic!("{what}: RFC 7523 §3 accepts it, got {e:?}"));
    }
}

#[test]
fn fapi_requires_the_issuer_as_a_single_string() {
    let (_dir, engine, clock) = setup_engine();
    // A FAPI 2.0 client in a standard realm, and a standard client in a FAPI
    // realm.
    let realm = create_test_realm(&engine);
    let fapi_client = register(&engine, &realm, true);
    let fapi_realm = create_test_realm(&engine);
    let plain_in_fapi_realm = register(&engine, &fapi_realm, false);
    let realm_obj = engine.get_realm(&fapi_realm).expect("get").expect("realm");
    let mut config = realm_obj.config().clone();
    config.fapi_profile = Some(FapiProfile::Baseline);
    engine
        .update_realm(
            &fapi_realm,
            &crate::identity::UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("set fapi profile");

    for (realm, (client, key), who) in [
        (&realm, fapi_client, "fapi2 client"),
        (&fapi_realm, plain_in_fapi_realm, "client of a FAPI realm"),
    ] {
        for (aud, what) in audiences(&engine.realm_issuer_url(realm)) {
            let single = matches!(aud, Audience::Single(_));
            let outcome = engine.verify_client_assertion(
                realm,
                &client,
                &assertion(&clock, &client, &key, aud),
            );
            if single {
                outcome.unwrap_or_else(|e| panic!("{who}, {what}: must verify, got {e:?}"));
            } else {
                assert!(
                    matches!(outcome, Err(IdentityError::InvalidClientAssertion { .. })),
                    "{who}, {what}: FAPI 2.0 §5.3.2.1 accepts only a string aud, got {outcome:?}"
                );
            }
        }
    }
}
