//! A FAPI 2.0 client is never public and always holds keys it can
//! authenticate with.
//!
//! `OAuthClient::is_public` ignored the profile, and `update_client` set
//! `profile = Fapi2` on a client with no JWKS and no assertion key — exactly
//! what `hearth.yaml` reconcile does for `profile: fapi2`. The result counted
//! as PUBLIC, so `/as/par` accepted it on its `client_id` alone. Now:
//!
//! * a FAPI 2.0 client is never public and requires an assertion, so a
//!   keyless one (stored before this fix) fails closed everywhere;
//! * registration, update and reconcile refuse a FAPI 2.0 client that would
//!   hold no key Hearth can verify an assertion with (inline `jwks` or an
//!   assertion key — a `jwks_uri` is never fetched) or that holds a secret.

use super::*;

use crate::identity::oidc::UpdateClientRequest;
use crate::identity::ClientProfile;

const REDIRECT: &str = "https://app.example.com/callback";

fn jwks() -> String {
    // A syntactically valid Ed25519 public JWK (the key itself is never used).
    serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }]})
    .to_string()
}

fn public_client(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> OAuthClient {
    engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "public".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                ..Default::default()
            },
        )
        .expect("register public client")
}

fn assert_fapi_violation<T: std::fmt::Debug>(outcome: Result<T, IdentityError>, what: &str) {
    assert!(
        matches!(outcome, Err(IdentityError::FapiViolation { .. })),
        "{what}: expected FapiViolation, got {outcome:?}"
    );
}

#[test]
fn a_keyless_fapi2_client_is_never_public() {
    let mut client = OAuthClient::new(
        ClientId::generate(),
        "legacy keyless FAPI 2.0 client".to_string(),
        vec![REDIRECT.to_string()],
        Timestamp::from_micros(1),
    );
    assert!(
        client.is_public(),
        "control: a keyless standard client is public"
    );
    client.set_profile(ClientProfile::Fapi2);
    assert!(
        !client.is_public(),
        "a FAPI 2.0 client must never be accepted on its client_id alone"
    );
    assert!(
        client.requires_client_assertion(),
        "a FAPI 2.0 client authenticates with private_key_jwt only"
    );
}

#[test]
fn registration_refuses_a_fapi2_client_that_cannot_authenticate() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let fapi2 = |jwks: Option<String>, jwks_uri: Option<String>, generated: bool| {
        engine.register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "fapi2".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                profile: ClientProfile::Fapi2,
                jwks,
                jwks_uri,
                generated_client_secret: generated
                    .then(crate::identity::GeneratedClientSecret::generate),
                ..Default::default()
            },
        )
    };
    assert_fapi_violation(fapi2(None, None, false), "no keys");
    assert_fapi_violation(
        fapi2(None, Some("https://rp.example.com/jwks".to_string()), false),
        "jwks_uri only (never fetched)",
    );
    assert_fapi_violation(
        fapi2(Some(jwks()), None, true),
        "a generated secret beside the JWKS",
    );
    let ok = fapi2(Some(jwks()), None, false).expect("inline JWKS registers");
    assert!(!ok.is_public());
}

#[test]
fn update_refuses_to_make_a_keyless_client_fapi2() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let client = public_client(&engine, &realm);
    let outcome = engine.update_client(
        &realm,
        client.client_id(),
        &UpdateClientRequest {
            profile: Some(ClientProfile::Fapi2),
            ..Default::default()
        },
    );
    assert_fapi_violation(outcome, "profile=fapi2 on a keyless client");
    let stored = engine
        .get_client(&realm, client.client_id())
        .expect("get")
        .expect("exists");
    assert_eq!(stored.profile(), ClientProfile::Standard, "nothing written");

    // The same update carrying the client's JWKS succeeds.
    let updated = engine
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                profile: Some(ClientProfile::Fapi2),
                jwks: Some(Some(jwks())),
                ..Default::default()
            },
        )
        .expect("profile=fapi2 with a JWKS");
    assert!(updated.profile().is_fapi2());
    assert!(!updated.is_public());

    // And a FAPI 2.0 client cannot drop its last key.
    let outcome = engine.update_client(
        &realm,
        client.client_id(),
        &UpdateClientRequest {
            jwks: Some(None),
            ..Default::default()
        },
    );
    assert_fapi_violation(outcome, "removing a FAPI 2.0 client's JWKS");
}
