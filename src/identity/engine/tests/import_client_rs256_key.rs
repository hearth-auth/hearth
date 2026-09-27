//! An overwrite restore validates a client, deletes the live one, then
//! re-imports the archived record. `import_client` still loaded the realm's
//! RS256 ID-token key after the delete — and a stored key that will not
//! unwrap or decode fails there, not only on storage — so an RS256 client
//! could be deleted and never restored. `validate_import_client` now loads
//! the key too, so the record is refused before anything is deleted.

use super::*;

fn rs256_request(id: &ClientId) -> ImportClientRequest {
    ImportClientRequest {
        id: Some(id.clone()),
        client_name: "rs256".to_string(),
        redirect_uris: vec!["https://app.example.com/cb".to_string()],
        client_secret: Some("an-rs256-client-secret-0123456789".to_string()),
        grant_types: vec!["authorization_code".to_string()],
        id_token_signed_response_alg: Some("RS256".to_string()),
        ..Default::default()
    }
}

#[test]
fn validate_import_client_refuses_an_rs256_client_whose_realm_key_will_not_load() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "rs256-realm".to_string(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    let live = ClientId::generate();
    engine
        .import_client(&realm, &rs256_request(&live))
        .expect("an RS256 client provisions the realm's RSA key");
    engine
        .validate_import_client(&realm, &rs256_request(&ClientId::generate()))
        .expect("control: with a usable key the record validates");

    // The stored key no longer unwraps (corruption, or a KEK mismatch).
    engine
        .storage
        .put(
            &keys::system_realm_id(),
            &keys::encode_realm_id_token_rsa_key(&realm),
            b"not a sealed RSA key",
        )
        .expect("corrupt the stored key");
    engine.realm_id_token_rsa_keys.remove(&realm);

    let err = engine
        .validate_import_client(&realm, &rs256_request(&ClientId::generate()))
        .expect_err(
            "an RS256 record whose realm key cannot load must be refused at validation, \
             before an overwrite deletes the live client",
        );
    assert!(
        !matches!(err, IdentityError::InvalidInput { .. }),
        "the refusal is the key failure, not a request error: {err:?}"
    );
}
