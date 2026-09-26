//! `private_key_jwt` assertion-JTI replay markers: bounded lifetime.
//!
//! `verify_client_assertion` burns every assertion's `jti` into
//! `oauth:ca-jti:{jti}` so the assertion cannot be replayed. It serves the
//! token endpoint, `/introspect` and `/revoke`, so it runs once per
//! authenticated request on some of the busiest endpoints the server has.
//!
//! The marker used to be a bare `b"1"` with no expiry, and no cleanup sweep
//! knew the prefix — every authenticated request leaked one row for the life
//! of the realm. The marker now records the instant after which the assertion
//! it guards can no longer be accepted (`exp` + clock skew), exactly like the
//! JAR, DPoP and nonce sentinels, and the periodic sweep reclaims it past that
//! instant.
//!
//! What must still hold: a replay inside the assertion's lifetime is refused,
//! and the sweep never deletes a marker whose assertion could still verify.

use super::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::identity::oidc::UpdateClientRequest;
use crate::identity::tokens::{Audience, JwtAssertionClaims};

const ONE_SEC_MICROS: i64 = 1_000_000;

/// Registers a secretless client whose only credential is an Ed25519
/// assertion key, and returns it with the matching private key.
fn register_pkjwt(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
) -> (crate::core::ClientId, SigningKey) {
    let key = SigningKey::generate().expect("key");
    let client_id = engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("pkjwt-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["client_credentials".to_string()],
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
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

fn now_secs(clock: &FakeClock) -> i64 {
    clock.now().as_micros() / ONE_SEC_MICROS
}

/// Signs an assertion for `client_id` expiring `ttl_secs` from the fake clock.
fn sign(
    engine: &EmbeddedIdentityEngine,
    clock: &FakeClock,
    realm: &RealmId,
    client_id: &crate::core::ClientId,
    key: &SigningKey,
    jti: &str,
    ttl_secs: i64,
) -> (String, i64) {
    let now = now_secs(clock);
    let exp = now + ttl_secs;
    let jwt = key
        .issue_assertion_jwt(&JwtAssertionClaims {
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            aud: Audience::single(engine.realm_issuer_url(realm)),
            exp,
            jti: Some(jti.to_string()),
            iat: Some(now),
        })
        .expect("sign assertion");
    (jwt, exp)
}

fn marker(engine: &EmbeddedIdentityEngine, realm: &RealmId, jti: &str) -> Option<Vec<u8>> {
    engine
        .storage
        .get(realm, &keys::encode_client_assertion_jti(jti))
        .expect("marker read")
}

fn assert_replay_refused(result: Result<(), IdentityError>, what: &str) {
    match result {
        Err(IdentityError::InvalidClientAssertion { reason }) => assert!(
            reason.contains("replay"),
            "{what}: must be refused as a replay, got reason {reason:?}"
        ),
        other => panic!("{what}: expected a replay refusal, got {other:?}"),
    }
}

#[test]
fn replayed_assertion_is_refused_within_its_lifetime() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let (client_id, key) = register_pkjwt(&engine, &realm);
    let (jwt, _exp) = sign(&engine, &clock, &realm, &client_id, &key, "jti-replay", 60);

    engine
        .verify_client_assertion(&realm, &client_id, &jwt)
        .expect("first presentation must authenticate");

    assert_replay_refused(
        engine.verify_client_assertion(&realm, &client_id, &jwt),
        "immediate replay",
    );

    // Still refused late in the assertion's lifetime, after a sweep has run.
    clock.advance(59 * ONE_SEC_MICROS);
    engine.sweep_expired(&realm).expect("sweep");
    assert_replay_refused(
        engine.verify_client_assertion(&realm, &client_id, &jwt),
        "replay one second before exp, after a sweep",
    );
}

#[test]
fn marker_records_assertion_exp_plus_clock_skew() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let (client_id, key) = register_pkjwt(&engine, &realm);
    let (jwt, exp) = sign(&engine, &clock, &realm, &client_id, &key, "jti-shape", 120);

    engine
        .verify_client_assertion(&realm, &client_id, &jwt)
        .expect("authenticate");

    let stored = marker(&engine, &realm, "jti-shape").expect("marker must be written");
    assert_eq!(
        stored,
        (exp + CLOCK_SKEW_SECS).to_le_bytes().to_vec(),
        "marker must carry the assertion's exp + clock skew as an 8-byte LE i64"
    );
}

#[test]
fn sweep_reclaims_marker_once_the_assertion_can_no_longer_verify() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let (client_id, key) = register_pkjwt(&engine, &realm);
    let (jwt, exp) = sign(&engine, &clock, &realm, &client_id, &key, "jti-swept", 60);

    engine
        .verify_client_assertion(&realm, &client_id, &jwt)
        .expect("authenticate");
    assert!(marker(&engine, &realm, "jti-swept").is_some());

    // Move to exactly exp + skew: the assertion is dead on its own exp check.
    let target = (exp + CLOCK_SKEW_SECS) * ONE_SEC_MICROS;
    clock.advance(target - clock.now().as_micros());

    let stats = engine.sweep_expired(&realm).expect("sweep");
    assert!(
        marker(&engine, &realm, "jti-swept").is_none(),
        "an expired marker must be reclaimed by the periodic sweep"
    );
    assert_eq!(stats.client_assertion_jtis_deleted, 1, "stats: {stats:?}");

    // Reclaiming the marker must not reopen the assertion.
    match engine.verify_client_assertion(&realm, &client_id, &jwt) {
        Err(IdentityError::InvalidClientAssertion { reason }) => assert!(
            reason.contains("expired"),
            "the swept assertion must be refused as expired, got {reason:?}"
        ),
        other => panic!("swept assertion must not verify, got {other:?}"),
    }
}

#[test]
fn sweep_keeps_marker_inside_the_skew_window() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let (client_id, key) = register_pkjwt(&engine, &realm);
    let (jwt, exp) = sign(&engine, &clock, &realm, &client_id, &key, "jti-kept", 60);
    // An unrelated, still-live marker must survive a sweep that reclaims
    // nothing — the control for the deletion test above.
    let (other, _) = sign(&engine, &clock, &realm, &client_id, &key, "jti-other", 300);

    engine
        .verify_client_assertion(&realm, &client_id, &jwt)
        .expect("authenticate");
    engine
        .verify_client_assertion(&realm, &client_id, &other)
        .expect("authenticate other");

    // Past exp, but one second short of exp + skew: a node whose clock lags
    // by up to the skew could still accept the assertion, so keep the marker.
    let target = (exp + CLOCK_SKEW_SECS - 1) * ONE_SEC_MICROS;
    clock.advance(target - clock.now().as_micros());

    let stats = engine.sweep_expired(&realm).expect("sweep");
    assert_eq!(stats.client_assertion_jtis_deleted, 0, "stats: {stats:?}");
    assert!(
        marker(&engine, &realm, "jti-kept").is_some(),
        "a marker inside the skew window must survive the sweep"
    );
    assert!(
        marker(&engine, &realm, "jti-other").is_some(),
        "a live marker must survive the sweep"
    );
    assert_replay_refused(
        engine.verify_client_assertion(&realm, &client_id, &other),
        "replay of the still-live assertion after a sweep",
    );
}
