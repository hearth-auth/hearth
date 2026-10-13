//! Tokens issued before 4.0 carry prefixed IDs (`sub` = `user_<uuid>`,
//! `sid` = `session_<uuid>`, `tid` = `realm_<uuid>`). Hearth now issues bare
//! UUIDs, and it still accepts the old forms until those tokens expire
//! (OpenSpec change `bare-entity-ids`).

use super::*;

use crate::identity::tokens::decode_claims_unverified;

/// Re-signs `token` with the claim forms a release before 4.0 issued.
fn with_legacy_ids(engine: &EmbeddedIdentityEngine, realm: &RealmId, token: &str) -> String {
    let mut claims = decode_claims_unverified(token).expect("decode");
    claims.sub = format!("user_{}", claims.sub);
    claims.sid = format!("session_{}", claims.sid);
    claims.tid = format!("realm_{}", claims.tid);
    engine
        .get_signing_key_or_default(realm)
        .issue_token(&claims)
        .expect("re-sign")
}

#[test]
fn a_token_with_prefixed_ids_stays_valid() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue");

    let fresh = decode_claims_unverified(tokens.access_token()).expect("decode");
    assert_eq!(fresh.sub, user.id().as_uuid().to_string(), "issued bare");
    assert_eq!(fresh.sid, session.id().as_uuid().to_string(), "issued bare");

    let legacy = with_legacy_ids(&engine, &realm, tokens.access_token());
    let claims = engine
        .validate_token(&realm, &legacy)
        .expect("a token with prefixed IDs validates");
    assert_eq!(claims.sub, format!("user_{}", user.id().as_uuid()));

    // UserInfo echoes the token's `sub`, which equals the `sub` of the ID
    // token the relying party holds (OIDC Core §5.3.2).
    let info = engine
        .userinfo(&realm, &legacy)
        .expect("userinfo reads a prefixed sub");
    assert_eq!(info.sub, claims.sub);
}

#[test]
fn a_refresh_token_with_prefixed_ids_still_refreshes() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue");

    let legacy = with_legacy_ids(&engine, &realm, tokens.refresh_token());
    // The grant family stores the hash of its current refresh token. Make
    // the re-signed token the current one, as if it had been issued so.
    let fid = decode_claims_unverified(&legacy)
        .expect("decode")
        .fid
        .expect("a grant family");
    let family_key = keys::encode_grant_family(&fid);
    let mut family: StoredGrantFamily = serde_json::from_slice(
        &engine
            .storage
            .get(&realm, &family_key)
            .expect("read family")
            .expect("family exists"),
    )
    .expect("parse family");
    family.current_refresh_hash = EmbeddedIdentityEngine::sha256_hex(legacy.as_bytes());
    engine
        .storage
        .put(
            &realm,
            &family_key,
            &serde_json::to_vec(&family).expect("encode family"),
        )
        .expect("write family");

    let renewed = engine
        .refresh_tokens(&realm, &legacy, None, None)
        .expect("a refresh token with prefixed IDs refreshes");
    let claims = decode_claims_unverified(renewed.access_token()).expect("decode");
    assert_eq!(
        claims.sub,
        user.id().as_uuid().to_string(),
        "re-issued bare"
    );
    assert_eq!(
        claims.sid,
        session.id().as_uuid().to_string(),
        "re-issued bare"
    );
}
