//! Concurrent revocations must never be lost from the revoked-JTI projection.
//!
//! Found by `make loadtest-smoke` once its revoke journey revoked tokens it
//! owned (task 26.43 follow-up): with 20 concurrent callers, about one
//! `client_credentials` token in eleven still introspected `active:true` after
//! `POST /revoke` had answered `200` — and stayed active on every later
//! introspection.
//!
//! The mechanism: every local control write bumps the persisted control epoch
//! (`bump_control_epoch`) *before* it records the new epoch in memory. A
//! validation that reads the persisted epoch in that window sees it ahead of
//! the local one, concludes another node asserted a control, and reloads the
//! control caches from storage with a `replace_all`. A second revocation whose
//! durable row lands after that reload's scan but whose cache insert lands
//! before its replace is overwritten — the durable row exists, the in-memory
//! blocklist the validation path trusts does not have it.
//!
//! The race is driven, not waited for: many threads mint, revoke and introspect
//! at once, and every token each of them revoked must read inactive. Before the
//! fix this fails within a few hundred cycles; it cannot fail after it.

use super::*;

use std::sync::Arc;

use crate::identity::oidc::{
    ClientCredentialsRequest, TokenIntrospectionRequest, TokenRevocationRequest,
};

const THREADS: usize = 16;
const CYCLES_PER_THREAD: usize = 60;

#[test]
fn concurrent_revocations_are_never_lost_from_the_revoked_jti_projection() {
    let (_dir, engine, _clock) = setup_engine();
    let engine = Arc::new(engine);
    let realm = create_test_realm(&engine);
    let secret = crate::identity::GeneratedClientSecret::generate();
    let client = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "M2M".to_string(),
                generated_client_secret: Some(secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: crate::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_id = client.client_id().clone();

    let barrier = Arc::new(std::sync::Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let engine = Arc::clone(&engine);
            let realm = realm.clone();
            let client_id = client_id.clone();
            let secret = secret.expose().to_string();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut revoked = Vec::with_capacity(CYCLES_PER_THREAD);
                for _ in 0..CYCLES_PER_THREAD {
                    let token = engine
                        .client_credentials_token(
                            &realm,
                            &ClientCredentialsRequest {
                                client_id: client_id.clone(),
                                client_secret: Some(secret.clone()),
                                scope: None,
                                dpop_jkt: None,
                                client_assertion_type: None,
                                client_assertion: None,
                            },
                        )
                        .expect("mint")
                        .access_token()
                        .to_string();
                    engine
                        .revoke_token(
                            &realm,
                            &TokenRevocationRequest {
                                token: token.clone(),
                                token_type_hint: Some("access_token".to_string()),
                                revoking_client_id: Some(client_id.clone()),
                            },
                        )
                        .expect("revoke");
                    revoked.push(token);
                }
                revoked
            })
        })
        .collect();

    let revoked: Vec<String> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("worker"))
        .collect();
    let still_active = revoked
        .iter()
        .filter(|token| {
            engine
                .introspect_token(
                    &realm,
                    &TokenIntrospectionRequest {
                        token: (*token).clone(),
                        token_type_hint: None,
                        introspecting_client_id: Some(client_id.clone()),
                    },
                )
                .expect("introspect")
                .active
        })
        .count();
    assert_eq!(
        still_active,
        0,
        "{still_active} of {} revoked tokens still introspect active: a concurrent \
         control-cache reload overwrote their revocation",
        revoked.len()
    );
}
