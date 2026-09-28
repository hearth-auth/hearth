//! GA audit 2026-09-28 L9 — PAR `request_uri` consumption was check-then-write
//! (read, test `used`, set `used`, write back), so concurrent authorizations
//! presenting one `request_uri` could each consume it. Consumption is now a
//! single `put_if_absent` on a per-`request_uri` marker.

use super::*;

use std::sync::Barrier;

use crate::identity::oidc::{CodeChallengeMethod, PushedAuthorizationRequest};

const RACERS: usize = 8;

#[test]
fn a_par_request_uri_is_consumed_once_under_concurrency() {
    use base64::Engine as _;
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let client = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "par-racer".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone();
    let digest = ring::digest::digest(&ring::digest::SHA256, b"par-racer-verifier-0123456789abc");
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

    for round in 0..5 {
        let pushed = engine
            .push_authorization_request(
                &realm,
                &PushedAuthorizationRequest {
                    client_id: client.clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "st".to_string(),
                    resource: None,
                    response_type: "code".to_string(),
                    code_challenge: Some(challenge.clone()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    request: None,
                    response_mode: None,
                    prompt: None,
                },
            )
            .expect("push PAR");
        let barrier = Barrier::new(RACERS);
        let wins = std::thread::scope(|s| {
            let handles: Vec<_> = (0..RACERS)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        engine.consume_par(&realm, &pushed.request_uri).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("racer"))
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(
            wins, 1,
            "round {round}: one request_uri, {wins} consumed it"
        );
    }
}
