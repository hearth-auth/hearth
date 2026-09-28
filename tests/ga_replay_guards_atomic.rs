//! GA audit 2026-09-28 L9 — single-use guards were check-then-write.
//!
//! The RFC 8693 `actor_token` jti guard and PAR `request_uri` consumption read
//! the marker, then wrote it. Two concurrent requests could both pass the read
//! (the write fsyncs the WAL before the key becomes visible, so the window is
//! wide) and both succeed. Each is now a single atomic step: `put_if_absent`
//! on a marker key (atomic in the embedded engine and Raft-routed in cluster
//! mode). The JAR `jti` twin is covered in `tests/jar.rs`; PAR consumption (its
//! return type is crate-private) in `src/identity/engine/tests/par_consume_race.rs`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::{Arc, Barrier};

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientCredentialsRequest, ClientTrustLevel, CreateUserRequest, IdentityEngine, IdentityError,
    RegisterClientRequest, Rfc8693Request, SessionContext, TokenIssuanceContext,
};

const RACERS: usize = 8;
const ROUNDS: usize = 5;
const SECRET: &str = "ga-replay-secret-0123456789!";

/// Runs `f` on `RACERS` threads released together; returns how many succeeded.
fn race<T: Send>(f: impl Fn(usize) -> Result<T, IdentityError> + Sync) -> usize {
    let barrier = Barrier::new(RACERS);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let (barrier, f) = (&barrier, &f);
                s.spawn(move || {
                    barrier.wait();
                    f(i).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    })
}

fn exchange_client(identity: &dyn IdentityEngine, realm: &RealmId) -> ClientId {
    identity
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("racer-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(SECRET.to_string()),
                grant_types: vec![
                    "client_credentials".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap()
        .client_id()
        .clone()
}

fn subject_token(identity: &dyn IdentityEngine, realm: &RealmId) -> String {
    let user = identity
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("racer-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Racer".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let session = identity
        .create_session(realm, user.id(), &SessionContext::default())
        .unwrap();
    identity
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                granted_scopes: std::iter::once("read".to_string()).collect(),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
        .access_token()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_concurrently_replayed_actor_token_is_accepted_once() {
    let h = common::TestHarness::embedded().await.unwrap();
    let identity: Arc<dyn IdentityEngine> = h.identity_arc();
    let realm = h.create_realm();
    let client = exchange_client(identity.as_ref(), &realm);

    for round in 0..ROUNDS {
        let actor_token = identity
            .client_credentials_token(
                &realm,
                &ClientCredentialsRequest {
                    client_id: client.clone(),
                    client_secret: Some(SECRET.to_string()),
                    scope: None,
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .unwrap()
            .access_token()
            .to_string();
        let subjects: Vec<String> = (0..RACERS)
            .map(|_| subject_token(identity.as_ref(), &realm))
            .collect();

        let wins = race(|i| {
            identity.rfc8693_token_exchange(
                &realm,
                &Rfc8693Request {
                    client_id: client.clone(),
                    subject_token: subjects[i].clone(),
                    subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                    actor_token: Some(actor_token.clone()),
                    actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                    requested_token_type: None,
                    scope: None,
                    resource: None,
                    audience: None,
                    dpop_jkt: None,
                },
            )
        });
        assert_eq!(
            wins, 1,
            "round {round}: one actor_token jti must admit exactly one exchange, {wins} won"
        );
    }
}
