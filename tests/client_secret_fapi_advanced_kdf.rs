#![allow(clippy::unwrap_used)]
//! A FAPI 2.0 Advanced realm refuses a client secret BEFORE the KDF gate
//! (KDF/PAR review L3).
//!
//! An Advanced realm accepts only `private_key_jwt`, so every secret is
//! refused — but the "is this an Argon2id secret?" pre-check ignored the
//! realm: an Argon2id client's secret waited for a KDF permit (or was shed
//! with `503`) before the engine refused it, while an unknown client got
//! `401` at once. The 503-vs-401 difference told a caller which client ids
//! exist and hold Argon2id secrets. The realm now decides first: `401
//! invalid_client` naming `private_key_jwt` for every client, with no gate
//! wait, even while the gate is saturated.

mod common;

use std::time::Duration;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, FapiProfile, KdfGateConfig, RealmConfig,
    RegisterClientRequest, UpdateRealmRequest,
};

const ARGON2_SECRET: &str = "operator-chosen-client-secret-1!";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_advanced_realm_refuses_an_argon2_secret_without_touching_the_gate() {
    assert!(
        hearth::identity::init_gate(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(200),
            retry_after: Duration::from_secs(2),
        }),
        "init_gate must win the process-global OnceLock"
    );
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm: RealmId = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-kdf-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone();
    // Registered before the realm turns Advanced: a caller-chosen secret is
    // stored as Argon2id.
    let argon2_client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "argon2".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(ARGON2_SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .unwrap()
        .client_id()
        .clone();
    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    fapi_profile: Some(FapiProfile::Advanced),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();

    // Saturate the gate: an Argon2id check that reached it would wait 200 ms
    // and be shed with 503.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    for (who, client) in [
        ("argon2 client", argon2_client),
        ("unknown client", ClientId::generate()),
    ] {
        for (endpoint, form) in [
            ("token", vec![("grant_type", "client_credentials")]),
            ("introspect", vec![("token", "not-a-token")]),
            ("revoke", vec![("token", "not-a-token")]),
        ] {
            let started = std::time::Instant::now();
            let resp = reqwest::Client::new()
                .post(format!("{base}/{endpoint}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .basic_auth(client.as_uuid().to_string(), Some(ARGON2_SECRET))
                .form(&form)
                .send()
                .await
                .unwrap();
            let elapsed = started.elapsed();
            let status = resp.status().as_u16();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            assert_eq!(status, 401, "{who} /{endpoint}: {body}");
            assert!(
                body["error_description"]
                    .as_str()
                    .is_some_and(|d| d.contains("private_key_jwt")),
                "{who} /{endpoint}: the refusal names private_key_jwt: {body}"
            );
            assert!(
                elapsed < Duration::from_millis(150),
                "{who} /{endpoint}: refused without waiting on the gate ({elapsed:?})"
            );
        }
    }

    release_tx.send(()).unwrap();
    holder.await.unwrap();
}
