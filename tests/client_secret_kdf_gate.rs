#![allow(clippy::unwrap_used)]
//! Argon2id client-secret verification runs behind the KDF admission gate.
//!
//! A caller-chosen client secret (`hearth.yaml`
//! `applications[].client_secret`, a migration import, or any client created
//! before generated secrets moved to SHA-256) is stored as Argon2id. Verifying
//! it used to run directly on a Tokio worker, outside the shared KDF gate that
//! bounds every password hash. `hearth.yaml` client ids are UUID v5 values
//! computable from the realm and application key, so an unauthenticated caller
//! could force one Argon2id run per request at `/token`, `/introspect`,
//! `/revoke`, `/device` (and their realm twins) — CPU and memory the
//! gate exists to cap.
//!
//! Pinned here: with the gate saturated (its sole permit held), those
//! verifications are SHED with `503` + `Retry-After` — the password paths'
//! convention — instead of running ungated; a Hearth-generated secret (the
//! fast `$hearth-sha256$` format) is NOT gated and still authenticates; and
//! once the permit frees, the Argon2id client authenticates again, proving the
//! 503 came from the gate.

mod common;

use std::time::Duration;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, GeneratedClientSecret, KdfGateConfig,
    RegisterClientRequest,
};

const ARGON2_SECRET: &str = "operator-chosen-client-secret-1!";

fn register(h: &common::TestHarness, realm: &RealmId, secret: RegisterSecret) -> ClientId {
    let (client_secret, generated_client_secret) = match secret {
        RegisterSecret::Argon2 => (Some(ARGON2_SECRET.to_string()), None),
        RegisterSecret::Generated(s) => (None, Some(s)),
    };
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("client-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret,
                generated_client_secret,
                grant_types: vec!["client_credentials".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

enum RegisterSecret {
    Argon2,
    Generated(GeneratedClientSecret),
}

async fn post(
    url: String,
    realm: Option<&RealmId>,
    client: &ClientId,
    secret: &str,
    form: &[(&str, &str)],
) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .basic_auth(client.as_uuid().to_string(), Some(secret))
        .form(form);
    if let Some(realm) = realm {
        req = req.header("X-Realm-ID", realm.as_uuid().to_string());
    }
    req.send().await.expect("request")
}

async fn assert_shed(resp: reqwest::Response, what: &str) {
    assert_eq!(
        resp.status().as_u16(),
        503,
        "{what}: an Argon2id client-secret verification must be shed by the saturated KDF \
         gate, not run ungated"
    );
    assert!(
        resp.headers().contains_key("retry-after"),
        "{what}: a shed response must carry Retry-After"
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        body["error_code"], "HEARTH_RATE_LIMITED",
        "{what}: a shed response carries the machine-readable error code: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn argon2_client_secrets_are_verified_behind_the_kdf_gate() {
    // A 1-permit gate, installed before anything touches `gate()`. nextest
    // runs this test in its own process, so it wins the OnceLock.
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: Duration::from_millis(40),
        retry_after: Duration::from_secs(2),
    });
    assert!(installed, "init_gate must win the process-global OnceLock");

    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("kdf-client-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let argon2_client = register(&h, &realm, RegisterSecret::Argon2);
    let generated = GeneratedClientSecret::generate();
    let fast_client = register(&h, &realm, RegisterSecret::Generated(generated.clone()));

    // Hold the sole permit; the signal fires from inside the gated closure.
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

    let introspect = [("token", "not-a-token")];
    let resp = post(
        format!("{base}/introspect"),
        Some(&realm),
        &argon2_client,
        ARGON2_SECRET,
        &introspect,
    )
    .await;
    assert_shed(resp, "POST /introspect").await;

    let resp = post(
        format!("{base}/realms/{realm_name}/revoke"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("token", "not-a-token")],
    )
    .await;
    assert_shed(resp, "POST /realms/{realm}/revoke").await;

    let resp = post(
        format!("{base}/realms/{realm_name}/token"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("grant_type", "client_credentials")],
    )
    .await;
    assert_shed(resp, "POST /realms/{realm}/token client_credentials").await;

    let argon2_id = argon2_client.as_uuid().to_string();
    let resp = post(
        format!("{base}/realms/{realm_name}/device_authorization"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("client_id", argon2_id.as_str())],
    )
    .await;
    assert_shed(resp, "POST /realms/{realm}/device_authorization").await;

    // A generated (fast-hash) secret is not gated: it authenticates while the
    // gate is saturated.
    let resp = post(
        format!("{base}/introspect"),
        Some(&realm),
        &fast_client,
        generated.expose(),
        &introspect,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a fast-hash client secret must not wait on the KDF gate"
    );

    // Free the permit: the Argon2id client authenticates again.
    release_tx.send(()).expect("release the permit");
    holder.await.expect("holder joins");
    let resp = post(
        format!("{base}/introspect"),
        Some(&realm),
        &argon2_client,
        ARGON2_SECRET,
        &introspect,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "with a free permit the Argon2id client must authenticate"
    );
}

/// A burst of Argon2id client authentications LARGER than the Tokio blocking
/// pool completes — every caller is served or shed — instead of hanging the
/// runtime.
///
/// The first gated client-secret check parked each calling worker with
/// `block_in_place` and waited for a permit on the thread it handed its core
/// to. Every such caller took a blocking-pool thread BEFORE it waited, so once
/// more callers arrived than `max_blocking_threads`, the handed-off cores got
/// no thread, nothing drove the timer that sheds a waiter, and the runtime sat
/// at 0 % CPU for ever (production: ~512+ concurrent Argon2id client auths on
/// the default pool). The runtime here is deliberately small — 2 workers, 8
/// blocking threads — and offered 64 concurrent `/introspect` calls.
#[test]
fn an_argon2_client_auth_burst_larger_than_the_blocking_pool_completes() {
    const CALLERS: usize = 64;
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Vec<u16>>();
    // The runtime lives on its own thread so a hang is reported as a failure
    // here instead of wedging the test process.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        let statuses = rt.block_on(async {
            assert!(
                hearth::identity::init_gate(KdfGateConfig {
                    max_in_flight: 2,
                    max_queue_wait: Duration::from_millis(250),
                    retry_after: Duration::from_secs(1),
                }),
                "init_gate must win the process-global OnceLock"
            );
            let h = common::TestHarness::server().await.expect("server harness");
            let base = h.base_url().expect("base_url").to_string();
            let realm = h
                .identity()
                .create_realm(&CreateRealmRequest {
                    name: format!("kdf-burst-{}", uuid::Uuid::new_v4()),
                    config: None,
                })
                .expect("create realm")
                .id()
                .clone();
            let client = register(&h, &realm, RegisterSecret::Argon2);
            let mut tasks = Vec::with_capacity(CALLERS);
            for _ in 0..CALLERS {
                let (base, realm, client) = (base.clone(), realm.clone(), client.clone());
                tasks.push(tokio::spawn(async move {
                    post(
                        format!("{base}/introspect"),
                        Some(&realm),
                        &client,
                        ARGON2_SECRET,
                        &[("token", "not-a-token")],
                    )
                    .await
                    .status()
                    .as_u16()
                }));
            }
            let mut statuses = Vec::with_capacity(CALLERS);
            for t in tasks {
                statuses.push(t.await.expect("caller joins"));
            }
            statuses
        });
        let _ = done_tx.send(statuses);
    });
    let statuses = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the runtime hung: an Argon2id client-auth burst larger than the blocking pool never completed");
    assert_eq!(statuses.len(), CALLERS);
    assert!(
        statuses.iter().all(|s| *s == 200 || *s == 503),
        "every caller must be served (200) or shed (503): {statuses:?}"
    );
    assert!(
        statuses.contains(&200),
        "a bounded gate still serves some of the burst: {statuses:?}"
    );
}
