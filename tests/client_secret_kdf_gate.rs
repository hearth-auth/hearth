#![allow(clippy::unwrap_used)]
//! Argon2id client-secret verification runs behind the KDF admission gate.
//!
//! A caller-chosen client secret (gRPC `RegisterClient`, `hearth.yaml`
//! `applications[].client_secret`, a migration import, or any client created
//! before generated secrets moved to SHA-256) is stored as Argon2id. Verifying
//! it used to run directly on a Tokio worker, outside the shared KDF gate that
//! bounds every password hash. `hearth.yaml` client ids are UUID v5 values
//! computable from the realm and application key, so an unauthenticated caller
//! could force one Argon2id run per request at `/token`, `/introspect`,
//! `/revoke`, `/device` (and their realm twins, and gRPC) — CPU and memory the
//! gate exists to cap.
//!
//! Pinned here: with the gate saturated (its sole permit held), those
//! verifications are SHED with `503` + `Retry-After` — the password paths'
//! convention — instead of running ungated; a Hearth-generated secret (the
//! fast `$hearth-sha256$` format) is NOT gated and still authenticates; and
//! once the permit frees, the Argon2id client authenticates again, proving the
//! 503 came from the gate.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, GeneratedClientSecret, KdfGateConfig,
    RegisterClientRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use tonic::{Code, Request as TonicRequest};

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

fn assert_shed(resp: &reqwest::Response, what: &str) {
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
}

/// gRPC `Introspect` with the Argon2id client is shed as `UNAVAILABLE`.
async fn assert_grpc_introspect_shed(h: &common::TestHarness, realm: &RealmId, client: &ClientId) {
    let svc = OAuthSvc::new(GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ));
    let mut req = TonicRequest::new(id_pb::TokenIntrospectionRequest {
        token: "not-a-token".to_string(),
        token_type_hint: None,
    });
    req.metadata_mut()
        .insert("x-realm-id", realm.as_uuid().to_string().parse().unwrap());
    req.metadata_mut().insert(
        "x-hearth-client-id",
        client.as_uuid().to_string().parse().unwrap(),
    );
    req.metadata_mut()
        .insert("x-hearth-client-secret", ARGON2_SECRET.parse().unwrap());
    let err = svc
        .introspect(req)
        .await
        .expect_err("a saturated gate must shed the gRPC Argon2id verification");
    assert_eq!(err.code(), Code::Unavailable, "gRPC shed: {err:?}");
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
    assert_shed(&resp, "POST /introspect");

    let resp = post(
        format!("{base}/realms/{realm_name}/revoke"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("token", "not-a-token")],
    )
    .await;
    assert_shed(&resp, "POST /realms/{realm}/revoke");

    let resp = post(
        format!("{base}/realms/{realm_name}/token"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("grant_type", "client_credentials")],
    )
    .await;
    assert_shed(&resp, "POST /realms/{realm}/token client_credentials");

    let argon2_id = argon2_client.as_uuid().to_string();
    let resp = post(
        format!("{base}/realms/{realm_name}/device_authorization"),
        None,
        &argon2_client,
        ARGON2_SECRET,
        &[("client_id", argon2_id.as_str())],
    )
    .await;
    assert_shed(&resp, "POST /realms/{realm}/device_authorization");

    // gRPC reaches the same verification.
    assert_grpc_introspect_shed(&h, &realm, &argon2_client).await;

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
