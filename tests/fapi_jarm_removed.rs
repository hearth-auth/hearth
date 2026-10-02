//! scope-trim-trusted-core, group 9: JARM and the FAPI 2.0 profile are
//! removed; DPoP enforcement no longer depends on them.
//!
//! A client that must use sender-constrained tokens says so with the RFC 9449
//! §5.2 client metadata `dpop_bound_access_tokens`. Every grant refuses such a
//! client without a `DPoP` proof — no FAPI profile is involved. The FAPI config
//! keys stop startup with a named error, discovery advertises neither JARM nor
//! FAPI, and a JARM `response_mode` is unsupported.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::config::{Config, ConfigError};
use hearth::identity::{
    ClientCredentialsRequest, CreateRealmRequest, IdentityError, RealmConfig, RegisterClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

// ─── Removed config keys ─────────────────────────────────────────────────────

const REMOVED: &[(&str, &str)] = &[
    (
        "realms:\n  acme:\n    fapi_profile: baseline\n",
        "realms.acme.fapi_profile",
    ),
    (
        "realms:\n  acme:\n    applications:\n      app:\n        name: App\n        \
         redirect_uris: [\"https://app.example/cb\"]\n        profile: fapi2\n",
        "realms.acme.applications.app.profile",
    ),
    (
        "realms:\n  acme:\n    oauth_clients:\n      app:\n        name: App\n        \
         redirect_uris: [\"https://app.example/cb\"]\n        profile: fapi2\n",
        "realms.acme.oauth_clients.app.profile",
    ),
];

fn assert_names_removed_fapi(err: &ConfigError, key: &str) {
    assert!(
        matches!(err, ConfigError::RemovedKey { .. }),
        "{key}: expected RemovedKey, got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&format!("'{key}'")), "{key}: {msg}");
    assert!(msg.contains("FAPI"), "{key}: {msg}");
    assert!(msg.contains("3.0.0"), "{key}: {msg}");
    assert!(
        msg.contains("dpop_bound_access_tokens"),
        "{key}: the message points at the replacement: {msg}"
    );
}

#[test]
fn fapi_keys_stop_both_loaders() {
    for (yaml, key) in REMOVED {
        let err = Config::from_yaml_str(yaml).expect_err("removed key must fail");
        assert_names_removed_fapi(&err, key);
        let err = Config::from_yaml_str_unchecked(yaml).expect_err("removed key must fail");
        assert_names_removed_fapi(&err, key);
    }
}

/// The replacement is a valid `hearth.yaml` key on an application.
#[test]
fn dpop_bound_access_tokens_is_an_application_key() {
    let yaml = "realms:\n  acme:\n    applications:\n      app:\n        name: App\n        \
                redirect_uris: [\"https://app.example/cb\"]\n        \
                dpop_bound_access_tokens: true\n";
    Config::from_yaml_str_unchecked(yaml).expect("the replacement key parses");
}

// ─── DPoP-required clients, with no FAPI profile ─────────────────────────────

const SECRET: &str = "dpop-required-client-secret-1";

fn m2m_client(h: &common::TestHarness, dpop_required: bool) -> (hearth::core::RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-req-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig::default()),
        })
        .expect("realm")
        .id()
        .clone();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "m2m".to_string(),
                redirect_uris: vec![],
                client_secret: Some(SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                dpop_bound_access_tokens: dpop_required,
                ..Default::default()
            },
        )
        .expect("register client");
    (realm, client.client_id().as_uuid().to_string())
}

fn cc_request(client_id: &str, dpop_jkt: Option<&str>) -> ClientCredentialsRequest {
    ClientCredentialsRequest {
        client_id: hearth::core::ClientId::new(uuid::Uuid::parse_str(client_id).expect("uuid")),
        client_secret: Some(SECRET.to_string()),
        scope: None,
        dpop_jkt: dpop_jkt.map(str::to_string),
        client_assertion_type: None,
        client_assertion: None,
    }
}

#[tokio::test]
async fn a_dpop_required_client_without_a_proof_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, client_id) = m2m_client(&h, true);
    let err = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&client_id, None))
        .expect_err("no proof, no token");
    assert!(
        matches!(err, IdentityError::InvalidDPopProof { .. }),
        "expected InvalidDPopProof, got {err:?}"
    );
}

#[tokio::test]
async fn a_dpop_required_client_with_a_proof_gets_a_bound_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, client_id) = m2m_client(&h, true);
    let jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let resp = h
        .identity()
        .client_credentials_token(&realm, &cc_request(&client_id, Some(jkt)))
        .expect("a proof satisfies the requirement");
    let claims = hearth::identity::decode_claims_unverified(resp.access_token())
        .expect("decode access token");
    assert_eq!(
        claims.cnf.as_ref().map(|c| c.jkt.as_str()),
        Some(jkt),
        "the token is bound to the proof's key"
    );
}

/// Control: a client without the flag still gets a bearer token.
#[tokio::test]
async fn a_client_without_the_flag_still_gets_a_bearer_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, client_id) = m2m_client(&h, false);
    h.identity()
        .client_credentials_token(&realm, &cc_request(&client_id, None))
        .expect("bearer tokens stay available");
}

// ─── Discovery, JARM response modes and registration ─────────────────────────

async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

#[tokio::test]
async fn discovery_advertises_neither_jarm_nor_fapi() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (status, doc) = send(
        app(&h),
        Request::builder()
            .uri("/.well-known/openid-configuration")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(
        doc.get("pushed_authorization_request_endpoint").is_some(),
        "control: PAR stays"
    );
    assert!(
        doc.get("dpop_signing_alg_values_supported").is_some(),
        "control: DPoP stays"
    );
    assert!(
        doc.get("authorization_signing_alg_values_supported")
            .is_none(),
        "{doc}"
    );
    assert!(doc.get("fapi_profile").is_none(), "{doc}");
    let modes = doc["response_modes_supported"]
        .as_array()
        .expect("response_modes_supported");
    assert!(
        !modes
            .iter()
            .any(|m| m.as_str().is_some_and(|m| m.ends_with("jwt"))),
        "no JARM response mode: {modes:?}"
    );
}

#[test]
fn jarm_response_modes_no_longer_parse() {
    for mode in ["query.jwt", "fragment.jwt", "form_post.jwt", "jwt"] {
        assert!(
            mode.parse::<hearth::identity::ResponseMode>().is_err(),
            "{mode} must be unsupported"
        );
    }
    assert!(
        "query".parse::<hearth::identity::ResponseMode>().is_ok(),
        "control: query stays"
    );
}

#[tokio::test]
async fn dynamic_registration_records_dpop_bound_access_tokens() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-dcr-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                dcr_policy: Some(hearth::identity::DcrPolicy::Open),
                ..Default::default()
            }),
        })
        .expect("realm")
        .id()
        .clone();
    let (status, body) = send(
        app(&h),
        Request::builder()
            .method("POST")
            .uri("/register")
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "client_name": "dpop-dcr",
                    "redirect_uris": ["https://app.example.com/cb"],
                    "grant_types": ["authorization_code"],
                    "dpop_bound_access_tokens": true,
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["dpop_bound_access_tokens"], true, "echoed: {body}");
    let client_id = hearth::core::ClientId::new(
        uuid::Uuid::parse_str(body["client_id"].as_str().expect("client_id")).expect("uuid"),
    );
    let stored = h
        .identity()
        .get_client(&realm, &client_id)
        .expect("lookup")
        .expect("client exists");
    assert!(stored.dpop_bound_access_tokens(), "stored on the client");
}
