#![allow(clippy::unwrap_used)]
//! An application declared in `hearth.yaml` declares its access-token
//! authorization mode (OpenSpec change `yaml-access-token-authorization`).
//!
//! A resource server introspects user tokens as a client in `introspection` or
//! `decision` mode. Only the admin API set that mode, and the admin API cannot
//! reach a YAML-declared realm at first start (the bootstrap tokens belong to
//! other realms). So a resource server declared in `hearth.yaml` got
//! `{"active": false}` for every user token of its realm.
//!
//! 1. The `access_token_authorization` key sets the mode, and the client can
//!    then introspect a user token that another client obtained.
//! 2. `hearth.yaml` owns the mode: reconcile applies a change, and an omitted
//!    key means `embedded`.
//! 3. Config load refuses a value other than `embedded`, `introspection` and
//!    `decision`.
//! 4. The admin API refuses to change the mode of a YAML-declared
//!    application. A request that names the stored mode still succeeds.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hearth::config::Config;
use hearth::core::{ClientId, RealmId};
use hearth::identity::reconcile::{deterministic_client_id, reconcile_realms};
use hearth::identity::{
    AccessTokenAuthorization, CreateUserRequest, IdentityError, OAuthClient, SessionContext,
    TokenIssuanceContext, UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const REALM: &str = "yamlata";
const API_SECRET: &str = "yaml-ata-api-secret-0123456789!";

/// The `hearth.yaml` text: realm `yamlata` with a public SPA client `spa` and
/// a confidential resource-server client `api`, whose extra keys are
/// `api_lines` (indented 8 spaces).
fn yaml(api_lines: &str) -> String {
    format!(
        r#"
auth:
  mfa_required: false
realms:
  {REALM}:
    applications:
      spa:
        name: "SPA"
        redirect_uris:
          - "https://spa.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
      api:
        name: "API"
        confidential: true
        client_secret: "{API_SECRET}"
        grant_types:
          - client_credentials
{api_lines}
"#
    )
}

fn config(api_lines: &str) -> Config {
    let mut config = Config::from_yaml_str_unchecked(&yaml(api_lines)).expect("parse yaml");
    config.dev_mode = true;
    config
}

fn reconcile(h: &common::TestHarness, api_lines: &str) {
    reconcile_realms(h.identity(), h.authz(), &config(api_lines)).expect("reconcile");
}

fn realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .get_realm_by_name(REALM)
        .expect("lookup realm")
        .expect("realm exists")
        .id()
        .clone()
}

fn api_id() -> ClientId {
    deterministic_client_id(REALM, "api")
}

fn api_client(h: &common::TestHarness) -> OAuthClient {
    h.identity()
        .get_client(&realm(h), &api_id())
        .expect("lookup client")
        .expect("the api client exists")
}

fn router_for(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// A user's access token, obtained through the `spa` client: a user-session
/// token with no `azp`.
fn spa_user_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("ata-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "ATA".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(deterministic_client_id(REALM, "spa")),
                ..TokenIssuanceContext::default()
            },
        )
        .expect("issue")
        .access_token()
        .to_string()
}

/// `POST /realms/yamlata/introspect` as the `api` client (HTTP Basic).
async fn introspect_as_api(h: &common::TestHarness, token: &str) -> serde_json::Value {
    let credentials = STANDARD.encode(format!("{}:{API_SECRET}", api_id().as_uuid()));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/realms/{REALM}/introspect"))
        .header("authorization", format!("Basic {credentials}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("token={token}")))
        .unwrap();
    let resp = router_for(h).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "introspection request");
    json_of(resp).await
}

// ── 1. the key sets the mode ─────────────────────────────────────────────────

/// The resource server declared in `hearth.yaml` alone can introspect the
/// SPA's user tokens and gets the live RBAC fields of its mode.
#[tokio::test]
async fn a_yaml_resource_server_introspects_another_clients_user_token() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, "        access_token_authorization: introspection");
    assert_eq!(
        api_client(&h).access_token_authorization(),
        AccessTokenAuthorization::Introspection
    );

    let token = spa_user_token(&h, &realm(&h));
    let body = introspect_as_api(&h, &token).await;
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["mode"], "introspection", "{body}");
}

/// The control: without the key the client is `embedded`, and the audience
/// rule hides the SPA's token from it.
#[tokio::test]
async fn without_the_key_the_yaml_client_cannot_introspect_it() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, "");
    assert_eq!(
        api_client(&h).access_token_authorization(),
        AccessTokenAuthorization::Embedded
    );

    let token = spa_user_token(&h, &realm(&h));
    let body = introspect_as_api(&h, &token).await;
    assert_eq!(body, serde_json::json!({ "active": false }));
}

// ── 2. hearth.yaml owns the mode ─────────────────────────────────────────────

#[tokio::test]
async fn reconcile_applies_a_changed_mode_and_an_omitted_key_means_embedded() {
    let h = common::TestHarness::in_process().await.expect("harness");
    for (lines, want) in [
        (
            "        access_token_authorization: introspection",
            AccessTokenAuthorization::Introspection,
        ),
        (
            "        access_token_authorization: decision",
            AccessTokenAuthorization::Decision,
        ),
        ("", AccessTokenAuthorization::Embedded),
    ] {
        reconcile(&h, lines);
        assert_eq!(
            api_client(&h).access_token_authorization(),
            want,
            "after reconciling {lines:?}"
        );
    }
}

// ── 3. config load ───────────────────────────────────────────────────────────

/// The YAML spelling is snake_case, the same as `trust_level`. The proto
/// spelling and unknown values are refused at load, not read as `embedded`.
#[test]
fn config_load_refuses_an_unknown_mode() {
    for value in ["INTROSPECTION", "resource_server"] {
        let text = yaml(&format!("        access_token_authorization: {value}"));
        let Err(err) = Config::from_yaml_str_unchecked(&text) else {
            panic!("access_token_authorization: {value} must be refused");
        };
        assert!(
            err.to_string().contains("unknown variant"),
            "{value}: {err}"
        );
    }
}

// ── 4. the admin API ─────────────────────────────────────────────────────────

/// A realm admin's access token for `realm`.
fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let _ = h.rbac().seed_realm(realm);
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "ata-admin@example.com".into(),
                display_name: "Admin".into(),
                ..Default::default()
            },
        )
        .expect("create user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn patch_api(
    h: &common::TestHarness,
    token: &str,
    realm: &RealmId,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/admin/applications/{}", api_id().as_uuid()))
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router_for(h).oneshot(req).await.unwrap();
    let status = resp.status();
    (status, json_of(resp).await)
}

#[tokio::test]
async fn the_admin_api_refuses_to_change_a_yaml_declared_mode() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, "        access_token_authorization: introspection");
    let realm = realm(&h);
    let token = admin_token(&h, &realm);

    for mode in ["decision", "embedded"] {
        let body = serde_json::json!({ "access_token_authorization": mode });
        let (status, resp) = patch_api(&h, &token, &realm, &body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}: {resp}");
        assert!(
            resp.to_string().contains("hearth.yaml"),
            "{body}: the refusal must name hearth.yaml: {resp}"
        );
        assert_eq!(
            api_client(&h).access_token_authorization(),
            AccessTokenAuthorization::Introspection,
            "{body} must not change the mode"
        );
    }

    // A client may send the whole application record: naming the stored
    // mode is not a change, so the rest of the edit goes through.
    let body = serde_json::json!({
        "client_name": "Renamed API",
        "access_token_authorization": "introspection",
    });
    let (status, resp) = patch_api(&h, &token, &realm, &body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(api_client(&h).client_name(), "Renamed API");
}

/// The engine gate behind the REST admin API.
#[tokio::test]
async fn the_engine_refuses_to_change_a_yaml_declared_mode() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, "        access_token_authorization: introspection");
    let realm = realm(&h);

    let err = h
        .identity()
        .update_client(
            &realm,
            &api_id(),
            &UpdateClientRequest {
                access_token_authorization: Some(AccessTokenAuthorization::Decision),
                ..Default::default()
            },
        )
        .expect_err("a mode change on a YAML-declared application must be refused");
    assert!(
        matches!(err, IdentityError::YamlManagedResource { .. }),
        "{err:?}"
    );

    h.identity()
        .update_client(
            &realm,
            &api_id(),
            &UpdateClientRequest {
                access_token_authorization: Some(AccessTokenAuthorization::Introspection),
                ..Default::default()
            },
        )
        .expect("naming the stored mode is not a change");
}
