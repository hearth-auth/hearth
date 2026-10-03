#![allow(clippy::unwrap_used)]
//! A `hearth.yaml`-managed application can never be silently turned into a
//! public client.
//!
//! Reconcile treats YAML as authoritative for `jwks`: an application whose
//! YAML declares none has its JWKS cleared at the next restart or SIGHUP.
//! `PATCH /admin/applications/{id}` (and gRPC `UpdateApplication`) accepted
//! `jwks` and `assertion_public_key` on YAML-managed applications —
//! only the admin console refused — so keys given to a secretless YAML app
//! over REST vanished at the next reload and the app became PUBLIC.
//!
//! 1. Credential changes on a YAML-managed application are
//!    refused on every runtime surface (the engine gate both REST and gRPC go
//!    through), the way a runtime delete already was.
//! 2. Reconcile refuses — and reports — a YAML change that would remove the
//!    last credential of a client that has one, leaving the client unchanged.
//! 3. Reconcile creates an application in ONE write carrying its JWKS. It
//!    used to write a public client first and apply the JWKS in a second
//!    write; when that second write failed, the public client stayed behind.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::config::Config;
use hearth::core::{ClientId, RealmId};
use hearth::identity::reconcile::{reconcile_realms, AppReconcileAction, ReconcileReport};
use hearth::identity::{
    CreateUserRequest, IdentityError, OAuthClient, SessionContext, UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const JWKS_YAML: &str = r"        jwks:
          keys:
            - kty: OKP
              crv: Ed25519
              kid: k1
              alg: EdDSA
              use: sig
              x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

const JWKS_JSON: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k2","alg":"EdDSA","use":"sig","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

/// A `hearth.yaml` with one realm `yamlcreds` holding one application
/// `svc` whose extra keys are `app_lines` (indented 8 spaces).
fn config(app_lines: &str) -> Config {
    let yaml = format!(
        r#"
auth:
  mfa_required: false
realms:
  yamlcreds:
    applications:
      svc:
        name: "Service"
        redirect_uris:
          - "https://svc.example.com/callback"
        grant_types:
          - authorization_code
{app_lines}
"#
    );
    let mut config = Config::from_yaml_str_unchecked(&yaml).expect("parse yaml");
    config.dev_mode = true;
    config
}

fn reconcile(h: &common::TestHarness, config: &Config) -> Result<ReconcileReport, IdentityError> {
    reconcile_realms(h.identity(), h.authz(), config)
}

fn realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .get_realm_by_name("yamlcreds")
        .expect("lookup realm")
        .expect("realm exists")
        .id()
        .clone()
}

fn find_client(h: &common::TestHarness) -> Option<OAuthClient> {
    h.identity()
        .list_clients(&realm(h), &hearth::core::PageRequest::new(0, 10))
        .expect("list clients")
        .items
        .into_iter()
        .find(|c| c.client_name() == "Service" || c.client_name() == "Renamed")
}

fn refused(report: &ReconcileReport) -> Option<&str> {
    report.applications.iter().find_map(|e| match &e.action {
        AppReconcileAction::Refused { reason } => Some(reason.as_str()),
        _ => None,
    })
}

// ── 1. runtime surfaces ──────────────────────────────────────────────────────

async fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let _ = h.rbac().seed_realm(realm);
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "yaml-admin@example.com".into(),
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

async fn patch(
    h: &common::TestHarness,
    token: &str,
    realm: &RealmId,
    client: &ClientId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/admin/applications/{}", client.as_uuid()))
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// `PATCH /admin/applications/{id}` refuses `jwks` and
/// `assertion_public_key` on a YAML-managed application with `409`, naming
/// `hearth.yaml`, and changes nothing. A non-credential edit still works.
#[tokio::test]
async fn rest_refuses_credential_changes_on_a_yaml_managed_application() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, &config("")).expect("reconcile");
    let realm = realm(&h);
    let client = find_client(&h).expect("client");
    assert!(client.is_yaml_managed() && client.is_public());
    let token = admin_token(&h, &realm).await;

    for body in [
        serde_json::json!({ "jwks": JWKS_JSON }),
        serde_json::json!({ "assertion_public_key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc" }),
    ] {
        let (status, resp) = patch(&h, &token, &realm, client.client_id(), body.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}: {resp}");
        assert!(
            resp.to_string().contains("hearth.yaml"),
            "{body}: the refusal must say the application is managed by hearth.yaml: {resp}"
        );
    }
    let after = find_client(&h).expect("client");
    assert_eq!(after.jwks(), None);
    assert_eq!(after.assertion_public_key(), None);

    let (status, resp) = patch(
        &h,
        &token,
        &realm,
        client.client_id(),
        serde_json::json!({ "client_name": "Renamed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a non-credential edit: {resp}");
}

/// The engine gate every runtime surface (REST and gRPC) goes through.
#[tokio::test]
async fn the_engine_refuses_credential_changes_on_a_yaml_managed_application() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, &config("")).expect("reconcile");
    let realm = realm(&h);
    let client = find_client(&h).expect("client");
    for request in [
        UpdateClientRequest {
            jwks: Some(Some(JWKS_JSON.to_string())),
            ..Default::default()
        },
        UpdateClientRequest {
            assertion_public_key: Some(None),
            ..Default::default()
        },
    ] {
        let err = h
            .identity()
            .update_client(&realm, client.client_id(), &request)
            .expect_err("a credential change on a YAML-managed application must be refused");
        assert!(
            matches!(err, IdentityError::YamlManagedResource { .. }),
            "{err:?}"
        );
    }
}

// ── 2. reconcile never removes the last credential ───────────────────────────

/// An application whose YAML declared a JWKS (and no secret) keeps it when
/// the YAML drops it: the change would make it public, so reconcile refuses
/// it, reports it, and leaves the client unchanged.
#[tokio::test]
async fn reconcile_refuses_to_remove_the_last_credential() {
    let h = common::TestHarness::in_process().await.expect("harness");
    reconcile(&h, &config(JWKS_YAML)).expect("reconcile v1");
    let before = find_client(&h).expect("client");
    assert!(before.jwks().is_some() && !before.is_public());

    let report = reconcile(&h, &config("")).expect("reconcile v2 must not abort startup");
    let after = find_client(&h).expect("client");
    assert_eq!(after.jwks(), before.jwks(), "the JWKS must be kept");
    assert!(
        !after.is_public(),
        "reconcile must never make a client public"
    );
    let reason = refused(&report).expect("the refusal must be in the reconcile report");
    assert!(reason.contains("public"), "{reason}");
}

/// Control: a confidential application (it holds a secret) may drop its
/// JWKS — it stays confidential.
#[tokio::test]
async fn reconcile_still_removes_a_jwks_that_is_not_the_last_credential() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let secret =
        "        confidential: true\n        client_secret: \"yaml-secret-0123456789abcdef\"";
    reconcile(&h, &config(&format!("{secret}\n{JWKS_YAML}"))).expect("v1");
    let report = reconcile(&h, &config(secret)).expect("v2");
    let after = find_client(&h).expect("client");
    assert_eq!(after.jwks(), None, "YAML stays authoritative");
    assert!(after.is_confidential());
    assert!(refused(&report).is_none());
}

// ── 3. atomic creation ───────────────────────────────────────────────────────

/// An application whose JWKS the engine refuses (here: it carries a private
/// key member) is not created at all — no public client is left behind by a
/// failed second write.
#[tokio::test]
async fn reconcile_creates_an_application_in_one_write_or_not_at_all() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let bad_jwks =
        format!("{JWKS_YAML}\n              d: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    let err = reconcile(&h, &config(&bad_jwks)).expect_err("an invalid JWKS must be refused");
    assert!(err.to_string().contains("jwks"), "{err}");
    assert!(
        find_client(&h).is_none(),
        "a failed creation must not leave a (public) client behind"
    );
}
