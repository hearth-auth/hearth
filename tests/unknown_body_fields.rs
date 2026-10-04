//! A-47 — request bodies of the admin and authentication APIs refuse fields
//! their shape does not declare (`abuse-prevention` A-47, `rbac-admin-api`
//! "Role assignment endpoints").
//!
//! A field the server does not know is refused rather than dropped: a caller
//! that believes it set a constraint (an organization scope, a flag) must learn
//! that the server did not read it, instead of getting a broader result than it
//! asked for.
//!
//! The OAuth/OIDC wire bodies (token, PAR, revocation, introspection,
//! authorize, device authorization) are the documented exceptions: RFC 6749
//! §3.1 requires the server to ignore unknown request parameters. They are not
//! listed here.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, RegisterClientRequest, SessionContext, User};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

/// The field name every refusal must name.
const UNKNOWN: &str = "x_unknown_field";

fn app(h: &common::TestHarness) -> axum::Router {
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
        .with_agent_identity(true)
        .with_agent_approval(true)
        .with_agent_advanced(true);
    router(Arc::new(state))
}

fn create_user(h: &common::TestHarness, realm: &RealmId, email: &str) -> User {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "Unknown Fields".into(),
                ..Default::default()
            },
        )
        .expect("create user")
}

/// A realm-admin access token for a fresh realm.
fn realm_admin(h: &common::TestHarness) -> (RealmId, String) {
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");
    let user = create_user(h, &realm, "admin@unknown-fields.test");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    (realm, token)
}

/// Sends `body` verbatim (so the key order is the one written) and returns the
/// status and the response body as text.
async fn send(
    app: axum::Router,
    method: &str,
    uri: &str,
    realm: &RealmId,
    token: &str,
    body: &str,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Scenario "A client update refuses unknown fields": a `PATCH
/// /admin/applications/{id}` body with an undeclared field is refused, and the
/// declared field that rode beside it is not applied either.
#[tokio::test]
async fn a47_client_update_refuses_unknown_fields() {
    let h = common::TestHarness::in_process().await.unwrap();
    let (realm, token) = realm_admin(&h);
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Original Name".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    let uri = format!("/admin/applications/{}", client.client_id().as_uuid());

    let (status, body) = send(
        app(&h),
        "PATCH",
        &uri,
        &realm,
        &token,
        &format!(r#"{{"client_name":"Renamed","{UNKNOWN}":true}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    assert!(
        body.contains(&format!("unknown field `{UNKNOWN}`")),
        "the refusal must name the undeclared field: {body}"
    );

    let reloaded = h
        .identity()
        .get_client(&realm, client.client_id())
        .unwrap()
        .expect("client exists");
    assert_eq!(
        reloaded.client_name(),
        "Original Name",
        "a refused body must change nothing"
    );

    // Control: the same update without the undeclared field is applied.
    let (status, body) = send(
        app(&h),
        "PATCH",
        &uri,
        &realm,
        &token,
        r#"{"client_name":"Renamed"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

/// Scenario "An unknown body field is refused" (`rbac-admin-api`): an
/// assignment body carrying a `scope` object instead of `org_id` is refused
/// with `422` on both the user and the group endpoint, and no assignment —
/// realm-scoped or otherwise — is created.
#[tokio::test]
async fn a47_role_assignment_refuses_scope_object() {
    let h = common::TestHarness::in_process().await.unwrap();
    let (realm, token) = realm_admin(&h);
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "reports.viewer".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                scope_kind: hearth::rbac::RoleScopeKind::default(),
                allow_reserved_permissions: false,
            },
        )
        .expect("create role");
    let role_id = format!("role_{}", role.id.as_uuid());
    let target = create_user(&h, &realm, "target@unknown-fields.test");
    let group = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Analysts".into(),
                slug: "analysts".into(),
                description: None,
            },
        )
        .expect("create group");
    let org = uuid::Uuid::new_v4();
    let body =
        format!(r#"{{"role_id":"{role_id}","scope":{{"type":"org","org_id":"org_{org}"}}}}"#);

    let user_uri = format!("/admin/users/{}/roles", target.id().as_uuid());
    let (status, resp) = send(app(&h), "POST", &user_uri, &realm, &token, &body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "user: {resp}");
    assert!(resp.contains("unknown field `scope`"), "user: {resp}");
    assert!(
        h.rbac()
            .list_user_assignments(&realm, target.id())
            .unwrap()
            .is_empty(),
        "a refused body must create no user assignment"
    );

    let group_uri = format!("/admin/groups/{}/roles", group.id.as_uuid());
    let (status, resp) = send(app(&h), "POST", &group_uri, &realm, &token, &body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "group: {resp}");
    assert!(resp.contains("unknown field `scope`"), "group: {resp}");
    assert!(
        h.rbac()
            .list_group_assignments(&realm, &group.id)
            .unwrap()
            .is_empty(),
        "a refused body must create no group assignment"
    );

    // Control: the documented shape is accepted on both endpoints.
    let ok = format!(r#"{{"role_id":"{role_id}"}}"#);
    let (status, resp) = send(app(&h), "POST", &user_uri, &realm, &token, &ok).await;
    assert_eq!(status, StatusCode::CREATED, "user control: {resp}");
    let (status, resp) = send(app(&h), "POST", &group_uri, &realm, &token, &ok).await;
    assert_eq!(status, StatusCode::CREATED, "group control: {resp}");
}

/// Scenario "An extension field slips into an admin body": every hand-written
/// admin and authentication body refuses an undeclared field with `422` and
/// names it. The undeclared field comes first, so the decoder meets it before
/// any declared field is checked: without the guard the response would name a
/// missing field instead.
#[tokio::test]
async fn a47_every_admin_and_auth_body_refuses_unknown_fields() {
    let h = common::TestHarness::in_process().await.unwrap();
    let (realm, token) = realm_admin(&h);

    let mut failures = Vec::new();
    for (method, uri, declared) in &body_cases(&realm) {
        // The nested-template row puts the undeclared field inside `locales`.
        let body = if declared.contains(r#""x":1"#) {
            format!(
                "{{{}}}",
                declared.replace(r#""x":1"#, &format!(r#""{UNKNOWN}":1"#))
            )
        } else {
            format!(r#"{{"{UNKNOWN}":true,{declared}}}"#)
        };
        let (status, resp) = send(app(&h), method, uri, &realm, &token, &body).await;
        if status != StatusCode::UNPROCESSABLE_ENTITY
            || !resp.contains(&format!("unknown field `{UNKNOWN}`"))
        {
            failures.push(format!("{method} {uri} -> {status}: {resp}"));
        }
    }
    assert!(
        failures.is_empty(),
        "these bodies accepted an undeclared field:\n{}",
        failures.join("\n")
    );
}

/// One row per body shape: (method, uri, declared fields that follow the
/// undeclared one). Path ids need not exist: the body is decoded first.
#[allow(clippy::too_many_lines)] // a table: one row per body shape
fn body_cases(realm: &RealmId) -> Vec<(&'static str, String, &'static str)> {
    let r = realm.as_uuid();
    let id = uuid::Uuid::new_v4();
    vec![
        (
            "PATCH",
            format!("/admin/applications/{id}"),
            r#""client_name":"n""#,
        ),
        (
            "POST",
            format!("/admin/users/{id}/roles"),
            r#""role_id":"role_x""#,
        ),
        (
            "POST",
            format!("/admin/groups/{id}/roles"),
            r#""role_id":"role_x""#,
        ),
        (
            "POST",
            format!("/admin/users/{id}/permissions"),
            r#""permission":"docs.read""#,
        ),
        (
            "POST",
            "/admin/webhooks".to_string(),
            r#""url":"https://hooks.example.com/h""#,
        ),
        ("PUT", format!("/admin/webhooks/{id}"), r#""enabled":false"#),
        (
            "POST",
            "/admin/organizations".to_string(),
            r#""slug":"acme","display_name":"Acme""#,
        ),
        (
            "PATCH",
            format!("/admin/organizations/{id}"),
            r#""display_name":"Acme""#,
        ),
        (
            "POST",
            format!("/admin/organizations/{id}/members/{id}/roles"),
            r#""role_name":"viewer""#,
        ),
        (
            "PUT",
            format!("/admin/realms/{r}/email-templates/verification"),
            r#""default":{"subject":"Hi"}"#,
        ),
        (
            "PUT",
            format!("/admin/realms/{r}/email-templates/verification"),
            // The nested body shape refuses undeclared fields too.
            r#""default":{"subject":"Hi"},"locales":{"fr":{"x":1}}"#,
        ),
        (
            "PATCH",
            format!("/admin/realms/{r}/users/{id}/required-actions"),
            r#""add":[]"#,
        ),
        (
            "POST",
            format!("/admin/realms/{r}/cross-realm-policies"),
            r#""allowed_capabilities":[]"#,
        ),
        ("POST", "/v1/agents".to_string(), r#""display_name":"bot""#),
        (
            "PATCH",
            format!("/v1/agents/{id}"),
            r#""display_name":"bot""#,
        ),
        (
            "POST",
            format!("/v1/agents/{id}/credentials/keys"),
            r#""label":"k""#,
        ),
        ("POST", "/v1/approval-requests".to_string(), r#""tool":"t""#),
        (
            "POST",
            format!("/v1/approval-requests/{id}/approve"),
            r#""capability_ttl_secs":60"#,
        ),
        (
            "POST",
            format!("/v1/approval-requests/{id}/deny"),
            r#""reason":"no""#,
        ),
        ("POST", "/v1/tools/invoke".to_string(), r#""tool":"t""#),
        ("POST", "/v1/aats".to_string(), r#""scope":[]"#),
        ("POST", "/v1/aats/derive".to_string(), r#""scope":[]"#),
        (
            "POST",
            "/v1/transaction-tokens".to_string(),
            r#""txn_id":"t""#,
        ),
        (
            "POST",
            "/v1/spiffe-mappings".to_string(),
            r#""spiffe_id":"spiffe://x/y""#,
        ),
        (
            "POST",
            "/v1/cross-realm-policies".to_string(),
            r#""allowed_capabilities":[]"#,
        ),
        (
            "POST",
            format!("/v1/{}/auth/magic-link", "unknown-fields"),
            r#""email":"a@b.test""#,
        ),
    ]
}

/// The admin-console JSON bodies refuse undeclared fields as well. They sit
/// behind a session cookie, so the shape is checked at the decoder.
#[test]
fn a47_console_json_bodies_refuse_unknown_fields() {
    use hearth::protocol::web::account::RenamePasskeyBody;
    use hearth::protocol::web::admin::realms::UpdateAuditRetentionBody;
    use hearth::protocol::web::admin::users::PatchRequiredActionsBody;
    use hearth::protocol::web::admin::webhooks::TestPingBody;

    fn refused<T: serde::de::DeserializeOwned>(json: &str) -> bool {
        match serde_json::from_str::<T>(json) {
            Ok(_) => false,
            Err(e) => e
                .to_string()
                .contains(&format!("unknown field `{UNKNOWN}`")),
        }
    }

    let extra = format!(r#""{UNKNOWN}":true"#);
    assert!(refused::<RenamePasskeyBody>(&format!(
        r#"{{{extra},"name":"Laptop"}}"#
    )));
    assert!(refused::<TestPingBody>(&format!(
        r#"{{{extra},"url":"https://hooks.example.com"}}"#
    )));
    assert!(refused::<UpdateAuditRetentionBody>(&format!(
        r#"{{{extra},"retention_days":30}}"#
    )));
    assert!(refused::<PatchRequiredActionsBody>(&format!(
        r#"{{{extra},"add":[]}}"#
    )));
}
