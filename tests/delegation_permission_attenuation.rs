//! Regression tests for AUTHORIZATION.md § 16 (HEA-1726).
//!
//! Prior to the fix, delegated (`act`) tokens copied the subject's RBAC `permissions`
//! verbatim. An actor with zero RBAC grants could acquire admin-level access by
//! performing a token exchange against a privileged user's token.
//!
//! Post-fix: `effective_permissions = intersection(subject.permissions, actor.permissions)`.
//!
//! Scenarios:
//! - Actor with NO permissions → delegated token has no permissions (not subject's full set)
//! - Actor with a subset of subject's permissions → delegated token holds only that subset
//! - Without actor_token (client acting as itself) → subject's permissions preserved (no change)
//! - Delegated token has empty roles and groups regardless of subject's

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AccessTokenAuthorization, ClientCredentialsRequest, ClientTrustLevel, CreateUserRequest,
    IdentityEngine, RegisterClientRequest, Rfc8693Request, SessionContext, TokenIssuanceContext,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|s| Permission::new(*s).expect("valid permission"))
        .collect()
}

/// Create a user in `realm` with a role that grants `permissions`. Returns the
/// user's signed access token, issued with `scope` so that the scope intersection
/// in token exchange does not produce an empty result.
fn make_subject_token_with_perms(
    h: &common::TestHarness,
    realm: &RealmId,
    permissions: &[&str],
    scope: &str,
) -> String {
    use std::collections::BTreeSet;

    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("subj-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Subject".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create subject user");

    let role = h
        .rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: format!("test-role-{}", uuid::Uuid::new_v4()),
                description: None,
                permissions: perms(permissions),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");

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
        .expect("assign role");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");

    let granted_scopes: BTreeSet<String> = scope.split_whitespace().map(String::from).collect();
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes,
                oid: None,
                resource: None,
            },
        )
        .expect("issue subject token")
        .access_token()
        .to_string()
}

/// Register an actor client with `declared_scopes` and issue a client_credentials
/// token for it. Returns `(client_id, access_token)`.
///
/// The actor client receives NO RBAC role assignments, so its `permissions` claim
/// is empty — matching the worst-case attack scenario for HEA-1726.
fn make_actor_token_no_rbac(
    identity: &dyn IdentityEngine,
    realm: &RealmId,
    scope: &str,
) -> (hearth::core::ClientId, String) {
    const SECRET: &str = "actor-secret-HEA-1726";
    let declared: Vec<String> = scope.split_whitespace().map(String::from).collect();
    let client = identity
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("actor-{}", uuid::Uuid::new_v4()),
                client_secret: Some(SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: declared,
                access_token_authorization: AccessTokenAuthorization::Embedded,
                ..Default::default()
            },
        )
        .expect("register actor client");
    let client_id = client.client_id().clone();
    let resp = identity
        .client_credentials_token(
            realm,
            &ClientCredentialsRequest {
                client_id: client_id.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: if scope.is_empty() {
                    None
                } else {
                    Some(scope.to_string())
                },
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("issue actor access token");
    (client_id, resp.access_token().to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Core regression for HEA-1726: actor with NO RBAC permissions performs a token
/// exchange against a privileged subject. The delegated token MUST have zero
/// permissions (intersection of subject's grants with actor's empty set).
///
/// Before the fix, the delegated token carried the subject's full permission set,
/// allowing any agent to escalate to the subject's authority via delegation.
#[tokio::test]
async fn actor_with_no_permissions_yields_empty_delegated_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    // Subject has significant RBAC grants. Use "openid" as the common scope so
    // the scope intersection in token exchange is non-empty ("openid" has no permission
    // filter per AUTHORIZATION.md § 9.3, so all RBAC permissions flow through).
    let subject_token = make_subject_token_with_perms(
        &h,
        &realm,
        &["app.admin", "app.delete", "billing.read"],
        "openid",
    );

    // Confirm the subject token actually carries permissions (verifies test setup).
    let subject_claims = h
        .identity()
        .validate_token(&realm, &subject_token)
        .expect("validate subject token");
    assert!(
        subject_claims
            .permissions
            .contains(&"app.admin".to_string()),
        "test setup: subject token must have app.admin"
    );

    // Actor has zero RBAC grants (new client, no role assignments).
    // Use the same "openid" scope so the scope intersection is non-empty.
    let (actor_client_id, actor_token) = make_actor_token_no_rbac(h.identity(), &realm, "openid");

    // Confirm actor token has no RBAC permissions (verifies test setup).
    let actor_claims = h
        .identity()
        .validate_token(&realm, &actor_token)
        .expect("validate actor token");
    assert!(
        actor_claims.permissions.is_empty(),
        "test setup: actor token must have no permissions"
    );

    let request = Rfc8693Request {
        client_id: actor_client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: Some(actor_token),
        actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
        requested_token_type: None,
        scope: Some("openid".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let resp = h
        .identity()
        .rfc8693_token_exchange(&realm, &request)
        .expect("token exchange must succeed");

    let delegated = h
        .identity()
        .validate_token(&realm, &resp.access_token)
        .expect("validate delegated token");

    // Core assertion: zero effective permissions despite subject having admin-level grants.
    assert!(
        delegated.permissions.is_empty(),
        "delegated token MUST have no permissions when actor has no permissions; \
         got: {:?}",
        delegated.permissions
    );

    // act claim must be present (token is delegated).
    assert!(
        delegated.act.is_some(),
        "delegated token must carry act claim"
    );

    // roles and groups must be empty on delegated tokens (§ 16.2).
    assert!(
        delegated.roles.is_empty(),
        "delegated token must have empty roles"
    );
    assert!(
        delegated.groups.is_empty(),
        "delegated token must have empty groups"
    );
}

/// When no actor_token is provided, the client acts as itself and the subject's
/// full permission set is preserved (no attenuation — actor_permissions defaults
/// to subject_permissions, so intersection = subject's permissions).
#[tokio::test]
async fn no_actor_token_preserves_subject_permissions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let subject_token =
        make_subject_token_with_perms(&h, &realm, &["docs.edit", "docs.view"], "openid");

    // Register a client_credentials client to act as the requester (no actor_token presented).
    let (client_id, _) = make_actor_token_no_rbac(h.identity(), &realm, "openid");

    let request = Rfc8693Request {
        client_id,
        subject_token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: Some("openid".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    let resp = h
        .identity()
        .rfc8693_token_exchange(&realm, &request)
        .expect("token exchange must succeed");

    let delegated = h
        .identity()
        .validate_token(&realm, &resp.access_token)
        .expect("validate delegated token");

    // Without an actor_token, actor_permissions = subject_permissions → full set preserved.
    assert!(
        delegated.permissions.contains(&"docs.edit".to_string()),
        "docs.edit must be present when no actor_token is provided"
    );
    assert!(
        delegated.permissions.contains(&"docs.view".to_string()),
        "docs.view must be present when no actor_token is provided"
    );
}
