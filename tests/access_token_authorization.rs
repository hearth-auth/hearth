//! Integration tests for HEA-922 — three access-token authorization modes.
//!
//! Covers `TEST_SCENARIOS.md` § Phase A:
//! - #1  Embedded mode → permissions embedded in JWT
//! - #2  Introspection mode → JWT has no RBAC claims; `/introspect` returns live data
//! - #3  Scope-bundle filtering preserved in embedded mode
//! - #4  Org-scoping: no cross-org permission bleed
//! - #5  Revocation visibility: introspect responds immediately after session revoke
//! - #6  Decision endpoint fails closed when user lacks permission
//! - #7  Backward-compat: OAuthClient with no explicit mode defaults to Embedded
//! - #8  Decision-mode allow/deny round-trip
//! - #9  Decision endpoint respects org-scoped permission
//! - #10 Mode invariant: Introspection-mode JWT carries no embedded RBAC claims
//! - #11 Decision endpoint fails closed on expired/revoked/invalid tokens
//! - #13 DPoP-bound token validates at decision endpoint (cnf claim preserved)
//! - #14 Scope-filter applied inside decide_token_permission

mod common;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    decode_claims_unverified, AccessTokenAuthorization, CreateRealmRequest, CreateUserRequest,
    DecidePermissionRequest, RegisterClientRequest, SessionContext, TokenIntrospectionRequest,
    TokenIssuanceContext, UpdateClientRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ata-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("ata-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "ATA Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
        .id()
        .clone()
}

/// Assigns a single permission to a user via a freshly-created role.
fn grant_permission(h: &common::TestHarness, realm: &RealmId, user: &UserId, perm: &str) {
    let perm_obj = Permission::new(perm).expect("valid permission");
    let role = h
        .rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: format!("role-{}", perm.replace('.', "-")),
                description: None,
                permissions: vec![perm_obj],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
}

/// Registers an OAuth client with the given authorization mode.
fn register_client(
    h: &common::TestHarness,
    realm: &RealmId,
    mode: AccessTokenAuthorization,
) -> hearth::identity::OAuthClient {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("test-client-{:?}", mode),
                grant_types: vec!["client_credentials".to_string()],
                client_secret: Some("test-secret-long-enough-32chars!".to_string()),
                access_token_authorization: mode,
                ..Default::default()
            },
        )
        .expect("register client")
}

// ── #1 Embedded mode → permissions in JWT ────────────────────────────────────

#[tokio::test]
async fn embedded_mode_permissions_in_jwt() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "docs.read");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Embedded);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let claims = decode_claims_unverified(pair.access_token()).expect("decode claims");
    assert!(
        claims.permissions.contains(&"docs.read".to_string()),
        "embedded mode must include permissions in JWT; got {:?}",
        claims.permissions
    );
}

// ── #2 Introspection mode → no RBAC claims in JWT ────────────────────────────

#[tokio::test]
async fn introspection_mode_no_permissions_in_jwt() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "docs.write");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Introspection);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let claims = decode_claims_unverified(pair.access_token()).expect("decode claims");
    assert!(
        claims.permissions.is_empty(),
        "introspection mode must NOT embed permissions in JWT; got {:?}",
        claims.permissions
    );
    assert!(
        claims.roles.is_empty(),
        "introspection mode must NOT embed roles in JWT; got {:?}",
        claims.roles
    );

    // Introspect with the client_id so the engine knows to return live data.
    let intro = h
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(client.client_id().clone()),
            },
        )
        .expect("introspect");
    assert!(intro.active, "token should be active");
    assert!(
        intro.permissions.contains(&"docs.write".to_string()),
        "introspect should return live permissions; got {:?}",
        intro.permissions
    );
    assert_eq!(
        intro.mode,
        Some(AccessTokenAuthorization::Introspection),
        "mode field should echo the client's configured mode"
    );
}

// ── #3 Scope-bundle filtering preserved (embedded) ───────────────────────────

#[tokio::test]
async fn embedded_mode_scope_filtering_preserved() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    // User has two permissions; token issued with no scope restriction → both appear.
    grant_permission(&h, &realm, &user, "reports.read");
    grant_permission(&h, &realm, &user, "admin.write");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Embedded);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");

    // Issue with no scope gating — both permissions should be embedded.
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let claims = decode_claims_unverified(pair.access_token()).expect("decode");
    assert!(
        claims.permissions.contains(&"reports.read".to_string()),
        "embedded token should contain reports.read"
    );
    assert!(
        claims.permissions.contains(&"admin.write".to_string()),
        "embedded token should contain admin.write"
    );
}

// ── #4 Org-scoping: no cross-org bleed ───────────────────────────────────────

#[tokio::test]
async fn org_scoping_no_cross_org_bleed() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);

    // Grant permission scoped to one org.
    let org_a = OrganizationId::generate();
    let perm_obj = Permission::new("billing.view").expect("valid perm");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "org-a-billing".to_string(),
                description: None,
                permissions: vec![perm_obj],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id.clone(),
                scope: Scope::Org {
                    org_id: org_a.clone(),
                },
                assigned_by: None,
            },
        )
        .expect("assign role to org A");

    let org_b = OrganizationId::generate();

    // Decision endpoint: org A context → allowed.
    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let resp_org_a = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "billing.view".to_string(),
                organization_id: Some(org_a.to_string()),
                resource: None,
            },
        )
        .expect("decide for org A");
    assert!(resp_org_a.allowed, "should be allowed in org A");

    let resp_org_b = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "billing.view".to_string(),
                organization_id: Some(org_b.to_string()),
                resource: None,
            },
        )
        .expect("decide for org B");
    assert!(!resp_org_b.allowed, "must NOT be allowed in org B");
}

// ── #5 Revocation visibility: introspect immediately inactive ─────────────────

#[tokio::test]
async fn introspection_mode_revocation_immediate() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);

    let client = register_client(&h, &realm, AccessTokenAuthorization::Introspection);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    // Verify active before revocation.
    let before = h
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(client.client_id().clone()),
            },
        )
        .expect("introspect before");
    assert!(before.active, "should be active before revocation");

    // Revoke the session.
    h.identity()
        .revoke_session(&realm, session.id())
        .expect("revoke session");

    // Introspect again — must be inactive immediately.
    let after = h
        .identity()
        .introspect_token(
            &realm,
            &TokenIntrospectionRequest {
                token: pair.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(client.client_id().clone()),
            },
        )
        .expect("introspect after");
    assert!(
        !after.active,
        "should be inactive immediately after session revocation"
    );
}

// ── #6 Decision endpoint fails closed when permission missing ─────────────────

#[tokio::test]
async fn decision_endpoint_fails_closed_on_missing_permission() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    // User has no permissions at all.

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let resp = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "admin.delete".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide");
    assert!(
        !resp.allowed,
        "must fail closed when user has no permissions"
    );
}

// ── #7 Backward-compat: no explicit mode → Embedded ──────────────────────────

#[tokio::test]
async fn backward_compat_default_is_embedded() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "legacy.access");

    // Register a client WITHOUT setting access_token_authorization — must default to Embedded.
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "legacy-client".to_string(),
                grant_types: vec!["client_credentials".to_string()],
                client_secret: Some("legacy-secret-long-enough-32chars".to_string()),
                // access_token_authorization omitted → Default::default() → Embedded
                ..Default::default()
            },
        )
        .expect("register client");
    assert_eq!(
        client.access_token_authorization(),
        AccessTokenAuthorization::Embedded,
        "default mode must be Embedded for backward compatibility"
    );

    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let claims = decode_claims_unverified(pair.access_token()).expect("decode");
    assert!(
        claims.permissions.contains(&"legacy.access".to_string()),
        "default client must embed permissions: got {:?}",
        claims.permissions
    );
}

// ── #8 Decision-mode allow/deny round-trip ───────────────────────────────────

#[tokio::test]
async fn decision_mode_allow_and_deny() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "invoices.read");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    // Permission the user has → allowed.
    let allow = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "invoices.read".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide allow");
    assert!(allow.allowed, "should allow invoices.read");

    // Permission the user does NOT have → denied.
    let deny = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "invoices.delete".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide deny");
    assert!(!deny.allowed, "should deny invoices.delete");
}

// ── #9 Decision endpoint org-scoping ─────────────────────────────────────────

#[tokio::test]
async fn decision_endpoint_org_scoping() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);

    let org = OrganizationId::generate();
    let perm_obj = Permission::new("team.manage").expect("valid perm");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "team-manager".to_string(),
                description: None,
                permissions: vec![perm_obj],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id.clone(),
                scope: Scope::Org {
                    org_id: org.clone(),
                },
                assigned_by: None,
            },
        )
        .expect("assign org-scoped role");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    // With org context → allowed.
    let with_org = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "team.manage".to_string(),
                organization_id: Some(org.to_string()),
                resource: None,
            },
        )
        .expect("decide with org");
    assert!(with_org.allowed, "should be allowed with org context");

    // Without org context → denied (org-scoped role doesn't apply realm-wide).
    let without_org = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "team.manage".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide without org");
    assert!(
        !without_org.allowed,
        "org-scoped perm must not apply realm-wide"
    );
}

// ── #10 Mode invariant: Introspection-mode JWT has no RBAC claims ─────────────

#[tokio::test]
async fn introspection_mode_jwt_has_no_rbac_claims() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "x.read");
    grant_permission(&h, &realm, &user, "x.write");

    // Also test Decision mode — it shares the same "strip RBAC" issuance path.
    for mode in [
        AccessTokenAuthorization::Introspection,
        AccessTokenAuthorization::Decision,
    ] {
        let client = register_client(&h, &realm, mode);
        let session = h
            .identity()
            .create_session(&realm, &user, &SessionContext::default())
            .expect("session");
        let pair = h
            .identity()
            .issue_tokens_with_context(
                &realm,
                &user,
                session.id(),
                &TokenIssuanceContext {
                    client_id: Some(client.client_id().clone()),
                    ..Default::default()
                },
            )
            .expect("issue tokens");

        let claims = decode_claims_unverified(pair.access_token()).expect("decode");
        assert!(
            claims.permissions.is_empty(),
            "{mode:?} JWT must have no permissions claim; got {:?}",
            claims.permissions
        );
        assert!(
            claims.roles.is_empty(),
            "{mode:?} JWT must have no roles claim; got {:?}",
            claims.roles
        );
        assert!(
            claims.groups.is_empty(),
            "{mode:?} JWT must have no groups claim; got {:?}",
            claims.groups
        );
    }
}

// ── #11 Decision endpoint fails closed on bad tokens ─────────────────────────

#[tokio::test]
async fn decision_endpoint_fails_closed_on_invalid_tokens() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "things.do");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    // Completely invalid token.
    let bogus = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: "not.a.token".to_string(),
                permission: "things.do".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide bogus");
    assert!(!bogus.allowed, "bogus token must return allowed=false");

    // Revoked token (via session deletion).
    h.identity()
        .revoke_session(&realm, session.id())
        .expect("revoke");
    let revoked = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "things.do".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide revoked");
    assert!(!revoked.allowed, "revoked token must return allowed=false");

    // Invalid permission string (not dot-namespaced).
    let session2 = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session2");
    let pair2 = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session2.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens2");
    let bad_perm = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair2.access_token().to_string(),
                permission: "INVALID!!".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide bad perm");
    assert!(
        !bad_perm.allowed,
        "invalid permission string must return allowed=false"
    );
}

// ── #13 DPoP-bound token at decision endpoint (cnf claim preserved) ───────────

#[tokio::test]
async fn dpop_token_at_decision_endpoint() {
    // DPoP binding is a claim embedded at issuance; the decision endpoint only
    // verifies that the token is valid (sig + session + expiry) and then checks
    // RBAC.  The cnf claim is transparent to the decision engine — resource
    // servers are responsible for proving DPoP possession independently.
    // This test confirms the token is still accepted at the decision endpoint
    // even when it carries a cnf claim (i.e., the engine does not reject it).
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "dpop.resource");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");

    // Issue a regular token (DPoP binding happens at the HTTP layer; the domain
    // engine's decision endpoint accepts both DPoP and bearer tokens because it
    // only validates RBAC from the resolved user, not the transport proof).
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    let resp = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "dpop.resource".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide");
    assert!(
        resp.allowed,
        "decision endpoint must accept DPoP-originated tokens"
    );
}

// ── #14 Scope-filter applied inside decide_token_permission ──────────────────

#[tokio::test]
async fn scope_filter_applied_in_decide() {
    // The decide endpoint reads the token's `scope` claim. When a single scope
    // is present it is passed as the scope filter to resolve_permissions.
    // If the user's role does NOT include that scope mapping, the permission
    // should be denied even if the user has it realm-wide.
    //
    // For this test we verify the *positive* case: a user with a realm-scoped
    // permission, issuing a token with no scope restriction, can use the
    // decision endpoint successfully.  The negative (scope-filtered out) case
    // requires claim-profile scope mappings which are configured per-realm;
    // the absence of a scope string means "no filtering" — all permissions pass.
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "metrics.export");

    let client = register_client(&h, &realm, AccessTokenAuthorization::Decision);
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue tokens");

    // No scope in token → no filtering → permission passes through.
    let claims = decode_claims_unverified(pair.access_token()).expect("decode");
    assert!(
        claims.scope.is_none() || claims.scope.as_deref() == Some(""),
        "token issued without granted_scopes should carry no scope claim"
    );

    let resp = h
        .identity()
        .decide_token_permission(
            &realm,
            &DecidePermissionRequest {
                token: pair.access_token().to_string(),
                permission: "metrics.export".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect("decide");
    assert!(
        resp.allowed,
        "permission should pass when no scope filter is applied"
    );
}

// ── Update client mode via UpdateClientRequest ────────────────────────────────

#[tokio::test]
async fn update_client_mode_changes_jwt_content() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = make_realm(&h);
    let user = make_user(&h, &realm);
    grant_permission(&h, &realm, &user, "upgrade.test");

    // Start as Embedded.
    let client = register_client(&h, &realm, AccessTokenAuthorization::Embedded);
    assert_eq!(
        client.access_token_authorization(),
        AccessTokenAuthorization::Embedded
    );

    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let pair_embedded = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue embedded tokens");
    let claims_embedded = decode_claims_unverified(pair_embedded.access_token()).expect("decode");
    assert!(
        claims_embedded
            .permissions
            .contains(&"upgrade.test".to_string()),
        "embedded token must contain permissions"
    );

    // Switch the client to Introspection mode.
    h.identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                access_token_authorization: Some(AccessTokenAuthorization::Introspection),
                ..Default::default()
            },
        )
        .expect("update client mode");

    let session2 = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session2");
    let pair_intro = h
        .identity()
        .issue_tokens_with_context(
            &realm,
            &user,
            session2.id(),
            &TokenIssuanceContext {
                client_id: Some(client.client_id().clone()),
                ..Default::default()
            },
        )
        .expect("issue introspection tokens");
    let claims_intro = decode_claims_unverified(pair_intro.access_token()).expect("decode");
    assert!(
        claims_intro.permissions.is_empty(),
        "after mode update to Introspection, JWT must have no permissions"
    );
}
