#![allow(clippy::unwrap_used)]
//! GA audit 3 B-2 / C-8 / C-9 — the live-RBAC surfaces answer for the TOKEN,
//! not for the user behind it.
//!
//! Introspection-mode resource servers (`/introspect`), decision-mode
//! resource servers (`POST /oauth/authorize`) and
//! `GET /v1/me/permissions` resolved the user's full live RBAC set for any
//! token they were handed:
//!
//! - **B-2** — a third-party client's token got the roles, groups and
//!   permissions the claim profile withholds from third-party clients
//!   (`first_party_only`), up to `hearth.admin`.
//! - **C-8** — the decision endpoint narrowed by the token's scope only when
//!   it carried exactly one, so `openid docs:read` bought more authority than
//!   `docs:read`; its `resource` (RFC 8707 audience check) was dropped; and a
//!   delegated (`act`) token was widened back to the user's full authority.
//! - **C-9** — the decision path skipped the audience cutoff, so a token for a
//!   removed protected resource kept getting `allowed: true`.
//!
//! The live answer is now what an `Embedded` token issued to the same client
//! for the same grant would carry, resolved now: the token's client claim
//! profile, narrowed by every permission-bearing scope, capped at the
//! delegated permissions for an `act` token, and refused for an audience the
//! token was not minted for.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, Uri, UserId};
use hearth::identity::{
    AccessTokenAuthorization, ClientTrustLevel, CreateRealmRequest, CreateUserRequest,
    DecidePermissionRequest, RegisterClientRequest, RegisterProtectedResourceRequest,
    Rfc8693Request, SessionContext, TokenIntrospectionRequest, TokenIssuanceContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, ScopeSpec, Subject};
use tower::ServiceExt as _;

const RS_SECRET: &str = "live-rbac-rs-secret-0123456789!";
const RS_A: &str = "https://a.example.com/api";
const RS_B: &str = "https://b.example.com/api";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

// ── Fixture ─────────────────────────────────────────────────────────────────

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    /// A first-party session token (no `client_id` claim), scope
    /// `openid profile`.
    session_token: String,
    /// A token issued to a consented third-party client (RFC 9068
    /// `client_id` = that client), scope `openid profile`.
    third_party_token: String,
    /// A declared resource server: confidential, `Introspection` mode.
    rs: ClientId,
}

async fn setup() -> Fixture {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("live-rbac-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("live-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Live".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    grant(&h, &realm, &user, "docs.viewer", "docs.view");

    let third_party = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "third-party-app".into(),
                redirect_uris: vec!["https://tp.example.com/cb".into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: true,
                trust_level: ClientTrustLevel::ThirdParty,
                declared_scopes: vec!["openid".into(), "profile".into()],
                ..RegisterClientRequest::default()
            },
        )
        .expect("third-party client")
        .client_id()
        .clone();
    let rs = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "resource-server".into(),
                grant_types: vec!["client_credentials".into()],
                client_secret: Some(RS_SECRET.into()),
                access_token_authorization: AccessTokenAuthorization::Introspection,
                trust_level: ClientTrustLevel::FirstParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("resource server")
        .client_id()
        .clone();

    let mut f = Fixture {
        h,
        realm,
        user,
        session_token: String::new(),
        third_party_token: String::new(),
        rs,
    };
    f.session_token = f.token(None, &["openid", "profile"], None);
    f.third_party_token = f.token(Some(&third_party), &["openid", "profile"], None);
    f
}

/// Grants `permission` to `user` through a fresh realm-scoped role.
fn grant(h: &common::TestHarness, realm: &RealmId, user: &UserId, role: &str, permission: &str) {
    let role = h
        .rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: role.into(),
                description: None,
                permissions: vec![Permission::new(permission).unwrap()],
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
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
}

impl Fixture {
    /// Gives the user `docs.delete` — the permission no narrowed token may
    /// reach.
    fn grant_delete(&self) {
        grant(
            &self.h,
            &self.realm,
            &self.user,
            "docs.remover",
            "docs.delete",
        );
    }

    /// Issues an access token for the user on a fresh session.
    fn token(&self, client: Option<&ClientId>, scopes: &[&str], resource: Option<&str>) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &self.user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens_with_context(
                &self.realm,
                &self.user,
                session.id(),
                &TokenIssuanceContext {
                    client_id: client.cloned(),
                    granted_scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
                    resource: resource.map(|r| Uri::try_from(r.to_string()).unwrap()),
                    ..TokenIssuanceContext::default()
                },
            )
            .expect("issue tokens")
            .access_token()
            .to_string()
    }

    fn decide(&self, token: &str, permission: &str, resource: Option<&str>) -> bool {
        self.h
            .identity()
            .decide_token_permission(
                &self.realm,
                &DecidePermissionRequest {
                    token: token.into(),
                    permission: permission.into(),
                    organization_id: None,
                    resource: resource.map(str::to_string),
                },
            )
            .expect("decide")
            .allowed
    }

    /// Introspects `token` as the declared resource server; returns
    /// `(active, permissions, roles, groups)`.
    fn introspect(&self, token: &str) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
        let r = self
            .h
            .identity()
            .introspect_token(
                &self.realm,
                &TokenIntrospectionRequest {
                    token: token.into(),
                    token_type_hint: None,
                    introspecting_client_id: Some(self.rs.clone()),
                },
            )
            .expect("introspect");
        (r.active, r.permissions, r.roles, r.groups)
    }

    fn register_resource(&self, uri: &str) -> hearth::identity::ProtectedResource {
        self.h
            .identity()
            .register_protected_resource(
                &self.realm,
                &RegisterProtectedResourceRequest {
                    resource_uri: uri.into(),
                    display_name: "RS".into(),
                    scopes: Vec::new(),
                    required_claims: Vec::new(),
                    introspection_client_id: None,
                },
            )
            .expect("register protected resource")
    }

    fn app(&self) -> axum::Router {
        router(Arc::new(AppState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
        )))
    }

    async fn http(
        &self,
        method: &str,
        uri: &str,
        authorization: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", authorization)
            .header("x-realm-id", self.realm.as_uuid().to_string());
        let body = match body {
            Some(json) => {
                req = req.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let resp = self.app().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

fn strings(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ── B-2: the token's client claim profile applies to live data ─────────────

/// The default claim profile withholds `roles`, `groups` and `permissions`
/// from third-party clients. An `Introspection`-mode resource server handed a
/// third-party client's token got all three, live.
#[tokio::test]
async fn introspection_releases_no_live_rbac_for_a_third_party_clients_token() {
    let f = setup().await;
    f.grant_delete();

    // Control: a first-party session token gets the user's live authority.
    let (active, perms, roles, _) = f.introspect(&f.session_token);
    assert!(active, "control token must be active");
    assert!(
        perms.contains(&"docs.delete".to_string()),
        "control: live permissions for a first-party token; got {perms:?}"
    );
    assert!(!roles.is_empty(), "control: live roles; got {roles:?}");

    let (active, perms, roles, groups) = f.introspect(&f.third_party_token);
    assert!(active, "the third-party token itself is valid");
    assert!(
        perms.is_empty() && roles.is_empty() && groups.is_empty(),
        "a third-party client's token must get no live RBAC data; got \
         permissions {perms:?}, roles {roles:?}, groups {groups:?}"
    );
}

/// A third-party client's token must not be answered `allowed: true` for the
/// user's permissions — the client may ask the decision endpoint itself.
#[tokio::test]
async fn decide_denies_a_third_party_clients_token() {
    let f = setup().await;
    f.grant_delete();

    assert!(
        f.decide(&f.session_token, "docs.delete", None),
        "control: a first-party token holding the permission is allowed"
    );
    assert!(
        !f.decide(&f.third_party_token, "docs.delete", None),
        "a third-party client's token must not be allowed the user's permission"
    );
    assert!(!f.decide(&f.third_party_token, "docs.view", None));
}

// ── C-8: every permission-bearing scope narrows ─────────────────────────────

/// `docs:read` narrowed a token to `docs.view`; `openid docs:read` — one more
/// scope — resolved the user's full set, because only a single-scope token
/// was narrowed. OIDC scopes carry no permissions and must not widen.
#[tokio::test]
async fn live_authority_is_narrowed_by_every_permission_scope_of_the_token() {
    let f = setup().await;
    f.grant_delete();
    f.h.rbac()
        .reconcile_scopes(
            &f.realm,
            &[ScopeSpec {
                name: "docs:read".into(),
                permissions: Some(vec!["docs.view".into()]),
            }],
        )
        .expect("register scope bundle");

    let narrowed = f.token(None, &["openid", "docs:read"], None);
    assert!(
        f.decide(&narrowed, "docs.view", None),
        "docs:read admits docs.view"
    );
    assert!(
        !f.decide(&narrowed, "docs.delete", None),
        "`openid docs:read` must be narrowed to docs:read — docs.delete is outside it"
    );
    let (_, perms, _, _) = f.introspect(&narrowed);
    assert_eq!(
        perms,
        vec!["docs.view".to_string()],
        "introspection must narrow by the same scopes"
    );

    // Control: OIDC-only scopes do not narrow.
    let oidc_only = f.token(None, &["openid", "profile"], None);
    assert!(f.decide(&oidc_only, "docs.delete", None));
}

// ── C-8: the decision endpoint's RFC 8707 audience check ────────────────────

/// `resource` on `POST /oauth/authorize` is documented as an RFC 8707
/// audience check but was dropped, so a token minted for resource server A
/// was `allowed` when replayed at resource server B.
#[tokio::test]
async fn decide_refuses_a_resource_the_token_was_not_minted_for() {
    let f = setup().await;
    f.register_resource(RS_A);
    f.register_resource(RS_B);
    let for_a = f.token(None, &["openid", "profile"], Some(RS_A));

    assert!(
        f.decide(&for_a, "docs.view", Some(RS_A)),
        "control: the token's own resource is accepted"
    );
    assert!(
        !f.decide(&for_a, "docs.view", Some(RS_B)),
        "a token minted for A must not be allowed at resource B"
    );
    assert!(
        !f.decide(&f.session_token, "docs.view", Some(RS_B)),
        "a token with no resource audience must not be allowed at resource B"
    );
}

// ── C-8: a delegated token stays capped at what was delegated ──────────────

/// An RFC 8693 token carries `act` and, as its permissions, the intersection
/// fixed at exchange time. Live resolution widened it back to the user's full
/// current set.
#[tokio::test]
async fn decide_caps_a_delegated_token_at_its_delegated_permissions() {
    let f = setup().await;
    let exchanger =
        f.h.identity()
            .register_client(
                &f.realm,
                &RegisterClientRequest {
                    client_name: "delegate".into(),
                    redirect_uris: vec!["https://agent.example.com/cb".into()],
                    client_secret: Some(RS_SECRET.into()),
                    grant_types: vec![TOKEN_EXCHANGE.into()],
                    trust_level: ClientTrustLevel::FirstParty,
                    ..RegisterClientRequest::default()
                },
            )
            .expect("exchanging client")
            .client_id()
            .clone();
    // The subject token carries only docs.view; so does the delegation.
    let delegated =
        f.h.identity()
            .rfc8693_token_exchange(
                &f.realm,
                &Rfc8693Request {
                    client_id: exchanger,
                    subject_token: f.session_token.clone(),
                    subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
                    actor_token: None,
                    actor_token_type: None,
                    requested_token_type: None,
                    scope: None,
                    resource: None,
                    audience: None,
                    dpop_jkt: None,
                },
            )
            .expect("token exchange")
            .access_token;
    f.grant_delete();

    assert!(
        f.decide(&f.session_token, "docs.delete", None),
        "control: the user's own first-party token sees the new grant live"
    );
    assert!(
        f.decide(&delegated, "docs.view", None),
        "the delegated permission stays allowed"
    );
    assert!(
        !f.decide(&delegated, "docs.delete", None),
        "a delegated token must not reach beyond the permissions it was delegated"
    );
    let (_, perms, roles, _) = f.introspect(&delegated);
    assert_eq!(perms, vec!["docs.view".to_string()]);
    assert!(
        roles.is_empty(),
        "a delegated token carries no roles; got {roles:?}"
    );
}

/// C-8 trigger 1: an actor (here a client whose client-credentials token
/// holds no permissions) exchanges the user's token. The delegation carries
/// actor ∩ subject = nothing; the decision endpoint answered from the user's
/// full live set instead ("an actor cannot gain RBAC permissions that it does
/// not already hold", AGENT_AUTH.md §3.3). The pre-fix `consent_delegations`
/// fixture relied on exactly this.
#[tokio::test]
async fn decide_denies_a_delegation_beyond_the_actors_permissions() {
    let f = setup().await;
    let actor =
        f.h.identity()
            .register_client(
                &f.realm,
                &RegisterClientRequest {
                    client_name: "actor".into(),
                    client_secret: Some(RS_SECRET.into()),
                    grant_types: vec!["client_credentials".into(), TOKEN_EXCHANGE.into()],
                    trust_level: ClientTrustLevel::FirstParty,
                    declared_scopes: vec!["openid".into(), "profile".into()],
                    ..RegisterClientRequest::default()
                },
            )
            .expect("actor client")
            .client_id()
            .clone();
    let actor_token =
        f.h.identity()
            .client_credentials_token(
                &f.realm,
                &hearth::identity::ClientCredentialsRequest {
                    client_id: actor.clone(),
                    client_secret: Some(RS_SECRET.into()),
                    scope: Some("openid profile".into()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("actor token")
            .access_token()
            .to_string();
    let delegated =
        f.h.identity()
            .rfc8693_token_exchange(
                &f.realm,
                &Rfc8693Request {
                    client_id: actor,
                    subject_token: f.session_token.clone(),
                    subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
                    actor_token: Some(actor_token),
                    actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".into()),
                    requested_token_type: None,
                    scope: None,
                    resource: None,
                    audience: None,
                    dpop_jkt: None,
                },
            )
            .expect("token exchange")
            .access_token;

    assert!(
        f.decide(&f.session_token, "docs.view", None),
        "control: the user holds docs.view"
    );
    assert!(
        !f.decide(&delegated, "docs.view", None),
        "an actor holding no permissions must not be allowed the user's docs.view"
    );
}

// ── C-9: the audience cutoff applies to decisions ───────────────────────────

/// Deleting a protected resource stops every token minted for it
/// (AGENT_AUTH.md §2.5). `validate_token` and introspection honoured the
/// cutoff; the decision path, engine and REST alike, did not.
#[tokio::test]
async fn decide_denies_a_token_for_a_removed_protected_resource() {
    let f = setup().await;
    let resource = f.register_resource(RS_A);
    let for_a = f.token(None, &["openid", "profile"], Some(RS_A));
    assert!(
        f.decide(&for_a, "docs.view", None),
        "control: allowed before removal"
    );
    let bearer = format!("Bearer {for_a}");
    let rest_decide = || {
        f.http(
            "POST",
            "/oauth/authorize",
            &bearer,
            Some(serde_json::json!({"permission": "docs.view"})),
        )
    };
    let (status, body) = rest_decide().await;
    assert_eq!(status, StatusCode::OK, "control: body {body}");
    assert_eq!(body["allowed"], true, "control: REST allowed; body {body}");

    f.h.identity()
        .delete_protected_resource(&f.realm, &resource.id)
        .expect("delete protected resource");

    assert!(
        !f.decide(&for_a, "docs.view", None),
        "a token for a removed protected resource must not be allowed"
    );
    let (status, body) = rest_decide().await;
    assert_eq!(status, StatusCode::OK, "body {body}");
    assert_eq!(
        body["allowed"], false,
        "POST /oauth/authorize must deny it too; body {body}"
    );
}

// ── B-2 on every surface ────────────────────────────────────────────────────

#[tokio::test]
async fn rest_decide_denies_a_third_party_clients_token() {
    let f = setup().await;
    let body = serde_json::json!({"permission": "docs.view"});

    let (status, allowed) = f
        .http(
            "POST",
            "/oauth/authorize",
            &format!("Bearer {}", f.session_token),
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        allowed["allowed"], true,
        "control: first-party token allowed"
    );

    let (status, denied) = f
        .http(
            "POST",
            "/oauth/authorize",
            &format!("Bearer {}", f.third_party_token),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        denied["allowed"], false,
        "POST /oauth/authorize must deny a third-party client's token; body {denied}"
    );
}

#[tokio::test]
async fn rest_introspect_releases_no_live_rbac_for_a_third_party_clients_token() {
    let f = setup().await;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{RS_SECRET}", f.rs.as_uuid()))
    );

    let (status, control) = f
        .http(
            "POST",
            "/introspect",
            &basic,
            Some(serde_json::json!({"token": f.session_token})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body {control}");
    assert!(
        strings(&control["permissions"]).contains("docs.view"),
        "control: live permissions for a first-party token; body {control}"
    );

    let (status, body) = f
        .http(
            "POST",
            "/introspect",
            &basic,
            Some(serde_json::json!({"token": f.third_party_token})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body {body}");
    assert_eq!(body["active"], true, "body {body}");
    assert!(
        strings(&body["permissions"]).is_empty()
            && strings(&body["roles"]).is_empty()
            && strings(&body["groups"]).is_empty(),
        "POST /introspect must release no live RBAC for a third-party token; body {body}"
    );
}

/// `GET /v1/me/permissions` handed a third-party app the user's full
/// `roles` / `groups` / `permissions` (B-5): the same profile rule applies.
#[tokio::test]
async fn me_permissions_releases_nothing_to_a_third_party_clients_token() {
    let f = setup().await;

    let (status, control) = f
        .http(
            "GET",
            "/v1/me/permissions",
            &format!("Bearer {}", f.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body {control}");
    assert!(
        strings(&control["permissions"]).contains("docs.view"),
        "control: a first-party token reads its own permissions; body {control}"
    );

    let (status, body) = f
        .http(
            "GET",
            "/v1/me/permissions",
            &format!("Bearer {}", f.third_party_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body {body}");
    assert!(
        strings(&body["permissions"]).is_empty()
            && strings(&body["roles"]).is_empty()
            && strings(&body["groups"]).is_empty(),
        "a third-party client's token must read no RBAC data; body {body}"
    );
}

// ── Round 2: decide answers for the token's organisation only ─────────────

/// `organization_id` on `POST /oauth/authorize` was caller-chosen, so a token
/// minted in organisation A was answered with the user's authority in
/// organisation B (or a realm-level token with any organisation's). The org
/// context is now the token's `oid`; a request naming another is denied.
#[tokio::test]
async fn decide_answers_only_for_the_tokens_organization() {
    use hearth::core::OrganizationId;
    use hearth::identity::{CreateOrganizationRequest, OrganizationConfig};

    let f = setup().await;
    let make_org = |slug: &str| -> OrganizationId {
        let org =
            f.h.identity()
                .create_organization(
                    &f.realm,
                    &CreateOrganizationRequest {
                        name: slug.to_string(),
                        slug: slug.to_string(),
                        description: None,
                        config: Some(OrganizationConfig::default()),
                        ..Default::default()
                    },
                )
                .expect("create organization")
                .id()
                .clone();
        let role =
            f.h.rbac()
                .create_role(
                    &f.realm,
                    &CreateRoleRequest {
                        name: format!("{slug}-manager"),
                        description: None,
                        permissions: vec![Permission::new("team.manage").unwrap()],
                        parent_roles: vec![],
                        ..Default::default()
                    },
                )
                .expect("create role");
        f.h.rbac()
            .assign_role(
                &f.realm,
                &AssignRoleRequest {
                    subject: Subject::User(f.user.clone()),
                    role_id: role.id,
                    scope: Scope::Org {
                        org_id: org.clone(),
                    },
                    assigned_by: None,
                },
            )
            .expect("assign org-scoped role");
        org
    };
    let org_a = make_org("org-a");
    let org_b = make_org("org-b");

    let session =
        f.h.identity()
            .create_session(&f.realm, &f.user, &SessionContext::default())
            .expect("session");
    let in_a =
        f.h.identity()
            .issue_tokens_with_context(
                &f.realm,
                &f.user,
                session.id(),
                &TokenIssuanceContext {
                    oid: Some(org_a.to_string()),
                    ..TokenIssuanceContext::default()
                },
            )
            .expect("issue tokens")
            .access_token()
            .to_string();
    let decide_in = |token: &str, org: Option<&OrganizationId>| {
        f.h.identity()
            .decide_token_permission(
                &f.realm,
                &DecidePermissionRequest {
                    token: token.into(),
                    permission: "team.manage".into(),
                    organization_id: org.map(ToString::to_string),
                    resource: None,
                },
            )
            .expect("decide")
            .allowed
    };

    assert!(
        decide_in(&in_a, Some(&org_a)),
        "control: the token's own organisation"
    );
    assert!(
        decide_in(&in_a, None),
        "no organization_id: the token's own organisation applies"
    );
    assert!(
        !decide_in(&in_a, Some(&org_b)),
        "a token minted in organisation A must not be answered for B"
    );
    assert!(
        !decide_in(&f.session_token, Some(&org_a)),
        "a realm-level token must not be answered for an organisation"
    );
}
