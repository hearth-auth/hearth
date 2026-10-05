#![allow(clippy::unwrap_used)]
//! One scope-resolution entry point on every issuance path
//! (`scope-consent-integrity` design §2).
//!
//! Scenarios of `custom-permissions` ("A scope is granted only when the user
//! satisfies all of it", "Ungrantable scopes are dropped for first-party and
//! fatal for third-party clients", "Release gates restrict which clients
//! receive a claim", "The token audience selects the scope registry",
//! "Refresh re-checks consent against the current registry") and of
//! `mcp-authorization` ("The `resource` parameter names a registered
//! resource").

mod common;

use hearth::config::Config;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::reconcile::{deterministic_client_id, reconcile_realms};
use hearth::identity::{
    decode_claims_unverified, AuthorizationRequest, ClientCredentialsRequest, CodeChallengeMethod,
    CreateUserRequest, IdentityError, TokenExchangeRequest, TokenIntrospectionRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

const REALM: &str = "scoperes";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const MCP: &str = "https://mcp.acme.com";
const SVC_SECRET: &str = "svc-secret-0123456789abcdef0123456789abcdef";

/// The realm YAML. `with_view_bundle: false` is the same realm after the
/// operator deleted `view:docs`.
fn realm_yaml(with_view_bundle: bool) -> String {
    let view = if with_view_bundle {
        "      - name: \"view:docs\"\n        display_name: View\n        permissions: [docs.view]\n"
    } else {
        ""
    };
    format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n\
         \x20   permissions:\n\
         \x20     - name: docs.view\n        display_name: View\n\
         \x20     - name: docs.list\n        display_name: List\n\
         \x20     - name: docs.share\n        display_name: Share\n\
         \x20     - name: docs.delete\n        display_name: Delete\n\
         \x20   scopes:\n\
         \x20     - name: \"read:docs\"\n        display_name: Read\n        permissions: [docs.view, docs.list, docs.share]\n\
         {view}\
         \x20   protected_resources:\n\
         \x20     - resource_uri: \"{MCP}\"\n        display_name: MCP\n        scopes:\n\
         \x20         - name: \"mcp:tools:invoke\"\n            display_name: Invoke\n            permissions: [docs.view]\n\
         \x20   claims:\n      mappings:\n\
         \x20       - claim: docs_flag\n          source:\n            source: constant\n            value: on\n\
         \x20         first_party_only: false\n          required_scopes: [\"read:docs\"]\n\
         \x20   oauth_clients:\n\
         \x20     fp:\n        name: First\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: first_party\n\
         \x20     tp:\n        name: Third\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: third_party\n\
         \x20       declared_scopes: [openid, profile, \"read:docs\", \"view:docs\", \"mcp:tools:invoke\"]\n\
         \x20     svc:\n        name: Service\n        grant_types: [client_credentials]\n\
         \x20       confidential: true\n        client_secret: \"{SVC_SECRET}\"\n        trust_level: first_party\n"
    )
}

fn reconcile(h: &common::TestHarness, with_view_bundle: bool) -> RealmId {
    let mut cfg = Config::from_yaml_str_unchecked(&realm_yaml(with_view_bundle)).expect("yaml");
    cfg.dev_mode = true;
    reconcile_realms(h.identity(), h.authz(), &cfg).expect("reconcile");
    h.identity()
        .get_realm_by_name(REALM)
        .unwrap()
        .expect("realm")
        .id()
        .clone()
}

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
}

fn client(key: &str) -> ClientId {
    deterministic_client_id(REALM, key)
}

/// The user holds `docs.view` and `docs.delete`: `view:docs` and
/// `mcp:tools:invoke` fully, `read:docs` only in part.
async fn setup() -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = reconcile(&h, true);
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("scope-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Scope".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.editor".into(),
                description: None,
                permissions: ["docs.view", "docs.delete"]
                    .iter()
                    .map(|p| Permission::new(*p).unwrap())
                    .collect(),
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    Fixture { h, realm, user }
}

impl Fixture {
    fn authorize(
        &self,
        client_key: &str,
        scope: &str,
        resource: Option<&str>,
    ) -> Result<String, IdentityError> {
        let client = client(client_key);
        if client_key == "tp" {
            let scopes: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
            self.h
                .identity()
                .grant_consent(
                    &self.realm,
                    &hearth::identity::ConsentGrant {
                        key: hearth::identity::ConsentKey {
                            user_id: self.user.clone(),
                            client_id: client.clone(),
                            org_id: None,
                            resource: resource
                                .map(|r| hearth::core::Uri::try_from(r.to_string()).unwrap()),
                        },
                        scopes,
                        via: hearth::identity::ConsentSurface::Web,
                    },
                )
                .expect("consent");
        }
        self.h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    organization: None,
                    client_id: client,
                    redirect_uri: REDIRECT_URI.into(),
                    response_type: "code".into(),
                    scope: scope.into(),
                    state: "s".into(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: resource.map(str::to_string),
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .map(|r| r.code().to_string())
    }

    fn exchange(
        &self,
        client_key: &str,
        code: String,
        resource: Option<&str>,
    ) -> Result<(String, String), IdentityError> {
        self.h
            .identity()
            .exchange_authorization_code(
                &self.realm,
                &TokenExchangeRequest {
                    client_id: client(client_key),
                    code,
                    redirect_uri: REDIRECT_URI.into(),
                    code_verifier: Some(PKCE_VERIFIER.into()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                    resource: resource.map(str::to_string),
                },
            )
            .map(|t| (t.access_token().to_string(), t.refresh_token().to_string()))
    }

    /// The code flow; returns `(access_token, refresh_token)`.
    fn code_flow(&self, client_key: &str, scope: &str, resource: Option<&str>) -> (String, String) {
        let code = self
            .authorize(client_key, scope, resource)
            .expect("authorize");
        self.exchange(client_key, code, None).expect("exchange")
    }
}

fn scope_of(token: &str) -> Vec<String> {
    decode_claims_unverified(token)
        .expect("decode")
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn permissions_of(token: &str) -> Vec<String> {
    let mut p = decode_claims_unverified(token).expect("decode").permissions;
    p.sort();
    p
}

fn is_invalid_scope(r: &Result<String, IdentityError>) -> bool {
    matches!(r, Err(IdentityError::InvalidScope { .. }))
}

#[tokio::test]
async fn a_bundle_is_granted_only_when_fully_held() {
    let f = setup().await;
    let (access, _) = f.code_flow("fp", "read:docs docs.view", None);
    assert_eq!(
        scope_of(&access),
        vec!["docs.view"],
        "a partly held bundle is not granted"
    );
    assert_eq!(permissions_of(&access), vec!["docs.view"]);
}

#[tokio::test]
async fn a_third_party_client_never_gets_an_unsatisfiable_bundle() {
    let f = setup().await;
    let r = f.authorize("tp", "openid read:docs", None);
    assert!(
        is_invalid_scope(&r),
        "no code for a bundle the user holds in part"
    );
}

#[tokio::test]
async fn gates_run_on_granted_scopes_only() {
    let f = setup().await;
    let (access, _) = f.code_flow("fp", "openid read:docs", None);
    let claims = decode_claims_unverified(&access).expect("decode");
    assert_eq!(scope_of(&access), vec!["openid"]);
    assert!(
        !claims.custom.contains_key("docs_flag"),
        "a gate on a scope that was not granted does not pass"
    );
    assert!(
        claims.permissions.is_empty(),
        "every requested bundle was dropped, so no permission is granted"
    );
}

#[tokio::test]
async fn an_unknown_scope_from_a_first_party_client_is_refused() {
    let f = setup().await;
    let r = f.authorize("fp", "openid nosuch:bundle", None);
    assert!(
        is_invalid_scope(&r),
        "a scope no registry defines is refused"
    );
}

#[tokio::test]
async fn only_resource_bundles_apply_under_a_resource() {
    let f = setup().await;
    let r = f.authorize("fp", "view:docs", Some(MCP));
    assert!(
        is_invalid_scope(&r),
        "a realm bundle is not legal under a resource"
    );
    let r = f.authorize("fp", "docs.view", Some(MCP));
    assert!(
        is_invalid_scope(&r),
        "a raw permission is not legal under a resource"
    );

    let (access, _) = f.code_flow("tp", "openid mcp:tools:invoke", Some(MCP));
    let claims = decode_claims_unverified(&access).expect("decode");
    assert_eq!(scope_of(&access), vec!["openid", "mcp:tools:invoke"]);
    assert!(claims.aud.contains(MCP), "the token is for the resource");
}

#[tokio::test]
async fn a_third_party_client_with_only_oidc_scopes_gets_no_permissions() {
    let f = setup().await;
    let (access, _) = f.code_flow("tp", "openid profile", None);
    assert_eq!(permissions_of(&access), Vec::<String>::new());
    let introspected =
        f.h.identity()
            .introspect_token(
                &f.realm,
                &TokenIntrospectionRequest {
                    token: access,
                    token_type_hint: None,
                    introspecting_client_id: Some(client("tp")),
                },
            )
            .expect("introspect");
    assert!(
        introspected.permissions.is_empty(),
        "introspection releases no permissions for an OIDC-only third-party grant"
    );
}

#[tokio::test]
async fn a_deleted_bundle_never_widens_a_refreshed_token() {
    let f = setup().await;
    let (access, refresh) = f.code_flow("fp", "view:docs", None);
    assert_eq!(permissions_of(&access), vec!["docs.view"]);

    reconcile(&f.h, false);
    let r =
        f.h.identity()
            .refresh_tokens(&f.realm, &refresh, None, None);
    assert!(
        matches!(r, Err(IdentityError::InvalidGrant { .. })),
        "a refresh of a deleted bundle fails with invalid_grant"
    );
}

#[tokio::test]
async fn a_token_requests_resource_is_applied() {
    let f = setup().await;
    let cc = |resource: Option<&str>| {
        f.h.identity().client_credentials_token(
            &f.realm,
            &ClientCredentialsRequest {
                client_id: client("svc"),
                client_secret: Some(SVC_SECRET.into()),
                scope: None,
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: resource.map(str::to_string),
            },
        )
    };
    let token = cc(Some(MCP)).expect("registered resource");
    let claims = decode_claims_unverified(token.access_token()).expect("decode");
    assert!(claims.aud.contains(MCP), "the resource is in the audience");
    assert!(matches!(
        cc(Some("https://unregistered.example.com")),
        Err(IdentityError::InvalidTarget { .. })
    ));
}

#[tokio::test]
async fn a_code_exchange_names_another_resource() {
    let f = setup().await;
    let code = f
        .authorize("tp", "openid mcp:tools:invoke", Some(MCP))
        .expect("authorize");
    let r = f.exchange("tp", code, Some("https://other.example.com"));
    assert!(matches!(r, Err(IdentityError::InvalidTarget { .. })));
}

#[tokio::test]
async fn a_refresh_names_another_resource() {
    let f = setup().await;
    let (_, refresh) = f.code_flow("tp", "openid mcp:tools:invoke", Some(MCP));
    let r = f.h.identity().refresh_tokens_for_resource(
        &f.realm,
        &refresh,
        None,
        None,
        Some("https://other.example.com"),
    );
    assert!(matches!(r, Err(IdentityError::InvalidTarget { .. })));
    f.h.identity()
        .refresh_tokens_for_resource(&f.realm, &refresh, None, None, Some(MCP))
        .expect("the grant's own resource is accepted");
}
