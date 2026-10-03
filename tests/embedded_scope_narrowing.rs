#![allow(clippy::unwrap_used)]
//! GA audit 3 B-4 — embedded tokens are narrowed by their granted scopes
//! identically at the code exchange, on refresh and at the device grant.
//!
//! The code exchange narrowed only a single-scope grant (`openid docs:read`
//! resolved the user's full set), refresh rotation re-resolved with no scope
//! at all — a token narrowed to a bundle at the exchange came back with the
//! user's full set, `hearth.admin` included, on its first refresh — and the
//! device grant minted with no scope. Every issuance path now resolves with
//! `RbacEngine::resolve_for_granted_scopes`, the rule live resolution uses.

mod common;

use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    decode_claims_unverified, AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod,
    CreateRealmRequest, CreateUserRequest, DeviceAuthorizationRequest, RegisterClientRequest,
    TokenExchangeRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, ScopeSpec, Subject};

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    client: ClientId,
}

/// A user holding `docs.view`, `docs.delete` and `reports.export`; the realm
/// bundle `docs:read` admits `docs.view` only; a first-party client
/// registered for the code, refresh and device grants.
async fn setup() -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("narrow-{}", uuid::Uuid::new_v4()),
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
                email: format!("narrow-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Narrow".into(),
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
                name: "docs.owner".into(),
                description: None,
                permissions: ["docs.view", "docs.delete", "reports.export"]
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
    h.rbac()
        .reconcile_scopes(
            &realm,
            &[ScopeSpec {
                name: "docs:read".into(),
                permissions: Some(vec!["docs.view".into()]),
            }],
        )
        .expect("scope bundle");
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "narrowing-app".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec![
                    "authorization_code".into(),
                    "refresh_token".into(),
                    DEVICE_GRANT.into(),
                ],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![
                    "openid".into(),
                    "profile".into(),
                    "offline_access".into(),
                    "docs:read".into(),
                ],
                ..RegisterClientRequest::default()
            },
        )
        .expect("client")
        .client_id()
        .clone();
    Fixture {
        h,
        realm,
        user,
        client,
    }
}

impl Fixture {
    /// Runs the code flow for `scope`; returns `(access_token, refresh_token)`.
    fn code_flow(&self, scope: &str) -> (String, String) {
        let code = self
            .h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    client_id: self.client.clone(),
                    redirect_uri: REDIRECT_URI.into(),
                    response_type: "code".into(),
                    scope: scope.into(),
                    state: "s".into(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .expect("authorize")
            .code()
            .to_string();
        let tokens = self
            .h
            .identity()
            .exchange_authorization_code(
                &self.realm,
                &TokenExchangeRequest {
                    client_id: self.client.clone(),
                    code,
                    redirect_uri: REDIRECT_URI.into(),
                    code_verifier: Some(PKCE_VERIFIER.into()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .expect("exchange");
        (
            tokens.access_token().to_string(),
            tokens.refresh_token().to_string(),
        )
    }
}

fn permissions(access_token: &str) -> Vec<String> {
    let mut perms = decode_claims_unverified(access_token)
        .expect("decode")
        .permissions;
    perms.sort();
    perms
}

/// B-4's trigger: narrowed at the exchange, widened to the user's full set
/// (in production, `hearth.admin` included) by the first refresh.
#[tokio::test]
async fn a_token_narrowed_to_a_bundle_stays_narrowed_after_refresh() {
    let f = setup().await;
    let (access, refresh) = f.code_flow("docs:read");
    assert_eq!(
        permissions(&access),
        vec!["docs.view".to_string()],
        "the code exchange narrows to the bundle"
    );

    let rotated =
        f.h.identity()
            .refresh_tokens(&f.realm, &refresh, None, None)
            .expect("refresh");
    assert_eq!(
        permissions(rotated.access_token()),
        vec!["docs.view".to_string()],
        "a refresh must keep the grant's narrowing"
    );
}

/// With an OIDC scope beside the bundle the exchange did not narrow at all.
#[tokio::test]
async fn the_code_exchange_narrows_by_every_permission_scope() {
    let f = setup().await;
    let (access, refresh) = f.code_flow("openid docs:read");
    assert_eq!(
        permissions(&access),
        vec!["docs.view".to_string()],
        "`openid docs:read` must be narrowed exactly as `docs:read`"
    );
    let rotated =
        f.h.identity()
            .refresh_tokens(&f.realm, &refresh, None, None)
            .expect("refresh");
    assert_eq!(
        permissions(rotated.access_token()),
        vec!["docs.view".to_string()]
    );

    // Control: OIDC scopes alone carry no permissions and narrow nothing.
    let (access, _) = f.code_flow("openid profile");
    assert_eq!(
        permissions(&access),
        vec![
            "docs.delete".to_string(),
            "docs.view".to_string(),
            "reports.export".to_string()
        ]
    );
}

/// The device grant minted with no scope and the user's full set.
#[tokio::test]
async fn the_device_grant_narrows_to_its_scope() {
    let f = setup().await;
    let started =
        f.h.identity()
            .device_authorize(
                &f.realm,
                &DeviceAuthorizationRequest {
                    client_id: f.client.clone(),
                    scope: Some("openid docs:read".into()),
                },
            )
            .expect("device authorize");
    f.h.identity()
        .approve_device(&f.realm, &started.user_code, &f.user)
        .expect("approve");
    let tokens =
        f.h.identity()
            .poll_device_token(&f.realm, &started.device_code, &f.client, None)
            .expect("poll");

    let claims = decode_claims_unverified(tokens.access_token()).expect("decode");
    assert_eq!(
        claims.scope.as_deref(),
        Some("docs:read openid"),
        "the device token carries its granted scope"
    );
    assert_eq!(
        permissions(tokens.access_token()),
        vec!["docs.view".to_string()],
        "the device grant narrows to its scope"
    );
    let rotated =
        f.h.identity()
            .refresh_tokens(&f.realm, tokens.refresh_token(), None, None)
            .expect("refresh");
    assert_eq!(
        permissions(rotated.access_token()),
        vec!["docs.view".to_string()]
    );
}
