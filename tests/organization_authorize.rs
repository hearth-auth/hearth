#![allow(clippy::unwrap_used)]
//! The `organization` parameter at `/authorize` (`scope-consent-integrity`
//! design §1).
//!
//! Scenarios of `rbac-token-claims` "The organization context comes from the
//! authorization request": "A member signs in to an organization", "A
//! non-member names an organization" and "Membership ends before a refresh".

mod common;

use hearth::config::Config;
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::reconcile::{deterministic_client_id, reconcile_realms};
use hearth::identity::{
    decode_claims_unverified, AuthorizationRequest, CodeChallengeMethod, CreateOrganizationRequest,
    CreateUserRequest, IdentityError, OidcTokenResponse, OrganizationRole, OrganizationStatus,
    TokenExchangeRequest, UpdateOrganizationRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

const REALM: &str = "orgauth";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn realm_yaml() -> String {
    format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n\
         \x20   permissions:\n\
         \x20     - name: docs.view\n        display_name: View\n\
         \x20     - name: docs.edit\n        display_name: Edit\n\
         \x20   oauth_clients:\n\
         \x20     fp:\n        name: First\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: first_party\n"
    )
}

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    /// `acme`: the user is a member and holds `docs.edit` there.
    acme: OrganizationId,
    /// `globex`: an active organization the user is not a member of.
    globex: OrganizationId,
}

async fn setup() -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let mut cfg = Config::from_yaml_str_unchecked(&realm_yaml()).expect("yaml");
    cfg.dev_mode = true;
    reconcile_realms(h.identity(), h.authz(), &cfg).expect("reconcile");
    let realm = h
        .identity()
        .get_realm_by_name(REALM)
        .unwrap()
        .expect("realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("org-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Org".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    let org = |slug: &str| {
        h.identity()
            .create_organization(
                &realm,
                &CreateOrganizationRequest {
                    name: slug.to_string(),
                    slug: slug.to_string(),
                    description: None,
                    config: None,
                    attributes: Default::default(),
                },
            )
            .expect("organization")
            .id()
            .clone()
    };
    let acme = org("acme");
    let globex = org("globex");
    h.identity()
        .add_member(&realm, &acme, &user, OrganizationRole::Member)
        .expect("membership");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "acme.editor".into(),
                description: None,
                permissions: vec![Permission::new("docs.edit").unwrap()],
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
                scope: Scope::Org {
                    org_id: acme.clone(),
                },
                assigned_by: None,
            },
        )
        .expect("assign");
    Fixture {
        h,
        realm,
        user,
        acme,
        globex,
    }
}

impl Fixture {
    fn authorize(&self, organization: Option<&str>) -> Result<String, IdentityError> {
        self.h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    client_id: deterministic_client_id(REALM, "fp"),
                    redirect_uri: REDIRECT_URI.into(),
                    response_type: "code".into(),
                    scope: "openid".into(),
                    state: "s".into(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    organization: organization.map(str::to_string),
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .map(|r| r.code().to_string())
    }

    fn exchange(&self, code: String) -> OidcTokenResponse {
        self.h
            .identity()
            .exchange_authorization_code(
                &self.realm,
                &TokenExchangeRequest {
                    client_id: deterministic_client_id(REALM, "fp"),
                    code,
                    redirect_uri: REDIRECT_URI.into(),
                    code_verifier: Some(PKCE_VERIFIER.into()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                    resource: None,
                },
            )
            .expect("exchange")
    }
}

fn oid_of(token: &str) -> Option<String> {
    decode_claims_unverified(token).expect("decode").oid
}

fn has_permission(token: &str, permission: &str) -> bool {
    decode_claims_unverified(token)
        .expect("decode")
        .permissions
        .iter()
        .any(|p| p == permission)
}

#[tokio::test]
async fn a_member_signs_in_to_an_organization() {
    let f = setup().await;
    let acme = f.acme.as_uuid().to_string();

    // By slug.
    let tokens = f.exchange(f.authorize(Some("acme")).expect("authorize"));
    assert_eq!(
        oid_of(tokens.access_token()).as_deref(),
        Some(acme.as_str())
    );
    assert_eq!(oid_of(tokens.id_token()).as_deref(), Some(acme.as_str()));
    assert_eq!(
        oid_of(tokens.refresh_token()).as_deref(),
        Some(acme.as_str())
    );
    assert!(
        has_permission(tokens.access_token(), "docs.edit"),
        "the organization-scoped role applies in the organization"
    );

    // By ID.
    let tokens = f.exchange(f.authorize(Some(&acme)).expect("authorize by ID"));
    assert_eq!(
        oid_of(tokens.access_token()).as_deref(),
        Some(acme.as_str())
    );

    // Without the parameter the flow stays in realm context.
    let tokens = f.exchange(f.authorize(None).expect("authorize"));
    assert_eq!(oid_of(tokens.access_token()), None);
    assert!(!has_permission(tokens.access_token(), "docs.edit"));
}

#[tokio::test]
async fn a_non_member_names_an_organization() {
    let f = setup().await;
    let not_a_member = f.authorize(Some("globex"));
    let unknown = f.authorize(Some("no-such-org"));
    let unknown_id = f.authorize(Some(&OrganizationId::generate().as_uuid().to_string()));
    for r in [&not_a_member, &unknown, &unknown_id] {
        assert!(
            matches!(r, Err(IdentityError::OrganizationAccessDenied)),
            "refused as one case: {:?}",
            r.as_ref().err()
        );
    }

    // A member of a suspended organization gets the same answer.
    f.h.identity()
        .update_organization(
            &f.realm,
            &f.acme,
            &UpdateOrganizationRequest {
                status: Some(OrganizationStatus::Suspended),
                ..Default::default()
            },
        )
        .expect("suspend");
    assert!(matches!(
        f.authorize(Some("acme")),
        Err(IdentityError::OrganizationAccessDenied)
    ));
    let _ = &f.globex;
}

#[tokio::test]
async fn membership_ends_before_a_refresh() {
    let f = setup().await;
    let tokens = f.exchange(f.authorize(Some("acme")).expect("authorize"));
    let refreshed =
        f.h.identity()
            .refresh_tokens(&f.realm, tokens.refresh_token(), None, None)
            .expect("a member refreshes");
    let acme = f.acme.as_uuid().to_string();
    assert_eq!(
        oid_of(refreshed.access_token()).as_deref(),
        Some(acme.as_str())
    );
    assert!(
        has_permission(refreshed.access_token(), "docs.edit"),
        "refresh resolves permissions in the organization"
    );

    f.h.identity()
        .remove_member(&f.realm, &f.acme, &f.user)
        .expect("remove member");
    let r =
        f.h.identity()
            .refresh_tokens(&f.realm, refreshed.refresh_token(), None, None);
    assert!(
        matches!(r, Err(IdentityError::InvalidGrant { .. })),
        "a refresh after the membership ended fails with invalid_grant"
    );
}
