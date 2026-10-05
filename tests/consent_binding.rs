#![allow(clippy::unwrap_used)]
//! Consent bound to the organization and the resource, checked by
//! disclosure (`scope-consent-integrity` design §5).
//!
//! Scenarios of `custom-permissions` "Consent is bound to the organization
//! context and the resource", "The consent digest covers what the user agreed
//! to disclose", "Refresh re-checks consent against the current registry" and
//! "Revoking an application removes all of its consent".

mod common;

use std::collections::BTreeSet;

use hearth::audit::{Actor, AuditAction, AuditQuery};
use hearth::config::Config;
use hearth::core::{ClientId, OrganizationId, RealmId, Uri, UserId};
use hearth::identity::reconcile::{deterministic_client_id, reconcile_realms};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, ConsentGrant, ConsentKey, ConsentState,
    ConsentSurface, CreateOrganizationRequest, CreateUserRequest, IdentityError, OrganizationRole,
    TokenExchangeRequest,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

const REALM: &str = "consentbind";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const MCP: &str = "https://mcp.acme.com";

/// The operator's registry, as each test changes it.
#[derive(Clone, Copy, Default)]
struct Registry {
    /// `read:docs = [docs.read, docs.list]` instead of `[docs.read]`.
    broadened: bool,
    /// `read:docs` removed from the YAML.
    bundle_deleted: bool,
    /// A mapper that releases `salary` to third-party clients.
    salary_mapper: bool,
}

fn realm_yaml(r: Registry) -> String {
    let bundle = if r.bundle_deleted {
        String::new()
    } else {
        let perms = if r.broadened {
            "[docs.read, docs.list]"
        } else {
            "[docs.read]"
        };
        format!(
            "\x20     - name: \"read:docs\"\n        display_name: Read\n        permissions: {perms}\n"
        )
    };
    let salary = if r.salary_mapper {
        "\x20   claims:\n      mappings:\n\
         \x20       - claim: salary\n          source:\n            source: constant\n            value: secret\n\
         \x20         first_party_only: false\n"
    } else {
        ""
    };
    format!(
        "auth:\n  mfa_required: false\nrealms:\n  {REALM}:\n    session_ttl: \"12h\"\n\
         \x20   permissions:\n\
         \x20     - name: docs.read\n        display_name: Read\n\
         \x20     - name: docs.list\n        display_name: List\n\
         \x20   scopes:\n\
         \x20     - name: \"view:docs\"\n        display_name: View\n        permissions: [docs.read]\n\
         {bundle}\
         \x20   protected_resources:\n\
         \x20     - resource_uri: \"{MCP}\"\n        display_name: MCP\n        scopes:\n\
         \x20         - name: \"mcp:tools:invoke\"\n            display_name: Invoke\n            permissions: [docs.read]\n\
         {salary}\
         \x20   oauth_clients:\n\
         \x20     tp:\n        name: Third\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: third_party\n\
         \x20       declared_scopes: [openid, profile, \"read:docs\", \"view:docs\", \"mcp:tools:invoke\"]\n\
         \x20     tpx:\n        name: Spanning\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: third_party\n\
         \x20       consent_spans_orgs: true\n\
         \x20       declared_scopes: [openid, profile, \"read:docs\"]\n\
         \x20     fp:\n        name: First\n        redirect_uris: [\"{REDIRECT_URI}\"]\n\
         \x20       grant_types: [authorization_code, refresh_token]\n        trust_level: first_party\n"
    )
}

fn reconcile(h: &common::TestHarness, r: Registry) -> RealmId {
    let mut cfg = Config::from_yaml_str_unchecked(&realm_yaml(r)).expect("yaml");
    cfg.dev_mode = true;
    reconcile_realms(h.identity(), h.authz(), &cfg).expect("reconcile");
    h.identity()
        .get_realm_by_name(REALM)
        .unwrap()
        .expect("realm")
        .id()
        .clone()
}

fn client(key: &str) -> ClientId {
    deterministic_client_id(REALM, key)
}

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    org_a: OrganizationId,
    org_b: OrganizationId,
}

/// The user holds `docs.read` and `docs.list`, and is a member of `org-a`
/// and `org-b`.
async fn setup(r: Registry) -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = reconcile(&h, r);
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("consent-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Consent".into(),
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
                name: "docs.reader".into(),
                description: None,
                permissions: ["docs.read", "docs.list"]
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
    let org = |slug: &str| {
        let id = h
            .identity()
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
            .clone();
        h.identity()
            .add_member(&realm, &id, &user, OrganizationRole::Member)
            .expect("membership");
        id
    };
    let org_a = org("org-a");
    let org_b = org("org-b");
    Fixture {
        h,
        realm,
        user,
        org_a,
        org_b,
    }
}

impl Fixture {
    fn key(
        &self,
        client_key: &str,
        org: Option<&OrganizationId>,
        resource: Option<&str>,
    ) -> ConsentKey {
        ConsentKey {
            user_id: self.user.clone(),
            client_id: client(client_key),
            org_id: org.cloned(),
            resource: resource.map(|r| Uri::try_from(r.to_string()).unwrap()),
        }
    }

    fn consent(
        &self,
        client_key: &str,
        org: Option<&OrganizationId>,
        resource: Option<&str>,
        scope: &str,
    ) {
        self.h
            .identity()
            .grant_consent(
                &self.realm,
                &ConsentGrant {
                    key: self.key(client_key, org, resource),
                    scopes: scope.split_whitespace().map(str::to_string).collect(),
                    via: ConsentSurface::Web,
                },
            )
            .expect("consent");
    }

    fn decision(
        &self,
        client_key: &str,
        scope: &str,
        resource: Option<&str>,
        org: Option<&OrganizationId>,
    ) -> ConsentState {
        let org = org.map(|o| o.as_uuid().to_string());
        self.h
            .identity()
            .authorization_scopes(
                &self.realm,
                &self.user,
                &client(client_key),
                scope,
                resource,
                org.as_deref(),
            )
            .expect("resolve")
            .consent
    }

    /// The code flow for a client that holds consent; returns the refresh
    /// token.
    fn code_flow(&self, client_key: &str, scope: &str) -> String {
        let code = self
            .h
            .identity()
            .authorize(
                &self.realm,
                &AuthorizationRequest {
                    client_id: client(client_key),
                    redirect_uri: REDIRECT_URI.into(),
                    response_type: "code".into(),
                    scope: scope.into(),
                    state: "s".into(),
                    nonce: None,
                    code_challenge: Some(PKCE_CHALLENGE.into()),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    resource: None,
                    organization: None,
                    user_id: self.user.clone(),
                    amr_values: vec![],
                    response_mode: None,
                    request: None,
                },
            )
            .expect("authorize")
            .code()
            .to_string();
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
                    resource: None,
                },
            )
            .expect("exchange")
            .refresh_token()
            .to_string()
    }

    fn refresh(&self, refresh_token: &str) -> Result<String, IdentityError> {
        self.h
            .identity()
            .refresh_tokens(&self.realm, refresh_token, None, None)
            .map(|t| t.refresh_token().to_string())
    }

    fn audit_count(&self, action: AuditAction) -> usize {
        self.h
            .audit()
            .query(&AuditQuery::for_realm(self.realm.clone()))
            .expect("audit query")
            .iter()
            .filter(|e| e.action == action)
            .count()
    }
}

#[tokio::test]
async fn consent_is_scoped_to_the_organization() {
    let f = setup(Registry::default()).await;
    f.consent("tp", Some(&f.org_a), None, "openid read:docs");
    assert_eq!(
        f.decision("tp", "openid read:docs", None, Some(&f.org_a)),
        ConsentState::Held
    );
    assert_eq!(
        f.decision("tp", "openid read:docs", None, Some(&f.org_b)),
        ConsentState::Missing,
        "consent given in organization A does not cover organization B"
    );
    assert_eq!(
        f.decision("tp", "openid read:docs", None, None),
        ConsentState::Missing,
        "nor realm context"
    );
}

#[tokio::test]
async fn consent_that_spans_organizations() {
    let f = setup(Registry::default()).await;
    f.consent("tpx", None, None, "openid read:docs");
    f.consent("tp", None, None, "openid read:docs");
    assert_eq!(
        f.decision("tpx", "openid read:docs", None, Some(&f.org_b)),
        ConsentState::Held,
        "consent_spans_orgs lets the realm row cover an organization"
    );
    assert_eq!(
        f.decision("tp", "openid read:docs", None, Some(&f.org_b)),
        ConsentState::Missing,
        "without consent_spans_orgs it does not"
    );
}

#[tokio::test]
async fn consent_is_scoped_to_the_resource() {
    let f = setup(Registry::default()).await;
    f.consent("tp", None, None, "openid");
    assert_eq!(f.decision("tp", "openid", None, None), ConsentState::Held);
    assert_eq!(
        f.decision("tp", "openid", Some(MCP), None),
        ConsentState::Missing,
        "a consent for Hearth as audience does not cover a protected resource"
    );
}

#[tokio::test]
async fn a_first_party_client_has_no_consent_step() {
    let f = setup(Registry::default()).await;
    assert_eq!(
        f.decision("fp", "openid read:docs", None, None),
        ConsentState::NotRequired
    );
}

#[tokio::test]
async fn revoking_an_application_removes_every_consent_row() {
    let f = setup(Registry::default()).await;
    f.consent("tp", None, None, "openid");
    f.consent("tp", Some(&f.org_a), None, "openid");
    f.consent("tp", None, Some(MCP), "openid");
    // Another client's row is not touched.
    f.consent("tpx", None, None, "openid");

    let deleted =
        f.h.identity()
            .revoke_consent(
                &f.realm,
                &f.user,
                &client("tp"),
                &Actor::User(f.user.clone()),
            )
            .expect("revoke");
    assert_eq!(deleted, 3);
    for (org, resource) in [(None, None), (Some(&f.org_a), None), (None, Some(MCP))] {
        assert!(
            f.h.identity()
                .get_consent(&f.realm, &f.key("tp", org, resource))
                .expect("get")
                .is_none(),
            "no consent row for the client remains"
        );
    }
    assert!(f
        .h
        .identity()
        .get_consent(&f.realm, &f.key("tpx", None, None))
        .expect("get")
        .is_some());

    let events =
        f.h.audit()
            .query(&AuditQuery::for_realm(f.realm.clone()))
            .expect("audit query");
    let rows: BTreeSet<(Option<String>, Option<String>)> = events
        .iter()
        .filter(|e| e.action == AuditAction::ClientConsentRevoked)
        .map(|e| {
            let meta = e.metadata.clone().unwrap_or_default();
            let field = |k: &str| meta.get(k).and_then(|v| v.as_str()).map(str::to_string);
            (field("context_oid"), field("resource_uri"))
        })
        .collect();
    let expected: BTreeSet<(Option<String>, Option<String>)> = [
        (None, None),
        (Some(f.org_a.as_uuid().to_string()), None),
        (None, Some(MCP.to_string())),
    ]
    .into_iter()
    .collect();
    assert_eq!(rows, expected, "one ClientConsentRevoked per deleted row");
    assert_eq!(f.audit_count(AuditAction::ClientConsentRevoked), 3);
}

#[tokio::test]
async fn a_new_mapper_invalidates_consent() {
    let f = setup(Registry::default()).await;
    f.consent("tp", None, None, "openid read:docs");
    assert_eq!(
        f.decision("tp", "openid read:docs", None, None),
        ConsentState::Held
    );
    reconcile(
        &f.h,
        Registry {
            salary_mapper: true,
            ..Registry::default()
        },
    );
    assert_eq!(
        f.decision("tp", "openid read:docs", None, None),
        ConsentState::Missing,
        "a claim the user never agreed to release asks again"
    );
}

#[tokio::test]
async fn a_removed_mapper_does_not_ask_again() {
    let with_salary = Registry {
        salary_mapper: true,
        ..Registry::default()
    };
    let f = setup(with_salary).await;
    f.consent("tp", None, None, "openid read:docs");
    reconcile(&f.h, Registry::default());
    assert_eq!(
        f.decision("tp", "openid read:docs", None, None),
        ConsentState::Held,
        "disclosing less never asks again"
    );
}

#[tokio::test]
async fn a_broadened_bundle_requires_consent_again() {
    let f = setup(Registry::default()).await;
    f.consent("tp", None, None, "openid read:docs");
    let refresh = f.code_flow("tp", "openid read:docs");
    let refresh = f.refresh(&refresh).expect("consent still covers the grant");

    reconcile(
        &f.h,
        Registry {
            broadened: true,
            ..Registry::default()
        },
    );
    let r = f.refresh(&refresh);
    assert!(
        matches!(r, Err(IdentityError::RefreshConsentRequired)),
        "the next refresh asks for consent again"
    );
    assert_eq!(f.audit_count(AuditAction::ConsentRequiredOnRefresh), 1);
}

#[tokio::test]
async fn a_deleted_bundle_ends_the_consent() {
    let f = setup(Registry::default()).await;
    f.consent("tp", None, None, "openid read:docs");
    let refresh = f.code_flow("tp", "openid read:docs");

    reconcile(
        &f.h,
        Registry {
            bundle_deleted: true,
            ..Registry::default()
        },
    );
    let r = f.refresh(&refresh);
    assert!(
        matches!(r, Err(IdentityError::RefreshConsentRequired)),
        "a refresh of a deleted bundle fails with invalid_grant and consent_required"
    );
    assert!(
        f.h.identity()
            .get_consent(&f.realm, &f.key("tp", None, None))
            .expect("get")
            .is_none(),
        "the whole consent row is deleted"
    );
}
