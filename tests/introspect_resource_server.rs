//! G6 — a token exchanged with `audience=` only (openspec/specs/mcp-authorization/spec.md, openspec/specs/oidc-provider/spec.md
//! §3.4.1a) carries no Hearth audience, so introspection refused it for every
//! caller, the resource server it was minted for included: such a token could
//! only be verified offline, and removing its resource could not stop it.
//!
//! A protected resource now names the client its resource server introspects
//! as (`protected_resources[].introspection_client`, the key of an
//! application in the same realm). That client — and only that client — may
//! introspect a token whose `aud` names the resource, whether or not the
//! token also names Hearth. An unrelated client still gets `active: false`
//! (GA audit L11).

#![allow(clippy::unwrap_used)]

mod common;

use hearth::config::Config;
use hearth::core::{ClientId, RealmId};
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::{
    ClientTrustLevel, CreateUserRequest, RegisterClientRequest, Rfc8693Request, SessionContext,
    TokenIntrospectionRequest, TokenIssuanceContext,
};

const REALM: &str = "rsintrospect";
const RS: &str = "https://mcp.example.com";
const TE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SECRET: &str = "rs-introspect-secret-0123456789!";

fn yaml(introspection_client: &str) -> String {
    format!(
        r#"
auth:
  mfa_required: false
realms:
  {REALM}:
    applications:
      mcp-rs:
        name: "MCP resource server"
        redirect_uris:
          - "https://mcp.example.com/cb"
        grant_types:
          - client_credentials
        confidential: true
        client_secret: "{SECRET}"
      other-rs:
        name: "Another resource server"
        redirect_uris:
          - "https://other.example.com/cb"
        grant_types:
          - client_credentials
        confidential: true
        client_secret: "{SECRET}"
    protected_resources:
      - resource_uri: "{RS}"
        display_name: "MCP"
        introspection_client: {introspection_client}
"#
    )
}

fn reconciled(h: &common::TestHarness) -> RealmId {
    let mut config = Config::from_yaml_str_unchecked(&yaml("mcp-rs")).expect("parse yaml");
    config.dev_mode = true;
    reconcile_realms(h.identity(), h.authz(), &config).expect("reconcile");
    h.identity()
        .get_realm_by_name(REALM)
        .expect("lookup")
        .expect("realm")
        .id()
        .clone()
}

/// The YAML-managed client named `name`.
fn app(h: &common::TestHarness, realm: &RealmId, name: &str) -> ClientId {
    h.identity()
        .list_clients(realm, &hearth::core::PageRequest::new(0, 50))
        .expect("list clients")
        .items
        .into_iter()
        .find(|c| c.client_name() == name)
        .unwrap_or_else(|| panic!("no application named {name}"))
        .client_id()
        .clone()
}

/// A token exchanged for `audience=RS` only: its `aud` is `[RS]`.
fn audience_only_token(h: &common::TestHarness, realm: &RealmId) -> String {
    // The scope registry refuses a scope the realm does not define.
    h.declare_scopes(realm, &["read"]);
    let exchanger = h
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "exchanger".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(SECRET.to_string()),
                grant_types: vec![TE.to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap()
        .client_id()
        .clone();
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "rs-introspect@example.com".to_string(),
                display_name: "RS".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .unwrap();
    let subject = h
        .identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                granted_scopes: std::iter::once("read".to_string()).collect(),
                ..TokenIssuanceContext::default()
            },
        )
        .unwrap()
        .access_token()
        .to_string();
    let token = h
        .identity()
        .rfc8693_token_exchange(
            realm,
            &Rfc8693Request {
                client_id: exchanger,
                subject_token: subject,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource: None,
                audience: Some(RS.to_string()),
                dpop_jkt: None,
            },
        )
        .expect("exchange for the resource")
        .access_token;
    let claims = hearth::identity::tokens::decode_claims_unverified(&token).unwrap();
    assert!(
        claims.aud.contains(RS) && !claims.aud.contains("hearth"),
        "precondition: an audience-only token, aud = {:?}",
        claims.aud
    );
    token
}

fn active_for(h: &common::TestHarness, realm: &RealmId, token: &str, caller: &ClientId) -> bool {
    h.identity()
        .introspect_token(
            realm,
            &TokenIntrospectionRequest {
                token: token.to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(caller.clone()),
            },
        )
        .expect("introspect")
        .active
}

#[tokio::test]
async fn the_resource_server_named_in_aud_can_introspect_an_audience_only_token() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = reconciled(&h);
    let token = audience_only_token(&h, &realm);
    let rs = app(&h, &realm, "MCP resource server");
    assert!(
        active_for(&h, &realm, &token, &rs),
        "the resource server the token was exchanged for could not introspect it"
    );
}

#[tokio::test]
async fn another_resource_server_cannot_introspect_it() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = reconciled(&h);
    let token = audience_only_token(&h, &realm);
    let other = app(&h, &realm, "Another resource server");
    assert!(
        !active_for(&h, &realm, &token, &other),
        "a client the resource does not name introspected its token (L11)"
    );
}

#[test]
fn an_introspection_client_must_name_an_application_of_the_realm() {
    let fields = |key: &str| -> Vec<String> {
        let mut config = Config::from_yaml_str_unchecked(&yaml(key)).expect("parse yaml");
        config.dev_mode = true;
        config
            .validate_all()
            .into_iter()
            .map(|issue| issue.field)
            .filter(|f| f.contains("introspection_client"))
            .collect()
    };
    assert_eq!(
        fields("no-such-app"),
        vec![format!(
            "realms.{REALM}.protected_resources[0].introspection_client"
        )],
        "an introspection_client naming no application must be refused, naming the key"
    );
    assert!(
        fields("mcp-rs").is_empty(),
        "an introspection_client naming an application of the realm is accepted"
    );
}
