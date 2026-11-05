//! #632, part 1 (OpenSpec `fix-spec-drift-defects` tasks 2.2, 2.3 and 3.1):
//! agent audit events carry the delegation context (`agent-identity`,
//! "Agent audit events carry the delegation context").
//!
//! - The `AgentDelegation` event records the full `delegation_chain`: the
//!   user, then each earlier actor, then the new actor.
//! - An allowed `POST /v1/tools/invoke` records `actor`, `tool` and
//!   `token_jti`, so an audit query by tool finds it.

mod common;

use hearth::audit::{AuditAction, AuditEvent, AuditQuery};
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AccessTokenAuthorization, ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest,
    CreateUserRequest, IdentityEngine, RegisterClientRequest, Rfc8693Request, SessionContext,
    TokenIssuanceContext,
};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

const SCOPE: &str = "mcp:tools:invoke";

fn make_realm(h: &common::TestHarness) -> RealmId {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("agent-audit-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.declare_scopes(&realm, &[SCOPE]);
    realm
}

fn make_user(identity: &dyn IdentityEngine, realm: &RealmId) -> UserId {
    identity
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("agent-audit-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Agent Audit User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

/// A user access token with `SCOPE`.
fn user_token(identity: &dyn IdentityEngine, realm: &RealmId, user: &UserId) -> String {
    let session = identity
        .create_session(realm, user, &SessionContext::default())
        .expect("session");
    identity
        .issue_tokens_with_context(
            realm,
            user,
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes: std::iter::once(SCOPE.to_string()).collect(),
                oid: None,
                resource: None,
                dpop_jkt: None,
            },
        )
        .expect("subject token")
        .access_token()
        .to_string()
}

/// A new exchanging client and its `client_credentials` actor token.
fn actor_client(identity: &dyn IdentityEngine, realm: &RealmId) -> (ClientId, String) {
    const SECRET: &str = "agent-audit-secret!";
    let client_id = identity
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("agent-audit-actor-{}", uuid::Uuid::new_v4()),
                client_secret: Some(SECRET.to_string()),
                grant_types: vec![
                    "client_credentials".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![SCOPE.to_string()],
                access_token_authorization: AccessTokenAuthorization::Embedded,
                ..Default::default()
            },
        )
        .expect("register actor client")
        .client_id()
        .clone();
    let token = identity
        .client_credentials_token(
            realm,
            &ClientCredentialsRequest {
                client_id: client_id.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: Some(SCOPE.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("actor token")
        .access_token()
        .to_string();
    (client_id, token)
}

/// Exchanges `subject_token` as a new actor client and returns the new token.
fn exchange(identity: &dyn IdentityEngine, realm: &RealmId, subject_token: String) -> String {
    let (client_id, actor_token) = actor_client(identity, realm);
    identity
        .rfc8693_token_exchange(
            realm,
            &Rfc8693Request {
                client_id,
                subject_token,
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: Some(actor_token),
                actor_token_type: Some("urn:ietf:params:oauth:token-type:jwt".to_string()),
                requested_token_type: None,
                scope: Some(SCOPE.to_string()),
                resource: None,
                audience: None,
                dpop_jkt: None,
                dpop_jti: None,
            },
        )
        .expect("exchange")
        .access_token
}

fn events(h: &common::TestHarness, realm: &RealmId, action: AuditAction) -> Vec<AuditEvent> {
    h.audit()
        .query(&AuditQuery {
            action: Some(action),
            limit: Some(100),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("query audit")
}

/// Scenario "Regression — the delegation event lacks the chain": a token
/// exchanged from a token whose `act` chain already names actor A records
/// user U, actor A and the new actor, in that order.
#[tokio::test]
async fn the_delegation_event_records_the_full_chain() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let identity = h.identity();
    let realm = make_realm(&h);
    let user = make_user(identity, &realm);

    let first = exchange(identity, &realm, user_token(identity, &realm, &user));
    let second = exchange(identity, &realm, first);

    let claims = identity.validate_token(&realm, &second).expect("validate");
    let new_actor = claims.act.as_ref().expect("act");
    let actor_a = new_actor.act.as_ref().expect("nested act");
    let jti = claims.jti.clone().expect("jti");
    let expected = serde_json::json!([claims.sub, actor_a.sub, new_actor.sub]);
    assert_eq!(claims.sub, user.to_string(), "setup: the subject is user U");

    let delegations = events(&h, &realm, AuditAction::AgentDelegation);
    let event = delegations
        .iter()
        .find(|e| e.resource_id == jti)
        .unwrap_or_else(|| panic!("no AgentDelegation event for {jti}: {delegations:#?}"));
    let metadata = event.metadata.as_ref().expect("metadata");
    assert_eq!(
        metadata.get("delegation_chain"),
        Some(&expected),
        "the AgentDelegation event must record the whole chain; metadata: {metadata}"
    );
}

/// Scenario "Regression — an allowed tool invocation has no context".
#[tokio::test]
async fn an_allowed_tool_invocation_records_its_context() {
    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();
    let realm = make_realm(&h);
    h.rbac().seed_realm(&realm).expect("seed realm");
    let user = make_user(h.identity(), &realm);
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("agent-audit-role-{}", uuid::Uuid::new_v4()),
                permissions: vec![Permission::new("tool.list_files.invoke").expect("valid")],
                ..Default::default()
            },
        )
        .expect("create role");
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
        .expect("assign role");
    let session = h
        .identity()
        .create_session(&realm, &user, &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, &user, session.id())
        .expect("tokens")
        .access_token()
        .to_string();
    let jti = h
        .identity()
        .validate_token(&realm, &token)
        .expect("validate")
        .jti
        .clone()
        .expect("jti");

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Realm-ID", realm.as_uuid().to_string())
        .json(&serde_json::json!({"tool": "list_files", "action": "invoke"}))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200, "the invocation is allowed");

    let invocations = events(&h, &realm, AuditAction::AgentToolInvocation);
    assert_eq!(invocations.len(), 1, "one invocation: {invocations:#?}");
    let metadata = invocations[0]
        .metadata
        .as_ref()
        .expect("an allowed invocation records its context");
    assert_eq!(
        metadata.get("actor"),
        Some(&serde_json::json!(user.to_string()))
    );
    assert_eq!(metadata.get("tool"), Some(&serde_json::json!("list_files")));
    assert_eq!(metadata.get("token_jti"), Some(&serde_json::json!(jti)));

    let by_tool = h
        .audit()
        .query(&AuditQuery {
            tool: Some("list_files".to_string()),
            limit: Some(100),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("query by tool");
    assert!(
        by_tool
            .iter()
            .any(|e| e.action == AuditAction::AgentToolInvocation),
        "an audit query by tool finds the invocation"
    );
}
