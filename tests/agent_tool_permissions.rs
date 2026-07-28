//! TDD tests for Phase C.1/C.2/C.3: tool permission grammar, deny-wins
//! evaluation, and scope intersection at delegation.
//!
//! These tests are red until the `tool_permissions` module is implemented.

mod common;

use hearth::identity::tool_permissions::{
    evaluate_tool_access, parse_tool_permission, ToolAccessDecision, ToolGroupMap,
    ToolPermissionKind,
};

// ─── C.1: Permission grammar parsing ────────────────────────────────────────

#[test]
fn parse_invoke_permission() {
    let (tool, kind) =
        parse_tool_permission("tool.send_email.invoke").expect("should parse invoke");
    assert_eq!(tool, "send_email");
    assert_eq!(kind, ToolPermissionKind::Invoke);
}

#[test]
fn parse_invoke_with_approval_permission() {
    let (tool, kind) = parse_tool_permission("tool.delete_email.invoke_with_approval")
        .expect("should parse invoke_with_approval");
    assert_eq!(tool, "delete_email");
    assert_eq!(kind, ToolPermissionKind::InvokeWithApproval);
}

#[test]
fn parse_deny_permission() {
    let (tool, kind) = parse_tool_permission("tool.dangerous_op.deny").expect("should parse deny");
    assert_eq!(tool, "dangerous_op");
    assert_eq!(kind, ToolPermissionKind::Deny);
}

#[test]
fn parse_toolgroup_invoke_permission() {
    let result = parse_tool_permission("toolgroup.email_suite.invoke");
    // toolgroup permissions are handled by a separate parse function
    // tool.* parse returns None for non-tool.* strings
    assert!(
        result.is_none(),
        "toolgroup prefix is not a tool.* permission"
    );
}

#[test]
fn parse_unrelated_permission_returns_none() {
    assert!(parse_tool_permission("openid").is_none());
    assert!(parse_tool_permission("email.read").is_none());
    assert!(parse_tool_permission("tool").is_none());
    assert!(parse_tool_permission("tool.").is_none());
    assert!(parse_tool_permission("tool.foo").is_none());
    assert!(parse_tool_permission("tool.foo.unknown_action").is_none());
    assert!(parse_tool_permission("").is_none());
}

// ─── C.2: Deny-wins evaluation ──────────────────────────────────────────────

#[test]
fn invoke_permission_yields_allow() {
    let perms = vec!["tool.send_email.invoke".to_string()];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "send_email", &groups);
    assert_eq!(decision, ToolAccessDecision::Allow);
}

#[test]
fn invoke_with_approval_yields_require_approval() {
    let perms = vec!["tool.delete_email.invoke_with_approval".to_string()];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "delete_email", &groups);
    assert_eq!(decision, ToolAccessDecision::RequireApproval);
}

#[test]
fn deny_permission_yields_deny() {
    let perms = vec!["tool.dangerous_op.deny".to_string()];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "dangerous_op", &groups);
    assert_eq!(decision, ToolAccessDecision::Deny);
}

#[test]
fn no_permission_for_tool_yields_deny() {
    let perms = vec!["tool.other_tool.invoke".to_string()];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "unrelated_tool", &groups);
    assert_eq!(decision, ToolAccessDecision::Deny);
}

#[test]
fn deny_wins_over_invoke() {
    // The core deny-wins invariant: deny always beats invoke
    let perms = vec![
        "tool.send_email.invoke".to_string(),
        "tool.send_email.deny".to_string(),
    ];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "send_email", &groups);
    assert_eq!(
        decision,
        ToolAccessDecision::Deny,
        "deny must win over invoke"
    );
}

#[test]
fn deny_wins_over_invoke_with_approval() {
    let perms = vec![
        "tool.delete_email.invoke_with_approval".to_string(),
        "tool.delete_email.deny".to_string(),
    ];
    let groups = ToolGroupMap::default();
    let decision = evaluate_tool_access(&perms, "delete_email", &groups);
    assert_eq!(
        decision,
        ToolAccessDecision::Deny,
        "deny must win over invoke_with_approval"
    );
}

#[test]
fn toolgroup_invoke_grants_group_tools_allow() {
    let mut groups = ToolGroupMap::default();
    groups.insert(
        "email_suite".to_string(),
        vec!["send_email".to_string(), "search_emails".to_string()],
    );
    let perms = vec!["toolgroup.email_suite.invoke".to_string()];
    let decision = evaluate_tool_access(&perms, "send_email", &groups);
    assert_eq!(decision, ToolAccessDecision::Allow);
}

#[test]
fn toolgroup_invoke_does_not_grant_tools_not_in_group() {
    let mut groups = ToolGroupMap::default();
    groups.insert("email_suite".to_string(), vec!["send_email".to_string()]);
    let perms = vec!["toolgroup.email_suite.invoke".to_string()];
    let decision = evaluate_tool_access(&perms, "delete_file", &groups);
    // Tool not in the group, and no direct permission: Deny
    assert_eq!(decision, ToolAccessDecision::Deny);
}

#[test]
fn toolgroup_deny_wins_even_when_direct_invoke_present() {
    let mut groups = ToolGroupMap::default();
    groups.insert("email_suite".to_string(), vec!["send_email".to_string()]);
    let perms = vec![
        "tool.send_email.invoke".to_string(),
        "toolgroup.email_suite.deny".to_string(),
    ];
    let decision = evaluate_tool_access(&perms, "send_email", &groups);
    assert_eq!(decision, ToolAccessDecision::Deny, "group deny must win");
}

// ─── C.2 property: deny always wins ─────────────────────────────────────────
//
// The property test lives in proptest form. We use a deterministic oracle here
// to satisfy the TDD red phase; the proptest crate version is in benches.

#[test]
fn deny_always_wins_property_deterministic() {
    let tools = ["send_email", "delete_file", "search_db", "invoke_payment"];
    let actions = ["invoke", "invoke_with_approval", "deny"];

    for tool in tools {
        for action in actions {
            // Build a permissions set that always includes deny, plus the action
            let mut perms = vec![format!("tool.{tool}.deny"), format!("tool.{tool}.{action}")];
            // Also add spurious other-tool permissions
            perms.push("tool.other.invoke".to_string());

            let decision = evaluate_tool_access(&perms, tool, &ToolGroupMap::default());
            assert_eq!(
                decision,
                ToolAccessDecision::Deny,
                "deny must always win for tool={tool} action={action}"
            );
        }
    }
}

// ─── C.3: Scope intersection at delegation ───────────────────────────────────

#[test]
fn scope_intersection_result_is_subset_of_inputs() {
    use hearth::identity::mcp::intersect_three;

    let subject = "mcp:tools:invoke email openid profile";
    let actor = "mcp:tools:invoke";
    let requested = "mcp:tools:invoke email";

    let result = intersect_three(subject, actor, Some(requested));

    // The intersection of all three inputs contains exactly `mcp:tools:invoke`
    // (the only scope common to subject, actor, AND requested). Assert it is
    // non-empty and carries that scope — otherwise every subset check below
    // would pass vacuously against an empty result.
    let result_scopes: Vec<&str> = result.split_whitespace().collect();
    assert!(
        !result_scopes.is_empty(),
        "intersection must be non-empty; got empty result"
    );
    assert!(
        result_scopes.contains(&"mcp:tools:invoke"),
        "intersection must retain the common `mcp:tools:invoke` scope; got: {result:?}"
    );

    // Result must be a subset of subject
    for scope in result.split_whitespace() {
        assert!(
            subject.split_whitespace().any(|s| s == scope),
            "scope `{scope}` in result but not in subject"
        );
    }
    // Result must be a subset of actor
    for scope in result.split_whitespace() {
        assert!(
            actor.split_whitespace().any(|s| s == scope),
            "scope `{scope}` in result but not in actor"
        );
    }
}

#[test]
fn scope_intersection_empty_subject_yields_empty() {
    use hearth::identity::mcp::intersect_three;
    let result = intersect_three("", "mcp:tools:invoke", Some("mcp:tools:invoke"));
    assert!(
        result.is_empty(),
        "empty subject must produce empty intersection"
    );
}

#[test]
fn scope_intersection_empty_actor_yields_empty() {
    use hearth::identity::mcp::intersect_three;
    let result = intersect_three("mcp:tools:invoke email", "", Some("mcp:tools:invoke"));
    assert!(
        result.is_empty(),
        "empty actor must produce empty intersection"
    );
}

// ─── C. Adversarial: server-side enforcement (HEA-1428) ──────────────────────

// ─── HEA-1723 security regressions: H2, M4, M5, M6 ────────────────────────

/// H2 regression: a `toolgroup.{g}.deny` permission on an otherwise-allowed tool
/// must produce `Deny` even when the tool-group map is populated from realm config.
///
/// Before HEA-1723 the handler always passed an empty `ToolGroupMap`, so group-level
/// denies silently fell through to `Allow`. This test calls the HTTP endpoint to
/// confirm end-to-end group-deny enforcement.
#[tokio::test]
async fn h2_group_deny_wins_over_direct_invoke() {
    use hearth::identity::{CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext};
    use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();

    // Create realm with tool_groups: dangerous_suite → [dangerous_op]
    let mut realm_config = RealmConfig::default();
    realm_config.tool_groups.insert(
        "dangerous_suite".to_string(),
        vec!["dangerous_op".to_string()],
    );

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("h2-group-deny-{}", uuid::Uuid::new_v4()),
            config: Some(realm_config),
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    // User holds direct invoke on the tool BUT the group deny applies.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("h2-user-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "H2 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let perm_invoke = Permission::new("tool.dangerous_op.invoke").expect("valid permission");
    let perm_group_deny =
        Permission::new("toolgroup.dangerous_suite.deny").expect("valid permission");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("h2-role-{}", uuid::Uuid::new_v4()),
                permissions: vec![perm_invoke, perm_group_deny],
                ..Default::default()
            },
        )
        .expect("create role");
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
        .expect("assign role");

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");
    let bearer_token = tokens.access_token().to_string();
    let realm_id_str = realm.as_uuid().to_string();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bearer_token}"))
        .header("X-Realm-ID", &realm_id_str)
        .json(&serde_json::json!({"tool": "dangerous_op", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "group deny must override direct invoke; got non-403"
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    let error = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("HEARTH_TOOL_ACCESS_DENIED") || error.contains("tool_access_denied"),
        "error must be tool_access_denied, got: {error}"
    );
}

/// M4 regression: a DPoP-bound access token (`cnf.jkt` present) presented as
/// plain bearer to `POST /v1/tools/invoke` must be rejected — the stolen-token
/// replay must fail even without the DPoP proof.
#[tokio::test]
async fn m4_bound_token_without_dpop_proof_rejected() {
    use hearth::identity::{
        ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest, RegisterClientRequest,
    };

    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m4-dpop-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    // Register a confidential client that supports client_credentials.
    let client_secret = format!("m4-secret-{}", uuid::Uuid::new_v4());
    let oauth_client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "M4 Test Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(client_secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: ClientTrustLevel::ThirdParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client");

    // Issue a DPoP-bound access token by passing a synthetic JKT thumbprint.
    // The `cnf.jkt` claim is embedded in the token by the engine.
    let fake_jkt = "m4-test-thumbprint-aAbBcCdDeEfF".to_string();
    let cc_resp = h
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: oauth_client.client_id().clone(),
                client_secret: Some(client_secret),
                scope: Some("openid".to_string()),
                dpop_jkt: Some(fake_jkt),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("client_credentials_token");
    let bound_token = cc_resp.access_token().to_string();
    let realm_id_str = realm.as_uuid().to_string();

    // Present the bound token WITHOUT a DPoP proof — must be rejected.
    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bound_token}"))
        .header("X-Realm-ID", &realm_id_str)
        .json(&serde_json::json!({"tool": "read_file", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "bound token without DPoP proof must be rejected with 401; got {}",
        resp.status()
    );
}

// Setup for M5 confused-deputy test: creates realm, agent B (the victim), and user A (the intruder).
struct M5Entities {
    realm: hearth::core::RealmId,
    agent_b_id: hearth::core::AgentId,
    user_a_id: hearth::core::UserId,
}

fn setup_m5_entities(h: &common::TestHarness) -> M5Entities {
    use hearth::identity::{AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest};
    use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m5-caller-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    let owner_b = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("m5-owner-b-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Owner B".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner b");
    let agent_b = h
        .identity()
        .create_agent(
            &realm,
            &CreateAgentRequest {
                display_name: "Agent B".to_string(),
                description: None,
                owner: AgentOwner::User(owner_b.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent b");

    let user_a = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("m5-user-a-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "User A".to_string(),
                ..Default::default()
            },
        )
        .expect("create user a");

    let perm = Permission::new("tool.secret_tool.invoke_with_approval").expect("valid");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("m5-role-{}", uuid::Uuid::new_v4()),
                permissions: vec![perm],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user_a.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role to user_a");

    M5Entities {
        realm,
        agent_b_id: agent_b.id().clone(),
        user_a_id: user_a.id().clone(),
    }
}

/// M5 regression: agent A presenting a capability token minted for agent B must
/// be rejected — the confused-deputy attack must fail even with a valid token.
#[tokio::test]
async fn m5_capability_token_caller_mismatch_rejected() {
    use hearth::identity::{ApprovalRequestStatus, CreateApprovalRequestInput, SessionContext};

    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();
    let M5Entities {
        realm,
        agent_b_id,
        user_a_id,
    } = setup_m5_entities(&h);

    // Mint a capability token for agent B (sub = agent_b UUID).
    let approval = h
        .identity()
        .create_approval_request(
            &realm,
            &CreateApprovalRequestInput {
                agent_id: agent_b_id,
                tool: "secret_tool".to_string(),
                action: "invoke".to_string(),
                context: serde_json::json!({}),
                delegation_chain: vec![],
                expires_in_secs: None,
            },
        )
        .expect("create approval");
    let approval_resp = h
        .identity()
        .approve_approval_request(&realm, &approval.request_id, None)
        .expect("approve");
    assert_eq!(approval_resp.status, ApprovalRequestStatus::Approved);
    let capability_token = approval_resp
        .capability_token
        .expect("capability token")
        .token;

    // Issue a bearer token for user A (sub = user_a UUID, different from agent_b UUID).
    let session_a = h
        .identity()
        .create_session(&realm, &user_a_id, &SessionContext::default())
        .expect("session a");
    let tokens_a = h
        .identity()
        .issue_tokens(&realm, &user_a_id, session_a.id())
        .expect("tokens a");
    let bearer_a = tokens_a.access_token().to_string();
    let realm_id_str = realm.as_uuid().to_string();

    // User A presents agent B's capability token — M5 must reject (sub mismatch).
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bearer_a}"))
        .header("X-Realm-ID", &realm_id_str)
        .header("X-Capability-Token", &capability_token)
        .json(&serde_json::json!({"tool": "secret_tool", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "capability token minted for agent B must not be usable by user A; got {}",
        resp.status()
    );
}

/// M6 regression: an `Allow`-path tool invocation must produce an `AgentToolInvocation`
/// audit record. Before HEA-1723, only the approval (capability-token) path emitted
/// audit events; plain `Allow` returned 200 silently.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn m6_allow_path_emits_audit_record() {
    use hearth::audit::{AuditAction, AuditQuery};
    use hearth::identity::{CreateRealmRequest, CreateUserRequest, SessionContext};
    use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m6-audit-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("m6-user-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "M6 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let perm = Permission::new("tool.list_files.invoke").expect("valid");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("m6-role-{}", uuid::Uuid::new_v4()),
                permissions: vec![perm],
                ..Default::default()
            },
        )
        .expect("create role");
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
        .expect("assign role");

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");
    let bearer_token = tokens.access_token().to_string();
    let realm_id_str = realm.as_uuid().to_string();

    // Invoke the tool — should be allowed.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bearer_token}"))
        .header("X-Realm-ID", &realm_id_str)
        .json(&serde_json::json!({"tool": "list_files", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200, "Allow path must return 200");

    // Verify an AgentToolInvocation audit record was emitted.
    let events = h
        .audit()
        .query(&AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::AgentToolInvocation),
            limit: Some(100),
            start_time: None,
            end_time: None,
            actor: None,
            agent_id: None,
            tool: None,
        })
        .expect("query audit");
    let tool_events: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::AgentToolInvocation)
        .collect();
    assert!(
        !tool_events.is_empty(),
        "Allow-path invocation must produce an AgentToolInvocation audit record"
    );
    // The resource_id should encode the tool and action.
    assert!(
        tool_events
            .iter()
            .any(|e| e.resource_id.contains("list_files")),
        "audit record must reference the invoked tool; got: {:?}",
        tool_events
            .iter()
            .map(|e| &e.resource_id)
            .collect::<Vec<_>>()
    );
}

/// An agent with `tool.delete_file.invoke_with_approval` permission that calls
/// `POST /v1/tools/invoke` WITHOUT a capability token must receive 403.
///
/// This is the regression test for the "zero production callers" bypass:
/// the server must evaluate access and demand a capability token — it cannot
/// rely on the MCP client to self-enforce.
#[tokio::test]
async fn agent_skips_approval_flow_direct_invoke_returns_403() {
    use hearth::identity::{CreateRealmRequest, CreateUserRequest, SessionContext};
    use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};

    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();

    // 1. Set up realm + RBAC.
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("tool-adv-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    // 2. Create a user and a role with invoke_with_approval permission.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("agent-adversarial-{}@test.example", uuid::Uuid::new_v4()),
                display_name: "Adversarial Agent".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let perm = Permission::new("tool.delete_file.invoke_with_approval").expect("valid permission");
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: format!("tool-perm-{}", uuid::Uuid::new_v4()),
                permissions: vec![perm],
                ..Default::default()
            },
        )
        .expect("create role");

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
        .expect("assign role");

    // 3. Issue a bearer token for the user.
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let tokens = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");
    let bearer_token = tokens.access_token().to_string();
    let realm_id_str = realm.as_uuid().to_string();

    // 4. Call POST /v1/tools/invoke WITHOUT a capability token — must return 403.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bearer_token}"))
        .header("X-Realm-ID", &realm_id_str)
        .json(&serde_json::json!({"tool": "delete_file", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "agent without capability token must receive 403 — capability bypass not allowed"
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    // Error code must indicate approval is required, not just a generic deny.
    let error = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("HEARTH_TOOL_APPROVAL_REQUIRED") || error.contains("tool_approval_required"),
        "error must signal approval required, got: {error}"
    );
}
