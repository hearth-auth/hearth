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
