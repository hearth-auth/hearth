//! Integration tests for Phase C.4: approval request lifecycle.
//!
//! Tests cover: create → pending, approve → Approved + capability token,
//! deny → Denied, CAS (can only transition from Pending).

mod common;

use std::sync::Arc;

use common::TestHarness;
use hearth::core::AgentId;
use hearth::identity::{
    AgentOwner, ApprovalRequestStatus, CreateAgentRequest, CreateApprovalRequestInput,
    CreateRealmRequest, CreateUserRequest, IdentityError,
};

fn make_realm(h: &TestHarness) -> hearth::core::RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("appr-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_agent(h: &TestHarness, realm_id: &hearth::core::RealmId) -> AgentId {
    let owner = h
        .identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("agent-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Agent Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner user");

    h.identity()
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "test-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

// ─── C.4.1: Create approval request ──────────────────────────────────────────

#[tokio::test]
async fn create_approval_request_returns_pending() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({"reason": "user requested file deletion"}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };

    let result = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create_approval_request should succeed");

    assert_eq!(result.status, ApprovalRequestStatus::Pending);
    assert_eq!(result.tool, "delete_file");
    assert_eq!(result.action, "invoke");
    assert!(!result.request_id.is_empty());
}

#[tokio::test]
async fn get_approval_request_returns_created_request() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: Some(3600),
    };

    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    let fetched = h
        .identity()
        .get_approval_request(&realm_id, &created.request_id)
        .expect("get");

    assert_eq!(fetched.request_id, created.request_id);
    assert_eq!(fetched.status, ApprovalRequestStatus::Pending);
}

// ─── C.4.2: Approve → capability token ───────────────────────────────────────

#[tokio::test]
async fn approve_request_issues_capability_token() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    let response = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, None)
        .expect("approve");

    assert_eq!(response.status, ApprovalRequestStatus::Approved);
    let cap = response
        .capability_token
        .expect("capability token should be present");
    assert!(!cap.token.is_empty());
    // Default TTL is 5 minutes (300 seconds)
    assert!(cap.expires_in_secs <= 300);
    assert!(cap.expires_in_secs > 0);
}

#[tokio::test]
async fn capability_token_ttl_capped_at_1h() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "dangerous_op".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    let response = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, Some(7200))
        .expect("approve with long TTL");

    let cap = response.capability_token.expect("capability token");
    assert!(
        cap.expires_in_secs <= 3600,
        "capability TTL must be capped at 1h (3600s), got {}",
        cap.expires_in_secs
    );
}

// ─── C.4.3: Deny ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn deny_request_transitions_to_denied() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    let response = h
        .identity()
        .deny_approval_request(
            &realm_id,
            &created.request_id,
            Some("policy violation".to_string()),
        )
        .expect("deny");

    assert_eq!(response.status, ApprovalRequestStatus::Denied);
    assert!(response.capability_token.is_none());
}

// ─── C.4.4: CAS — can only transition from Pending ────────────────────────────

#[tokio::test]
async fn cannot_approve_already_approved_request() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    h.identity()
        .approve_approval_request(&realm_id, &created.request_id, None)
        .expect("first approve");

    let result = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, None);
    assert!(
        matches!(result, Err(IdentityError::ApprovalRequestNotPending { .. })),
        "re-approving must return ApprovalRequestNotPending"
    );
}

#[tokio::test]
async fn cannot_deny_already_denied_request() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    h.identity()
        .deny_approval_request(&realm_id, &created.request_id, None)
        .expect("first deny");

    let result = h
        .identity()
        .deny_approval_request(&realm_id, &created.request_id, None);
    assert!(
        matches!(result, Err(IdentityError::ApprovalRequestNotPending { .. })),
        "re-denying must return ApprovalRequestNotPending"
    );
}

#[tokio::test]
async fn cannot_approve_denied_request() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    h.identity()
        .deny_approval_request(&realm_id, &created.request_id, None)
        .expect("deny");

    let result = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, None);
    assert!(
        matches!(result, Err(IdentityError::ApprovalRequestNotPending { .. })),
        "approving a denied request must return ApprovalRequestNotPending"
    );
}

// ─── C.4.5: Not found ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_nonexistent_request_returns_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);

    let result = h
        .identity()
        .get_approval_request(&realm_id, "nonexistent-request-id");
    assert!(
        matches!(result, Err(IdentityError::ApprovalRequestNotFound)),
        "non-existent approval request must return ApprovalRequestNotFound"
    );
}

// ─── C.4.6: List approval requests ───────────────────────────────────────────

#[tokio::test]
async fn list_approval_requests_returns_pending() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    for tool in ["send_email", "delete_file", "search_db"] {
        let req = CreateApprovalRequestInput {
            agent_id: agent_id.clone(),
            tool: tool.to_string(),
            action: "invoke".to_string(),
            context: serde_json::json!({}),
            delegation_chain: vec![],
            expires_in_secs: None,
        };
        h.identity()
            .create_approval_request(&realm_id, &req)
            .expect("create");
    }

    let list = h
        .identity()
        .list_approval_requests(&realm_id, Some(ApprovalRequestStatus::Pending), None, 10)
        .expect("list");

    assert_eq!(list.items.len(), 3);
    assert!(list
        .items
        .iter()
        .all(|r| r.status == ApprovalRequestStatus::Pending));
}

// ─── C.4.7: validate_capability_token — server-side enforcement ──────────────

/// A tool with `invoke_with_approval` permission must be rejected when the
/// capability token is missing or invalid. Regression test for the
/// zero-callers gap in evaluate_tool_access (HEA-1428).
#[tokio::test]
async fn missing_capability_token_returns_tool_approval_required() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    // Create and approve a request to get a real capability token.
    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    h.identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");

    // Call validate_capability_token with a garbage/missing token — must fail
    // with ToolApprovalRequired (not a panic or Ok).
    let result = h.identity().validate_capability_token(
        &realm_id,
        "not-a-real-token",
        "delete_file",
        "invoke",
    );
    assert!(
        matches!(
            result,
            Err(IdentityError::ToolApprovalRequired { ref tool }) if tool == "delete_file"
        ),
        "missing/invalid token must return ToolApprovalRequired, got: {result:?}"
    );
}

/// A valid capability token allows exactly one invocation; the second attempt
/// with the same token must be rejected (single-use JTI enforcement).
#[tokio::test]
async fn capability_token_single_use_enforcement() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    // Obtain a real capability token through the approval flow.
    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    let response = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, None)
        .expect("approve");
    let cap = response.capability_token.expect("capability token present");

    // First use: must succeed.
    let first =
        h.identity()
            .validate_capability_token(&realm_id, &cap.token, "send_email", "invoke");
    assert!(
        first.is_ok(),
        "first use of valid capability token must succeed, got: {first:?}"
    );

    // Second use of the same token: must be rejected (JTI blocklist).
    let second =
        h.identity()
            .validate_capability_token(&realm_id, &cap.token, "send_email", "invoke");
    assert!(
        matches!(
            second,
            Err(IdentityError::ToolApprovalRequired { ref tool }) if tool == "send_email"
        ),
        "replayed capability token must return ToolApprovalRequired, got: {second:?}"
    );
}

// ─── C.4.8: Concurrent approve — exactly one token ────────────────────────────

/// Ten concurrent `approve` calls on the same request must result in exactly
/// one success and nine `ApprovalRequestNotPending` errors, with at most one
/// capability token ever issued.
///
/// Regression test for the TOCTOU double-issuance race (HEA-1430).
#[tokio::test]
async fn concurrent_approve_issues_exactly_one_token() {
    let h = Arc::new(TestHarness::embedded().await.expect("harness init"));
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "concurrent_op".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    let request_id = created.request_id.clone();

    // Spawn 10 concurrent approve tasks on the same request_id.
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let identity = h.identity_arc();
            let realm_id = realm_id.clone();
            let request_id = request_id.clone();
            tokio::task::spawn_blocking(move || {
                identity.approve_approval_request(&realm_id, &request_id, None)
            })
        })
        .collect();

    let mut successes = 0u32;
    let mut not_pending = 0u32;
    for handle in handles {
        match handle.await.expect("task did not panic") {
            Ok(_) => successes += 1,
            Err(IdentityError::ApprovalRequestNotPending { .. }) => not_pending += 1,
            Err(e) => panic!("unexpected error from concurrent approve: {e:?}"),
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent approve must succeed");
    assert_eq!(
        not_pending, 9,
        "the remaining 9 must return ApprovalRequestNotPending"
    );
}

/// A capability token scoped to one tool/action must NOT authorize a different
/// tool invocation.
#[tokio::test]
async fn capability_token_tool_mismatch_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let req = CreateApprovalRequestInput {
        agent_id,
        tool: "send_email".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({}),
        delegation_chain: vec![],
        expires_in_secs: None,
    };
    let created = h
        .identity()
        .create_approval_request(&realm_id, &req)
        .expect("create");
    let response = h
        .identity()
        .approve_approval_request(&realm_id, &created.request_id, None)
        .expect("approve");
    let cap = response.capability_token.expect("capability token");

    // Use the send_email token to try to invoke delete_file — must be rejected.
    let result =
        h.identity()
            .validate_capability_token(&realm_id, &cap.token, "delete_file", "invoke");
    assert!(
        matches!(result, Err(IdentityError::ToolApprovalRequired { .. })),
        "token for send_email must not authorize delete_file: {result:?}"
    );
}
