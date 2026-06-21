//! Integration tests for Phase C.4: approval request lifecycle.
//!
//! Tests cover: create → pending, approve → Approved + capability token,
//! deny → Denied, CAS (can only transition from Pending).

mod common;

use common::TestHarness;
use hearth::core::AgentId;
use hearth::identity::{
    AgentOwner, ApprovalRequestStatus, CreateAgentRequest, CreateApprovalRequestInput,
    CreateRealmRequest, CreateUserRequest,
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
    assert!(result.is_err(), "re-approving must fail");
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
    assert!(result.is_err(), "re-denying must fail");
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
    assert!(result.is_err(), "approving a denied request must fail");
}

// ─── C.4.5: Not found ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_nonexistent_request_returns_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);

    let result = h
        .identity()
        .get_approval_request(&realm_id, "nonexistent-request-id");
    assert!(result.is_err());
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
