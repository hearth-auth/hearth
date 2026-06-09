//! Integration tests for Agent entity CRUD, lifecycle, and delegation chains.
//!
//! Covers HEA-1325 (AGENT_AUTH.md Phase A):
//! - A.1: AgentId newtype
//! - A.2: Agent entity CRUD + lifecycle (Active/Suspended/Revoked)
//! - A.7: Agent REST protocol endpoints
//!
//! TDD: tests written first; implementation in src/identity/engine/mod.rs.

mod common;

use hearth::core::{AgentId, RealmId, UserId};
use hearth::identity::{
    Agent, AgentOwner, AgentStatus, CreateAgentRequest, CreateRealmRequest, CreateUserRequest,
    IdentityEngine, IdentityError, ListAgentsQuery, UpdateAgentRequest,
};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("agent-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(identity: &dyn IdentityEngine, realm_id: &RealmId) -> UserId {
    let email = format!("agent-owner-{}@example.com", uuid::Uuid::new_v4());
    identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email,
                display_name: "Agent Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn create_agent(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    owner_id: &UserId,
    name: &str,
) -> Agent {
    identity
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: name.to_string(),
                description: Some(format!("Test agent: {name}")),
                owner: AgentOwner::User(owner_id.clone()),
                capabilities: vec!["urn:hearth:capability:email:send".to_string()],
                max_delegation_depth: 1,
            },
        )
        .expect("create agent")
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit: AgentId newtype
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn agent_id_display_has_agt_prefix() {
    let id = AgentId::generate();
    let s = format!("{id}");
    assert!(s.starts_with("agt_"), "expected agt_ prefix, got: {s}");
}

#[test]
fn agent_id_parse_round_trip() {
    let id = AgentId::generate();
    let s = format!("{id}");
    let parsed: AgentId = s.parse().expect("parse AgentId");
    assert_eq!(id, parsed);
}

#[test]
fn agent_id_serde_round_trip() {
    let id = AgentId::generate();
    let json = serde_json::to_string(&id).expect("serialize");
    let deserialized: AgentId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, deserialized);
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: A.2 — Agent CRUD
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_create_and_get() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "My Test Agent");

    assert!(format!("{}", agent.id()).starts_with("agt_"));
    assert_eq!(agent.display_name(), "My Test Agent");
    assert_eq!(agent.description(), "Test agent: My Test Agent");
    assert_eq!(agent.status(), AgentStatus::Active);
    assert_eq!(agent.max_delegation_depth(), 1);
    assert_eq!(
        agent.capabilities(),
        &["urn:hearth:capability:email:send".to_string()]
    );

    // Get by ID
    let fetched = identity
        .get_agent(&realm_id, agent.id())
        .expect("get agent")
        .expect("agent should exist");
    assert_eq!(fetched.id(), agent.id());
    assert_eq!(fetched.display_name(), "My Test Agent");
}

#[tokio::test]
async fn agent_update_metadata() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "Original Name");

    let updated = identity
        .update_agent(
            &realm_id,
            agent.id(),
            &UpdateAgentRequest {
                display_name: Some("Updated Name".to_string()),
                description: Some("Updated description".to_string()),
                capabilities: None,
                max_delegation_depth: Some(3),
            },
        )
        .expect("update agent");

    assert_eq!(updated.display_name(), "Updated Name");
    assert_eq!(updated.description(), "Updated description");
    assert_eq!(updated.max_delegation_depth(), 3);
    // Status unchanged
    assert_eq!(updated.status(), AgentStatus::Active);
}

#[tokio::test]
async fn agent_list_by_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let a1 = create_agent(identity, &realm_id, &user_id, "Agent Alpha");
    let a2 = create_agent(identity, &realm_id, &user_id, "Agent Beta");

    let page = identity
        .list_agents(&realm_id, &ListAgentsQuery::default(), None, 10)
        .expect("list agents");
    assert_eq!(page.items.len(), 2);
    let ids: Vec<_> = page.items.iter().map(|a| a.id().clone()).collect();
    assert!(ids.contains(a1.id()));
    assert!(ids.contains(a2.id()));
}

#[tokio::test]
async fn agent_list_filtered_by_owner() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_a = make_user(identity, &realm_id);
    let user_b = make_user(identity, &realm_id);

    let _agent_a = create_agent(identity, &realm_id, &user_a, "A's Agent");
    let _agent_b = create_agent(identity, &realm_id, &user_b, "B's Agent");

    let page = identity
        .list_agents(
            &realm_id,
            &ListAgentsQuery {
                owner_id: Some(AgentOwner::User(user_a.clone())),
                ..Default::default()
            },
            None,
            10,
        )
        .expect("list agents filtered");
    assert_eq!(page.items.len(), 1, "should only see user_a's agent");
    assert_eq!(page.items[0].display_name(), "A's Agent");
}

#[tokio::test]
async fn agent_delete() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "Deletable Agent");
    let agent_id = agent.id().clone();

    identity
        .delete_agent(&realm_id, &agent_id)
        .expect("delete agent");

    let result = identity
        .get_agent(&realm_id, &agent_id)
        .expect("get after delete");
    assert!(result.is_none(), "deleted agent should not be found");
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: A.2 — Lifecycle transitions
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_suspend_and_reactivate() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "Lifecycle Agent");
    assert_eq!(agent.status(), AgentStatus::Active);

    // Active → Suspended
    let suspended = identity
        .suspend_agent(&realm_id, agent.id())
        .expect("suspend agent");
    assert_eq!(suspended.status(), AgentStatus::Suspended);

    // Suspended → Active
    let reactivated = identity
        .reactivate_agent(&realm_id, agent.id())
        .expect("reactivate agent");
    assert_eq!(reactivated.status(), AgentStatus::Active);
}

#[tokio::test]
async fn agent_revoke_is_terminal() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "Terminal Agent");

    // Active → Revoked
    let revoked = identity
        .revoke_agent(&realm_id, agent.id())
        .expect("revoke agent");
    assert_eq!(revoked.status(), AgentStatus::Revoked);

    // Revoked → Active must fail
    let err = identity
        .reactivate_agent(&realm_id, agent.id())
        .expect_err("should not reactivate revoked agent");
    assert!(
        matches!(err, IdentityError::AgentRevoked),
        "expected AgentRevoked, got {err:?}"
    );

    // Revoked → Suspended must fail
    let err2 = identity
        .suspend_agent(&realm_id, agent.id())
        .expect_err("should not suspend revoked agent");
    assert!(
        matches!(err2, IdentityError::AgentRevoked),
        "expected AgentRevoked, got {err2:?}"
    );
}

#[tokio::test]
async fn agent_not_found_returns_none() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let result = identity
        .get_agent(&realm_id, &AgentId::generate())
        .expect("get nonexistent");
    assert!(result.is_none());
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: A.2 — Cross-realm isolation
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agents_are_realm_isolated() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_a = make_realm(identity);
    let realm_b = make_realm(identity);
    let user_a = make_user(identity, &realm_a);
    let user_b = make_user(identity, &realm_b);

    let agent_a = create_agent(identity, &realm_a, &user_a, "Realm A Agent");

    // Agent from realm A should not appear in realm B
    let page_b = identity
        .list_agents(&realm_b, &ListAgentsQuery::default(), None, 10)
        .expect("list realm_b");
    assert!(
        page_b.items.is_empty(),
        "no agents should appear in realm_b"
    );

    // Get agent from wrong realm should return None
    let result = identity
        .get_agent(&realm_b, agent_a.id())
        .expect("get cross-realm");
    assert!(result.is_none(), "cross-realm get should return None");

    let _ = user_b;
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: A.2 — Cascade delete validation
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_cascade_delete_on_realm_deletion() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent = create_agent(identity, &realm_id, &user_id, "Cascade Agent");
    let agent_id = agent.id().clone();

    // Delete the realm
    identity.delete_realm(&realm_id).expect("delete realm");

    // The engine should not panic; agent is gone with the realm
    // (We can't query it after realm deletion since realm is gone, but the
    // operation must not leave orphaned data. This test validates no panic.)
    let _ = agent_id;
}

// ──────────────────────────────────────────────────────────────────────────────
// Adversarial: max_delegation_depth bounds enforced
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_max_delegation_depth_must_be_1_to_10() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // depth=0 should be rejected
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Bad Depth Agent".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 0,
            },
        )
        .expect_err("depth=0 should be invalid");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for depth=0, got {err:?}"
    );

    // depth=11 should be rejected
    let err2 = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Bad Depth Agent".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 11,
            },
        )
        .expect_err("depth=11 should be invalid");
    assert!(
        matches!(err2, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for depth=11, got {err2:?}"
    );
}

#[tokio::test]
async fn agent_display_name_length_validated() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // Empty name
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: String::new(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
        )
        .expect_err("empty name should be invalid");
    assert!(matches!(err, IdentityError::InvalidInput { .. }));

    // Name too long (>256)
    let long_name = "x".repeat(257);
    let err2 = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: long_name,
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
        )
        .expect_err("name >256 chars should be invalid");
    assert!(matches!(err2, IdentityError::InvalidInput { .. }));
}
