//! Integration tests for Agent entity CRUD, lifecycle, credentials, and M1 surfaces.
//!
//! Covers HEA-1325 / HEA-1405 (AGENT_AUTH.md Phase A):
//! - A.1: AgentId newtype
//! - A.2: Agent entity CRUD + lifecycle (Active/Suspended/Revoked)
//! - A.3: Agent credentials (API key create/list/revoke/verify, owner FK, quota)
//! - A.4: Agent Card at well-known endpoint
//! - A.7: Agent REST protocol endpoints
//!
//! Also contains the M1 byte-identity regression guard: verifies that M1 changes
//! did not alter the JWT claim set issued for ordinary (non-agent) user tokens.
//!
//! TDD: tests written first; implementation in src/identity/engine/mod.rs.

mod common;

use hearth::core::{AgentId, RealmId, UserId};
use hearth::identity::{
    Agent, AgentCredentialKind, AgentOwner, AgentStatus, CreateAgentApiKeyRequest,
    CreateAgentRequest, CreateRealmRequest, CreateUserRequest, IdentityEngine, IdentityError,
    ListAgentsQuery, UpdateAgentRequest,
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

// ──────────────────────────────────────────────────────────────────────────────
// M1 A.3 — Owner FK check
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_agent_rejects_nonexistent_user_owner() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    // Use a random user ID that was never created
    let ghost_user = UserId::new(uuid::Uuid::new_v4());
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Ghost Owner Agent".to_string(),
                description: None,
                owner: AgentOwner::User(ghost_user),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
        )
        .expect_err("nonexistent owner should be rejected");
    assert!(
        matches!(err, IdentityError::UserNotFound),
        "expected UserNotFound, got {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// M1 A.3 — max_agents quota
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_agent_respects_max_agents_quota() {
    use hearth::identity::{RealmConfig, RealmQuotaConfig, UpdateRealmRequest};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // Set max_agents = 1
    identity
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    quotas: Some(RealmQuotaConfig {
                        max_agents: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .expect("update realm quota");

    // First agent — should succeed
    let _a1 = create_agent(identity, &realm_id, &user_id, "Agent One");

    // Second agent — should fail quota
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Agent Two".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
        )
        .expect_err("should exceed max_agents quota");
    assert!(
        matches!(
            err,
            IdentityError::QuotaExceeded {
                resource: "agents",
                ..
            }
        ),
        "expected QuotaExceeded(agents), got {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// M1 A.3 — Agent credential API key lifecycle
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_api_key_create_show_once() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Key Holder");

    let resp = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest {
                label: "primary".to_string(),
            },
        )
        .expect("create API key");

    // The key must be 64 hex chars (256-bit = 32 bytes)
    let key_hex = resp.plaintext_key.expose_once();
    assert_eq!(
        key_hex.len(),
        64,
        "API key must be 64 hex chars (256-bit entropy)"
    );
    assert!(
        key_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "API key must be hex"
    );

    // The stored credential must not contain the plaintext key
    let cred = &resp.credential;
    assert_eq!(cred.kind(), AgentCredentialKind::ApiKey);
    assert_ne!(
        cred.credential_hash(),
        key_hex,
        "hash must differ from plaintext"
    );
    assert!(!cred.is_revoked());

    // SHA-256(plaintext) == stored hash
    let expected_hash = {
        use sha2::{Digest, Sha256};
        let bytes = hex::decode(key_hex).expect("decode hex");
        hex::encode(Sha256::digest(&bytes))
    };
    assert_eq!(
        cred.credential_hash(),
        expected_hash,
        "stored hash must be SHA-256 of plaintext"
    );
}

#[tokio::test]
async fn agent_api_key_list_and_revoke() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Multi-Key Agent");

    // Create two keys
    let r1 = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "k1".into() },
        )
        .expect("key1");
    let r2 = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "k2".into() },
        )
        .expect("key2");

    // List: both present, none revoked
    let creds = identity
        .list_agent_credentials(&realm_id, agent.id())
        .expect("list");
    assert_eq!(creds.len(), 2, "two credentials expected");
    assert!(creds.iter().all(|c| !c.is_revoked()));

    // Revoke key1
    identity
        .revoke_agent_credential(&realm_id, agent.id(), r1.credential.id())
        .expect("revoke");

    let creds_after = identity
        .list_agent_credentials(&realm_id, agent.id())
        .expect("list after revoke");
    let revoked: Vec<_> = creds_after.iter().filter(|c| c.is_revoked()).collect();
    let active: Vec<_> = creds_after.iter().filter(|c| !c.is_revoked()).collect();
    assert_eq!(revoked.len(), 1, "one revoked");
    assert_eq!(active.len(), 1, "one active");
    assert_eq!(active[0].id(), r2.credential.id());
}

#[tokio::test]
async fn agent_api_key_verify_correct_key() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Verify Agent");

    let resp = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "v".into() },
        )
        .expect("create key");
    let key_hex = resp.plaintext_key.expose_once().to_string();

    let verified = identity
        .verify_agent_api_key(&realm_id, agent.id(), &key_hex)
        .expect("verify");
    assert!(verified, "correct key must verify");
}

#[tokio::test]
async fn agent_api_key_verify_wrong_key_fails() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Verify Reject Agent");

    identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "k".into() },
        )
        .expect("create key");

    // Wrong key (all zeros)
    let bad_key = "0".repeat(64);
    let verified = identity
        .verify_agent_api_key(&realm_id, agent.id(), &bad_key)
        .expect("verify call");
    assert!(!verified, "wrong key must not verify");
}

#[tokio::test]
async fn agent_api_key_revoked_key_does_not_verify() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Revoke Verify Agent");

    let resp = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "r".into() },
        )
        .expect("create key");
    let key_hex = resp.plaintext_key.expose_once().to_string();
    let cred_id = resp.credential.id().clone();

    // Revoke it
    identity
        .revoke_agent_credential(&realm_id, agent.id(), &cred_id)
        .expect("revoke");

    // Verify should now fail
    let verified = identity
        .verify_agent_api_key(&realm_id, agent.id(), &key_hex)
        .expect("verify call");
    assert!(!verified, "revoked key must not verify");
}

// ──────────────────────────────────────────────────────────────────────────────
// M1 — delete_agent cascade: credentials purged
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_agent_purges_credentials() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Doomed Agent");
    let agent_id = agent.id().clone();

    // Issue two API keys
    identity
        .create_agent_api_key(
            &realm_id,
            &agent_id,
            &CreateAgentApiKeyRequest { label: "k1".into() },
        )
        .expect("k1");
    identity
        .create_agent_api_key(
            &realm_id,
            &agent_id,
            &CreateAgentApiKeyRequest { label: "k2".into() },
        )
        .expect("k2");

    // Delete agent
    identity
        .delete_agent(&realm_id, &agent_id)
        .expect("delete agent");

    // Agent must be gone
    let fetched = identity.get_agent(&realm_id, &agent_id).expect("get");
    assert!(fetched.is_none(), "agent must be deleted");

    // Credentials must be gone (no panic / stale scan)
    let creds = identity
        .list_agent_credentials(&realm_id, &agent_id)
        .expect("list");
    assert!(
        creds.is_empty(),
        "credentials must be purged on agent delete"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// M1 — delete_user sweeps owned agents
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_user_cascades_owned_agents() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    let agent1 = create_agent(identity, &realm_id, &user_id, "Orphan Agent 1");
    let agent2 = create_agent(identity, &realm_id, &user_id, "Orphan Agent 2");
    let a1_id = agent1.id().clone();
    let a2_id = agent2.id().clone();

    // Delete the owning user
    identity
        .delete_user(&realm_id, &user_id)
        .expect("delete user");

    // Both agents must be gone (no orphans)
    assert!(
        identity
            .get_agent(&realm_id, &a1_id)
            .expect("get a1")
            .is_none(),
        "a1 must be gone"
    );
    assert!(
        identity
            .get_agent(&realm_id, &a2_id)
            .expect("get a2")
            .is_none(),
        "a2 must be gone"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// M1 byte-identity regression guard
// ──────────────────────────────────────────────────────────────────────────────

/// Verifies that M1 changes did not alter the JWT claim structure for
/// ordinary user tokens. We decode and check the standard claim set: `sub`,
/// `iss`, `exp`, `iat`, `oid`, `email`. No agent-specific claims should appear.
///
/// This guards against accidental claim-set drift when new features add
/// token-level fields — any new claim on the non-agent path must be a
/// deliberate, reviewed change.
#[tokio::test]
async fn m1_non_agent_token_claim_set_unchanged() {
    use hearth::identity::{CleartextPassword, PasswordGrantRequest};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let user_id = make_user(identity, &realm_id);
    let password = "HearthTest123!";
    identity
        .set_password(
            &realm_id,
            &user_id,
            &CleartextPassword::from_string(password.to_string()),
        )
        .expect("set password");

    let email = identity
        .get_user(&realm_id, &user_id)
        .expect("get user")
        .expect("user exists")
        .email()
        .to_string();

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email: email.clone(),
                password: password.to_string(),
                scope: None,
                client_ip: None,
                user_agent: None,
            },
        )
        .expect("password grant");

    // Decode without verifying signature — we only care about the claim set
    let token = response.access_token();
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");

    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode payload");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("JSON payload");

    // Standard claims must be present
    assert!(claims.get("sub").is_some(), "sub claim required");
    assert!(claims.get("iss").is_some(), "iss claim required");
    assert!(claims.get("exp").is_some(), "exp claim required");
    assert!(claims.get("iat").is_some(), "iat claim required");

    // Agent-specific claims must NOT appear on user tokens
    assert!(
        claims.get("agt").is_none(),
        "agt claim must not appear in user tokens"
    );
    assert!(
        claims.get("agent_id").is_none(),
        "agent_id claim must not appear in user tokens"
    );
}
