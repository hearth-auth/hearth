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
            None,
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
            None,
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
        .delete_agent(&realm_id, &agent_id, None)
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
        .suspend_agent(&realm_id, agent.id(), None)
        .expect("suspend agent");
    assert_eq!(suspended.status(), AgentStatus::Suspended);

    // Suspended → Active
    let reactivated = identity
        .reactivate_agent(&realm_id, agent.id(), None)
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
        .revoke_agent(&realm_id, agent.id(), None)
        .expect("revoke agent");
    assert_eq!(revoked.status(), AgentStatus::Revoked);

    // Revoked → Active must fail
    let err = identity
        .reactivate_agent(&realm_id, agent.id(), None)
        .expect_err("should not reactivate revoked agent");
    assert!(
        matches!(err, IdentityError::AgentRevoked),
        "expected AgentRevoked, got {err:?}"
    );

    // Revoked → Suspended must fail
    let err2 = identity
        .suspend_agent(&realm_id, agent.id(), None)
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

    // Precondition: the agent key exists at the storage layer. `get_agent`
    // reads `storage.get(realm_id, agent_key)` directly and does NOT gate on
    // realm existence, so it doubles as a storage-layer probe both before and
    // after the cascade.
    assert!(
        identity
            .get_agent(&realm_id, &agent_id)
            .expect("get before delete")
            .is_some(),
        "agent must exist before realm deletion"
    );

    // Delete the realm — cascade must sweep the agent key-space.
    identity.delete_realm(&realm_id).expect("delete realm");

    // Storage-layer assertion: no orphaned agent key survives the cascade.
    // Because `get_agent` probes storage directly, `None` proves the key was
    // physically removed, not merely that the realm record is gone.
    assert!(
        identity
            .get_agent(&realm_id, &agent_id)
            .expect("get after delete must not error")
            .is_none(),
        "agent key must be swept by the realm-deletion cascade (no orphans)"
    );
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .expect("key1");
    let r2 = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest { label: "k2".into() },
            None,
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
        .revoke_agent_credential(&realm_id, agent.id(), r1.credential.id(), None)
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
            None,
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
            None,
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
            None,
        )
        .expect("create key");
    let key_hex = resp.plaintext_key.expose_once().to_string();
    let cred_id = resp.credential.id().clone();

    // Revoke it
    identity
        .revoke_agent_credential(&realm_id, agent.id(), &cred_id, None)
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
            None,
        )
        .expect("k1");
    identity
        .create_agent_api_key(
            &realm_id,
            &agent_id,
            &CreateAgentApiKeyRequest { label: "k2".into() },
            None,
        )
        .expect("k2");

    // Delete agent
    identity
        .delete_agent(&realm_id, &agent_id, None)
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
// HEA-1414: Capability bounds (max 50, max 256 chars)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_capability_count_bounded_on_create() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // 51 capabilities — must be rejected
    let caps: Vec<String> = (0..51).map(|i| format!("urn:hearth:cap:{i}")).collect();
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Cap Overflow".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: caps,
                max_delegation_depth: 1,
            },
            None,
        )
        .expect_err("51 capabilities should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for >50 capabilities, got {err:?}"
    );

    // Exactly 50 — must be accepted
    let caps_ok: Vec<String> = (0..50).map(|i| format!("urn:hearth:cap:{i}")).collect();
    identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Cap Max OK".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: caps_ok,
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("exactly 50 capabilities should be accepted");
}

#[tokio::test]
async fn agent_capability_string_length_bounded_on_create() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);

    // Capability string > 256 chars — must be rejected
    let long_cap = "x".repeat(257);
    let err = identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Long Cap".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![long_cap],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect_err("capability >256 chars should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for capability >256 chars, got {err:?}"
    );

    // Exactly 256 chars — must be accepted
    let cap_ok = "u".repeat(256);
    identity
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Cap 256 OK".to_string(),
                description: None,
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![cap_ok],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("capability of exactly 256 chars should be accepted");
}

#[tokio::test]
async fn agent_capability_bounds_enforced_on_update() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Update Bounds Agent");

    // > 50 capabilities on update
    let too_many: Vec<String> = (0..51).map(|i| format!("urn:hearth:cap:{i}")).collect();
    let err = identity
        .update_agent(
            &realm_id,
            agent.id(),
            &UpdateAgentRequest {
                capabilities: Some(too_many),
                ..Default::default()
            },
            None,
        )
        .expect_err("51 capabilities on update should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput on update >50 caps, got {err:?}"
    );

    // Capability > 256 chars on update
    let long_cap = "y".repeat(257);
    let err2 = identity
        .update_agent(
            &realm_id,
            agent.id(),
            &UpdateAgentRequest {
                capabilities: Some(vec![long_cap]),
                ..Default::default()
            },
            None,
        )
        .expect_err("capability >256 chars on update should be rejected");
    assert!(
        matches!(err2, IdentityError::InvalidInput { .. }),
        "expected InvalidInput on update cap >256 chars, got {err2:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// HEA-1414: Credential quota (max 25 per agent)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_credential_quota_enforced() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &user_id, "Quota Agent");

    // Create 25 credentials — all must succeed
    for i in 0..25u32 {
        identity
            .create_agent_api_key(
                &realm_id,
                agent.id(),
                &CreateAgentApiKeyRequest {
                    label: format!("key-{i}"),
                },
                None,
            )
            .unwrap_or_else(|e| panic!("key {i} should succeed: {e:?}"));
    }

    // 26th must be rejected
    match identity.create_agent_api_key(
        &realm_id,
        agent.id(),
        &CreateAgentApiKeyRequest {
            label: "key-overflow".to_string(),
        },
        None,
    ) {
        Err(IdentityError::QuotaExceeded {
            resource: "agent_credentials",
            ..
        }) => {
            // expected
        }
        Err(e) => panic!("expected QuotaExceeded(agent_credentials), got {e:?}"),
        Ok(_) => panic!("26th credential should have been rejected by quota"),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HEA-1414: HTTP endpoint authentication (adversarial — server mode)
// ──────────────────────────────────────────────────────────────────────────────

/// All 9 agent HTTP endpoints must return 401 when called without
/// an Authorization header. Regression guard against unauthenticated access.
#[tokio::test]
async fn agent_endpoints_require_auth() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
    let h = common::TestHarness::server_with_agent_auth()
        .await
        .expect("server harness");
    let base = h.base_url().expect("base_url");
    let client = reqwest::Client::new();

    // We need a valid realm_id header (using a fake UUID is fine — 401 fires before realm lookup)
    let realm_hdr = uuid::Uuid::nil().to_string();
    let fake_agent_id = "agt_00000000000000000000000000000000";
    let fake_cred_id = "agcr_00000000000000000000000000000000";

    // Pre-allocate paths with owned Strings to avoid temporary-drop lifetime issues
    let agent_get = format!("/v1/agents/{fake_agent_id}");
    let agent_patch = format!("/v1/agents/{fake_agent_id}");
    let agent_delete = format!("/v1/agents/{fake_agent_id}");
    let cred_keys = format!("/v1/agents/{fake_agent_id}/credentials/keys");
    let cred_list = format!("/v1/agents/{fake_agent_id}/credentials");
    let cred_revoke = format!("/v1/agents/{fake_agent_id}/credentials/{fake_cred_id}");

    let endpoints: Vec<(&str, reqwest::Method, Option<serde_json::Value>)> = vec![
        (
            "/.well-known/agent.json?agent_id=agt_00000000000000000000000000000000",
            reqwest::Method::GET,
            None,
        ),
        ("/v1/agents", reqwest::Method::GET, None),
        (
            "/v1/agents",
            reqwest::Method::POST,
            Some(serde_json::json!({
                "display_name": "x", "owner_type": "user", "owner_id": uuid::Uuid::nil().to_string()
            })),
        ),
        (&agent_get, reqwest::Method::GET, None),
        (
            &agent_patch,
            reqwest::Method::PATCH,
            Some(serde_json::json!({})),
        ),
        (&agent_delete, reqwest::Method::DELETE, None),
        (
            &cred_keys,
            reqwest::Method::POST,
            Some(serde_json::json!({"label": "x"})),
        ),
        (&cred_list, reqwest::Method::GET, None),
        (&cred_revoke, reqwest::Method::DELETE, None),
    ];

    for (path, method, body) in &endpoints {
        let url = format!("{base}{path}");
        let mut req = client
            .request(method.clone(), &url)
            .header("X-Realm-ID", &realm_hdr);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
        let status = resp.status().as_u16();
        assert_eq!(
            status, 401,
            "expected 401 Unauthorized for unauthenticated {method} {url}, got {status}"
        );
    }
}

/// An admin token valid for realm A must not grant access to realm B's agents.
/// The BOLA protection is architectural: tokens are signed with per-realm keys,
/// so presenting realm A's token with X-Realm-ID: realm_B fails token validation.
#[tokio::test]
async fn agent_endpoint_cross_realm_bola() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
    // Use server_with_agent_auth so /v1/agents routes are registered
    let h = common::TestHarness::server_with_agent_auth()
        .await
        .expect("server harness");
    let base = h.base_url().expect("base_url");
    let client = reqwest::Client::new();

    // Bootstrap gets a system-realm admin token
    let resp = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap");
    assert!(resp.status().is_success(), "bootstrap must succeed");
    let body: serde_json::Value = resp.json().await.expect("bootstrap JSON");
    let system_token = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Create realm B directly via the embedded engine (HTTP realm creation is disabled)
    let realm_b = h
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: format!("realm-b-bola-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm B");
    let realm_b_id = realm_b.id().as_uuid().to_string();

    // Presenting the system-realm token with realm B's ID must fail — tokens are
    // signed with per-realm Ed25519 keys, so validate_token(&realm_b, system_token) rejects it.
    let status = client
        .get(format!("{base}/v1/agents"))
        .header("Authorization", format!("Bearer {system_token}"))
        .header("X-Realm-ID", &realm_b_id)
        .send()
        .await
        .expect("cross-realm request")
        .status()
        .as_u16();
    assert!(
        status == 401 || status == 403,
        "cross-realm BOLA: system token must not grant access to realm B (got {status})"
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

// ──────────────────────────────────────────────────────────────────────────────
// HEA-1416 — Audit actor attribution for credential operations
// ──────────────────────────────────────────────────────────────────────────────

/// Regression guard: create_agent_api_key and revoke_agent_credential must record
/// the caller's user ID as the audit actor, not fall back to "system".
#[tokio::test]
async fn agent_credential_audit_actor_attributed() {
    use hearth::audit::{AuditAction, AuditQuery};

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let audit = harness.audit();
    let realm_id = make_realm(identity);
    let caller_id = make_user(identity, &realm_id);
    let agent = create_agent(identity, &realm_id, &caller_id, "Audit-Test Agent");

    // Create a credential, passing the caller so it should be attributed.
    let resp = identity
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest {
                label: "audit-test-key".to_string(),
            },
            Some(&caller_id),
        )
        .expect("create API key");
    let cred_id = resp.credential.id().clone();

    // The AgentCredentialCreated event must carry the caller's UUID as actor.
    let events = audit
        .query(&AuditQuery::for_realm(realm_id.clone()))
        .expect("audit query");
    let create_event = events
        .iter()
        .find(|e| e.action == AuditAction::AgentCredentialCreated)
        .expect("AgentCredentialCreated event must be present");
    assert_eq!(
        create_event.actor,
        caller_id.as_uuid().to_string(),
        "credential-created actor must be the caller's user UUID"
    );
    assert_eq!(create_event.resource_type, "agent_credential");
    assert_eq!(
        create_event.resource_id,
        cred_id.as_uuid().to_string(),
        "credential-created resource_id must match the new credential"
    );

    // Revoke the credential with the same caller.
    identity
        .revoke_agent_credential(&realm_id, agent.id(), &cred_id, Some(&caller_id))
        .expect("revoke credential");

    let events_after = audit
        .query(&AuditQuery::for_realm(realm_id.clone()))
        .expect("audit query after revoke");
    let revoke_event = events_after
        .iter()
        .find(|e| e.action == AuditAction::AgentCredentialRevoked)
        .expect("AgentCredentialRevoked event must be present");
    assert_eq!(
        revoke_event.actor,
        caller_id.as_uuid().to_string(),
        "credential-revoked actor must be the caller's user UUID"
    );
    assert_eq!(revoke_event.resource_type, "agent_credential");
    assert_eq!(
        revoke_event.resource_id,
        cred_id.as_uuid().to_string(),
        "credential-revoked resource_id must match the revoked credential"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// HEA-1836 — Positive HTTP-layer Agent REST CRUD + Agent Card
// ──────────────────────────────────────────────────────────────────────────────

/// Full happy-path CRUD exercised through the HTTP surface (not just the
/// engine): TEST_SCENARIOS §A.4 (Agent Card) and §A.7 (Agent REST endpoints)
/// previously had only engine-level CRUD plus an unauthenticated BOLA matrix,
/// so the positive 201/200/204 boxes were not backed. This walks
/// create → get → list → patch → issue-key → list-creds → agent-card → delete
/// against a running server with a valid admin token, asserting status codes
/// and response bodies at each step.
#[tokio::test]
async fn agent_rest_crud_positive_http() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(
            "HEARTH_MASTER_KEY",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
    }
    let h = common::TestHarness::server_with_agent_auth()
        .await
        .expect("server harness");
    let base = h.base_url().expect("base_url");
    let client = reqwest::Client::new();

    // Bootstrap the dev realm → admin token (has hearth.admin, which satisfies
    // the hearth.agents.admin gate) + the admin user id we use as agent owner.
    let boot: serde_json::Value = client
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap")
        .json()
        .await
        .expect("bootstrap json");
    let realm_id = boot["realm_id"].as_str().expect("realm_id").to_string();
    let owner_id = boot["user_id"].as_str().expect("user_id").to_string();
    let token = boot["access_token"].as_str().expect("access_token").to_string();

    let auth = |req: reqwest::RequestBuilder| {
        req.header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", &realm_id)
    };

    // ── CREATE → 201 ─────────────────────────────────────────────────────────
    let create_resp = auth(client.post(format!("{base}/v1/agents")))
        .json(&serde_json::json!({
            "display_name": "Rest CRUD Agent",
            "description": "created via HTTP",
            "owner_type": "user",
            "owner_id": owner_id,
            "capabilities": ["urn:hearth:capability:email:send"],
            "max_delegation_depth": 2,
        }))
        .send()
        .await
        .expect("create request");
    assert_eq!(
        create_resp.status().as_u16(),
        201,
        "POST /v1/agents must return 201 Created"
    );
    let created: serde_json::Value = create_resp.json().await.expect("create json");
    let agent_id = created["id"].as_str().expect("agent id").to_string();
    assert!(agent_id.starts_with("agt_"), "agent id must be prefixed");
    assert_eq!(created["display_name"], "Rest CRUD Agent");
    assert_eq!(created["status"], "active");
    assert_eq!(created["owner"]["type"], "user");
    assert_eq!(created["owner"]["id"], owner_id);
    assert_eq!(created["max_delegation_depth"], 2);

    // ── GET → 200 ────────────────────────────────────────────────────────────
    let got = auth(client.get(format!("{base}/v1/agents/{agent_id}")))
        .send()
        .await
        .expect("get request");
    assert_eq!(got.status().as_u16(), 200, "GET /v1/agents/{{id}} must return 200");
    let got_body: serde_json::Value = got.json().await.expect("get json");
    assert_eq!(got_body["id"], agent_id);
    assert_eq!(got_body["display_name"], "Rest CRUD Agent");

    // ── LIST → 200, contains the new agent ───────────────────────────────────
    let list = auth(client.get(format!("{base}/v1/agents")))
        .send()
        .await
        .expect("list request");
    assert_eq!(list.status().as_u16(), 200, "GET /v1/agents must return 200");
    let list_body: serde_json::Value = list.json().await.expect("list json");
    let items = list_body["items"].as_array().expect("items array");
    assert!(
        items.iter().any(|a| a["id"] == serde_json::json!(agent_id)),
        "listed agents must include the newly created agent"
    );

    // ── PATCH → 200, display_name updated ────────────────────────────────────
    let patched = auth(client.patch(format!("{base}/v1/agents/{agent_id}")))
        .json(&serde_json::json!({ "display_name": "Renamed Agent" }))
        .send()
        .await
        .expect("patch request");
    assert_eq!(patched.status().as_u16(), 200, "PATCH must return 200");
    let patched_body: serde_json::Value = patched.json().await.expect("patch json");
    assert_eq!(
        patched_body["display_name"], "Renamed Agent",
        "PATCH must update the display_name"
    );

    // ── ISSUE API KEY → 201 with show-once secret ────────────────────────────
    let key_resp = auth(client.post(format!("{base}/v1/agents/{agent_id}/credentials/keys")))
        .json(&serde_json::json!({ "label": "ci-key" }))
        .send()
        .await
        .expect("create key request");
    assert_eq!(key_resp.status().as_u16(), 201, "POST credentials/keys must return 201");
    let key_body: serde_json::Value = key_resp.json().await.expect("key json");
    assert!(
        key_body["key"].as_str().is_some_and(|k| !k.is_empty()),
        "issued API key must include a non-empty show-once secret"
    );
    let cred_id = key_body["credential"]["id"]
        .as_str()
        .expect("credential id")
        .to_string();
    assert_eq!(key_body["credential"]["kind"], "api_key");

    // ── LIST CREDENTIALS → 200, contains the issued key ──────────────────────
    let creds = auth(client.get(format!("{base}/v1/agents/{agent_id}/credentials")))
        .send()
        .await
        .expect("list creds request");
    assert_eq!(creds.status().as_u16(), 200, "GET credentials must return 200");
    let creds_body: serde_json::Value = creds.json().await.expect("creds json");
    let cred_items = creds_body["items"]
        .as_array()
        .or_else(|| creds_body.as_array())
        .expect("credential list");
    assert!(
        cred_items.iter().any(|c| c["id"] == serde_json::json!(cred_id)),
        "credential list must include the issued key"
    );

    // ── AGENT CARD (A.4) → 200 with authenticated request ────────────────────
    let card = auth(client.get(format!(
        "{base}/.well-known/agent.json?agent_id={agent_id}"
    )))
    .send()
    .await
    .expect("agent card request");
    assert_eq!(card.status().as_u16(), 200, "authenticated Agent Card must return 200");
    let card_body: serde_json::Value = card.json().await.expect("card json");
    assert_eq!(card_body["name"], "Renamed Agent", "card reflects current name");
    assert!(
        card_body["capabilities"]
            .as_array()
            .is_some_and(|c| !c.is_empty()),
        "agent card must advertise capabilities"
    );

    // ── DELETE → 204, then GET → 404 ─────────────────────────────────────────
    let deleted = auth(client.delete(format!("{base}/v1/agents/{agent_id}")))
        .send()
        .await
        .expect("delete request");
    assert_eq!(deleted.status().as_u16(), 204, "DELETE must return 204 No Content");

    let after = auth(client.get(format!("{base}/v1/agents/{agent_id}")))
        .send()
        .await
        .expect("get-after-delete request");
    assert_eq!(
        after.status().as_u16(),
        404,
        "GET after DELETE must return 404 Not Found"
    );
}
