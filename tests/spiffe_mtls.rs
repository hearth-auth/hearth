//! Phase D.7 integration tests — SPIFFE / workload identity.
//!
//! Covers:
//! - D.7 SPIFFE ID registration (CRUD)
//! - D.7 SPIFFE ID format validation
//! - D.7 Lookup by SPIFFE ID
//! - D.7 Deletion removes mapping
//! - D.7 Adversarial: invalid SPIFFE URI rejected
//! - D.7 Adversarial: duplicate mapping rejected

mod common;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest, IdentityError,
    RegisterSpiffeIdRequest,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_realm(h: &TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("spiffe-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_agent(h: &TestHarness, realm_id: &RealmId) -> hearth::core::AgentId {
    let owner = h
        .identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("spiffe-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "SPIFFE Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");
    h.identity()
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "spiffe-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec!["urn:hearth:workload".to_string()],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

fn spiffe_id(agent_id: &hearth::core::AgentId) -> String {
    format!("spiffe://example.com/agent/{}", agent_id.as_uuid())
}

// ── D.7.1: Register SPIFFE mapping ───────────────────────────────────────────

#[tokio::test]
async fn register_spiffe_mapping_returns_record() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    let mapping = h
        .identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register SPIFFE mapping");

    assert_eq!(mapping.spiffe_id, sid);
    assert_eq!(mapping.agent_id, agent_id);
    assert_eq!(mapping.trust_domain, "example.com");
}

// ── D.7.2: Lookup by SPIFFE ID ───────────────────────────────────────────────

#[tokio::test]
async fn lookup_agent_by_spiffe_id_returns_mapped_agent() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register");

    let found = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, &sid)
        .expect("lookup")
        .expect("must find agent");

    assert_eq!(found, agent_id, "lookup must return the registered agent");
}

// ── D.7.3: Lookup of unknown SPIFFE ID returns None ──────────────────────────

#[tokio::test]
async fn lookup_unknown_spiffe_id_returns_none() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);

    let result = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, "spiffe://example.com/agent/not-registered")
        .expect("lookup must not fail");

    assert!(result.is_none(), "unknown SPIFFE ID must return None");
}

// ── D.7.4: Delete SPIFFE mapping ─────────────────────────────────────────────

#[tokio::test]
async fn delete_spiffe_mapping_removes_the_mapping() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register");

    h.identity()
        .delete_spiffe_mapping(&realm_id, &agent_id)
        .expect("delete");

    let result = h
        .identity()
        .lookup_agent_by_spiffe_id(&realm_id, &sid)
        .expect("lookup after delete");

    assert!(result.is_none(), "mapping must not exist after deletion");
}

// ── D.7.5: Adversarial — duplicate mapping rejected ─────────────────────────

#[tokio::test]
async fn duplicate_spiffe_mapping_is_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);
    let sid = spiffe_id(&agent_id);

    h.identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("first registration succeeds");

    let err = h
        .identity()
        .register_spiffe_mapping(
            &realm_id,
            &RegisterSpiffeIdRequest {
                agent_id: agent_id.clone(),
                spiffe_id: sid,
                trust_bundle_pem: None,
            },
        )
        .expect_err("duplicate registration must be rejected");

    assert!(
        matches!(err, IdentityError::SpiffeMappingConflict),
        "expected SpiffeMappingConflict, got {err:?}"
    );
}

// ── D.7.6: Adversarial — invalid SPIFFE ID format rejected ───────────────────

#[tokio::test]
async fn invalid_spiffe_id_format_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let invalid_ids = [
        "https://example.com/agent/123", // wrong scheme
        "spiffe://",                     // no domain or path
        "spiffe:///agent/123",           // empty trust domain
        "spiffe://example.com/user/123", // wrong path segment
    ];

    for invalid_id in invalid_ids {
        let err = h
            .identity()
            .register_spiffe_mapping(
                &realm_id,
                &RegisterSpiffeIdRequest {
                    agent_id: agent_id.clone(),
                    spiffe_id: invalid_id.to_string(),
                    trust_bundle_pem: None,
                },
            )
            .expect_err(&format!(
                "invalid SPIFFE ID '{invalid_id}' must be rejected"
            ));

        assert!(
            matches!(err, IdentityError::SpiffeIdInvalid { .. }),
            "expected SpiffeIdInvalid for '{invalid_id}', got {err:?}"
        );
    }
}

// ── D.7.7: Delete nonexistent mapping returns error ──────────────────────────

#[tokio::test]
async fn delete_nonexistent_spiffe_mapping_returns_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let err = h
        .identity()
        .delete_spiffe_mapping(&realm_id, &agent_id)
        .expect_err("deleting nonexistent mapping must fail");

    assert!(
        matches!(err, IdentityError::SpiffeMappingNotFound),
        "expected SpiffeMappingNotFound, got {err:?}"
    );
}
