//! Phase D.1 integration tests — Attenuating Authorization Tokens (AATs).
//!
//! Covers:
//! - D.1 derivation rules: scope only narrows
//! - D.1 chain validation
//! - D.1 adversarial: escalation via crafted AATs rejected
//! - D.1 revocation propagates to descendants

mod common;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{
    AatToolPermission, AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest,
    DeriveAatRequest, IdentityError, IssueAatRequest,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_realm(h: &TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("aat-test-{}", uuid::Uuid::new_v4()),
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
                email: format!("aat-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "AAT Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");
    h.identity()
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "aat-test-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 5,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

fn tool(name: &str, actions: &[&str]) -> AatToolPermission {
    AatToolPermission {
        tool: name.to_string(),
        actions: actions.iter().copied().map(str::to_string).collect(),
        constraints: serde_json::Value::Null,
    }
}

fn tool_with_constraints(
    name: &str,
    actions: &[&str],
    constraints: serde_json::Value,
) -> AatToolPermission {
    AatToolPermission {
        tool: name.to_string(),
        actions: actions.iter().copied().map(str::to_string).collect(),
        constraints,
    }
}

// ── D.1.1: Root AAT issuance ─────────────────────────────────────────────────

#[tokio::test]
async fn issue_root_aat_returns_signed_jwt() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let resp = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id: agent_id.clone(),
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    // Token should be a non-empty JWT (three dot-separated segments).
    let parts: Vec<&str> = resp.aat.split('.').collect();
    assert_eq!(parts.len(), 3, "root AAT must be a valid JWT (3 segments)");
    assert_eq!(resp.expires_in_secs, 300);
}

// ── D.1.2: Derivation rules — scope only narrows ─────────────────────────────

#[tokio::test]
async fn derive_aat_with_subset_scope_succeeds() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![
                    tool("send_email", &["invoke", "list"]),
                    tool("delete_file", &["invoke"]),
                ],
                scope: vec!["email:send".to_string(), "files:write".to_string()],
                aud: None,
                expires_in_secs: Some(600),
            },
        )
        .expect("issue root AAT");

    // Derive with a strict subset of tools and scope.
    let child = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat.clone(),
                tools: vec![tool("send_email", &["invoke"])], // narrows: only invoke, not list
                scope: vec!["email:send".to_string()],        // narrows: no files:write
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect("derive child AAT");

    // Child should also be a valid JWT.
    let parts: Vec<&str> = child.aat.split('.').collect();
    assert_eq!(parts.len(), 3, "child AAT must be a valid JWT");
    assert!(
        child.expires_in_secs <= 60,
        "child TTL must not exceed requested"
    );
}

// ── D.1.3: Derivation rejected on scope escalation ───────────────────────────

#[tokio::test]
async fn derive_aat_with_wider_scope_returns_escalation_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    // Attempt to add a new scope not present in the parent.
    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec![
                    "email:send".to_string(),
                    "files:delete".to_string(), // escalation!
                ],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("scope escalation must be rejected");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation, got {err:?}"
    );
}

// ── D.1.4: Adversarial — crafted AAT with wider tool permissions rejected ─────

#[tokio::test]
async fn crafted_aat_with_escalated_tool_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    // Attempt to derive with a tool not in the parent.
    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![
                    tool("send_email", &["invoke"]),
                    tool("delete_database", &["invoke"]), // not in parent!
                ],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("tool escalation must be rejected");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation, got {err:?}"
    );
}

// ── D.1.5: Adversarial — numeric constraint escalation rejected ───────────────

#[tokio::test]
async fn crafted_aat_with_looser_numeric_constraint_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool_with_constraints(
                    "search",
                    &["invoke"],
                    serde_json::json!({"max_results": 10}),
                )],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    // Attempt to widen the numeric constraint.
    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![tool_with_constraints(
                    "search",
                    &["invoke"],
                    serde_json::json!({"max_results": 1000}), // exceeds parent's 10!
                )],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("numeric constraint escalation must be rejected");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation, got {err:?}"
    );
}

// ── D.1.6: Validate AAT — presented AAT must be verifiable ───────────────────

#[tokio::test]
async fn validate_aat_succeeds_for_valid_token() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let resp = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    let claims = h
        .identity()
        .validate_aat(&realm_id, &resp.aat)
        .expect("validate_aat must succeed for a freshly issued token");

    assert!(!claims.jti.is_empty(), "jti must be present");
    assert!(
        claims.scope.contains(&"email:send".to_string()),
        "scope must carry email:send"
    );
    assert_eq!(
        claims.aat_chain.len(),
        1,
        "root AAT chain has exactly one entry"
    );
}

// ── D.1.7: Revocation propagates to descendants ───────────────────────────────

#[tokio::test]
async fn revocation_invalidates_child_aats() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("search", &["invoke"])],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(3600),
            },
        )
        .expect("issue root AAT");

    let root_claims = h
        .identity()
        .validate_aat(&realm_id, &root.aat)
        .expect("root validates before revocation");

    let child = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat.clone(),
                tools: vec![tool("search", &["invoke"])],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect("derive child");

    // Revoke the root.
    h.identity()
        .revoke_aat(&realm_id, &root_claims.jti)
        .expect("revoke root");

    // Both root and child should now fail validation.
    let root_err = h
        .identity()
        .validate_aat(&realm_id, &root.aat)
        .expect_err("root must be invalid after revocation");
    assert!(
        matches!(root_err, IdentityError::AatRevoked),
        "expected AatRevoked for root, got {root_err:?}"
    );

    let child_err = h
        .identity()
        .validate_aat(&realm_id, &child.aat)
        .expect_err("child must be invalid after parent revocation");
    assert!(
        matches!(child_err, IdentityError::AatRevoked),
        "expected AatRevoked for child, got {child_err:?}"
    );
}

// ── D.1-SECURITY: non-Object constraint type bypass (HEA-1440) ───────────────

/// Issuing a root AAT with a string constraint must be rejected.
/// PoC: previously a root could be issued with `constraints: "basic"`, after
/// which deriving with `constraints: "admin"` bypassed narrowing validation.
#[tokio::test]
async fn string_constraint_rejected_at_issuance() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let err = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool_with_constraints(
                    "fs",
                    &["invoke"],
                    serde_json::Value::String("basic".to_string()),
                )],
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect_err("string constraint must be rejected at issuance");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation for string constraint at issuance, got {err:?}"
    );
}

/// Issuing a root AAT with an array constraint must be rejected.
#[tokio::test]
async fn array_constraint_rejected_at_issuance() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let err = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool_with_constraints(
                    "fs",
                    &["invoke"],
                    serde_json::json!(["read", "write"]),
                )],
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect_err("array constraint must be rejected at issuance");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation for array constraint at issuance, got {err:?}"
    );
}

/// Derivation with a string child constraint must be rejected even when the
/// parent's constraint is null.  Previously the `if let (Object, Object)` guard
/// fell through and the `else if` only caught the null-parent case.
#[tokio::test]
async fn derive_aat_string_child_constraint_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("fs", &["invoke"])], // null constraints — valid
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT with null constraints");

    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![tool_with_constraints(
                    "fs",
                    &["invoke"],
                    serde_json::Value::String("admin".to_string()), // escalation via type confusion
                )],
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("string child constraint must be rejected");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation for string child constraint, got {err:?}"
    );
}

/// Same-value string constraints are also rejected: semantics of narrowing
/// for non-object types are undefined regardless of whether child == parent.
#[tokio::test]
async fn derive_aat_same_string_child_constraint_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let root = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("fs", &["invoke"])], // null constraints — valid
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT with null constraints");

    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![tool_with_constraints(
                    "fs",
                    &["invoke"],
                    serde_json::Value::String("basic".to_string()), // even same-string is rejected
                )],
                scope: vec!["fs:read".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("same string child constraint must be rejected");

    assert!(
        matches!(err, IdentityError::AatScopeEscalation),
        "expected AatScopeEscalation for same-string child constraint, got {err:?}"
    );
}

// ── D.1.8: Forged signature is rejected ──────────────────────────────────────

#[tokio::test]
async fn forged_aat_signature_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let resp = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("search", &["invoke"])],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    // Tamper with the signature by flipping the last byte.
    let mut parts: Vec<&str> = resp.aat.split('.').collect();
    let mut sig = parts[2].to_string();
    let last = sig.pop().unwrap_or('A');
    sig.push(if last == 'A' { 'B' } else { 'A' });
    parts[2] = &sig;
    let forged = parts.join(".");

    let err = h
        .identity()
        .validate_aat(&realm_id, &forged)
        .expect_err("forged AAT must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidToken),
        "expected InvalidToken for forged AAT, got {err:?}"
    );
}
