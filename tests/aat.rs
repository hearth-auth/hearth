//! Phase D.1 integration tests — Attenuating Authorization Tokens (AATs).
//!
//! Covers:
//! - D.1 derivation rules: scope only narrows
//! - D.1 chain validation
//! - D.1 adversarial: escalation via crafted AATs rejected
//! - D.1 adversarial: derive from revoked parent rejected (jti-reuse)
//! - D.1 adversarial: forged act-chain payload claim rejected
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

// ── D.1.9: Adversarial — tampered payload without re-signing rejected ─────────

/// Decode the AAT payload, inject a wider scope, re-encode *without* re-signing.
/// The Ed25519 signature covers the original `header.payload` bytes, so modifying
/// the payload without a new signature is detected as `InvalidToken`.
#[tokio::test]
async fn crafted_aat_tampered_scope_payload_rejected() {
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

    let parts: Vec<&str> = resp.aat.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 segments");

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let raw = b64.decode(parts[1]).expect("decode payload");
    let mut claims: serde_json::Value = serde_json::from_slice(&raw).expect("parse claims JSON");

    // Inject a scope not present in the original token.
    claims["scope"]
        .as_array_mut()
        .expect("scope is array")
        .push(serde_json::Value::String("admin:write".to_string()));

    let tampered = b64.encode(serde_json::to_vec(&claims).expect("re-serialize"));
    // Reassemble with the *original* signature — which now mismatches.
    let forged = format!("{}.{}.{}", parts[0], tampered, parts[2]);

    let err = h
        .identity()
        .validate_aat(&realm_id, &forged)
        .expect_err("tampered-payload AAT must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidToken),
        "expected InvalidToken for tampered payload, got {err:?}"
    );
}

/// Inflate the `aat_chain` claim without re-signing to test that the signature
/// check fires before chain-depth or revocation logic.
#[tokio::test]
async fn crafted_aat_forged_chain_depth_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let resp = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![],
                scope: vec!["x:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue root AAT");

    let parts: Vec<&str> = resp.aat.split('.').collect();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let raw = b64.decode(parts[1]).expect("decode payload");
    let mut claims: serde_json::Value = serde_json::from_slice(&raw).expect("parse claims JSON");

    // Stuff fake JTIs into aat_chain to push apparent depth to the cap (5).
    let chain = claims["aat_chain"]
        .as_array_mut()
        .expect("aat_chain is array");
    for i in 0..4usize {
        chain.push(serde_json::Value::String(format!("fake-jti-{i}")));
    }
    let tampered = b64.encode(serde_json::to_vec(&claims).expect("re-serialize"));
    let forged = format!("{}.{}.{}", parts[0], tampered, parts[2]);

    let err = h
        .identity()
        .validate_aat(&realm_id, &forged)
        .expect_err("forged chain must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidToken),
        "expected InvalidToken for forged chain, got {err:?}"
    );
}

/// Cross-sign: take the header+payload from AAT B but the signature from AAT A.
/// The signature does not cover B's payload, so validation must return `InvalidToken`.
#[tokio::test]
async fn crafted_aat_cross_signed_rejected() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_id = make_agent(&h, &realm_id);

    let aat_a = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id: agent_id.clone(),
                tools: vec![tool("search", &["invoke"])],
                scope: vec!["search:read".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue AAT A");

    let aat_b = h
        .identity()
        .issue_aat(
            &realm_id,
            &IssueAatRequest {
                agent_id,
                tools: vec![tool("admin", &["invoke"])],
                scope: vec!["admin:write".to_string()],
                aud: None,
                expires_in_secs: Some(300),
            },
        )
        .expect("issue AAT B");

    let parts_a: Vec<&str> = aat_a.aat.split('.').collect();
    let parts_b: Vec<&str> = aat_b.aat.split('.').collect();

    // Forge: B's header+payload with A's signature.
    let forged = format!("{}.{}.{}", parts_b[0], parts_b[1], parts_a[2]);

    let err = h
        .identity()
        .validate_aat(&realm_id, &forged)
        .expect_err("cross-signed AAT must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidToken),
        "expected InvalidToken for cross-signed AAT, got {err:?}"
    );
}

// ── D.1 Property tests ────────────────────────────────────────────────────────

mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn make_harness_sync() -> TestHarness {
        tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(TestHarness::embedded())
            .expect("harness init")
    }

    /// Strategy: non-empty, deduplicated list of scope strings (e.g. `"ab:cde"`).
    fn scope_list() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec("[a-z]{2,6}:[a-z]{2,8}", 1..=8usize)
            .prop_map(|mut v| {
                v.sort();
                v.dedup();
                v
            })
            .prop_filter("non-empty after dedup", |v| !v.is_empty())
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        /// Property: for any non-empty scope set `P`, deriving an AAT with scope ⊆ P succeeds;
        /// deriving with any scope ∉ P returns `AatScopeEscalation`.
        #[test]
        fn aat_attenuation_scope_only_narrows(
            parent_scopes in scope_list(),
            extra_scope in "[a-z]{2,6}:extra[0-9]",
        ) {
            // Make sure the extra scope doesn't accidentally appear in the parent.
            prop_assume!(!parent_scopes.contains(&extra_scope));

            let h = make_harness_sync();
            let realm_id = make_realm(&h);
            let agent_id = make_agent(&h, &realm_id);

            let root = h
                .identity()
                .issue_aat(
                    &realm_id,
                    &IssueAatRequest {
                        agent_id,
                        tools: vec![],
                        scope: parent_scopes.clone(),
                        aud: None,
                        expires_in_secs: Some(3600),
                    },
                )
                .expect("issue root AAT");

            // Deriving with the full parent scope (equal set) must succeed.
            let equal_result = h.identity().derive_aat(
                &realm_id,
                &DeriveAatRequest {
                    parent_aat: root.aat.clone(),
                    tools: vec![],
                    scope: parent_scopes.clone(),
                    aud: None,
                    expires_in_secs: Some(60),
                },
            );
            prop_assert!(
                equal_result.is_ok(),
                "derive with equal scope must succeed; err={equal_result:?}"
            );

            // Deriving with a scope NOT in parent must return AatScopeEscalation.
            let mut escalated = parent_scopes.clone();
            escalated.push(extra_scope.clone());

            let esc_result = h.identity().derive_aat(
                &realm_id,
                &DeriveAatRequest {
                    parent_aat: root.aat.clone(),
                    tools: vec![],
                    scope: escalated,
                    aud: None,
                    expires_in_secs: Some(60),
                },
            );
            prop_assert!(
                matches!(esc_result, Err(IdentityError::AatScopeEscalation)),
                "derive with extra scope must return AatScopeEscalation; scope={extra_scope}, got={esc_result:?}"
            );
        }
    }
}

// ── D.1.8: Forged signature is rejected ──────────────────────────────────────

#[tokio::test]
async fn crafted_aat_jti_reuse_derive_from_revoked_rejected() {
    // A revoked AAT must not be usable as a parent for derivation.
    // This covers the "mismatched jti reuse" adversarial case: the
    // revoked JTI is still present in the aat_chain, making it invalid.
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

    // Extract the JTI via validate_aat (returns AatClaims with the jti field).
    let claims = h
        .identity()
        .validate_aat(&realm_id, &root.aat)
        .expect("validate root AAT to extract JTI");
    let jti = claims.jti.clone();

    // Revoke the root AAT.
    h.identity()
        .revoke_aat(&realm_id, &jti)
        .expect("revoke root AAT");

    // Attempt to derive from the revoked parent — must fail.
    let err = h
        .identity()
        .derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![tool("send_email", &["invoke"])],
                scope: vec!["email:send".to_string()],
                aud: None,
                expires_in_secs: Some(60),
            },
        )
        .expect_err("derive from revoked parent must be rejected");

    assert!(
        matches!(err, IdentityError::AatRevoked),
        "expected AatRevoked when parent JTI is revoked, got {err:?}"
    );
}

// ── D.1.9: Forged act-chain claim is rejected ────────────────────────────────

#[tokio::test]
async fn crafted_aat_forged_act_chain_rejected() {
    // Tampering with the aat_chain payload claim invalidates the Ed25519 signature.
    // This proves the chain is tamper-evident: you cannot inject a false ancestor.
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

    // Decode the payload, inject a fake ancestor JTI into aat_chain.
    let parts: Vec<&str> = resp.aat.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 segments");
    let payload_json =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .expect("decode payload");
    let mut claims: serde_json::Value =
        serde_json::from_slice(&payload_json).expect("parse claims JSON");

    // Inject a fake JTI into the aat_chain to forge a longer delegation chain.
    if let Some(chain) = claims.get_mut("aat_chain").and_then(|v| v.as_array_mut()) {
        chain.insert(0, serde_json::json!("fake-ancestor-jti-00000000"));
    }

    let forged_payload = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(&claims).expect("re-serialize"),
    );

    // Reassemble: original header + tampered payload + original signature.
    let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

    let err = h
        .identity()
        .validate_aat(&realm_id, &forged)
        .expect_err("forged act-chain AAT must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidToken),
        "expected InvalidToken for tampered aat_chain, got {err:?}"
    );
}

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
