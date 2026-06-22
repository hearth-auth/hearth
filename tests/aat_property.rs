//! Property tests for Attenuating Authorization Token (AAT) scope-narrowing invariants.
//!
//! Covers `docs/specs/TEST_SCENARIOS.md` §"Agent Auth — AAT" — Property:
//! - For any parent scope set P and attenuated scope set A where A ⊆ P, derive_aat succeeds.
//! - For any P and A where A ⊄ P, derive_aat returns AatScopeEscalation.

mod common;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{
    AatToolPermission, AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest,
    DeriveAatRequest, IdentityError, IssueAatRequest,
};
use proptest::prelude::*;

fn make_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Returns the proptest case count from env, defaulting to 256.
fn proptest_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

// ── Strategies ───────────────────────────────────────────────────────────────

/// Generate a non-empty vec of scope strings like "email:send".
fn arb_scopes(min: usize, max: usize) -> BoxedStrategy<Vec<String>> {
    proptest::collection::vec("[a-z]{2,6}:[a-z]{2,8}", min..max).boxed()
}

/// Generate a (parent, subset) pair where `subset ⊆ parent`.
fn arb_valid_scope_pair() -> BoxedStrategy<(Vec<String>, Vec<String>)> {
    arb_scopes(1, 7)
        .prop_flat_map(|parent| {
            let n = parent.len();
            // Boolean mask: each entry decides whether to include the corresponding parent scope.
            proptest::collection::vec(any::<bool>(), n).prop_map(move |mask| {
                let sub: Vec<String> = parent
                    .iter()
                    .zip(mask.iter())
                    .filter_map(|(s, take)| if *take { Some(s.clone()) } else { None })
                    .collect();
                (parent.clone(), sub)
            })
        })
        .boxed()
}

/// Generate a (parent, escalated) pair where `escalated ⊄ parent`.
/// The escalated set is the parent plus one extra scope guaranteed not in it.
fn arb_escalation_scope_pair() -> BoxedStrategy<(Vec<String>, Vec<String>)> {
    (arb_scopes(1, 6), "[a-z]{2,6}:[a-z]{2,8}")
        .prop_filter("extra scope must not be in parent", |(parent, extra)| {
            !parent.contains(extra)
        })
        .prop_map(|(mut parent, extra)| {
            let mut escalated = parent.clone();
            escalated.push(extra);
            // Give escalated a shuffled ordering independent of parent.
            escalated.sort();
            parent.sort();
            (parent, escalated)
        })
        .boxed()
}

// ── Setup helpers ─────────────────────────────────────────────────────────────

fn setup_realm_and_agent(h: &TestHarness) -> (RealmId, hearth::core::AgentId) {
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("aat-prop-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let owner = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("prop-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Prop Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    let agent_id = h
        .identity()
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "prop-test-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner),
                capabilities: vec![],
                max_delegation_depth: 5,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone();

    (realm_id, agent_id)
}

fn root_tool() -> AatToolPermission {
    AatToolPermission {
        tool: "test_tool".to_string(),
        actions: vec!["invoke".to_string()],
        constraints: serde_json::Value::Null,
    }
}

// ── Property 1: valid subset derive always succeeds ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: proptest_cases(), ..Default::default() })]

    #[test]
    fn scope_subset_derive_always_succeeds(
        (parent_scope, attenuated_scope) in arb_valid_scope_pair()
    ) {
        let rt = make_rt();
        let h = rt.block_on(TestHarness::embedded()).expect("harness init");
        let (realm_id, agent_id) = setup_realm_and_agent(&h);

        // Issue root AAT with the full parent scope set.
        let root = h
            .identity()
            .issue_aat(
                &realm_id,
                &IssueAatRequest {
                    agent_id,
                    tools: vec![root_tool()],
                    scope: parent_scope.clone(),
                    aud: None,
                    expires_in_secs: Some(300),
                },
            )
            .expect("issue root AAT");

        // Derive with a subset scope — must always succeed.
        let result = h.identity().derive_aat(
            &realm_id,
            &DeriveAatRequest {
                parent_aat: root.aat,
                tools: vec![root_tool()],
                scope: attenuated_scope.clone(),
                aud: None,
                expires_in_secs: Some(60),
            },
        );

        prop_assert!(
            result.is_ok(),
            "derive_aat must succeed when attenuated_scope ({attenuated_scope:?}) ⊆ parent_scope ({parent_scope:?}), got: {result:?}"
        );
    }
}

// ── Property 2: scope escalation is always rejected ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: proptest_cases(), ..Default::default() })]

    #[test]
    fn scope_escalation_always_rejected(
        (parent_scope, escalated_scope) in arb_escalation_scope_pair()
    ) {
        let rt = make_rt();
        let h = rt.block_on(TestHarness::embedded()).expect("harness init");
        let (realm_id, agent_id) = setup_realm_and_agent(&h);

        let root = h
            .identity()
            .issue_aat(
                &realm_id,
                &IssueAatRequest {
                    agent_id,
                    tools: vec![root_tool()],
                    scope: parent_scope.clone(),
                    aud: None,
                    expires_in_secs: Some(300),
                },
            )
            .expect("issue root AAT");

        // Derive with escalated scope (superset) — must always fail.
        let err = h
            .identity()
            .derive_aat(
                &realm_id,
                &DeriveAatRequest {
                    parent_aat: root.aat,
                    tools: vec![root_tool()],
                    scope: escalated_scope.clone(),
                    aud: None,
                    expires_in_secs: Some(60),
                },
            )
            .expect_err("scope escalation must be rejected");

        prop_assert!(
            matches!(err, IdentityError::AatScopeEscalation),
            "expected AatScopeEscalation when escalated_scope ({escalated_scope:?}) ⊄ parent_scope ({parent_scope:?}), got: {err:?}"
        );
    }
}
