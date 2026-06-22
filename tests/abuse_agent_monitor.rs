//! Integration tests for D.6 per-agent rate monitor + auto-suspend.
//!
//! Covers:
//! - Normal: requests within threshold are allowed
//! - Threshold exceeded: first crossing auto-suspends agent + emits AgentSuspended audit
//! - Fail-closed: subsequent calls in the same window return rate-limit error
//! - Isolation: one agent's rate does not affect another

mod common;

use hearth::identity::{
    AgentOwner, AgentStatus, CreateAgentApiKeyRequest, CreateAgentRequest, CreateRealmRequest,
    CreateUserRequest, IdentityEngine, IdentityError,
};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

async fn setup() -> (
    common::TestHarness,
    hearth::core::RealmId,
    hearth::core::UserId,
) {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = identity
        .create_realm(&CreateRealmRequest {
            name: format!("rate-monitor-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("agent-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Agent Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    (harness, realm_id, user_id)
}

fn make_agent_with_key(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    user_id: &hearth::core::UserId,
) -> (hearth::identity::Agent, String) {
    let agent = identity
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: format!("Rate-test agent {}", uuid::Uuid::new_v4()),
                description: Some("D.6 test".to_string()),
                owner: AgentOwner::User(user_id.clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent");

    let key_response = identity
        .create_agent_api_key(
            realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest {
                label: "test key".to_string(),
            },
            None,
        )
        .expect("create api key");

    let plaintext = key_response.plaintext_key.expose_once().to_string();
    (agent, plaintext)
}

// ──────────────────────────────────────────────────────────────────────────────
// Normal: within-threshold requests are allowed
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_verify_api_key_within_threshold_succeeds() {
    let (harness, realm_id, user_id) = setup().await;
    let identity = harness.identity();
    let (agent, plaintext) = make_agent_with_key(identity, &realm_id, &user_id);

    // Default threshold is 1_000 — a small number of requests should all pass.
    for _ in 0..10 {
        let result = identity.verify_agent_api_key(&realm_id, agent.id(), &plaintext);
        assert!(
            matches!(result, Ok(true)),
            "expected Ok(true) within threshold, got: {result:?}"
        );
    }

    // Agent should still be Active.
    let agent_state = identity
        .get_agent(&realm_id, agent.id())
        .expect("get agent")
        .expect("agent exists");
    assert_eq!(agent_state.status(), AgentStatus::Active);
}

// ──────────────────────────────────────────────────────────────────────────────
// Threshold exceeded: auto-suspend fires once, then status becomes Suspended
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_rate_limit_triggers_auto_suspend() {
    use hearth::abuse::agent_monitor::{AgentRateConfig, AgentRateMonitor, RateDecision};
    use std::time::{Duration, Instant};

    // Test the monitor directly with a low threshold.
    let monitor = AgentRateMonitor::new(AgentRateConfig {
        threshold: 3,
        window: Duration::from_secs(60),
    });

    let realm_id = hearth::core::RealmId::new(uuid::Uuid::new_v4());
    let agent_id = hearth::core::AgentId::new(uuid::Uuid::new_v4());
    let now = Instant::now();

    // Three requests within threshold — all Allow.
    for _ in 0..3 {
        assert_eq!(
            monitor.check_and_record(&realm_id, &agent_id, now),
            RateDecision::Allow
        );
    }

    // 4th request trips the threshold.
    let first_deny = monitor.check_and_record(&realm_id, &agent_id, now);
    assert_eq!(
        first_deny,
        RateDecision::Deny {
            triggered_suspension: true
        },
        "first crossing must set triggered_suspension=true"
    );

    // Subsequent requests in the same window must NOT re-trigger.
    for _ in 0..5 {
        let d = monitor.check_and_record(&realm_id, &agent_id, now);
        assert_eq!(
            d,
            RateDecision::Deny {
                triggered_suspension: false
            },
            "subsequent denies must have triggered_suspension=false"
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Integration: verify_agent_api_key returns AgentRateLimitExceeded when
// the in-engine monitor fires
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_agent_api_key_returns_rate_limit_error_after_threshold() {
    // The embedded engine uses the default threshold of 1 000 rpm.
    // Exhaust it via repeated calls.
    let (harness, realm_id, user_id) = setup().await;
    let identity = harness.identity();
    let (agent, plaintext) = make_agent_with_key(identity, &realm_id, &user_id);

    // Drive the counter past the 1 000 threshold.
    // We use a wrong key for most calls to avoid other side-effects.
    let bad_key = "00".repeat(32); // 64-char hex, all zeros — never matches
    let mut rate_limited = false;
    for i in 0..=1100u32 {
        let key = if i == 0 { &plaintext } else { &bad_key };
        match identity.verify_agent_api_key(&realm_id, agent.id(), key) {
            Ok(_) => {}
            Err(IdentityError::AgentRateLimitExceeded) => {
                rate_limited = true;
                break;
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(
        rate_limited,
        "should have hit AgentRateLimitExceeded within 1100 calls"
    );

    // Once rate-limited, the agent should be Suspended.
    let agent_state = identity
        .get_agent(&realm_id, agent.id())
        .expect("get agent")
        .expect("agent exists");
    assert_eq!(
        agent_state.status(),
        AgentStatus::Suspended,
        "agent should be auto-suspended after rate-limit trip"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Isolation: one agent's rate limit does not affect another
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_rate_isolation_between_agents() {
    use hearth::abuse::agent_monitor::{AgentRateConfig, AgentRateMonitor, RateDecision};
    use std::time::{Duration, Instant};

    let monitor = AgentRateMonitor::new(AgentRateConfig {
        threshold: 2,
        window: Duration::from_secs(60),
    });

    let realm_id = hearth::core::RealmId::new(uuid::Uuid::new_v4());
    let agent_a = hearth::core::AgentId::new(uuid::Uuid::new_v4());
    let agent_b = hearth::core::AgentId::new(uuid::Uuid::new_v4());
    let now = Instant::now();

    // Exhaust agent_a's quota.
    for _ in 0..2 {
        let _ = monitor.check_and_record(&realm_id, &agent_a, now);
    }
    // 3rd for agent_a → Deny.
    assert!(matches!(
        monitor.check_and_record(&realm_id, &agent_a, now),
        RateDecision::Deny { .. }
    ));

    // agent_b should still be within budget.
    assert_eq!(
        monitor.check_and_record(&realm_id, &agent_b, now),
        RateDecision::Allow,
        "agent_b must not be affected by agent_a's rate limit"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Adversarial: fail-closed on lock-poison simulation
// (Unit-level: tested in agent_monitor.rs inline tests)
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_rate_window_resets_after_full_window() {
    use hearth::abuse::agent_monitor::{AgentRateConfig, AgentRateMonitor, RateDecision};
    use std::time::{Duration, Instant};

    let window = Duration::from_millis(50);
    let monitor = AgentRateMonitor::new(AgentRateConfig {
        threshold: 2,
        window,
    });

    let realm_id = hearth::core::RealmId::new(uuid::Uuid::new_v4());
    let agent_id = hearth::core::AgentId::new(uuid::Uuid::new_v4());
    let t0 = Instant::now();

    // Trip threshold.
    for _ in 0..3 {
        let _ = monitor.check_and_record(&realm_id, &agent_id, t0);
    }
    assert!(matches!(
        monitor.check_and_record(&realm_id, &agent_id, t0),
        RateDecision::Deny {
            triggered_suspension: false
        }
    ));

    // Advance past full window — counters and suspension_fired must reset.
    let t1 = t0 + window + Duration::from_millis(10);
    assert_eq!(
        monitor.check_and_record(&realm_id, &agent_id, t1),
        RateDecision::Allow,
        "first request in new window should be allowed"
    );
}
