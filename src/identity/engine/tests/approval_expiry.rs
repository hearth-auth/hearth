//! #632 part 2 (OpenSpec `fix-spec-drift-defects` task 4.1): an approval
//! request whose `expires_at` has passed without a decision reads `Expired`
//! (`agent-approvals`, "Regression — an expired request still reads Pending").
//!
//! Nothing wrote `ApprovalRequestStatus::Expired`, so such a request stayed
//! `Pending` in get and list, and `?status=expired` found nothing.

use super::*;

use crate::identity::{
    AgentOwner, ApprovalRequestStatus, CreateAgentRequest, CreateApprovalRequestInput,
};

/// Queues a request for `agent` that expires after `expires_in_secs`.
fn request(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    agent: &crate::core::AgentId,
    expires_in_secs: i64,
) -> String {
    engine
        .create_approval_request(
            realm,
            &CreateApprovalRequestInput {
                agent_id: agent.clone(),
                tool: "deploy".to_string(),
                action: "invoke".to_string(),
                context: serde_json::json!({}),
                delegation_chain: vec![],
                expires_in_secs: Some(expires_in_secs),
            },
        )
        .expect("create approval request")
        .request_id
}

fn listed(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    status: Option<ApprovalRequestStatus>,
) -> Vec<(String, ApprovalRequestStatus)> {
    let mut items: Vec<_> = engine
        .list_approval_requests(realm, status, None, 100)
        .expect("list")
        .items
        .into_iter()
        .map(|r| (r.request_id, r.status))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

#[test]
fn an_expired_request_reads_expired_in_get_and_list() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let owner = create_test_user(&engine, &realm);
    let agent = engine
        .create_agent(
            &realm,
            &CreateAgentRequest {
                display_name: "expiry-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent");
    let expiring = request(&engine, &realm, agent.id(), 60);
    let lasting = request(&engine, &realm, agent.id(), 3600);

    clock.advance(61 * 1_000_000);

    let status = |id: &str| engine.get_approval_request(&realm, id).expect("get").status;
    assert_eq!(status(&expiring), ApprovalRequestStatus::Expired);
    assert_eq!(status(&lasting), ApprovalRequestStatus::Pending);

    assert_eq!(
        listed(&engine, &realm, Some(ApprovalRequestStatus::Expired)),
        vec![(expiring.clone(), ApprovalRequestStatus::Expired)],
        "?status=expired lists the expired request"
    );
    assert_eq!(
        listed(&engine, &realm, Some(ApprovalRequestStatus::Pending)),
        vec![(lasting.clone(), ApprovalRequestStatus::Pending)],
        "?status=pending no longer lists the expired request"
    );
    let mut all = vec![
        (expiring, ApprovalRequestStatus::Expired),
        (lasting, ApprovalRequestStatus::Pending),
    ];
    all.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(listed(&engine, &realm, None), all, "an unfiltered list");
}
