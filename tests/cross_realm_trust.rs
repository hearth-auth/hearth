//! Phase D.4 integration tests — cross-realm trust policies.
//!
//! Covers:
//! - Policy CRUD (create / get / list / delete)
//! - Capability check returns true when policy permits
//! - Adversarial: capability not in policy returns false (trust bypass)
//! - Adversarial: expired policy is not respected (see D.4.9 below)

mod common;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{CreateCrossRealmPolicyRequest, CreateRealmRequest, IdentityError};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_realm(h: &TestHarness, suffix: &str) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("xrealm-{suffix}-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

// ── D.4.1: Create policy ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_cross_realm_policy_returns_policy_record() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    let policy = h
        .identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source.clone(),
                allowed_capabilities: vec!["search:read".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create cross-realm policy");

    assert!(!policy.policy_id.is_empty(), "policy_id must be assigned");
    assert_eq!(policy.source_realm_id, source);
    assert_eq!(policy.target_realm_id, target);
    assert_eq!(policy.allowed_capabilities, vec!["search:read"]);
    assert!(policy.expires_at.is_none(), "no expiry when not specified");
}

// ── D.4.2: Get policy ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_cross_realm_policy_returns_stored_record() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    let created = h
        .identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source,
                allowed_capabilities: vec!["email:send".to_string()],
                expires_in_secs: Some(3600),
            },
        )
        .expect("create");

    let fetched = h
        .identity()
        .get_cross_realm_policy(&target, &created.policy_id)
        .expect("get")
        .expect("policy must exist");

    assert_eq!(fetched.policy_id, created.policy_id);
    assert!(fetched.expires_at.is_some(), "expires_at must be set");
}

// ── D.4.3: List policies ─────────────────────────────────────────────────────

#[tokio::test]
async fn list_cross_realm_policies_returns_all_in_realm() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source_a = make_realm(&h, "src-a");
    let source_b = make_realm(&h, "src-b");

    h.identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source_a,
                allowed_capabilities: vec!["cap:a".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create A");

    h.identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source_b,
                allowed_capabilities: vec!["cap:b".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create B");

    let policies = h
        .identity()
        .list_cross_realm_policies(&target)
        .expect("list");

    assert_eq!(policies.len(), 2, "must list both policies");
}

// ── D.4.4: Delete policy ─────────────────────────────────────────────────────

#[tokio::test]
async fn delete_cross_realm_policy_removes_record() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    let policy = h
        .identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source,
                allowed_capabilities: vec!["cap".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create");

    h.identity()
        .delete_cross_realm_policy(&target, &policy.policy_id)
        .expect("delete");

    let fetched = h
        .identity()
        .get_cross_realm_policy(&target, &policy.policy_id)
        .expect("get after delete");

    assert!(fetched.is_none(), "policy must not exist after deletion");
}

// ── D.4.5: Delete nonexistent returns error ───────────────────────────────────

#[tokio::test]
async fn delete_nonexistent_cross_realm_policy_returns_error() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");

    let err = h
        .identity()
        .delete_cross_realm_policy(&target, &uuid::Uuid::new_v4().to_string())
        .expect_err("deleting nonexistent policy must fail");

    assert!(
        matches!(err, IdentityError::CrossRealmPolicyNotFound),
        "expected CrossRealmPolicyNotFound, got {err:?}"
    );
}

// ── D.4.6: Capability check — allowed ────────────────────────────────────────

#[tokio::test]
async fn check_cross_realm_policy_returns_true_for_permitted_capability() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    h.identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source.clone(),
                allowed_capabilities: vec!["search:read".to_string(), "email:send".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create policy");

    let allowed = h
        .identity()
        .check_cross_realm_policy(&target, &source, "search:read")
        .expect("check");

    assert!(allowed, "permitted capability must return true");
}

// ── D.4.7: Adversarial — capability not in policy ────────────────────────────

#[tokio::test]
async fn check_cross_realm_policy_returns_false_for_unpermitted_capability() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    h.identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source.clone(),
                allowed_capabilities: vec!["search:read".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("create policy");

    let allowed = h
        .identity()
        .check_cross_realm_policy(&target, &source, "admin:delete_all")
        .expect("check");

    assert!(
        !allowed,
        "capability not in policy must return false (trust bypass prevented)"
    );
}

// ── D.4.8: No policy = no access ─────────────────────────────────────────────

#[tokio::test]
async fn check_cross_realm_policy_returns_false_when_no_policy_exists() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    // No policy created.
    let allowed = h
        .identity()
        .check_cross_realm_policy(&target, &source, "any:capability")
        .expect("check");

    assert!(
        !allowed,
        "no policy must mean no access (no implicit trust)"
    );
}

// ── D.4.9: Expired policy is not respected ───────────────────────────────────

/// A cross-realm policy that has already expired must NOT grant access, even
/// when it would otherwise permit the requested capability.
///
/// The module doc claimed this was covered but no test existed. The engine's
/// `check_cross_realm_policy_inner` enforces `now >= exp → skip`; this test
/// exercises that branch with `expires_in_secs: 0` (expires at creation time,
/// so any subsequent check sees `now >= exp` as true).
#[tokio::test]
async fn check_cross_realm_policy_returns_false_for_expired_policy() {
    let h = TestHarness::embedded().await.expect("harness init");
    let target = make_realm(&h, "target");
    let source = make_realm(&h, "source");

    // Create a policy that expires the instant it is created (secs = 0).
    h.identity()
        .create_cross_realm_policy(
            &target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source.clone(),
                allowed_capabilities: vec!["data:read".to_string()],
                // expires_at = clock.now() + 0 → immediately expired for any
                // subsequent call where clock.now() >= expires_at.
                expires_in_secs: Some(0),
            },
        )
        .expect("create expired policy");

    // The capability IS listed in the policy, but the policy is expired — must
    // return false rather than granting access.
    let allowed = h
        .identity()
        .check_cross_realm_policy(&target, &source, "data:read")
        .expect("check");

    assert!(
        !allowed,
        "expired policy must not grant access even for a listed capability"
    );
}

// ── Task 25.15: legacy system-sourced policies are named at start-up ─────────
//
// Task 25.11 refuses to *author* a policy naming the system realm as its source
// unless a system-realm actor writes it. That guard is write-side only: a
// policy written before it shipped is still stored, is still consulted by
// `check_cross_realm_policy`, and still silently narrows what the platform
// operator may do inside that realm. `find_system_sourced_cross_realm_policies`
// is what the start-up path walks to name them; these tests pin its contract.

/// Writes a policy directly through the engine, bypassing the protocol-edge
/// guard 25.11 added — which is exactly how a pre-25.11 policy got there.
fn store_policy(h: &TestHarness, target: &RealmId, source: &RealmId, caps: &[&str]) -> String {
    h.identity()
        .create_cross_realm_policy(
            target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: source.clone(),
                allowed_capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
                expires_in_secs: None,
            },
        )
        .expect("create policy")
        .policy_id
}

#[tokio::test]
async fn system_sourced_policy_in_a_tenant_realm_is_reported() {
    let h = TestHarness::embedded().await.expect("harness");
    let tenant = make_realm(&h, "legacy-target");
    let policy_id = store_policy(
        &h,
        &tenant,
        &RealmId::new(uuid::Uuid::nil()),
        &["search:read"],
    );

    let found = hearth::identity::find_system_sourced_cross_realm_policies(h.identity());

    let hit = found
        .iter()
        .find(|p| p.policy_id == policy_id)
        .unwrap_or_else(|| {
            panic!(
                "a policy naming the system realm as its source in tenant realm \
                 {tenant:?} must be reported; got {found:?}"
            )
        });
    assert_eq!(
        hit.target_realm_id, tenant,
        "the report must name the realm that stores the policy, because that is \
         the realm the operator has been gated out of"
    );
    assert_eq!(
        hit.allowed_capabilities,
        vec!["search:read".to_string()],
        "the report must carry the capability list: an operator locked out of a \
         realm is looking at exactly this short list"
    );
}

#[tokio::test]
async fn tenant_to_tenant_policy_is_not_reported() {
    let h = TestHarness::embedded().await.expect("harness");
    let target = make_realm(&h, "t2t-target");
    let source = make_realm(&h, "t2t-source");
    let policy_id = store_policy(&h, &target, &source, &["search:read"]);

    let found = hearth::identity::find_system_sourced_cross_realm_policies(h.identity());
    assert!(
        !found.iter().any(|p| p.policy_id == policy_id),
        "an ordinary tenant-to-tenant policy does not gate the operator and must \
         not be reported; got {found:?}"
    );
}

#[tokio::test]
async fn a_realm_with_no_policies_reports_nothing_for_itself() {
    let h = TestHarness::embedded().await.expect("harness");
    let quiet = make_realm(&h, "quiet");

    let found = hearth::identity::find_system_sourced_cross_realm_policies(h.identity());
    assert!(
        !found.iter().any(|p| p.target_realm_id == quiet),
        "a realm with no stored policy must never appear in the report; got {found:?}"
    );
}
