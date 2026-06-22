//! Integration tests for Protected Resource registration (AGENT_AUTH.md §2.5 / B.1).
//!
//! Covers:
//! - B.1: CRUD for protected resources
//! - B.3: Scope list storage (PRM content is tested via the HTTP endpoint)
//! - B.2: resource_uri uniqueness within realm

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    IdentityEngine, IdentityError, RegisterProtectedResourceRequest, UpdateProtectedResourceRequest,
};

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: format!("pr-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_resource_request(uri: &str) -> RegisterProtectedResourceRequest {
    RegisterProtectedResourceRequest {
        resource_uri: uri.to_string(),
        display_name: format!("MCP Server at {uri}"),
        scopes: vec![
            "mcp:tools:invoke".to_string(),
            "mcp:resources:read".to_string(),
        ],
        required_claims: vec!["sub".to_string()],
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// B.1: Registration + retrieval
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_register_and_get() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let req = make_resource_request("https://mcp.example.com");
    let resource = identity
        .register_protected_resource(&realm_id, &req)
        .expect("register protected resource");

    assert_eq!(resource.resource_uri, "https://mcp.example.com");
    assert_eq!(resource.display_name, req.display_name);
    assert_eq!(resource.scopes, req.scopes);

    // Retrieve by ID
    let fetched = identity
        .get_protected_resource(&realm_id, &resource.id)
        .expect("get protected resource")
        .expect("should be present");

    assert_eq!(fetched.id, resource.id);
    assert_eq!(fetched.resource_uri, resource.resource_uri);
}

#[tokio::test]
async fn protected_resource_list() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let r1 = identity
        .register_protected_resource(
            &realm_id,
            &make_resource_request("https://mcp1.example.com"),
        )
        .expect("register r1");
    let r2 = identity
        .register_protected_resource(
            &realm_id,
            &make_resource_request("https://mcp2.example.com"),
        )
        .expect("register r2");

    let list = identity
        .list_protected_resources(&realm_id)
        .expect("list protected resources");

    assert_eq!(list.len(), 2);
    let ids: Vec<_> = list.iter().map(|r| &r.id).collect();
    assert!(ids.contains(&&r1.id));
    assert!(ids.contains(&&r2.id));
}

#[tokio::test]
async fn protected_resource_list_empty_initially() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let list = identity.list_protected_resources(&realm_id).expect("list");
    assert!(list.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────────
// B.2: resource_uri uniqueness within realm
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_duplicate_uri_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect("first registration");

    let err = identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect_err("duplicate URI should be rejected");

    assert!(
        matches!(err, IdentityError::DuplicateResourceUri),
        "expected DuplicateResourceUri, got: {err}"
    );
}

#[tokio::test]
async fn protected_resource_same_uri_allowed_in_different_realms() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_a = make_realm(identity);
    let realm_b = make_realm(identity);

    identity
        .register_protected_resource(&realm_a, &make_resource_request("https://mcp.example.com"))
        .expect("register in realm A");

    // Same URI in realm B should succeed (isolation).
    identity
        .register_protected_resource(&realm_b, &make_resource_request("https://mcp.example.com"))
        .expect("register same URI in realm B should succeed");
}

// ──────────────────────────────────────────────────────────────────────────────
// B.1: Update
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_update_display_name() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let resource = identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect("register");

    let updated = identity
        .update_protected_resource(
            &realm_id,
            &resource.id,
            &UpdateProtectedResourceRequest {
                display_name: Some("Updated Name".to_string()),
                scopes: None,
                required_claims: None,
            },
        )
        .expect("update");

    assert_eq!(updated.display_name, "Updated Name");
    // Other fields unchanged
    assert_eq!(updated.resource_uri, "https://mcp.example.com");
    assert_eq!(updated.scopes, resource.scopes);
}

#[tokio::test]
async fn protected_resource_update_scopes() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let resource = identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect("register");

    let new_scopes = vec![
        "mcp:tools:invoke".to_string(),
        "mcp:prompts:read".to_string(),
    ];
    let updated = identity
        .update_protected_resource(
            &realm_id,
            &resource.id,
            &UpdateProtectedResourceRequest {
                display_name: None,
                scopes: Some(new_scopes.clone()),
                required_claims: None,
            },
        )
        .expect("update scopes");

    assert_eq!(updated.scopes, new_scopes);
}

#[tokio::test]
async fn protected_resource_update_not_found_returns_error() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let fake_id = hearth::core::ResourceServerId::generate();
    let err = identity
        .update_protected_resource(
            &realm_id,
            &fake_id,
            &UpdateProtectedResourceRequest::default(),
        )
        .expect_err("non-existent resource should error");

    assert!(
        matches!(err, IdentityError::ProtectedResourceNotFound),
        "expected ProtectedResourceNotFound, got: {err}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// B.1: Deletion
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_delete() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let resource = identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect("register");

    identity
        .delete_protected_resource(&realm_id, &resource.id)
        .expect("delete");

    // Resource should no longer be retrievable.
    let fetched = identity
        .get_protected_resource(&realm_id, &resource.id)
        .expect("get after delete should not error");
    assert!(
        fetched.is_none(),
        "resource should be absent after deletion"
    );

    // The URI index should be cleared — re-registering same URI should succeed.
    identity
        .register_protected_resource(&realm_id, &make_resource_request("https://mcp.example.com"))
        .expect("re-register after delete should succeed");
}

#[tokio::test]
async fn protected_resource_delete_not_found_returns_error() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let fake_id = hearth::core::ResourceServerId::generate();
    let err = identity
        .delete_protected_resource(&realm_id, &fake_id)
        .expect_err("deleting non-existent resource should error");

    assert!(
        matches!(err, IdentityError::ProtectedResourceNotFound),
        "expected ProtectedResourceNotFound, got: {err}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// B.1: Validation
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_empty_uri_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let req = RegisterProtectedResourceRequest {
        resource_uri: String::new(),
        display_name: "Test".to_string(),
        scopes: vec![],
        required_claims: vec![],
    };

    let err = identity
        .register_protected_resource(&realm_id, &req)
        .expect_err("empty URI should be rejected");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );
}

#[tokio::test]
async fn protected_resource_relative_uri_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_id = make_realm(identity);

    let req = RegisterProtectedResourceRequest {
        resource_uri: "/relative/path".to_string(),
        display_name: "Test".to_string(),
        scopes: vec![],
        required_claims: vec![],
    };

    let err = identity
        .register_protected_resource(&realm_id, &req)
        .expect_err("relative URI should be rejected");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Realm isolation: resources from realm A invisible to realm B
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_realm_isolation() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("test setup failed");
    let identity = harness.identity();
    let realm_a = make_realm(identity);
    let realm_b = make_realm(identity);

    let resource_a = identity
        .register_protected_resource(
            &realm_a,
            &make_resource_request("https://mcp-a.example.com"),
        )
        .expect("register in realm A");

    // Realm B should not see realm A's resource.
    let fetched = identity
        .get_protected_resource(&realm_b, &resource_a.id)
        .expect("get from realm B should not error");
    assert!(
        fetched.is_none(),
        "realm B should not see realm A's resource"
    );

    let list_b = identity
        .list_protected_resources(&realm_b)
        .expect("list in realm B");
    assert!(list_b.is_empty(), "realm B list should be empty");
}
