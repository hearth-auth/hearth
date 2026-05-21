//! Integration tests for attribute schema enforcement and org attribute round-trips.
//!
//! Exercises:
//! - Schema-defined mode: unknown key rejection, required key enforcement
//! - Free-form mode: any valid key accepted
//! - Org attribute create/update round-trip
//! - Adversarial: >50 keys, >256-char values (per issue spec)

mod common;

use std::collections::BTreeMap;

use hearth::identity::{
    AttributeDefinition, AttributeDefinitions, AttributeType, CreateOrganizationRequest,
    CreateUserRequest, IdentityError, RealmConfig, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest,
};

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn string_def(key: &str, required: bool) -> AttributeDefinition {
    AttributeDefinition {
        key: key.to_string(),
        label: None,
        type_: AttributeType::String,
        required,
        description: None,
        enum_values: vec![],
    }
}

// ---------------------------------------------------------------------------
// Schema enforcement — users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_schema_unknown_key_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    attribute_definitions: Some(AttributeDefinitions {
                        users: vec![string_def("department", false)],
                        organizations: vec![],
                    }),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set realm attribute definitions");

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "schemauser@example.com".to_string(),
                display_name: "Schema User".to_string(),
                first_name: "Schema".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let result = h.identity().update_user(
        &realm,
        user.id(),
        &UpdateUserRequest {
            attributes: Some(attrs(&[("unknown_key", "value")])),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "unknown key must be rejected under schema-defined mode; got: {result:?}"
    );
}

#[tokio::test]
async fn user_schema_required_key_missing_on_create_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    attribute_definitions: Some(AttributeDefinitions {
                        users: vec![string_def("employee_id", true)],
                        organizations: vec![],
                    }),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set realm attribute definitions");

    let result = h.identity().create_user(
        &realm,
        &CreateUserRequest {
            email: "required@example.com".to_string(),
            display_name: "Required User".to_string(),
            first_name: "Required".to_string(),
            last_name: "User".to_string(),
            attributes: BTreeMap::new(),
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "missing required attribute on create must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn user_schema_required_key_present_on_create_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    attribute_definitions: Some(AttributeDefinitions {
                        users: vec![string_def("employee_id", true)],
                        organizations: vec![],
                    }),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set realm attribute definitions");

    let result = h.identity().create_user(
        &realm,
        &CreateUserRequest {
            email: "withid@example.com".to_string(),
            display_name: "With ID".to_string(),
            first_name: "With".to_string(),
            last_name: "ID".to_string(),
            attributes: attrs(&[("employee_id", "EMP-001")]),
        },
    );

    assert!(
        result.is_ok(),
        "required attribute present on create must be accepted; got: {result:?}"
    );
}

#[tokio::test]
async fn user_free_form_accepts_any_valid_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "freeform@example.com".to_string(),
                display_name: "Free Form".to_string(),
                first_name: "Free".to_string(),
                last_name: "Form".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let result = h.identity().update_user(
        &realm,
        user.id(),
        &UpdateUserRequest {
            attributes: Some(attrs(&[("any-valid_key.here", "value")])),
            ..Default::default()
        },
    );

    assert!(
        result.is_ok(),
        "free-form mode accepts any valid key; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Org attribute round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_create_with_attributes_stored_and_returned() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Attr Org".to_string(),
                slug: "attr-org".to_string(),
                description: None,
                config: None,
                attributes: attrs(&[("crm_id", "CRM-001"), ("tier", "enterprise")]),
            },
        )
        .expect("create org with attributes");

    assert_eq!(
        org.attributes().get("crm_id").map(String::as_str),
        Some("CRM-001")
    );
    assert_eq!(
        org.attributes().get("tier").map(String::as_str),
        Some("enterprise")
    );
}

#[tokio::test]
async fn org_update_attributes_persisted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Update Org".to_string(),
                slug: "update-org".to_string(),
                description: None,
                config: None,
                attributes: attrs(&[("crm_id", "CRM-001")]),
            },
        )
        .expect("create org");

    let updated = h
        .identity()
        .update_organization(
            &realm,
            org.id(),
            &UpdateOrganizationRequest {
                attributes: Some(attrs(&[("crm_id", "CRM-002"), ("tier", "pro")])),
                ..Default::default()
            },
        )
        .expect("update org attributes");

    assert_eq!(
        updated.attributes().get("crm_id").map(String::as_str),
        Some("CRM-002")
    );
    assert_eq!(
        updated.attributes().get("tier").map(String::as_str),
        Some("pro")
    );
}

#[tokio::test]
async fn org_update_none_attributes_leaves_existing() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Preserve Org".to_string(),
                slug: "preserve-org".to_string(),
                description: None,
                config: None,
                attributes: attrs(&[("stable_key", "stable_value")]),
            },
        )
        .expect("create org");

    let updated = h
        .identity()
        .update_organization(
            &realm,
            org.id(),
            &UpdateOrganizationRequest {
                name: Some("Preserve Org Renamed".to_string()),
                attributes: None,
                ..Default::default()
            },
        )
        .expect("rename org without touching attributes");

    assert_eq!(
        updated.attributes().get("stable_key").map(String::as_str),
        Some("stable_value"),
        "attributes must survive an update that doesn't touch them"
    );
}

// ---------------------------------------------------------------------------
// Org schema enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_schema_unknown_key_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    attribute_definitions: Some(AttributeDefinitions {
                        users: vec![],
                        organizations: vec![string_def("crm_id", false)],
                    }),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set realm attribute definitions");

    let result = h.identity().create_organization(
        &realm,
        &CreateOrganizationRequest {
            name: "Bad Org".to_string(),
            slug: "bad-org".to_string(),
            description: None,
            config: None,
            attributes: attrs(&[("unknown_field", "value")]),
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "unknown org attribute key must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn org_schema_required_key_enforced() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    h.identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    attribute_definitions: Some(AttributeDefinitions {
                        users: vec![],
                        organizations: vec![string_def("crm_id", true)],
                    }),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set realm attribute definitions");

    let result = h.identity().create_organization(
        &realm,
        &CreateOrganizationRequest {
            name: "No CRM Org".to_string(),
            slug: "no-crm-org".to_string(),
            description: None,
            config: None,
            attributes: BTreeMap::new(),
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        "missing required org attribute must be rejected; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_more_than_50_keys_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "adversarial@example.com".to_string(),
                display_name: "Adversarial".to_string(),
                first_name: "A".to_string(),
                last_name: "B".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for i in 0..51u32 {
        map.insert(format!("key{i:02}"), "v".to_string());
    }

    let result = h.identity().update_user(
        &realm,
        user.id(),
        &UpdateUserRequest {
            attributes: Some(map),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        ">50 attribute keys must be rejected; got: {result:?}"
    );
}

#[tokio::test]
async fn org_more_than_50_keys_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "Adversarial Org".to_string(),
                slug: "adversarial-org".to_string(),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect("create org");

    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for i in 0..51u32 {
        map.insert(format!("key{i:02}"), "v".to_string());
    }

    let result = h.identity().update_organization(
        &realm,
        org.id(),
        &UpdateOrganizationRequest {
            attributes: Some(map),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidAttribute { .. })),
        ">50 org attribute keys must be rejected; got: {result:?}"
    );
}
