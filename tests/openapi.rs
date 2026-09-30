//! OpenAPI spec serving and parity gate tests (HEA-972).
//!
//! These tests verify that:
//! - The merged spec is valid JSON and parses as OpenAPI 3.0.
//! - The supplement YAML parses as valid OpenAPI 3.0.
//! - Key routes from both proto-derived and supplement sources appear in
//!   the merged spec.
//! - Routes in `grpc-only.txt` have no REST path in the merged spec.
//! - The `/docs` endpoint path is present (Swagger UI).
//!
//! # Parity gate
//! The tests here serve as a lightweight drift gate between the Axum router
//! and the committed spec.  For every checked route the constant list below
//! must stay in sync with the actual route table in `src/protocol/http.rs`.

use hearth::protocol::web::openapi::{MERGED_SPEC_JSON, SUPPLEMENT_SPEC};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn merged() -> Value {
    serde_json::from_str(MERGED_SPEC_JSON).expect("MERGED_SPEC_JSON must be valid JSON")
}

// ---------------------------------------------------------------------------
// Format invariants
// ---------------------------------------------------------------------------

#[test]
fn merged_spec_is_openapi3() {
    let v = merged();
    assert_eq!(
        v["openapi"].as_str().unwrap_or(""),
        "3.0.3",
        "merged spec must declare openapi: 3.0.3"
    );
}

#[test]
fn merged_spec_has_info_title() {
    let v = merged();
    let title = v["info"]["title"].as_str().unwrap_or("");
    assert!(
        !title.is_empty(),
        "merged spec must have a non-empty info.title"
    );
    assert!(
        !title.contains("supplement"),
        "merged spec title must not say 'supplement': got {title}"
    );
}

#[test]
fn merged_spec_has_paths_object() {
    let v = merged();
    let paths = v["paths"]
        .as_object()
        .expect("merged spec must have 'paths' object");
    assert!(
        paths.len() > 30,
        "merged spec should have >30 paths, got {}",
        paths.len()
    );
}

#[test]
fn supplement_spec_parses_as_valid_yaml() {
    // Confirm the raw embedded YAML is syntactically valid.
    let v: serde_norway::Value =
        serde_norway::from_str(SUPPLEMENT_SPEC).expect("SUPPLEMENT_SPEC must be valid YAML");
    assert!(v.is_mapping(), "supplement must be a YAML mapping at root");
}

// ---------------------------------------------------------------------------
// Coverage: supplement-sourced (non-proto) routes
// ---------------------------------------------------------------------------

/// These paths come exclusively from the hand-written supplement.
/// If any of them disappear the supplement is broken.
#[test]
fn supplement_routes_present_in_merged_spec() {
    let v = merged();
    let paths = v["paths"].as_object().expect("paths");

    let supplement_paths = [
        "/health",
        "/healthz",
        "/readyz",
        "/metrics",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/jwks",
        "/token",
        "/authorize",
        "/revoke",
        "/introspect",
        "/userinfo",
        "/v1/me/permissions",
        "/webauthn/register/begin",
        "/webauthn/register/complete",
        "/webauthn/auth/begin",
        "/webauthn/auth/complete",
        "/webauthn/credentials",
        "/scim/v2/Users",
        "/scim/v2/Groups",
        "/admin/bootstrap",
        "/openapi.json",
        "/openapi.yaml",
        "/docs",
    ];

    let mut missing = Vec::new();
    for path in supplement_paths {
        if !paths.contains_key(path) {
            missing.push(path);
        }
    }
    assert!(
        missing.is_empty(),
        "supplement routes missing from merged spec: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// Coverage: proto-derived routes
// ---------------------------------------------------------------------------

/// These paths come from proto `google.api.http` annotations.
/// If any disappear, the proto-derived JSON generation is broken.
#[test]
fn proto_derived_routes_present_in_merged_spec() {
    let v = merged();
    let paths = v["paths"].as_object().expect("paths");

    let proto_paths = [
        "/admin/users",
        "/admin/users/{id}",
        "/admin/realms",
        "/admin/realms/{id}",
        "/admin/applications",
        "/admin/applications/{clientId}",
        "/admin/roles",
        "/admin/roles/{roleId}",
        "/admin/groups",
        "/admin/groups/{groupId}",
        "/admin/audit",
    ];

    let mut missing = Vec::new();
    for path in proto_paths {
        if !paths.contains_key(path) {
            missing.push(path);
        }
    }
    assert!(
        missing.is_empty(),
        "proto-derived routes missing from merged spec: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// Parity gate: gRPC-only routes absent from merged REST spec
// ---------------------------------------------------------------------------

/// Routes that are intentionally gRPC-only (listed in docs/api/grpc-only.txt)
/// must not appear as REST paths in the merged spec.  If they do, either
/// grpc-only.txt needs updating or the supplement has a stale entry.
#[test]
fn grpc_only_routes_absent_from_merged_rest_spec() {
    let v = merged();
    let paths = v["paths"].as_object().expect("paths");

    // Organization admin endpoints are gRPC-only (see grpc-only.txt).
    // The REST path would be /admin/organizations if we had wired it.
    let grpc_only_axum_paths = ["/admin/organizations", "/admin/organizations/{id}"];

    for path in grpc_only_axum_paths {
        if let Some(item) = paths.get(path) {
            // If the path exists it must not have a GET or POST — those would
            // indicate we accidentally wired a REST route for a gRPC-only RPC.
            assert!(
                item.get("get").is_none() && item.get("post").is_none(),
                "gRPC-only path {path} must not have GET or POST in merged REST spec"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Swagger UI endpoint
// ---------------------------------------------------------------------------

#[test]
fn docs_path_has_get_operation() {
    let v = merged();
    assert!(
        v["paths"]["/docs"]["get"].is_object(),
        "/docs must have a GET operation for Swagger UI"
    );
}

// ---------------------------------------------------------------------------
// YAML-managed realms (GA audit round 3, G-7)
// ---------------------------------------------------------------------------

/// Realms are declared in `hearth.yaml`: REST `POST /admin/realms` and
/// `PATCH /admin/realms/{id}` answer `405`, gRPC `CreateRealm` / `UpdateRealm`
/// answer `FAILED_PRECONDITION`. The spec must not advertise them as working
/// `200` operations, while the realm reads and the archived-realm purge stay.
#[test]
fn yaml_managed_realm_writes_are_not_documented() {
    let v = merged();
    let paths = v["paths"].as_object().expect("paths");

    let mut advertised = Vec::new();
    for (path, item) in paths {
        for (method, op) in item.as_object().into_iter().flatten() {
            let id = op["operationId"].as_str().unwrap_or_default();
            if matches!(
                id,
                "IdentityAdminService_CreateRealm" | "IdentityAdminService_UpdateRealm"
            ) {
                advertised.push(format!("{method} {path} ({id})"));
            }
        }
    }
    assert!(
        advertised.is_empty(),
        "realm writes must not be documented: {advertised:?}"
    );

    assert!(v["paths"]["/admin/realms"]["get"].is_object(), "ListRealms");
    assert!(
        v["paths"]["/admin/realms/{id}"]["get"].is_object(),
        "GetRealm"
    );
    assert!(
        v["paths"]["/admin/realms/{id}"]["delete"].is_object(),
        "DeleteRealm"
    );
}

// ---------------------------------------------------------------------------
// Client registration routes answer 201 Created
// ---------------------------------------------------------------------------

/// The client-create routes answer `201 Created` (SDK.md requires SDKs to
/// treat 201 as success); the spec documented `200`, so a generated client
/// that checks the documented status treated every creation as unexpected.
/// The secret-regeneration route answers `200` with the client record.
#[test]
fn client_create_routes_document_201_and_regeneration_200() {
    let v = merged();
    for path in ["/admin/applications", "/clients", "/register"] {
        let responses = v["paths"][path]["post"]["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("POST {path} has responses"));
        assert!(responses.contains_key("201"), "POST {path}: {responses:?}");
        assert!(!responses.contains_key("200"), "POST {path}: {responses:?}");
    }
    let regen = &v["paths"]["/admin/applications/{clientId}/regenerate-secret"]["post"];
    assert_eq!(
        regen["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/v1OAuthClient",
        "{regen}"
    );
}
