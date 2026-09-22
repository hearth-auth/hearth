#![allow(clippy::unwrap_used)]
//! Task 26.9 (raised by the 23.9 gRPC audit, finding G-4) — the reflection gate
//! must authenticate, not merely notice a header.
//!
//! `grpc_reflection_auth_interceptor`'s whole check was that the
//! `authorization` value starts with `"Bearer "` and is longer than that. So
//! `Bearer x` passed. Its own doc comment says the gate exists to "prevent
//! anonymous schema enumeration", and an attacker supplying eight characters is
//! anonymous by any definition: nothing looked up the token, no realm was
//! consulted, and no permission was checked.
//!
//! Reflection publishes the full service and message schema of every admin RPC,
//! so this is a reconnaissance surface, not a cosmetic one.
//!
//! Each test names what it distinguishes. The last one is the control: without
//! it, refusing everything would pass the first three.

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::server::{grpc_reflection_auth_interceptor, GrpcState};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use tonic::{Code, Request};

struct Ctx {
    _h: common::TestHarness,
    state: GrpcState,
    realm: RealmId,
    token: String,
}

/// Builds a realm with one realm-admin user and returns that user's token.
async fn ctx() -> Ctx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("refl-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Reflector".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seed");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();
    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    Ctx {
        _h: h,
        state,
        realm,
        token,
    }
}

/// Builds a reflection request carrying the given metadata.
fn request(authorization: Option<&str>, realm: Option<&RealmId>) -> Request<()> {
    let mut req = Request::new(());
    if let Some(value) = authorization {
        req.metadata_mut()
            .insert("authorization", value.parse().expect("auth meta"));
    }
    if let Some(r) = realm {
        req.metadata_mut().insert(
            "x-realm-id",
            r.as_uuid().to_string().parse().expect("realm meta"),
        );
    }
    req
}

/// The finding itself: eight characters of nothing used to be enough.
#[tokio::test]
async fn reflection_refuses_a_bearer_that_is_not_a_token() {
    let ctx = ctx().await;
    let gate = grpc_reflection_auth_interceptor(ctx.state.clone());

    let err = gate(request(Some("Bearer x"), Some(&ctx.realm)))
        .expect_err("`Bearer x` is not a token and must be refused");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// A well-formed but unissued token must fail too, or the gate is only
/// checking shape.
#[tokio::test]
async fn reflection_refuses_a_forged_token() {
    let ctx = ctx().await;
    let gate = grpc_reflection_auth_interceptor(ctx.state.clone());

    // Same three-segment shape as a real JWT, signed by nobody.
    let forged = "eyJhbGciOiJFZDI1NTE5In0.eyJzdWIiOiJ1c2VyX2ZvcmdlZCJ9.bm90LWEtc2lnbmF0dXJl";
    let err = gate(request(Some(&format!("Bearer {forged}")), Some(&ctx.realm)))
        .expect_err("a token nobody issued must be refused");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// A real token with no realm header must fail: the token is only meaningful
/// against the realm that issued it.
#[tokio::test]
async fn reflection_refuses_a_real_token_with_no_realm() {
    let ctx = ctx().await;
    let gate = grpc_reflection_auth_interceptor(ctx.state.clone());

    let err = gate(request(Some(&format!("Bearer {}", ctx.token)), None))
        .expect_err("a token with no realm to validate it against must be refused");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// Control — a real admin token still gets through.
///
/// Without this, a gate that refused every request would pass all three tests
/// above while silently removing reflection from the operators who need it.
#[tokio::test]
async fn reflection_admits_a_real_admin_token() {
    let ctx = ctx().await;
    let gate = grpc_reflection_auth_interceptor(ctx.state.clone());

    assert!(
        gate(request(
            Some(&format!("Bearer {}", ctx.token)),
            Some(&ctx.realm)
        ))
        .is_ok(),
        "a valid realm-admin token must still be able to use reflection"
    );
}
