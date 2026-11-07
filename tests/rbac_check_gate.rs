//! #636: the `rbac_check` bench's `resolve_permissions` gate times the RBAC
//! engine's `resolve_permissions` for the spec's typical user (5 roles,
//! 10 groups, 30 permissions), not a bench-local JWT decode.
//!
//! The gate and this test share the fixture and the timed operation, so this
//! test checks what the gate measures.

#[path = "../benches/support/rbac_typical_user.rs"]
mod typical_user;

use typical_user::{TypicalUser, GROUPS, PERMISSIONS, ROLES};

#[test]
fn the_gate_times_the_engine_resolution_of_the_typical_user() {
    let mut fixture = TypicalUser::build();
    let resolved = fixture.resolve();
    assert_eq!(resolved.roles.len(), ROLES, "roles: {:?}", resolved.roles);
    assert_eq!(
        resolved.groups.len(),
        GROUPS,
        "groups: {:?}",
        resolved.groups
    );
    assert_eq!(
        resolved.permissions.len(),
        PERMISSIONS,
        "permissions: {:?}",
        resolved.permissions
    );
    assert_eq!(
        (ROLES, GROUPS, PERMISSIONS),
        (5, 10, 30),
        "the spec's typical user"
    );

    // The untimed write between samples does not change the user's answer.
    fixture.invalidate();
    assert_eq!(fixture.resolve(), resolved);
}

/// The gate in `benches/rbac_check.rs` builds the typical user and times its
/// resolution. Before #636 it timed `do_jwt_lookup`, a base64 + JSON decode of
/// a forged token that never reached the RBAC engine.
#[test]
fn the_resolve_permissions_gate_times_the_typical_user() {
    let bench = include_str!("../benches/rbac_check.rs");
    let gate = bench
        .split("fn gate_resolve_permissions_p99()")
        .nth(1)
        .expect("benches/rbac_check.rs has gate_resolve_permissions_p99")
        .split("\nfn ")
        .next()
        .expect("the gate body");
    assert!(
        gate.contains("TypicalUser::build()") && gate.contains(".resolve()"),
        "the gate must time TypicalUser::resolve:\n{gate}"
    );
    assert!(
        !gate.contains("do_jwt_lookup"),
        "the gate must not time the bench-local JWT decode:\n{gate}"
    );
}
