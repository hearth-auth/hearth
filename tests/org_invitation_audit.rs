//! Task 26.17 (subsystem audit 2026-09-21, finding O-4) — the organisation
//! invitation lifecycle must leave an audit trail.
//!
//! At HEAD `create_invitation`, `accept_invitation` and `revoke_invitation`
//! contained zero `record_audit` calls and `AuditAction` had no variant they
//! could have used. This is the path by which an arbitrary external email
//! address becomes a member of an organisation with a chosen role — and,
//! when that address has no account, `accept_invitation` auto-creates the
//! user. The only traces were a `GroupMemberAdded` event from the delegated
//! `add_member` and a `UserCreated` event; nothing said who invited whom, for
//! which role, or that an invitation was later revoked.

mod common;

use hearth::audit::{AuditAction, AuditFailurePolicy, AuditQuery};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateInvitationRequest, CreateOrganizationRequest, CreateUserRequest, OrganizationConfig,
    OrganizationRole,
};

fn make_org(h: &common::TestHarness, realm: &RealmId, slug: &str) -> OrganizationId {
    h.identity()
        .create_organization(
            realm,
            &CreateOrganizationRequest {
                name: slug.to_string(),
                slug: slug.to_string(),
                description: None,
                config: Some(OrganizationConfig { max_members: None }),
                ..Default::default()
            },
        )
        .expect("create org")
        .id()
        .clone()
}

fn make_user(h: &common::TestHarness, realm: &RealmId) -> UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("inviter-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Inviter".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

/// Every audit event in the realm carrying `action`.
fn events_for(
    h: &common::TestHarness,
    realm: &RealmId,
    action: AuditAction,
) -> Vec<hearth::audit::AuditEvent> {
    h.audit()
        .query(&AuditQuery {
            action: Some(action),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query")
}

// ---------------------------------------------------------------------------
// Failure policy
// ---------------------------------------------------------------------------

#[test]
fn invitation_actions_carry_the_intended_failure_policies() {
    // Creating and accepting an invitation are grants. Every other grant in
    // this table (`OrgCreated`, `GroupMemberAdded`, `RoleAssigned`) is
    // LogOnly: the WAL is still the durable record and a logging outage must
    // not abort an onboarding flow whose membership write has already landed.
    assert_eq!(
        AuditAction::InvitationCreated.failure_policy(),
        AuditFailurePolicy::LogOnly
    );
    assert_eq!(
        AuditAction::InvitationAccepted.failure_policy(),
        AuditFailurePolicy::LogOnly
    );
    // Revocation is the security control. This table makes every revocation
    // (`RoleRevoked`, `ConsentRevoked`, `AgentCredentialRevoked`,
    // `AatRevoked`) FailOperation so a control can never be applied without a
    // record of it, and `tests/audit_discard_guard.rs` then forbids
    // discarding the write.
    assert_eq!(
        AuditAction::InvitationRevoked.failure_policy(),
        AuditFailurePolicy::FailOperation
    );
}

#[test]
fn invitation_actions_round_trip_through_the_wire_tag() {
    for action in [
        AuditAction::InvitationCreated,
        AuditAction::InvitationAccepted,
        AuditAction::InvitationRevoked,
    ] {
        let tag = action.as_str();
        assert_eq!(
            tag.parse::<AuditAction>().expect("parse wire tag"),
            action,
            "wire tag {tag} must round-trip"
        );
        assert!(
            AuditAction::all().contains(&action),
            "{action:?} missing from AuditAction::all(); the admin filter \
             dropdown would never offer it"
        );
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_invitation_is_audited_with_inviter_org_and_role() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-invite-create");
    let inviter = make_user(&h, &realm);

    let (invitation, _token) = h
        .identity()
        .create_invitation(
            &realm,
            &CreateInvitationRequest {
                org_id: org.clone(),
                email: "newcomer@example.com".to_string(),
                role: OrganizationRole::Admin,
                invited_by: inviter.clone(),
            },
        )
        .expect("create invitation");

    let events = events_for(&h, &realm, AuditAction::InvitationCreated);
    assert_eq!(events.len(), 1, "exactly one InvitationCreated event");
    let e = &events[0];
    assert_eq!(e.resource_type, "org_invitation");
    assert_eq!(e.resource_id, invitation.id().as_uuid().to_string());
    assert_eq!(
        e.actor,
        inviter.as_uuid().to_string(),
        "the invitation must be attributed to the inviter"
    );
    let meta = e.metadata.as_ref().expect("metadata present");
    assert_eq!(meta["org_id"], org.as_uuid().to_string());
    assert_eq!(meta["role"], "Admin");
    assert_eq!(
        meta["email"], "newcomer@example.com",
        "the invited address is the whole point of the record"
    );
}

#[tokio::test]
async fn accept_invitation_is_audited_with_the_user_it_provisioned() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-invite-accept");

    let (invitation, token) = h
        .identity()
        .create_invitation(
            &realm,
            &CreateInvitationRequest {
                org_id: org.clone(),
                email: "autocreated@example.com".to_string(),
                role: OrganizationRole::Member,
                invited_by: make_user(&h, &realm),
            },
        )
        .expect("create invitation");

    let membership = h
        .identity()
        .accept_invitation(&realm, &token)
        .expect("accept invitation");

    let events = events_for(&h, &realm, AuditAction::InvitationAccepted);
    assert_eq!(events.len(), 1, "exactly one InvitationAccepted event");
    let e = &events[0];
    assert_eq!(e.resource_type, "org_invitation");
    assert_eq!(e.resource_id, invitation.id().as_uuid().to_string());
    assert_eq!(
        e.actor,
        membership.user_id().as_uuid().to_string(),
        "acceptance is attributed to the user who accepted — including the \
         one auto-created for an unknown address"
    );
    let meta = e.metadata.as_ref().expect("metadata present");
    assert_eq!(meta["org_id"], org.as_uuid().to_string());
    assert_eq!(meta["role"], "Member");
    assert_eq!(
        meta["user_created"], true,
        "an acceptance that provisions a brand-new account must say so"
    );
}

#[tokio::test]
async fn revoke_invitation_is_audited() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let org = make_org(&h, &realm, "acme-invite-revoke");

    let (invitation, _token) = h
        .identity()
        .create_invitation(
            &realm,
            &CreateInvitationRequest {
                org_id: org.clone(),
                email: "revoked@example.com".to_string(),
                role: OrganizationRole::Member,
                invited_by: make_user(&h, &realm),
            },
        )
        .expect("create invitation");

    h.identity()
        .revoke_invitation(&realm, invitation.id())
        .expect("revoke invitation");

    let events = events_for(&h, &realm, AuditAction::InvitationRevoked);
    assert_eq!(events.len(), 1, "exactly one InvitationRevoked event");
    let e = &events[0];
    assert_eq!(e.resource_type, "org_invitation");
    assert_eq!(e.resource_id, invitation.id().as_uuid().to_string());
    let meta = e.metadata.as_ref().expect("metadata present");
    assert_eq!(meta["org_id"], org.as_uuid().to_string());

    // A second revoke is refused, so it must not append a second record.
    assert!(h
        .identity()
        .revoke_invitation(&realm, invitation.id())
        .is_err());
    assert_eq!(
        events_for(&h, &realm, AuditAction::InvitationRevoked).len(),
        1,
        "a refused revoke must not append an audit record"
    );
}
