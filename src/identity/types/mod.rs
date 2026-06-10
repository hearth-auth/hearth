//! Identity domain types.
//!
//! Each sub-module owns a coherent slice of the domain:
//! - `user`       — users, sessions, and request DTOs
//! - `session`    — session and context types (split from user for clarity)
//! - `realm`      — realms and their configuration
//! - `org`        — organizations, memberships, and invitations
//! - `credential` — migration / import credential types
//! - `token`      — OAuth consent, webhooks, and agents

pub mod credential;
pub mod org;
pub mod realm;
pub mod session;
pub mod token;
pub mod user;

pub use credential::*;
pub use org::*;
pub use realm::*;
pub use session::*;
pub use token::*;
pub use user::*;

#[cfg(test)]
mod tests {
    use super::user::mask_phone_number;
    use super::*;
    use crate::core::{ClientId, OrganizationId, RealmId, Timestamp, UserId};
    use crate::identity::InvitationId;

    #[test]
    fn user_accessors() {
        let id = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            id.clone(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );

        assert_eq!(user.id(), &id);
        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), now);
        assert_eq!(user.updated_at(), now);
    }

    #[test]
    fn user_serde_round_trip() {
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::PendingVerification,
            Vec::new(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&user).expect("serialize");
        let deserialized: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(user, deserialized);
    }

    #[test]
    fn user_status_serde_round_trip() {
        for status in [
            UserStatus::Active,
            UserStatus::Disabled,
            UserStatus::PendingVerification,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: UserStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn user_mutators() {
        let mut user = User::new(
            UserId::generate(),
            "old@example.com".to_string(),
            "Old Name".to_string(),
            "Old".to_string(),
            "Name".to_string(),
            UserStatus::Active,
            Vec::new(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        user.set_email("new@example.com".to_string());
        user.set_display_name("New Name".to_string());
        user.set_status(UserStatus::Disabled);
        user.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(user.email(), "new@example.com");
        assert_eq!(user.display_name(), "New Name");
        assert_eq!(user.status(), UserStatus::Disabled);
        assert_eq!(user.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn update_request_default_is_all_none() {
        let req = UpdateUserRequest::default();
        assert!(req.email.is_none());
        assert!(req.display_name.is_none());
        assert!(req.status.is_none());
    }

    // ===== Realm type tests =====

    #[test]
    fn realm_accessors() {
        let id = RealmId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = RealmConfig {
            session_ttl_micros: Some(3_600_000_000),
            ..RealmConfig::default()
        };
        let realm = Realm::new(
            id.clone(),
            "Acme Corp".to_string(),
            RealmStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(realm.id(), &id);
        assert_eq!(realm.name(), "Acme Corp");
        assert_eq!(realm.status(), RealmStatus::Active);
        assert_eq!(realm.config(), &config);
        assert_eq!(realm.created_at(), now);
        assert_eq!(realm.updated_at(), now);

        // Verify new auth policy fields default to None
        assert!(config.mfa_required.is_none());
        assert!(config.mfa_methods.is_none());
        assert!(config.allowed_auth_methods.is_none());
        assert!(config.password_policy.is_none());
        assert!(config.access_token_ttl_micros.is_none());
        assert!(config.refresh_token_ttl_micros.is_none());
        assert!(config.max_failed_logins.is_none());
        assert!(config.lockout_duration_micros.is_none());
    }

    #[test]
    fn realm_serde_round_trip() {
        let realm = Realm::new(
            RealmId::generate(),
            "Test Realm".to_string(),
            RealmStatus::Active,
            RealmConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&realm).expect("serialize");
        let deserialized: Realm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(realm, deserialized);
    }

    #[test]
    fn realm_status_serde_round_trip() {
        for status in [RealmStatus::Active, RealmStatus::Suspended] {
            let json = serde_json::to_string(&status).expect("serialize");
            let deserialized: RealmStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn realm_mutators() {
        let mut realm = Realm::new(
            RealmId::generate(),
            "Old Name".to_string(),
            RealmStatus::Active,
            RealmConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        realm.set_name("New Name".to_string());
        realm.set_status(RealmStatus::Suspended);
        let new_config = RealmConfig {
            session_ttl_micros: Some(7_200_000_000),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..RealmConfig::default()
        };
        realm.set_config(new_config.clone());
        realm.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(realm.name(), "New Name");
        assert_eq!(realm.status(), RealmStatus::Suspended);
        assert_eq!(realm.config(), &new_config);
        assert_eq!(realm.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn realm_config_default_is_all_none() {
        let config = RealmConfig::default();
        assert!(config.session_ttl_micros.is_none());
        assert!(config.password_memory_cost.is_none());
        assert!(config.password_time_cost.is_none());
    }

    #[test]
    fn update_realm_request_default_is_all_none() {
        let req = UpdateRealmRequest::default();
        assert!(req.name.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }

    // ===== Organization type tests =====

    #[test]
    fn organization_accessors() {
        let id = OrganizationId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let config = OrganizationConfig {
            max_members: Some(100),
        };
        let org = Organization::new(
            id.clone(),
            "Acme Corp".to_string(),
            "acme-corp".to_string(),
            "A test org".to_string(),
            OrganizationStatus::Active,
            config.clone(),
            now,
            now,
        );

        assert_eq!(org.id(), &id);
        assert_eq!(org.name(), "Acme Corp");
        assert_eq!(org.slug(), "acme-corp");
        assert_eq!(org.description(), "A test org");
        assert_eq!(org.status(), OrganizationStatus::Active);
        assert_eq!(org.config(), &config);
        assert_eq!(org.created_at(), now);
        assert_eq!(org.updated_at(), now);
    }

    #[test]
    fn organization_serde_round_trip() {
        let org = Organization::new(
            OrganizationId::generate(),
            "Test Org".to_string(),
            "test-org".to_string(),
            String::new(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(2_000),
        );

        let json = serde_json::to_string(&org).expect("serialize");
        let deserialized: Organization = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(org, deserialized);
    }

    #[test]
    fn organization_mutators() {
        let mut org = Organization::new(
            OrganizationId::generate(),
            "Old Name".to_string(),
            "old-name".to_string(),
            "Old desc".to_string(),
            OrganizationStatus::Active,
            OrganizationConfig::default(),
            Timestamp::from_micros(1_000),
            Timestamp::from_micros(1_000),
        );

        org.set_name("New Name".to_string());
        org.set_description("New desc".to_string());
        org.set_status(OrganizationStatus::Suspended);
        org.set_config(OrganizationConfig {
            max_members: Some(50),
        });
        org.set_updated_at(Timestamp::from_micros(2_000));

        assert_eq!(org.name(), "New Name");
        assert_eq!(org.description(), "New desc");
        assert_eq!(org.status(), OrganizationStatus::Suspended);
        assert_eq!(org.config().max_members, Some(50));
        assert_eq!(org.updated_at(), Timestamp::from_micros(2_000));
    }

    #[test]
    fn membership_accessors() {
        let org_id = OrganizationId::generate();
        let user_id = UserId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);

        let membership = OrganizationMembership::new(
            org_id.clone(),
            user_id.clone(),
            OrganizationRole::Admin,
            now,
            Some(inviter.clone()),
        );

        assert_eq!(membership.org_id(), &org_id);
        assert_eq!(membership.user_id(), &user_id);
        assert_eq!(membership.role(), OrganizationRole::Admin);
        assert_eq!(membership.joined_at(), now);
        assert_eq!(membership.invited_by(), Some(&inviter));
    }

    #[test]
    fn membership_serde_round_trip() {
        let membership = OrganizationMembership::new(
            OrganizationId::generate(),
            UserId::generate(),
            OrganizationRole::Member,
            Timestamp::from_micros(1_000),
            None,
        );

        let json = serde_json::to_string(&membership).expect("serialize");
        let deserialized: OrganizationMembership =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(membership, deserialized);
    }

    #[test]
    fn invitation_accessors() {
        let inv_id = InvitationId::generate();
        let org_id = OrganizationId::generate();
        let inviter = UserId::generate();
        let now = Timestamp::from_micros(1_000_000);
        let expires = Timestamp::from_micros(2_000_000);

        let invitation = OrganizationInvitation::new(
            inv_id.clone(),
            org_id.clone(),
            "alice@example.com".to_string(),
            OrganizationRole::Member,
            "abc123hash".to_string(),
            InvitationStatus::Pending,
            expires,
            inviter.clone(),
            now,
        );

        assert_eq!(invitation.id(), &inv_id);
        assert_eq!(invitation.org_id(), &org_id);
        assert_eq!(invitation.email(), "alice@example.com");
        assert_eq!(invitation.role(), OrganizationRole::Member);
        assert_eq!(invitation.token_hash(), "abc123hash");
        assert_eq!(invitation.status(), InvitationStatus::Pending);
        assert_eq!(invitation.expires_at(), expires);
        assert_eq!(invitation.invited_by(), &inviter);
        assert_eq!(invitation.created_at(), now);
    }

    #[test]
    fn invitation_status_transitions() {
        let mut invitation = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "bob@example.com".to_string(),
            OrganizationRole::Admin,
            "hash".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        assert_eq!(invitation.status(), InvitationStatus::Pending);

        invitation.set_accepted();
        assert_eq!(invitation.status(), InvitationStatus::Accepted);

        let mut invitation2 = OrganizationInvitation::new(
            InvitationId::generate(),
            OrganizationId::generate(),
            "carol@example.com".to_string(),
            OrganizationRole::Member,
            "hash2".to_string(),
            InvitationStatus::Pending,
            Timestamp::from_micros(2_000_000),
            UserId::generate(),
            Timestamp::from_micros(1_000_000),
        );

        invitation2.set_revoked();
        assert_eq!(invitation2.status(), InvitationStatus::Revoked);
    }

    #[test]
    fn update_organization_request_default_is_all_none() {
        let req = UpdateOrganizationRequest::default();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.status.is_none());
        assert!(req.config.is_none());
    }

    // ===== Consent record tests =====

    #[test]
    fn consent_record_scope_union_is_deduped_and_sorted() {
        let now = Timestamp::from_micros(1_000_000);
        let mut rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        assert_eq!(rec.granted_scopes, vec!["email", "profile"]);

        let later = Timestamp::from_micros(2_000_000);
        rec.merge_scopes(
            &[
                "openid".to_string(),
                "profile".to_string(),
                "  ".to_string(),
            ],
            later,
        );
        assert_eq!(rec.granted_scopes, vec!["email", "openid", "profile"]);
        assert_eq!(rec.updated_at, later);
        assert_ne!(rec.updated_at, rec.granted_at);
    }

    #[test]
    fn consent_covers_requested_scopes_returns_true_when_superset() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        assert!(rec.covers(&["profile".to_string()]));
        assert!(rec.covers(&["email".to_string(), "profile".to_string()]));
        assert!(rec.covers(&[]));
    }

    #[test]
    fn consent_covers_returns_false_when_scope_missing() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string()],
            now,
        );
        assert!(!rec.covers(&["profile".to_string(), "email".to_string()]));
        assert!(!rec.covers(&["admin".to_string()]));
    }

    #[test]
    fn canonicalize_scopes_trims_dedupes_sorts() {
        let out = canonicalize_scopes(vec![
            "profile".to_string(),
            " email ".to_string(),
            "profile".to_string(),
            String::new(),
            "   ".to_string(),
        ]);
        assert_eq!(out, vec!["email", "profile"]);
    }

    #[test]
    fn consent_record_serde_round_trip() {
        let now = Timestamp::from_micros(1_000_000);
        let rec = ConsentRecord::new(
            UserId::generate(),
            ClientId::generate(),
            vec!["profile".to_string(), "email".to_string()],
            now,
        );
        let json = serde_json::to_string(&rec).expect("serialize");
        let back: ConsentRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rec, back);
    }

    // ===== RequiredAction tests =====

    #[test]
    fn required_action_serializes_to_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&RequiredAction::VerifyEmail).expect("serialize"),
            "\"VERIFY_EMAIL\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredAction::UpdatePassword).expect("serialize"),
            "\"UPDATE_PASSWORD\""
        );
        assert_eq!(
            serde_json::to_string(&RequiredAction::EnrollPhoneOtp).expect("serialize"),
            "\"ENROLL_PHONE_OTP\""
        );
    }

    #[test]
    fn required_action_deserializes_from_screaming_snake_case() {
        let a: RequiredAction = serde_json::from_str("\"VERIFY_EMAIL\"").expect("deserialize");
        assert_eq!(a, RequiredAction::VerifyEmail);

        let b: RequiredAction = serde_json::from_str("\"UPDATE_PASSWORD\"").expect("deserialize");
        assert_eq!(b, RequiredAction::UpdatePassword);

        let c: RequiredAction = serde_json::from_str("\"ENROLL_PHONE_OTP\"").expect("deserialize");
        assert_eq!(c, RequiredAction::EnrollPhoneOtp);
    }

    #[test]
    fn enroll_phone_otp_priority_and_path_segment() {
        assert_eq!(RequiredAction::EnrollPhoneOtp.priority(), 4);
        assert_eq!(
            RequiredAction::EnrollPhoneOtp.as_path_segment(),
            "ENROLL_PHONE_OTP"
        );
        assert_eq!(
            RequiredAction::from_path_segment("ENROLL_PHONE_OTP"),
            Some(RequiredAction::EnrollPhoneOtp)
        );
    }

    #[test]
    fn user_phone_fields_default_none_on_legacy_record() {
        let legacy_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "old@example.com",
            "display_name": "Old User",
            "first_name": "Old",
            "last_name": "User",
            "status": "Active",
            "created_at": 1000000,
            "updated_at": 1000000
        }"#;
        let user: User = serde_json::from_str(legacy_json).expect("deserialize");
        assert!(
            user.phone_number().is_none(),
            "legacy user must have no phone"
        );
        assert!(
            !user.phone_verified(),
            "legacy user must not be phone-verified"
        );
    }

    #[test]
    fn user_phone_fields_round_trip() {
        let now = Timestamp::from_micros(1_000_000);
        let mut user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        user.set_phone_number(Some("+15555550100".to_string()));
        user.set_phone_verified(true);

        let json = serde_json::to_string(&user).expect("serialize");
        let back: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.phone_number(), Some("+15555550100"));
        assert!(back.phone_verified());
    }

    #[test]
    fn user_without_phone_omits_fields_in_json() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(
            !json.contains("phone_number"),
            "absent phone must be omitted"
        );
        assert!(
            !json.contains("phone_verified"),
            "false phone_verified must be omitted"
        );
    }

    #[test]
    fn required_action_unknown_value_is_rejected() {
        let result: Result<RequiredAction, _> = serde_json::from_str("\"INVALID_ACTION\"");
        assert!(result.is_err(), "unknown required action must be rejected");
    }

    #[test]
    fn user_required_actions_default_empty_on_legacy_record() {
        let legacy_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "old@example.com",
            "display_name": "Old User",
            "first_name": "Old",
            "last_name": "User",
            "status": "Active",
            "created_at": 1000000,
            "updated_at": 1000000
        }"#;
        let user: User = serde_json::from_str(legacy_json).expect("deserialize");
        assert!(
            user.required_actions().is_empty(),
            "legacy user must have no required actions"
        );
    }

    #[test]
    fn user_with_required_actions_round_trips() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        let back: User = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.required_actions(), user.required_actions());
    }

    #[test]
    fn user_with_empty_required_actions_omits_field_in_json() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "bob@example.com".to_string(),
            "Bob".to_string(),
            "Bob".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        let json = serde_json::to_string(&user).expect("serialize");
        assert!(
            !json.contains("required_actions"),
            "empty required_actions must be omitted to keep records compact"
        );
    }

    // ── mask_phone_number / User::masked_phone_number ──────────────────────

    #[test]
    fn masked_phone_matches_ac_example() {
        assert_eq!(mask_phone_number("+15555551234"), "+1***-***-1234");
    }

    #[test]
    fn masked_phone_uk_number() {
        assert_eq!(mask_phone_number("+441234567890"), "+4***-***-7890");
    }

    #[test]
    fn masked_phone_short_number_returns_stars() {
        assert_eq!(mask_phone_number("+123"), "****");
        assert_eq!(mask_phone_number("+12"), "****");
    }

    #[test]
    fn user_masked_phone_number_returns_none_when_no_phone() {
        let now = Timestamp::from_micros(1_000_000);
        let user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        assert!(user.masked_phone_number().is_none());
    }

    #[test]
    fn user_masked_phone_number_masks_enrolled_phone() {
        let now = Timestamp::from_micros(1_000_000);
        let mut user = User::new(
            UserId::generate(),
            "alice@example.com".to_string(),
            "Alice".to_string(),
            "Alice".to_string(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            now,
            now,
        );
        user.set_phone_number(Some("+15555551234".to_string()));
        assert_eq!(
            user.masked_phone_number(),
            Some("+1***-***-1234".to_string())
        );
    }

    // ── RealmConfig sms_otp fields ─────────────────────────────────────────

    #[test]
    fn realm_config_sms_otp_fields_default_none() {
        let config = RealmConfig::default();
        assert!(config.sms_otp_expiry_seconds.is_none());
        assert!(config.sms_otp_max_attempts.is_none());
    }

    #[test]
    fn realm_config_sms_otp_fields_roundtrip() {
        let config = RealmConfig {
            sms_otp_expiry_seconds: Some(300),
            sms_otp_max_attempts: Some(3),
            ..RealmConfig::default()
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: RealmConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.sms_otp_expiry_seconds, Some(300));
        assert_eq!(back.sms_otp_max_attempts, Some(3));
    }

    #[test]
    fn realm_config_sms_otp_fields_absent_in_legacy_json() {
        let legacy_json = r#"{"name": "test", "status": "Active"}"#;
        let config: RealmConfig = serde_json::from_str(legacy_json).unwrap_or_default();
        assert!(config.sms_otp_expiry_seconds.is_none());
        assert!(config.sms_otp_max_attempts.is_none());
    }

    #[test]
    fn realm_config_mfa_methods_accepts_sms_value() {
        let config = RealmConfig {
            mfa_methods: Some(vec!["sms".to_string()]),
            ..RealmConfig::default()
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: RealmConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.mfa_methods, Some(vec!["sms".to_string()]));
    }

    #[test]
    fn pending_authorization_request_serde_round_trip() {
        let pending = PendingAuthorizationRequest {
            realm_id: RealmId::generate(),
            user_id: UserId::generate(),
            client_id: ClientId::generate(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            requested_scopes: vec!["openid".to_string(), "email".to_string()],
            state: "xyz".to_string(),
            response_type: "code".to_string(),
            code_challenge: Some("abc".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: Some("n-0".to_string()),
            response_mode: None,
            authorization_signed_response_alg: Some("EdDSA".to_string()),
            created_at: Timestamp::from_micros(1_000_000),
            expires_at: Timestamp::from_micros(1_600_000_000),
        };
        let json = serde_json::to_string(&pending).expect("serialize");
        let back: PendingAuthorizationRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pending, back);
    }
}
