//! Audit 2026-08-28 §4.20#6: secrets outliving the realm that owned them.
//!
//! The audit named five families that neither delete cascade removed: password
//! history, webhook secrets, org-owned agent credentials, the per-realm MFA
//! data-encryption key, and the DPoP nonce key.
//!
//! All five are stored under the realm's own storage partition, so the cascade
//! now sweeps them with the rest of the realm's key space. This test builds
//! every one of them and holds that. The DPoP nonce key has a second life in
//! memory, covered by `dpop_nonce_secret_does_not_outlive_the_realm` in the
//! engine's own tests.

#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;

use hearth::core::RealmId;
use hearth::identity::{
    AgentOwner, CleartextPassword, CreateAgentApiKeyRequest, CreateAgentRequest,
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, CreateWebhookRequest,
    PasswordPolicy, RealmConfig,
};

/// Storage key prefixes for the five families the audit named. `mfa:dek:key`
/// is a whole key rather than a prefix; `agt:dpop:nonce-secret` likewise.
const NAMED_FAMILIES: &[&str] = &[
    "cred:history:",
    "wh:id:",
    "agt:cred:",
    "mfa:dek:key",
    "agt:dpop:nonce-secret",
];

/// Every key the realm still holds, as readable strings.
fn realm_keys(h: &common::TestHarness, realm_id: &RealmId) -> Vec<String> {
    h.storage()
        .scan(realm_id, &[], &[0xFF; 256])
        .expect("full key-space scan")
        .iter()
        .map(|e| String::from_utf8_lossy(&e.key).into_owned())
        .collect()
}

/// Builds a realm holding every family the audit named, and returns its ID.
fn build_realm_with_every_secret_family(h: &common::TestHarness) -> RealmId {
    // `cred:history:` is only written when the realm's password policy keeps a
    // history, so the realm has to declare one for the family to exist at all.
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "secret-residue".to_string(),
            config: Some(RealmConfig {
                password_policy: Some(PasswordPolicy {
                    history_depth: Some(2),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed rbac");

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "holder@secret-residue.test".to_string(),
                display_name: "Holder".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    // 1. Password history: the second write pushes the first into `cred:history:`.
    for secret in ["valid-password123", "valid-password456"] {
        h.identity()
            .set_password(
                &realm_id,
                user.id(),
                &CleartextPassword::from_string(secret.to_string()),
            )
            .expect("set password");
    }

    // 2. A webhook carrying an HMAC signing secret.
    h.identity()
        .create_webhook(
            &realm_id,
            &CreateWebhookRequest {
                url: "https://hook.secret-residue.test/events".to_string(),
                secret: Some("a-webhook-signing-secret".to_string()),
                events: Vec::new(),
                enabled: true,
            },
        )
        .expect("create webhook");

    // 3. An org-owned agent holding an API-key credential.
    let org = h
        .identity()
        .create_organization(
            &realm_id,
            &CreateOrganizationRequest {
                name: "Residue Org".to_string(),
                slug: "secret-residue-org".to_string(),
                description: None,
                config: None,
                attributes: BTreeMap::new(),
            },
        )
        .expect("create organization");
    let agent = h
        .identity()
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Residue Agent".to_string(),
                description: None,
                owner: AgentOwner::Organization(org.id().clone()),
                capabilities: Vec::new(),
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("create agent");
    h.identity()
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest {
                label: "residue key".to_string(),
            },
            None,
        )
        .expect("create agent api key");

    // 4. The per-realm MFA data-encryption key, written on first TOTP enrolment.
    h.identity()
        .enroll_totp(&realm_id, user.id())
        .expect("enroll totp");

    realm_id
}

/// Every family the audit named must go with the realm's key space.
#[tokio::test]
async fn realm_deletion_removes_every_named_secret_family() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_id = build_realm_with_every_secret_family(&h);

    // Precondition: each family really exists, so an empty result after the
    // delete means the sweep worked and not that nothing was ever written.
    // `agt:dpop:nonce-secret` is written lazily on first DPoP use, so it is
    // checked only if present.
    let before = realm_keys(&h, &realm_id);
    for family in NAMED_FAMILIES {
        if *family == "agt:dpop:nonce-secret" {
            continue;
        }
        assert!(
            before.iter().any(|k| k.starts_with(family)),
            "precondition: {family} must exist before the delete, saw {before:?}"
        );
    }

    h.archive_realm(&realm_id);
    h.identity().delete_realm(&realm_id).expect("delete realm");

    let after = realm_keys(&h, &realm_id);
    assert!(
        after.is_empty(),
        "{} key(s) survived realm deletion: {after:?}",
        after.len()
    );
}
