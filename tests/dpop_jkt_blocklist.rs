//! Phase D integration tests — DPoP JKT thumbprint blocklist (§10.4).
//!
//! Covers:
//! - `block_dpop_jkt`: token with blocked `cnf.jkt` is rejected with `DPopJktBlocked`
//! - `unblock_dpop_jkt`: token is accepted again after unblocking
//! - Tokens without `cnf` are unaffected by the blocklist
//! - Startup recovery: blocked JKTs survive engine restart via storage scan
//! - Adversarial: blocking is idempotent

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, Timestamp};
use hearth::identity::{
    ClientCredentialsRequest, CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, IdentityError, RegisterClientRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Shared DPoP JKT thumbprint ────────────────────────────────────────────────
// A valid base64url-encoded SHA-256 thumbprint (used as a representative value).
const DUMMY_JKT: &str = "OKVsYiUkGsOrgWxWpGpzDRzZpISBgekj0RvDqxNYors";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Issues a `client_credentials` access token bound to `DUMMY_JKT`.
/// Returns `(access_token, jkt)`.
async fn issue_dpop_bound_token(
    harness: &common::TestHarness,
    realm_id: &RealmId,
) -> (String, String) {
    let client = harness
        .identity()
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: format!("dpop-blocklist-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![],
                client_secret: Some("test-secret-42!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let resp = harness
        .identity()
        .client_credentials_token(
            realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some("test-secret-42!".to_string()),
                scope: Some("openid".to_string()),
                dpop_jkt: Some(DUMMY_JKT.to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("client_credentials with dpop_jkt");

    (resp.access_token().to_string(), DUMMY_JKT.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A DPoP-bound token is rejected after its `cnf.jkt` is blocked.
#[tokio::test]
async fn block_dpop_jkt_rejects_bound_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-block-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let (token, jkt) = issue_dpop_bound_token(&h, &realm_id).await;

    // Token is valid before blocking.
    h.identity()
        .validate_token(&realm_id, &token)
        .expect("token valid before block");

    // Block the thumbprint.
    h.identity()
        .block_dpop_jkt(&realm_id, &jkt)
        .expect("block_dpop_jkt");

    // Token must now be rejected.
    let err = h
        .identity()
        .validate_token(&realm_id, &token)
        .expect_err("token must be rejected after block");

    assert!(
        matches!(err, IdentityError::DPopJktBlocked),
        "expected DPopJktBlocked, got {err:?}"
    );
}

/// Unblocking a JKT restores token validity.
#[tokio::test]
async fn unblock_dpop_jkt_restores_validity() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-unblock-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let (token, jkt) = issue_dpop_bound_token(&h, &realm_id).await;

    h.identity().block_dpop_jkt(&realm_id, &jkt).unwrap();
    assert!(
        matches!(
            h.identity().validate_token(&realm_id, &token),
            Err(IdentityError::DPopJktBlocked)
        ),
        "token must be blocked"
    );

    h.identity().unblock_dpop_jkt(&realm_id, &jkt).unwrap();

    h.identity()
        .validate_token(&realm_id, &token)
        .expect("token valid after unblock");
}

/// Tokens without a `cnf.jkt` claim are unaffected by the blocklist.
#[tokio::test]
async fn non_dpop_token_unaffected_by_blocklist() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-plain-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: format!("plain-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![],
                client_secret: Some("plain-secret!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap();

    let resp = h
        .identity()
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some("plain-secret!".to_string()),
                scope: Some("openid".to_string()),
                dpop_jkt: None, // no DPoP binding
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .unwrap();

    // Block a random thumbprint — must not affect this token.
    h.identity()
        .block_dpop_jkt(&realm_id, "some-unrelated-thumbprint")
        .unwrap();

    h.identity()
        .validate_token(&realm_id, resp.access_token())
        .expect("non-DPoP token unaffected by blocklist");
}

/// Blocking an already-blocked JKT is idempotent.
#[tokio::test]
async fn block_dpop_jkt_is_idempotent() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-idem-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    h.identity()
        .block_dpop_jkt(&realm_id, DUMMY_JKT)
        .expect("first block");
    h.identity()
        .block_dpop_jkt(&realm_id, DUMMY_JKT)
        .expect("second block is idempotent");
}

/// Blocked JKTs survive an engine restart (startup storage scan).
#[test]
fn blocked_jkt_survives_engine_restart() {
    let dir = tempfile::tempdir().expect("tempdir");

    let open_engine = |storage_config: StorageConfig| {
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_config).expect("storage"))
            as Arc<dyn StorageEngine>;
        let clock = Arc::new(hearth::core::FakeClock::new(Timestamp::from_micros(
            1_000_000_000,
        ))) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        EmbeddedIdentityEngine::new(
            storage,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit,
        )
        .expect("engine")
    };

    // First engine: create realm, block a JKT.
    let engine1 = open_engine(StorageConfig::dev(dir.path().to_path_buf()));
    let realm_id = engine1
        .create_realm(&CreateRealmRequest {
            name: "restart-jkt-test".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let jkt = "restart-test-thumbprint-xyz";
    engine1.block_dpop_jkt(&realm_id, jkt).expect("block");

    // Simulate restart: drop old engine, open new one on same storage.
    drop(engine1);
    let engine2 = open_engine(StorageConfig::dev(dir.path().to_path_buf()));

    // Unblocking must succeed — proving the blocklist entry was persisted and
    // loaded into the in-memory projection on startup.
    engine2
        .unblock_dpop_jkt(&realm_id, jkt)
        .expect("unblock after restart — entry must survive from storage");
}
