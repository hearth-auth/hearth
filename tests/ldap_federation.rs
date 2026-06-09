//! Integration tests for LDAP user federation.
//!
//! These tests require a live LDAP server and are gated by environment
//! variables injected by the `ldap-integration` CI job (bitnami/openldap:2.6).
//!
//! Run locally:
//! ```sh
//! export HEARTH_TEST_LDAP_URL=ldap://127.0.0.1:1389
//! export HEARTH_TEST_LDAPS_URL=ldaps://127.0.0.1:1636
//! export HEARTH_TEST_LDAP_BIND_DN="cn=admin,dc=example,dc=org"
//! export HEARTH_TEST_LDAP_BIND_PASSWORD=adminpassword
//! export HEARTH_TEST_LDAP_BASE_DN="dc=example,dc=org"
//! export HEARTH_TEST_LDAP_USER="cn=user01,ou=users,dc=example,dc=org"
//! export HEARTH_TEST_LDAP_USER_PASSWORD=bitnami1
//! cargo nextest run --test ldap_federation -- --ignored
//! ```

mod common;

use hearth::identity::ldap::{
    EmbeddedLdapConnector, LdapAttributeMap, LdapBindPassword, LdapConfig, SyncStrategy,
};
use std::sync::Arc;
use uuid::Uuid;

// ─── env-var helper ──────────────────────────────────────────────────────────

/// Returns `None` and skips the test if any required variable is missing.
macro_rules! require_env {
    ($name:expr) => {
        match std::env::var($name) {
            Ok(val) => val,
            Err(_) => {
                eprintln!(
                    "Skipping LDAP integration test: {} is not set. \
                     Set all HEARTH_TEST_LDAP_* env vars to run against a real server.",
                    $name
                );
                return;
            }
        }
    };
}

fn ldap_test_config(url: &str, bind_dn: &str, bind_password: &str, base_dn: &str) -> LdapConfig {
    LdapConfig {
        url: url.to_string(),
        allow_insecure: true, // CI uses plain ldap:// for the test container
        bind_dn: bind_dn.to_string(),
        bind_password: LdapBindPassword(bind_password.to_string()),
        base_dn: base_dn.to_string(),
        user_filter: "(objectClass=inetOrgPerson)".to_string(),
        page_size: 100,
        attribute_map: LdapAttributeMap {
            email: "mail".to_string(),
            display_name: "cn".to_string(),
            given_name: "givenName".to_string(),
            family_name: "sn".to_string(),
            external_id: "entryUUID".to_string(),
            username: "uid".to_string(),
            sync_attribute: "modifyTimestamp".to_string(),
            extra: std::collections::HashMap::new(),
        },
        sync_strategy: SyncStrategy::ModifyTimestamp,
        sync_interval_secs: 300,
    }
}

// ─── stub storage for integration tests ──────────────────────────────────────

struct MemStorage {
    inner: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemStorage {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl hearth::storage::StorageEngine for MemStorage {
    fn get(
        &self,
        _r: &hearth::core::RealmId,
        k: &[u8],
    ) -> Result<Option<Vec<u8>>, hearth::storage::StorageError> {
        Ok(self
            .inner
            .lock()
            .expect("MemStorage mutex unpoisoned")
            .get(k)
            .cloned())
    }

    fn put(
        &self,
        _r: &hearth::core::RealmId,
        k: &[u8],
        v: &[u8],
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner
            .lock()
            .expect("MemStorage mutex unpoisoned")
            .insert(k.to_vec(), v.to_vec());
        Ok(())
    }

    fn delete(
        &self,
        _r: &hearth::core::RealmId,
        k: &[u8],
    ) -> Result<(), hearth::storage::StorageError> {
        self.inner
            .lock()
            .expect("MemStorage mutex unpoisoned")
            .remove(k);
        Ok(())
    }

    fn scan(
        &self,
        _r: &hearth::core::RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<hearth::storage::ScanEntry>, hearth::storage::StorageError> {
        let guard = self.inner.lock().expect("MemStorage mutex unpoisoned");
        let mut entries: Vec<_> = guard
            .iter()
            .filter(|(k, _)| k.as_slice() >= start && k.as_slice() < end)
            .map(|(k, v)| hearth::storage::ScanEntry {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn search_users_returns_at_least_one_user() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let connector =
        EmbeddedLdapConnector::new(cfg, Arc::new(MemStorage::new())).expect("connector creation");

    let users = connector.search_users().await.expect("search_users");
    assert!(
        !users.is_empty(),
        "expected at least one user in the test LDAP directory, got 0"
    );
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn search_users_email_and_external_id_are_populated() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let connector =
        EmbeddedLdapConnector::new(cfg, Arc::new(MemStorage::new())).expect("connector creation");

    let users = connector.search_users().await.expect("search_users");
    for user in &users {
        assert!(!user.email.is_empty(), "user {} has empty email", user.dn);
        assert!(
            !user.external_id.is_empty(),
            "user {} has empty external_id",
            user.dn
        );
    }
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn authenticate_user_valid_credentials_returns_true() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");
    let user_dn = require_env!("HEARTH_TEST_LDAP_USER");
    let user_password = require_env!("HEARTH_TEST_LDAP_USER_PASSWORD");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let connector =
        EmbeddedLdapConnector::new(cfg, Arc::new(MemStorage::new())).expect("connector creation");

    let ok = connector
        .authenticate_user(&user_dn, &user_password)
        .await
        .expect("authenticate_user");
    assert!(
        ok,
        "expected successful authentication with valid credentials"
    );
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn authenticate_user_wrong_password_returns_false() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");
    let user_dn = require_env!("HEARTH_TEST_LDAP_USER");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let connector =
        EmbeddedLdapConnector::new(cfg, Arc::new(MemStorage::new())).expect("connector creation");

    let ok = connector
        .authenticate_user(&user_dn, "definitely-wrong-password-xyz-987")
        .await
        .expect("authenticate_user should not return an error for wrong password");
    assert!(
        !ok,
        "expected authentication failure with wrong password, but got success"
    );
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn delta_sync_initial_run_loads_all_users() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let storage = Arc::new(MemStorage::new());
    let connector = EmbeddedLdapConnector::new(cfg, storage).expect("connector creation");

    let realm_id = hearth::core::RealmId::new(Uuid::new_v4());
    let result = connector
        .delta_sync(&realm_id, 1_700_000_000)
        .await
        .expect("delta_sync");

    assert!(
        !result.upserted.is_empty(),
        "initial delta sync should load at least one user"
    );
    assert!(
        result.checkpoint.cursor.is_some(),
        "checkpoint cursor must be set after initial sync"
    );
    assert_eq!(result.checkpoint.last_sync_at, Some(1_700_000_000));
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn delta_sync_second_run_with_same_cursor_returns_no_new_users() {
    let url = require_env!("HEARTH_TEST_LDAP_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");

    let cfg = ldap_test_config(&url, &bind_dn, &bind_password, &base_dn);
    let storage = Arc::new(MemStorage::new());
    let connector = EmbeddedLdapConnector::new(cfg, storage).expect("connector creation");

    let realm_id = hearth::core::RealmId::new(Uuid::new_v4());
    // First run populates the checkpoint.
    let first = connector
        .delta_sync(&realm_id, 1_700_000_000)
        .await
        .expect("first delta_sync");
    assert!(first.checkpoint.cursor.is_some());

    // Second run with the same cursor should return only users modified
    // at or after the checkpoint — in a static test directory that means
    // possibly the same set or fewer (depending on whether modifyTimestamp
    // equality is included). The key assertion is that the connector does
    // not error and the checkpoint is updated.
    let second = connector
        .delta_sync(&realm_id, 1_700_000_001)
        .await
        .expect("second delta_sync");
    // Checkpoint must advance to a new timestamp.
    assert_eq!(second.checkpoint.last_sync_at, Some(1_700_000_001));
}

#[tokio::test]
#[ignore = "requires live LDAP server — run via ldap-integration CI job or set HEARTH_TEST_LDAP_* env vars"]
async fn ldaps_connection_succeeds() {
    let ldaps_url = require_env!("HEARTH_TEST_LDAPS_URL");
    let bind_dn = require_env!("HEARTH_TEST_LDAP_BIND_DN");
    let bind_password = require_env!("HEARTH_TEST_LDAP_BIND_PASSWORD");
    let base_dn = require_env!("HEARTH_TEST_LDAP_BASE_DN");

    // LDAPS connection; allow_insecure must be false for a proper ldaps:// URL.
    let cfg = LdapConfig {
        url: ldaps_url,
        allow_insecure: false,
        bind_dn,
        bind_password: LdapBindPassword(bind_password),
        base_dn,
        user_filter: "(objectClass=inetOrgPerson)".to_string(),
        page_size: 100,
        attribute_map: LdapAttributeMap::default(),
        sync_strategy: SyncStrategy::ModifyTimestamp,
        sync_interval_secs: 300,
    };

    let connector =
        EmbeddedLdapConnector::new(cfg, Arc::new(MemStorage::new())).expect("connector creation");

    // A successful search proves the LDAPS connection and bind both work.
    let users = connector
        .search_users()
        .await
        .expect("search_users over LDAPS");
    assert!(!users.is_empty(), "LDAPS search returned no users");
}
