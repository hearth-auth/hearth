//! `EmbeddedLdapConnector` — concrete LDAP connector implementation.
//!
//! Wraps the `ldap3` async client. All methods are off the hot path; callers
//! may use them from async tasks without needing `spawn_blocking`.

use std::sync::Arc;

use ldap3::controls::{Control, ControlType, PagedResults, RawControl};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError as Ldap3Error, Scope, SearchEntry};
use rustls::crypto::ring::default_provider as ring_provider;
use tracing::{debug, warn};

use crate::core::RealmId;
use crate::identity::ldap::{
    error::LdapError,
    filter::{build_full_sync_filter, build_modify_timestamp_filter, build_usn_changed_filter},
    keys::encode_ldap_checkpoint,
    mapping::{map_entry, requested_attributes},
    types::{DeltaSyncResult, LdapConfig, LdapSyncCheckpoint, LdapUser, SyncStrategy},
};
use crate::storage::StorageEngine;

/// LDAP connector backed by the embedded storage engine for checkpoints.
///
/// Constructed once per configured realm and held behind an `Arc`. All
/// operations open a fresh LDAP connection (short-lived sessions avoid stale
/// server-side connection limits) and close it when done.
pub struct EmbeddedLdapConnector {
    pub(crate) config: LdapConfig,
    storage: Arc<dyn StorageEngine>,
}

impl std::fmt::Debug for EmbeddedLdapConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedLdapConnector")
            .field("url", &self.config.url)
            .field("base_dn", &self.config.base_dn)
            .finish_non_exhaustive()
    }
}

impl EmbeddedLdapConnector {
    /// Creates a new connector from the given config.
    ///
    /// Returns `LdapError::InvalidUrl` immediately when:
    /// - The URL does not start with `ldaps://` and `allow_insecure` is `false`.
    /// - The URL is empty.
    pub fn new(config: LdapConfig, storage: Arc<dyn StorageEngine>) -> Result<Self, LdapError> {
        if config.url.is_empty() {
            return Err(LdapError::InvalidUrl {
                reason: "URL must not be empty".to_string(),
            });
        }
        if !config.allow_insecure && !config.url.starts_with("ldaps://") {
            return Err(LdapError::InvalidUrl {
                reason: format!(
                    "plain ldap:// is not permitted; use ldaps:// (url='{}'). \
                     Set allow_insecure=true only in test environments.",
                    config.url
                ),
            });
        }
        Ok(Self { config, storage })
    }

    /// Opens an authenticated LDAP connection using the service-account credentials.
    async fn connect_and_bind(&self) -> Result<Ldap, LdapError> {
        // Rustls 0.23+ requires an explicit process-level CryptoProvider.
        // Install ring here so LDAPS works whether called from main() or tests.
        let _ = ring_provider().install_default();
        let settings = LdapConnSettings::new().set_no_tls_verify(false);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| LdapError::ConnectionFailed {
                reason: e.to_string(),
            })?;

        // Drive the connection in a background task — ldap3 requires this.
        ldap3::drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, self.config.bind_password.as_str())
            .await
            .map_err(|e| LdapError::ConnectionFailed {
                reason: format!("bind call failed: {e}"),
            })?
            .success()
            .map_err(|_| LdapError::BindFailed)?;

        Ok(ldap)
    }

    /// Maps an `ldap3::LdapError` from a failed `success()` call to `LdapError::SearchFailed`.
    fn map_search_error(err: Ldap3Error) -> LdapError {
        match err {
            Ldap3Error::LdapResult { result } => LdapError::SearchFailed {
                result_code: result.rc,
                reason: result.text,
            },
            other => LdapError::SearchFailed {
                result_code: 0,
                reason: other.to_string(),
            },
        }
    }

    /// Extracts the paging cookie from an LDAP response control list.
    ///
    /// Returns an empty `Vec` when no paged-results control is present or the
    /// cookie is empty (last page).
    fn extract_paging_cookie(ctrls: &[Control]) -> Vec<u8> {
        for ctrl in ctrls {
            if matches!(ctrl.0, Some(ControlType::PagedResults)) {
                let pr = ctrl.1.parse::<PagedResults>();
                if !pr.cookie.is_empty() {
                    return pr.cookie;
                }
            }
        }
        vec![]
    }

    /// Builds a paged-results request control for the given page size and cookie.
    fn paged_control(size: u32, cookie: Vec<u8>) -> RawControl {
        PagedResults {
            size: size as i32,
            cookie,
        }
        .into()
    }

    /// Loads all user pages matching `filter`, using Simple Paged Results.
    async fn search_paged(
        &self,
        ldap: &mut Ldap,
        filter: &str,
        attrs: &[String],
    ) -> Result<Vec<LdapUser>, LdapError> {
        let page_size = self.config.page_size;
        let attr_map = &self.config.attribute_map;
        let mut users = Vec::new();
        let mut cookie: Vec<u8> = vec![];

        loop {
            let controls: Vec<RawControl> = if page_size > 0 {
                vec![Self::paged_control(page_size, cookie.clone())]
            } else {
                vec![]
            };

            let (rs, result) = ldap
                .with_controls(controls)
                .search(
                    &self.config.base_dn,
                    Scope::Subtree,
                    filter,
                    attrs.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                )
                .await
                .map_err(|e| LdapError::SearchFailed {
                    result_code: 0,
                    reason: e.to_string(),
                })?
                .success()
                .map_err(Self::map_search_error)?;

            for entry in rs {
                let se = SearchEntry::construct(entry);
                match map_entry(&se.dn, &se.attrs, attr_map) {
                    Ok(user) => users.push(user),
                    Err(e) => {
                        warn!(error = %e, "LDAP entry skipped: attribute mapping failed");
                    }
                }
            }

            if page_size == 0 {
                break;
            }

            cookie = Self::extract_paging_cookie(&result.ctrls);
            if cookie.is_empty() {
                break;
            }
        }

        Ok(users)
    }

    /// Reads the stored sync checkpoint for a realm from WAL storage.
    fn load_checkpoint(&self, realm_id: &RealmId) -> Result<LdapSyncCheckpoint, LdapError> {
        let key = encode_ldap_checkpoint(realm_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(|e| LdapError::Storage(Box::new(e)))?
        {
            None => Ok(LdapSyncCheckpoint::default()),
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| LdapError::CorruptCheckpoint {
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Persists the sync checkpoint to WAL storage.
    fn save_checkpoint(
        &self,
        realm_id: &RealmId,
        checkpoint: &LdapSyncCheckpoint,
    ) -> Result<(), LdapError> {
        let key = encode_ldap_checkpoint(realm_id);
        let bytes = serde_json::to_vec(checkpoint).map_err(|e| LdapError::Internal {
            reason: format!("checkpoint serialize: {e}"),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(|e| LdapError::Storage(Box::new(e)))?;
        Ok(())
    }
}

/// Public interface for LDAP federation operations.
///
/// All methods are async and off the hot path.
impl EmbeddedLdapConnector {
    /// Searches for all users matching the configured `user_filter`.
    ///
    /// Uses Simple Paged Results to avoid server-side size limits.
    /// Skips entries with mapping failures and logs a warning for each.
    pub async fn search_users(&self) -> Result<Vec<LdapUser>, LdapError> {
        let filter = build_full_sync_filter(
            &self.config.user_filter,
            &self.config.attribute_map.external_id,
        )?;
        let attrs = requested_attributes(&self.config.attribute_map);

        debug!(
            url = %self.config.url,
            base_dn = %self.config.base_dn,
            filter = %filter,
            "LDAP full user search"
        );

        let mut ldap = self.connect_and_bind().await?;
        let users = self.search_paged(&mut ldap, &filter, &attrs).await?;
        ldap.unbind().await.ok();
        Ok(users)
    }

    /// Authenticates a user by performing a bind as their DN.
    ///
    /// Returns `true` on successful bind, `false` on `InvalidCredentials`.
    /// All other LDAP errors propagate as `LdapError`.
    ///
    /// The password is never cached, logged, or stored.
    ///
    /// # Security contract
    /// `user_dn` MUST be obtained from a prior [`search_paged`] call.
    /// Never construct `user_dn` from user-provided strings — doing so risks anonymous-bind
    /// bypass on RFC 4513-compliant servers.
    pub async fn authenticate_user(
        &self,
        user_dn: &str,
        password: &str,
    ) -> Result<bool, LdapError> {
        if user_dn.is_empty() || password.is_empty() {
            return Ok(false);
        }
        let _ = ring_provider().install_default();
        let settings = LdapConnSettings::new().set_no_tls_verify(false);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| LdapError::ConnectionFailed {
                reason: e.to_string(),
            })?;
        ldap3::drive!(conn);

        let result =
            ldap.simple_bind(user_dn, password)
                .await
                .map_err(|e| LdapError::ConnectionFailed {
                    reason: format!("bind call failed: {e}"),
                })?;

        ldap.unbind().await.ok();

        match result.rc {
            0 => Ok(true),
            // RFC 4511 § 4.1.9: resultCode 49 = invalidCredentials
            49 => Ok(false),
            _ => Err(LdapError::AuthenticationFailed),
        }
    }

    /// Runs a delta sync, fetching only entries modified since the last checkpoint.
    ///
    /// On the first call (no checkpoint) this is equivalent to a full sync.
    /// The checkpoint is updated atomically after the sync batch completes.
    pub async fn delta_sync(
        &self,
        realm_id: &RealmId,
        now_secs: u64,
    ) -> Result<DeltaSyncResult, LdapError> {
        let checkpoint = self.load_checkpoint(realm_id)?;
        let attr_map = &self.config.attribute_map;
        let attrs = requested_attributes(attr_map);

        let filter = match &checkpoint.cursor {
            None => build_full_sync_filter(&self.config.user_filter, &attr_map.external_id)?,
            Some(cursor) => match self.config.sync_strategy {
                SyncStrategy::ModifyTimestamp => build_modify_timestamp_filter(
                    &self.config.user_filter,
                    &attr_map.sync_attribute,
                    &attr_map.external_id,
                    cursor,
                )?,
                SyncStrategy::UsnChanged => build_usn_changed_filter(
                    &self.config.user_filter,
                    &attr_map.sync_attribute,
                    &attr_map.external_id,
                    cursor,
                )?,
            },
        };

        debug!(
            realm = %realm_id.as_uuid(),
            cursor = ?checkpoint.cursor,
            filter = %filter,
            "LDAP delta sync"
        );

        let mut ldap = self.connect_and_bind().await?;
        let users = self.search_paged(&mut ldap, &filter, &attrs).await?;
        ldap.unbind().await.ok();

        // Advance the high-watermark to the maximum sync_cursor seen.
        let new_cursor =
            advance_cursor(&users, self.config.sync_strategy, checkpoint.cursor.clone());

        let new_checkpoint = LdapSyncCheckpoint {
            cursor: new_cursor,
            last_sync_at: Some(now_secs),
            last_sync_count: users.len() as u64,
        };
        self.save_checkpoint(realm_id, &new_checkpoint)?;

        Ok(DeltaSyncResult {
            upserted: users,
            skipped: 0,
            checkpoint: new_checkpoint,
        })
    }
}

/// Computes the new sync cursor high-watermark from a batch of synced users.
///
/// USN cursors are integers and MUST be compared numerically — lexicographic max
/// incorrectly ranks "999" above "1000" at digit-length boundaries.
/// Timestamp cursors use lexicographic max because ISO-8601 strings sort correctly.
fn advance_cursor(
    users: &[LdapUser],
    strategy: SyncStrategy,
    prev: Option<String>,
) -> Option<String> {
    match strategy {
        SyncStrategy::UsnChanged => {
            let max_usn = users
                .iter()
                .filter_map(|u| {
                    u.sync_cursor
                        .parse::<u64>()
                        .map_err(|_| warn!(cursor = %u.sync_cursor, "USN cursor parse failed"))
                        .ok()
                })
                .max()
                .map(|n| n.to_string());
            max_usn.or(prev)
        }
        SyncStrategy::ModifyTimestamp => users
            .iter()
            .map(|u| u.sync_cursor.as_str())
            .max()
            .map(str::to_string)
            .or(prev),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ldap::types::{LdapAttributeMap, LdapBindPassword};
    use std::collections::HashMap;
    use std::sync::Arc;
    use uuid::Uuid;

    fn make_config(url: &str, allow_insecure: bool) -> LdapConfig {
        LdapConfig {
            url: url.to_string(),
            allow_insecure,
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: LdapBindPassword::new("secret".to_string()),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(objectClass=person)".to_string(),
            page_size: 500,
            attribute_map: LdapAttributeMap::default(),
            sync_strategy: SyncStrategy::ModifyTimestamp,
            sync_interval_secs: 300,
        }
    }

    struct NullStorage;
    impl StorageEngine for NullStorage {
        fn get(
            &self,
            _r: &RealmId,
            _k: &[u8],
        ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
            Ok(None)
        }
        fn put(
            &self,
            _r: &RealmId,
            _k: &[u8],
            _v: &[u8],
        ) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }
        fn delete(&self, _r: &RealmId, _k: &[u8]) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }
        fn scan(
            &self,
            _r: &RealmId,
            _s: &[u8],
            _e: &[u8],
        ) -> Result<Vec<crate::storage::ScanEntry>, crate::storage::StorageError> {
            Ok(vec![])
        }
    }

    #[test]
    fn new_rejects_plain_ldap_by_default() {
        let cfg = make_config("ldap://127.0.0.1:389", false);
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("expected InvalidUrl error for plain ldap://");
        assert!(matches!(err, LdapError::InvalidUrl { .. }));
    }

    #[test]
    fn new_accepts_ldaps_url() {
        let cfg = make_config("ldaps://ldap.example.com:636", false);
        assert!(EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage)).is_ok());
    }

    #[test]
    fn new_accepts_plain_ldap_when_insecure_flag_set() {
        let cfg = make_config("ldap://127.0.0.1:389", true);
        assert!(EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage)).is_ok());
    }

    #[test]
    fn new_rejects_empty_url() {
        let cfg = make_config("", true);
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("expected InvalidUrl error for empty URL");
        assert!(matches!(err, LdapError::InvalidUrl { .. }));
    }

    #[test]
    fn load_checkpoint_returns_default_when_absent() {
        let cfg = make_config("ldaps://ldap.example.com:636", false);
        let conn = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect("valid ldaps config should construct successfully");
        let realm_id = RealmId::new(Uuid::nil());
        let cp = conn
            .load_checkpoint(&realm_id)
            .expect("NullStorage should return default checkpoint");
        assert!(cp.cursor.is_none());
        assert!(cp.last_sync_at.is_none());
        assert_eq!(cp.last_sync_count, 0);
    }

    fn make_ldap_user(sync_cursor: &str) -> LdapUser {
        LdapUser {
            dn: "uid=test,dc=example,dc=com".to_string(),
            external_id: "test-uuid".to_string(),
            email: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            given_name: None,
            family_name: None,
            username: None,
            sync_cursor: sync_cursor.to_string(),
            extra: HashMap::new(),
        }
    }

    // LOW-3: USN cursors that cross a digit-length boundary must be compared
    // numerically — "1000" > "999" as integers but "999" > "1000" lexicographically.
    #[test]
    fn advance_cursor_usn_picks_numeric_max_across_digit_boundary() {
        let users = vec![make_ldap_user("999"), make_ldap_user("1000")];
        let result = advance_cursor(&users, SyncStrategy::UsnChanged, None);
        assert_eq!(
            result.as_deref(),
            Some("1000"),
            "USN max must use numeric comparison"
        );
    }

    #[test]
    fn advance_cursor_usn_falls_back_to_prev_when_no_users() {
        let result = advance_cursor(&[], SyncStrategy::UsnChanged, Some("500".to_string()));
        assert_eq!(result.as_deref(), Some("500"));
    }

    // LOW-4: empty DN or empty password must short-circuit before any network call.
    #[tokio::test]
    async fn authenticate_user_rejects_empty_dn() {
        let cfg = make_config("ldaps://ldap.example.com:636", false);
        let conn = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect("valid ldaps config should construct successfully");
        let result = conn
            .authenticate_user("", "password") // lgtm[rust/hard-coded-credentials]
            .await
            .expect("authenticate_user must not error on empty DN");
        assert!(!result, "empty DN must not authenticate");
    }

    #[tokio::test]
    async fn authenticate_user_rejects_empty_password() {
        let cfg = make_config("ldaps://ldap.example.com:636", false);
        let conn = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect("valid ldaps config should construct successfully");
        let result = conn
            .authenticate_user("uid=user,dc=example,dc=com", "") // lgtm[rust/hard-coded-credentials]
            .await
            .expect("authenticate_user must not error on empty password");
        assert!(!result, "empty password must not authenticate");
    }
}
