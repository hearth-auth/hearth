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
    filter::{
        build_full_sync_filter, build_modify_timestamp_filter, build_usn_changed_filter,
        validate_attribute_descriptor, validate_user_filter,
    },
    keys::encode_ldap_checkpoint,
    mapping::{map_page, requested_attributes},
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
    /// - The `base_dn` is empty (an empty base is the root DSE, never the
    ///   subtree a user-federation connector means to search).
    ///
    /// Returns `LdapError::InvalidFilter` or `LdapError::InvalidAttributeName`
    /// when a configured value that is string-concatenated into a search
    /// filter is not well-formed (task 26.7 / finding L-4). This is the
    /// boundary the check belongs on: it is the one place untrusted
    /// configuration enters the connector, and failing here means an operator
    /// — or, once the connector is reachable, a realm administrator — learns
    /// about a bad `user_filter` or attribute name at configuration time
    /// rather than getting a silently wrong result set on every sync. The
    /// filter builders re-validate at the sink, because `LdapConfig` has
    /// public fields and can be assembled without going through this
    /// constructor.
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
        if config.base_dn.is_empty() {
            return Err(LdapError::InvalidUrl {
                reason: "base_dn must not be empty".to_string(),
            });
        }
        validate_user_filter(&config.user_filter)?;
        for attribute in requested_attributes(&config.attribute_map) {
            validate_attribute_descriptor(&attribute)?;
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
    ///
    /// Returns the mapped users **and** the number of entries the directory
    /// returned that could not be mapped and were therefore dropped. The
    /// caller is responsible for reporting that count: it used to be computed
    /// nowhere and reported as a hard-coded `0` (task 26.8 / finding L-5).
    async fn search_paged(
        &self,
        ldap: &mut Ldap,
        filter: &str,
        attrs: &[String],
    ) -> Result<(Vec<LdapUser>, u64), LdapError> {
        let page_size = self.config.page_size;
        let attr_map = &self.config.attribute_map;
        let mut users = Vec::new();
        let mut skipped: u64 = 0;
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

            let page: Vec<(String, std::collections::HashMap<String, Vec<String>>)> = rs
                .into_iter()
                .map(|entry| {
                    let se = SearchEntry::construct(entry);
                    (se.dn, se.attrs)
                })
                .collect();
            let (mut mapped, page_skipped) = map_page(&page, attr_map);
            users.append(&mut mapped);
            skipped += page_skipped;

            if page_size == 0 {
                break;
            }

            cookie = Self::extract_paging_cookie(&result.ctrls);
            if cookie.is_empty() {
                break;
            }
        }

        Ok((users, skipped))
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
    ///
    /// Entries whose attributes cannot be mapped are dropped, each with its
    /// own warning, and a summary warning carrying the total is emitted when
    /// the count is non-zero. The returned `Vec` therefore does **not**
    /// necessarily hold every entry the directory matched; callers that need
    /// that distinction should use [`Self::delta_sync`], whose
    /// `DeltaSyncResult.skipped` carries the count.
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
        let (users, skipped) = self.search_paged(&mut ldap, &filter, &attrs).await?;
        ldap.unbind().await.ok();
        if skipped > 0 {
            warn!(
                skipped,
                returned = users.len(),
                "LDAP search dropped entries that could not be mapped"
            );
        }
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
    ///
    /// # Skipped entries and the checkpoint (task 26.8 / finding L-5)
    ///
    /// Entries the directory returns but whose attributes cannot be mapped —
    /// most commonly a missing `mail` — are dropped. `DeltaSyncResult.skipped`
    /// used to be a hard-coded `0`, so a run that dropped ten thousand
    /// accounts reported a clean sync. It now carries the real count, the
    /// count is persisted on the checkpoint as `last_skipped_count`, and a
    /// non-zero count is logged at WARN.
    ///
    /// The cursor still advances past dropped entries. That is a deliberate
    /// policy choice, not an oversight, and the alternatives are worse:
    ///
    /// - **Not advancing at all** turns one permanently unmappable entry into
    ///   a permanently stalled sync — every subsequent run re-fetches the same
    ///   page and makes no progress, and the directory's genuinely new users
    ///   never arrive.
    /// - **Clamping to just below the oldest skipped entry** has the same
    ///   effect, because the entry is dropped for a reason that re-polling
    ///   cannot change: the attribute is absent in the directory.
    ///
    /// A mapping failure is a configuration or data problem that a human has
    /// to resolve (fix the `attribute_map`, or populate the attribute), and
    /// once resolved the entry is picked up by the next *full* sync. So the
    /// connector makes progress and reports honestly, rather than stalling
    /// silently. `skipped` is the number an operator's dashboard must alert
    /// on; treating a non-zero value as a successful run is the caller's bug,
    /// and this doc comment is the contract that says so.
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
        let (users, skipped) = self.search_paged(&mut ldap, &filter, &attrs).await?;
        ldap.unbind().await.ok();

        if skipped > 0 {
            warn!(
                realm = %realm_id.as_uuid(),
                skipped,
                mapped = users.len(),
                "LDAP delta sync dropped entries that could not be mapped; \
                 the cursor advances past them and they will not be retried \
                 until the next full sync"
            );
        }

        let result = build_delta_result(
            users,
            skipped,
            self.config.sync_strategy,
            checkpoint.cursor.clone(),
            now_secs,
        );
        self.save_checkpoint(realm_id, &result.checkpoint)?;

        Ok(result)
    }
}

/// Assembles the delta-sync result and the checkpoint that will be persisted.
///
/// Split out of [`EmbeddedLdapConnector::delta_sync`] so the accounting can be
/// tested without a live directory: the skipped count and the cursor policy
/// documented on `delta_sync` are decided entirely here.
fn build_delta_result(
    users: Vec<LdapUser>,
    skipped: u64,
    strategy: SyncStrategy,
    prev_cursor: Option<String>,
    now_secs: u64,
) -> DeltaSyncResult {
    // Advance the high-watermark to the maximum sync_cursor seen. Note that
    // only *mapped* users carry a cursor, so a page in which every entry was
    // dropped leaves the cursor where it was and the next run re-fetches it.
    let new_cursor = advance_cursor(&users, strategy, prev_cursor);

    let checkpoint = LdapSyncCheckpoint {
        cursor: new_cursor,
        last_sync_at: Some(now_secs),
        last_sync_count: users.len() as u64,
        last_skipped_count: skipped,
    };

    DeltaSyncResult {
        upserted: users,
        skipped,
        checkpoint,
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

        fn list_realms(&self) -> Result<Vec<crate::core::RealmId>, crate::storage::StorageError> {
            Ok(vec![])
        }

        // NullStorage has no persistent storage, so snapshot marker operations
        // are intentional no-ops.
        fn begin_snapshot_restore(
            &self,
            _snapshot_id: &str,
        ) -> Result<(), crate::storage::StorageError> {
            Ok(())
        }

        fn complete_snapshot_restore(&self) -> Result<(), crate::storage::StorageError> {
            Ok(())
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

    // ── 26.8 / finding L-5 ────────────────────────────────────────────────
    //
    // `delta_sync` returned `skipped: 0` unconditionally while dropping every
    // entry whose attributes would not map, and advanced the high-watermark
    // past them. A directory where 10,000 accounts lack `mail` produced a
    // result an operator's dashboard could not distinguish from a clean run.

    #[test]
    fn delta_result_reports_the_entries_that_were_dropped() {
        let users = vec![make_ldap_user("20240101120000Z")];
        let result = build_delta_result(
            users,
            10_000,
            SyncStrategy::ModifyTimestamp,
            Some("20231231000000Z".to_string()),
            1_700_000_000,
        );
        assert_eq!(
            result.skipped, 10_000,
            "a run that dropped 10,000 entries must not report a clean sync"
        );
        assert_eq!(
            result.checkpoint.last_skipped_count, 10_000,
            "the drop count must survive on the persisted checkpoint"
        );
        assert_eq!(result.checkpoint.last_sync_count, 1);
    }

    // The documented policy: the cursor DOES advance past a dropped entry,
    // because refusing to advance turns one unmappable entry into a
    // permanently stalled sync. The honesty comes from `skipped`, not from
    // withholding progress.
    #[test]
    fn delta_result_advances_the_cursor_past_dropped_entries_and_says_so() {
        let users = vec![make_ldap_user("20240201000000Z")];
        let result = build_delta_result(
            users,
            3,
            SyncStrategy::ModifyTimestamp,
            Some("20240101000000Z".to_string()),
            1_700_000_000,
        );
        assert_eq!(
            result.checkpoint.cursor.as_deref(),
            Some("20240201000000Z"),
            "the cursor must advance so the sync keeps making progress"
        );
        assert!(result.skipped > 0, "and the run must say it was not clean");
    }

    // A page in which every entry was dropped carries no cursor at all, so the
    // high-watermark stays put and the next run re-fetches it.
    #[test]
    fn delta_result_keeps_the_previous_cursor_when_nothing_mapped() {
        let result = build_delta_result(
            vec![],
            7,
            SyncStrategy::ModifyTimestamp,
            Some("20240101000000Z".to_string()),
            1_700_000_000,
        );
        assert_eq!(
            result.checkpoint.cursor.as_deref(),
            Some("20240101000000Z"),
            "an all-dropped page must not move the high-watermark"
        );
        assert_eq!(result.skipped, 7);
        assert_eq!(result.checkpoint.last_sync_count, 0);
    }

    // ── 26.7 / finding L-4 ────────────────────────────────────────────────
    //
    // `EmbeddedLdapConnector::new` is the one place operator-supplied
    // configuration enters the module, so it is where the values that get
    // string-concatenated into a search filter have to be checked.

    #[test]
    fn new_rejects_a_user_filter_that_breaks_out_of_its_enclosing_expression() {
        let mut cfg = make_config("ldaps://ldap.example.com:636", false);
        cfg.user_filter = "(objectClass=*))(uid=admin".to_string();
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("a user_filter that closes its own parenthesis must be refused");
        assert!(
            matches!(err, LdapError::InvalidFilter { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_an_attribute_name_that_can_close_the_filter() {
        let mut cfg = make_config("ldaps://ldap.example.com:636", false);
        cfg.attribute_map.external_id = "entryUUID)(uid=*".to_string();
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("a ')' in an attribute name must be refused at construction");
        assert!(
            matches!(err, LdapError::InvalidAttributeName { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_a_malformed_extra_attribute_name() {
        let mut cfg = make_config("ldaps://ldap.example.com:636", false);
        cfg.attribute_map
            .extra
            .insert("department)(uid=*".to_string(), "dept".to_string());
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("extra attribute keys reach the search too and must be checked");
        assert!(
            matches!(err, LdapError::InvalidAttributeName { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_an_empty_base_dn() {
        let mut cfg = make_config("ldaps://ldap.example.com:636", false);
        cfg.base_dn = String::new();
        let err = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect_err("an empty base_dn searches the root DSE, never the intended subtree");
        assert!(matches!(err, LdapError::InvalidUrl { .. }), "got {err:?}");
    }

    #[test]
    fn new_accepts_an_ad_style_attribute_map() {
        let mut cfg = make_config("ldaps://ldap.example.com:636", false);
        cfg.attribute_map.external_id = "objectGUID".to_string();
        cfg.attribute_map.sync_attribute = "uSNChanged".to_string();
        cfg.attribute_map.username = "sAMAccountName".to_string();
        cfg.user_filter = "(&(objectClass=user)(!(objectClass=computer)))".to_string();
        assert!(EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage)).is_ok());
    }

    // LOW-4: empty DN or empty password must short-circuit before any network call.
    #[tokio::test]
    async fn authenticate_user_rejects_empty_dn() {
        let cfg = make_config("ldaps://ldap.example.com:636", false);
        let conn = EmbeddedLdapConnector::new(cfg, Arc::new(NullStorage))
            .expect("valid ldaps config should construct successfully");
        let result = conn
            .authenticate_user("", "password")
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
            .authenticate_user("uid=user,dc=example,dc=com", "")
            .await
            .expect("authenticate_user must not error on empty password");
        assert!(!result, "empty password must not authenticate");
    }
}
