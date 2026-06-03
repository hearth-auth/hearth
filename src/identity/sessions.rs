//! `SessionStore` pluggable trait (P-7) and its embedded reference adapter.
//!
//! Defines the interface for session persistence so multi-node deployments
//! can swap the embedded WAL store for an external backend (Redis, Postgres, …)
//! without modifying the identity engine core.
//!
//! The embedded adapter delegates to the WAL-backed storage engine that the
//! identity engine already uses. External adapters implement `SessionStore`
//! and are passed to the engine at construction time.
//!
//! | Component            | Purpose                                      |
//! |----------------------|----------------------------------------------|
//! | [`SessionStore`]     | Trait: load, save, and list sessions         |
//! | [`EmbeddedSessionStore`] | Reference adapter backed by the WAL storage engine |

use std::sync::Arc;

use crate::core::{RealmId, SessionId, UserId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::types::{Page, Session};
use crate::storage::StorageEngine;

/// Pluggable session-storage backend (P-7).
///
/// Implementations must be `Send + Sync + 'static` so the engine can hold
/// them as `Arc<dyn SessionStore>` and share them across threads.
///
/// All methods are **synchronous** (blocking) to match the embedded WAL
/// engine's design contract. Async adapters must wrap calls in
/// `tokio::task::spawn_blocking`.
///
/// ## Fail-open contract
///
/// Per §6.1 of the abuse-prevention plan, a `SessionStore` that cannot reach
/// its backing store SHOULD return an appropriate `IdentityError` variant so
/// callers can decide whether to fail-open or fail-closed. Callers in the hot
/// path (`get_session`) treat storage errors as "session not found" to avoid
/// locking out users during transient outages.
pub trait SessionStore: Send + Sync + 'static {
    /// Returns the raw session record (possibly revoked / expired), or `None`
    /// if not present in the store.
    ///
    /// Callers apply validity checks (`Session::is_valid`, `Session::is_policy_expired`)
    /// after loading. The store itself does not filter on validity.
    fn load_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError>;

    /// Persists a session record (new or mutated).
    ///
    /// Called after `create_session` (new) and after `revoke_session` /
    /// `refresh_session` (mutation). Implementations must be idempotent:
    /// re-saving an identical session is a no-op with no observable effect.
    fn save_session(&self, realm_id: &RealmId, session: &Session) -> Result<(), IdentityError>;

    /// Returns a page of sessions belonging to a single user.
    ///
    /// Results are ordered by creation time (newest first). The `cursor` is
    /// an opaque continuation token from a previous call's `Page::next_cursor`.
    fn list_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;

    /// Returns a page of all sessions in a realm.
    ///
    /// Ordered by session ID. Used by the session reaper to sweep expired
    /// sessions proactively (A-18).
    fn list_by_realm(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError>;
}

/// Reference `SessionStore` adapter backed by the embedded WAL storage engine.
///
/// This is the default adapter for single-node deployments. It delegates
/// directly to `StorageEngine::get` / `put` / `scan`, matching what
/// `EmbeddedIdentityEngine` already does internally.
///
/// Multi-node deployments that need cluster-wide session visibility (e.g. for
/// concurrent-session enforcement across nodes) should implement `SessionStore`
/// against Redis or a shared database instead.
pub struct EmbeddedSessionStore {
    storage: Arc<dyn StorageEngine>,
}

impl EmbeddedSessionStore {
    /// Creates a new `EmbeddedSessionStore` sharing the given storage engine.
    pub fn new(storage: Arc<dyn StorageEngine>) -> Self {
        Self { storage }
    }
}

impl SessionStore for EmbeddedSessionStore {
    fn load_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let key = keys::encode_session_id(session_id);
        match self.storage.get(realm_id, &key) {
            Ok(Some(data)) => {
                let session = serde_json::from_slice::<Session>(&data).map_err(|e| {
                    IdentityError::Serialization {
                        reason: e.to_string(),
                    }
                })?;
                Ok(Some(session))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(IdentityError::Storage(Box::new(e))),
        }
    }

    fn save_session(&self, realm_id: &RealmId, session: &Session) -> Result<(), IdentityError> {
        let key = keys::encode_session_id(session.id());
        let bytes = serde_json::to_vec(session).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(|e| IdentityError::Storage(Box::new(e)))
    }

    fn list_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let prefix = keys::encode_user_sessions_prefix(user_id);
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("ses:user:{}:{uuid_str}", user_id.as_uuid()).into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let index_entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;

        let mut items = Vec::new();
        for entry in index_entries.iter().take(limit + 1) {
            let key_str = String::from_utf8_lossy(&entry.key);
            let Some(session_uuid_str) = key_str.rsplit(':').next() else {
                continue;
            };
            let Ok(session_uuid) = session_uuid_str.parse::<uuid::Uuid>() else {
                continue;
            };
            let session_id = SessionId::new(session_uuid);
            let session_key = keys::encode_session_id(&session_id);
            if let Some(data) = self
                .storage
                .get(realm_id, &session_key)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?
            {
                let session: Session =
                    serde_json::from_slice(&data).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                items.push(session);
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            items
                .last()
                .map(|s| URL_SAFE_NO_PAD.encode(s.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn list_by_realm(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let prefix = keys::session_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("ses:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;

        let mut items = Vec::new();
        for entry in &entries {
            if items.len() > limit {
                break;
            }
            let session: Session =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(session);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            items
                .last()
                .map(|s| URL_SAFE_NO_PAD.encode(s.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }
}
