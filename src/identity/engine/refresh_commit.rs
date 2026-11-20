//! The one durable write of a refresh-token rotation (#890).
//!
//! A rotation spends the presented refresh token, stores the grant family's
//! new hash, slides the session's expiry and records `TokenRefreshed`. These
//! were four writes, each waiting for its own WAL sync: a write waits for the
//! sync in progress and then for its own, about 7 ms on a disk with a 3.7 ms
//! sync. A refresh held a place of `storage.max_writes_in_flight` four times
//! in a row, and the write limit refused refreshes near 900/s on AWS (c7i.large,
//! gp3). The claim and the family write were also separate: a refusal of the
//! family write left the token spent, so the client's retry was a replay that
//! revoked the family and the session. `examples/refresh_write_path.rs`
//! measures this path.
//!
//! Now the claim is the guard of one conditional batch
//! ([`StorageEngine::enqueue_batch_if_absent`](crate::storage::StorageEngine::enqueue_batch_if_absent))
//! that also holds the family, the session and the audit event. A refused or
//! failed write leaves all of them unwritten, and the token redeemable.

use std::cell::{Cell, RefCell};

use crate::audit::{AuditAction, AuditError, CreateAuditEvent};
use crate::core::{RealmId, SessionId, Timestamp};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::types::Session;
use crate::storage::StorageError;

use super::single_use::single_use_marker;
use super::EmbeddedIdentityEngine;

/// What [`EmbeddedIdentityEngine::commit_refresh_rotation`] did.
pub(super) enum RotationCommit {
    /// The rotation is durable.
    Committed,
    /// The presented token's claim already existed, so nothing was written:
    /// the token was already rotated (a replay) or spent by a revocation.
    AlreadyClaimed,
}

impl EmbeddedIdentityEngine {
    /// The session a refresh may extend: `SessionNotFound` when it is
    /// revoked, expired, or past a timeout policy, which also evicts it.
    ///
    /// The caller MUST hold the session's row lock
    /// ([`Self::session_row_lock`]): the eviction is a write of the row, and
    /// the lock keeps it from racing a refresh's write (audit GA 2026-09-28
    /// B7).
    pub(super) fn refreshable_session_locked(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError> {
        let session = self
            .load_session_raw(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;
        let now = self.clock.now();
        // Cannot refresh a revoked, TTL-expired, or A-18 policy-expired session.
        if !session.is_valid(now) || session.is_policy_expired(now) {
            if session.is_valid(now) && session.is_policy_expired(now) {
                let _ = self.evict_session_by_policy(realm_id, &session, now);
            }
            return Err(IdentityError::SessionNotFound);
        }
        Ok(session)
    }

    /// Spends the presented refresh token and persists its rotation in ONE
    /// atomic write: the token's single-use claim (`claim_key`, dated
    /// `claim_expires_at`), the rotated grant family (`family_row`), the
    /// session's sliding expiry and the `TokenRefreshed` event.
    ///
    /// The caller holds the grant family's rotation lock. The session's row
    /// lock is taken here, before the write is enqueued, and held until it is
    /// durable: an enqueue can make this thread the group-commit leader, and
    /// a lock taken after it could wait on a writer that waits for this
    /// thread.
    ///
    /// # Errors
    ///
    /// `SessionNotFound` when the session can no longer be refreshed; a
    /// storage error when the write is refused or fails. In both cases nothing
    /// was written and the token is not spent.
    pub(super) fn commit_refresh_rotation(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
        claim_key: &[u8],
        claim_expires_at: Timestamp,
        family_row: (Vec<u8>, Vec<u8>),
    ) -> Result<RotationCommit, IdentityError> {
        let row_lock = self.session_row_lock(realm_id, session_id);
        // INVARIANT: guard held only across the sync load + write + durability wait; no .await in scope.
        let row = row_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut session = self.refreshable_session_locked(realm_id, session_id)?;
        session.refresh(self.clock.now(), self.config.session.ttl_micros);
        // A refresh does not write the session's created-time index entries
        // (#847); the live-session entry exists while the row is not revoked.
        let rows = [
            family_row,
            (
                keys::encode_session_id(session.id()),
                Self::serialize_session(&session)?,
            ),
            (keys::encode_live_session(session.id()), Vec::new()),
        ];
        let marker = single_use_marker(claim_expires_at);
        let event = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: "system".to_string(),
            action: AuditAction::TokenRefreshed,
            resource_type: "token".to_string(),
            resource_id: session_id.as_uuid().to_string(),
            metadata: None,
        };

        // The audit event joins the batch through the audit engine's merged
        // append (HEA-1954). A lost claim or a refused write is told to it as
        // an enqueue error, so it rolls its chain head back; the cells say
        // which it was.
        let claimed = Cell::new(false);
        let refused: RefCell<Option<StorageError>> = RefCell::new(None);
        let merged = self.audit.with_pending_append(
            &event,
            Box::new(|audit_rows| {
                let mut batch = rows.to_vec();
                batch.extend_from_slice(audit_rows);
                match self
                    .storage
                    .enqueue_batch_if_absent(realm_id, claim_key, &marker, &batch)
                {
                    Ok(Some(handle)) => Ok(handle),
                    Ok(None) => {
                        claimed.set(true);
                        Err(StorageError::Io(std::io::Error::other(
                            "the refresh token was already claimed",
                        )))
                    }
                    Err(e) => {
                        let message = e.to_string();
                        *refused.borrow_mut() = Some(e);
                        Err(StorageError::Io(std::io::Error::other(message)))
                    }
                }
            }),
        );
        match merged {
            Ok(pending) => {
                let durable = self.storage.await_batch_durable(pending.handle);
                if durable.is_err() {
                    (pending.on_failure)();
                } else {
                    (pending.on_success)();
                }
                durable.map_err(Self::storage_err)?;
            }
            Err(_) if claimed.get() => return Ok(RotationCommit::AlreadyClaimed),
            Err(e) => {
                if let Some(refusal) = refused.take() {
                    return Err(Self::storage_err(refusal));
                }
                // No merged append: an audit engine without one, or an audit
                // error before the enqueue. The rotation is written alone,
                // then its event; `TokenRefreshed` is LogOnly.
                if !matches!(e, AuditError::MergedAppendNotSupported) {
                    tracing::warn!(
                        error = %e,
                        "audit pre-enqueue failed for TokenRefreshed (LogOnly); \
                         writing the rotation without it"
                    );
                }
                let Some(handle) = self
                    .storage
                    .enqueue_batch_if_absent(realm_id, claim_key, &marker, &rows)
                    .map_err(Self::storage_err)?
                else {
                    return Ok(RotationCommit::AlreadyClaimed);
                };
                self.storage
                    .await_batch_durable(handle)
                    .map_err(Self::storage_err)?;
                self.record_audit(
                    realm_id,
                    None,
                    AuditAction::TokenRefreshed,
                    "token",
                    &session_id.as_uuid().to_string(),
                )?;
            }
        }
        drop(row);

        if session.is_valid(self.clock.now()) {
            self.session_cache_insert(realm_id, &session);
        } else {
            self.session_cache_invalidate(realm_id, session.id());
        }
        Ok(RotationCommit::Committed)
    }
}
