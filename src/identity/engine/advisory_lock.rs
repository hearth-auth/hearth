//! Refcount-reclaimed per-key advisory locks.
//!
//! Several TOCTOU fixes in [`EmbeddedIdentityEngine`](super::EmbeddedIdentityEngine)
//! serialize a read-modify-write on a *caller-supplied* key: the SHA-256 of an
//! authorization code, the SHA-256 of a magic-link or password-reset token.
//! Each is a `Mutex<HashMap<String, Arc<Mutex<()>>>>` whose entries were only
//! ever inserted. An unauthenticated caller therefore controlled the map's
//! cardinality — one entry per distinct code or token ever presented, valid or
//! not, retained for the life of the process (audit 2026-08-28 §4.3#4).
//!
//! # Why refcounting rather than a capacity bound
//!
//! A capacity bound with eviction would have to evict a *live* entry once the
//! map filled, and evicting a lock that a task is holding silently deletes the
//! mutual exclusion the lock exists to provide: a second request for the same
//! code would insert a fresh mutex and run concurrently with the first. Under
//! an attacker-driven insert rate that is exactly when it would happen.
//!
//! Refcounting is exact instead. [`AdvisoryLock`] holds one strong reference
//! alongside the map's own; when the last handle drops, `Drop` reclaims the
//! entry. The reclamation check runs while holding the outer map lock, and an
//! acquirer can only clone a handle while holding that same lock, so an entry
//! another task is about to take always shows an extra strong reference and is
//! never removed out from under it.

use std::collections::HashMap;
use std::sync::{Arc, LockResult, Mutex, MutexGuard};

/// The map type an [`AdvisoryLock`] is drawn from.
pub(super) type AdvisoryLockMap = Mutex<HashMap<String, Arc<Mutex<()>>>>;

/// A handle to one per-key advisory lock.
///
/// Acquire the mutual exclusion with [`AdvisoryLock::lock`]; the returned guard
/// borrows from this handle, so the handle necessarily outlives it and the map
/// entry is reclaimed only after the guard is released.
///
/// Callers keep the existing two-step shape:
///
/// ```text
/// let lock = self.code_exchange_lock(&code_hash);
/// let _guard = lock.lock().expect("code_exchange_lock poisoned");
/// ```
///
/// Rust drops bindings in reverse declaration order, so `_guard` is released
/// before `lock`, and the reclamation in [`Drop`] never runs while the mutex is
/// still held by this caller.
pub(super) struct AdvisoryLock<'a> {
    /// The map this entry was drawn from; re-locked on drop to reclaim.
    map: &'a AdvisoryLockMap,
    /// The map key, retained so `Drop` can address the entry.
    key: String,
    /// This handle's strong reference to the per-key mutex.
    inner: Arc<Mutex<()>>,
}

impl<'a> AdvisoryLock<'a> {
    /// Returns the handle for `key`, inserting a fresh mutex when absent.
    ///
    /// The outer map guard is released before this returns, so two callers with
    /// different keys never contend on anything but the (uncontended) map lock.
    ///
    /// # Panics
    ///
    /// Panics if the outer map mutex is poisoned, matching the previous
    /// behaviour of the accessors this replaces: a poisoned advisory-lock map
    /// means a prior holder panicked mid-critical-section and the serialization
    /// guarantee is already void.
    pub(super) fn acquire(map: &'a AdvisoryLockMap, key: &str) -> Self {
        let inner = {
            let mut guard = map.lock().expect("advisory lock map poisoned");
            Arc::clone(
                guard
                    .entry(key.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        Self {
            map,
            key: key.to_string(),
            inner,
        }
    }

    /// Locks the per-key mutex.
    ///
    /// Mirrors [`Mutex::lock`], including the poisoning `Result`, so call sites
    /// that previously held an `Arc<Mutex<()>>` are unchanged.
    pub(super) fn lock(&self) -> LockResult<MutexGuard<'_, ()>> {
        self.inner.lock()
    }

    /// Returns the underlying mutex, for identity comparisons in tests.
    #[cfg(test)]
    pub(super) fn mutex(&self) -> &Mutex<()> {
        &self.inner
    }
}

impl Drop for AdvisoryLock<'_> {
    fn drop(&mut self) {
        let Ok(mut guard) = self.map.lock() else {
            // A poisoned map means some holder panicked. Leaking one entry is
            // strictly better than panicking again inside a drop.
            return;
        };
        // Two strong references — the map's and ours — means no other handle
        // exists, and none can be created without the map lock we hold. Any
        // other count means a live holder (or a task that has already cloned
        // the handle and is about to lock it), so the entry stays.
        if let Some(existing) = guard.get(&self.key) {
            if Arc::strong_count(existing) == 2 && Arc::ptr_eq(existing, &self.inner) {
                guard.remove(&self.key);
            }
        }
    }
}
