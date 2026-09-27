//! Control-cache coherence: the caches that decide a control on the
//! validation path, kept in step with storage without ever making validation
//! wait.
//!
//! Three caches are authoritative on the validation path — a miss is a
//! decision, not a reason to consult storage: the revoked-JTI blocklist, the
//! DPoP key blocklist and realm statuses. The node that serves a control write
//! applies it to its own caches at once. Every other node learns of it through
//! the *control epoch*, a counter in storage that each control write bumps
//! atomically ([`crate::storage::StorageEngine::increment_u64`]) and that
//! replicates with the rows it describes; a node whose caches trail the
//! persisted epoch reloads them from storage.
//!
//! # Who does what
//!
//! * **Validation** only compares epochs. When it sees the persisted epoch
//!   ahead of the one these caches reflect, it [signals](ControlPlane::signal)
//!   the reloader: one atomic `fetch_max` and an `unpark`. No lock, no
//!   allocation, no reload of its own (ARCHITECTURE.md §3.2 rule 3). In
//!   cluster mode the replicated epoch row signals the reloader directly from
//!   the state machine, so validation is not even the usual trigger.
//! * **The reloader** is one background thread per engine. It scans storage
//!   with no lock held, then swaps the new contents in.
//! * **Writers** — a local control write, or a replicated row projected by the
//!   Raft observer — apply their change to the caches under the `journal`
//!   lock, which only writers and the reloader ever take.
//!
//! # Why a writer's change survives a concurrent reload
//!
//! A reload marks the journal as *recording* before its scan starts, and every
//! writer that applies a change while it records also appends the change to
//! the journal. Under the same lock, the reload replays the journal onto its
//! scan and swaps the result in. A writer's durable row is written before its
//! change is applied, so each change is either
//!
//! * applied before recording began — then its row predates the scan, which
//!   therefore includes it;
//! * applied while recording — then it is replayed onto the scan; or
//! * applied after the swap — then it lands on the new contents.
//!
//! The lock covers only in-memory work: appending one entry, or replaying the
//! journal and storing one pointer per shard. Nobody holds it across storage
//! I/O, and validation never takes it. A reload whose scan fails records
//! nothing and retries with backoff, so a failed scan can never consume the
//! epoch it was reloading for.
//!
//! # Epoch bookkeeping
//!
//! `applied` is the epoch the caches are known to reflect. A local writer
//! learns the value its bump produced and records it, but may only advance
//! `applied` through a contiguous run of epochs this node applied itself: a
//! gap means another node's control is in between, which only a reload can
//! bring in. A reload records the persisted epoch it read *before* its scan,
//! because any control bumped later may be missing from the scan and must
//! cause another reload.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};

use super::sharded_cache::ShardedEpochMap;
use crate::core::{Clock, EpochCell, RealmId, SessionId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::tokens::TokenClaims;
use crate::identity::types::{Realm, RealmStatus, Session};
use crate::storage::StorageEngine;

/// How long the reloader waits after a signal before it compares epochs.
///
/// On a cluster leader the observer sees this node's own epoch bump replicate
/// back a moment before the writer records it, and on a single node a
/// validation can read a fresh bump in the same window. Waiting this long lets
/// the writer finish, so a node does not reload for a control it has already
/// applied.
const RELOAD_SETTLE: Duration = Duration::from_millis(5);

/// Minimum time between the starts of two reloads.
///
/// A reload scans every revocation, blocked key and realm and drops the
/// session and token-claims caches, so a steady stream of controls elsewhere
/// must not turn into a steady stream of reloads here. Controls that arrive
/// inside the window are coalesced into the next reload. Matches the
/// validation path's own epoch debounce, so the propagation bound documented
/// there (task 24.6) is unchanged.
const RELOAD_MIN_SPACING: Duration = Duration::from_millis(200);

/// First retry delay after a failed reload; doubles up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_millis(100);

/// Longest retry delay after repeated reload failures.
const RETRY_MAX: Duration = Duration::from_secs(5);

/// How long the idle reloader parks before re-checking on its own, in case a
/// signal raced the publication of its thread handle.
const IDLE_RECHECK: Duration = Duration::from_secs(1);

/// The in-process session cache, keyed by `(realm, session)`.
pub(super) type SessionCache = EpochCell<HashMap<(RealmId, SessionId), Arc<Session>>>;

/// The in-process token-claims cache, keyed by the SHA-256 of the raw JWT.
pub(super) type ClaimsCache = EpochCell<HashMap<[u8; 32], Arc<TokenClaims>>>;

/// One change to a control cache, as a writer applies it and as a reload
/// replays it.
pub(super) enum ControlOp {
    /// Add `{realm_uuid}:{jti}` to the revoked-JTI blocklist until `exp`
    /// (Unix seconds; `i64::MAX` for a legacy row without one).
    RevokeJti {
        /// The composite cache key.
        key: String,
        /// Expiry in Unix seconds.
        exp: i64,
    },
    /// Remove a revoked-JTI entry whose row was deleted (the expiry sweep).
    ForgetJti {
        /// The composite cache key.
        key: String,
    },
    /// Add a JWK thumbprint to the DPoP blocklist.
    BlockJkt(String),
    /// Remove a JWK thumbprint from the DPoP blocklist.
    UnblockJkt(String),
    /// Record a realm's lifecycle status.
    SetRealmStatus(RealmId, RealmStatus),
    /// Drop a realm's status (the realm was deleted).
    ForgetRealmStatus(RealmId),
}

/// Handles to every cache a control reload rebuilds or flushes. Cloning
/// shares the caches.
#[derive(Clone)]
pub(super) struct ControlCaches {
    /// Realm lifecycle statuses; an absent realm reads as active.
    pub(super) realm_status: Arc<EpochCell<HashMap<RealmId, RealmStatus>>>,
    /// `{realm_uuid}:{jti}` → expiry.
    pub(super) revoked_jti: Arc<ShardedEpochMap<String, i64>>,
    /// Blocked DPoP JWK thumbprints.
    pub(super) blocked_jkt: Arc<ShardedEpochMap<String, ()>>,
    /// Live sessions; dropped by every reload so a session revoked elsewhere
    /// is re-read from storage.
    pub(super) sessions: Arc<SessionCache>,
    /// Generation guarding cache-miss fills of [`Self::sessions`].
    pub(super) session_gen: Arc<AtomicU64>,
    /// Verified token claims; dropped by every reload.
    pub(super) claims: Arc<ClaimsCache>,
    /// Generation guarding cache-miss fills of [`Self::claims`] (HEA-2097).
    pub(super) claims_gen: Arc<AtomicU64>,
}

impl ControlCaches {
    /// Empty caches.
    pub(super) fn new() -> Self {
        Self {
            realm_status: Arc::new(EpochCell::from_pointee(HashMap::new())),
            revoked_jti: Arc::new(ShardedEpochMap::new()),
            blocked_jkt: Arc::new(ShardedEpochMap::new()),
            sessions: Arc::new(EpochCell::from_pointee(HashMap::new())),
            session_gen: Arc::new(AtomicU64::new(0)),
            claims: Arc::new(EpochCell::from_pointee(HashMap::new())),
            claims_gen: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Drops every cached session so the next lookup re-reads storage.
    ///
    /// The generation moves first, then a `SeqCst` fence, then the store:
    /// a cache-miss fill that loaded a session before this flush either sees
    /// the new generation and discards its insert, or has already inserted and
    /// is removed by the store (see `EmbeddedIdentityEngine::get_session_arc`).
    pub(super) fn flush_sessions(&self) {
        self.session_gen.fetch_add(1, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        self.sessions.store(Arc::new(HashMap::new()));
    }

    /// Drops every memoized token-claims entry (HEA-2097 ordering: the
    /// generation moves before the map is cleared).
    pub(super) fn flush_claims(&self) {
        self.claims_gen.fetch_add(1, Ordering::AcqRel);
        self.claims.store(Arc::new(HashMap::new()));
    }
}

/// Writer/reloader state, guarded by [`ControlPlane::journal`].
#[derive(Default)]
struct Journal {
    /// A reload is between its "start recording" and its swap.
    recording: bool,
    /// Changes applied while recording, in application order.
    ops: Vec<ControlOp>,
    /// Epochs this node bumped and applied that are above `applied` but not
    /// yet contiguous with it.
    local_epochs: BTreeSet<u64>,
}

/// A reload's scan of storage, not yet published.
struct Scan {
    epoch: u64,
    realm_status: HashMap<RealmId, RealmStatus>,
    revoked_jti: HashMap<String, i64>,
    blocked_jkt: HashSet<String>,
}

/// Owns the control caches' coherence with storage. See the module docs.
pub(super) struct ControlPlane {
    storage: Arc<dyn StorageEngine>,
    clock: Arc<dyn Clock>,
    caches: ControlCaches,
    /// Highest control epoch the caches are known to reflect.
    applied: AtomicU64,
    /// Highest persisted epoch anyone has signalled.
    target: AtomicU64,
    /// A full reload was requested regardless of epochs (snapshot install, or
    /// a retry after a failed forced reload).
    force: AtomicBool,
    /// Set when the owning engine drops; the reloader exits.
    shutdown: AtomicBool,
    /// Taken only by control writers and the reloader — never by validation.
    journal: Mutex<Journal>,
    /// One reload at a time (the background thread and a snapshot install).
    reload_exclusive: Mutex<()>,
    /// The reloader thread, once started, for `unpark`.
    worker: OnceLock<Thread>,
    /// The runtime the engine was built in: cluster storage reads block on
    /// it, so the reloader thread enters it.
    runtime: Option<tokio::runtime::Handle>,
    /// Test hook run by a reload after its scan and before it replays the
    /// journal and swaps: the reload is held mid-flight.
    #[cfg(test)]
    scan_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every holder leaves the guarded state consistent (it is replaced
    // wholesale or appended to), so a poisoned lock is still usable.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ControlPlane {
    /// A control plane over `caches`. Call [`Self::start`] to run the
    /// background reloader.
    pub(super) fn new(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        caches: ControlCaches,
    ) -> Arc<Self> {
        Arc::new(Self {
            storage,
            clock,
            caches,
            applied: AtomicU64::new(0),
            target: AtomicU64::new(0),
            force: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            journal: Mutex::new(Journal::default()),
            reload_exclusive: Mutex::new(()),
            worker: OnceLock::new(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            #[cfg(test)]
            scan_hook: Mutex::new(None),
        })
    }

    /// Starts the background reloader. Returns its handle for the owner to
    /// join after [`Self::shutdown`], or `None` if the thread could not be
    /// spawned (validation then relies on start-up state and local writes;
    /// the failure is logged).
    pub(super) fn start(self: &Arc<Self>) -> Option<JoinHandle<()>> {
        let plane = Arc::clone(self);
        match std::thread::Builder::new()
            .name("hearth-control-reload".to_string())
            .spawn(move || plane.run())
        {
            Ok(handle) => {
                let _ = self.worker.set(handle.thread().clone());
                Some(handle)
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "could not start the control-cache reloader; controls asserted on other \
                     nodes will bind here only after a restart"
                );
                None
            }
        }
    }

    /// Stops the background reloader; the owner then joins its handle.
    pub(super) fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.wake();
    }

    /// The control epoch the caches are known to reflect.
    pub(super) fn applied_epoch(&self) -> u64 {
        self.applied.load(Ordering::Acquire)
    }

    /// Tells the reloader the persisted epoch is at least `persisted`.
    ///
    /// Safe on the validation path: one atomic load, and when the epoch has
    /// moved one `fetch_max` and an `unpark`. No lock, no allocation, never
    /// waits for the reload.
    pub(super) fn signal(&self, persisted: u64) {
        if persisted <= self.applied.load(Ordering::Acquire) {
            return;
        }
        self.target.fetch_max(persisted, Ordering::AcqRel);
        self.wake();
    }

    /// Asks the reloader for a full reload whatever the epochs say.
    pub(super) fn request_full_reload(&self) {
        self.force.store(true, Ordering::Release);
        self.wake();
    }

    fn wake(&self) {
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
    }

    /// Applies one control change to the caches, and records `epoch` — the
    /// value this node's own bump for the change produced — when there is one.
    ///
    /// Called by local control writers after their durable row and epoch bump
    /// are written, and by the Raft observer to project a replicated row (with
    /// no epoch: the observer never writes). Takes the journal lock for
    /// in-memory work only.
    pub(super) fn apply(&self, op: Option<ControlOp>, epoch: Option<u64>) {
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let mut journal = lock(&self.journal);
        if let Some(op) = op {
            self.apply_to_caches(&op, now_secs);
            if journal.recording {
                journal.ops.push(op);
            }
        }
        if let Some(epoch) = epoch {
            self.record_local_epoch(&mut journal, epoch);
        }
    }

    fn apply_to_caches(&self, op: &ControlOp, now_secs: i64) {
        match op {
            ControlOp::RevokeJti { key, exp } => {
                // Evict expired entries in the target shard while it is cloned.
                self.caches
                    .revoked_jti
                    .insert_retaining(key.clone(), *exp, |_, &e| e == i64::MAX || now_secs < e);
            }
            ControlOp::ForgetJti { key } => self.caches.revoked_jti.remove(key.as_str()),
            ControlOp::BlockJkt(jkt) => self.caches.blocked_jkt.insert(jkt.clone(), ()),
            ControlOp::UnblockJkt(jkt) => self.caches.blocked_jkt.remove(jkt.as_str()),
            ControlOp::SetRealmStatus(realm, status) => {
                self.caches.realm_status.rcu(|current| {
                    let mut next = HashMap::clone(current);
                    next.insert(realm.clone(), *status);
                    next
                });
            }
            ControlOp::ForgetRealmStatus(realm) => {
                self.caches.realm_status.rcu(|current| {
                    let mut next = HashMap::clone(current);
                    next.remove(realm);
                    next
                });
            }
        }
    }

    /// Advances `applied` through `epoch` if every epoch between them was
    /// also applied here; otherwise parks `epoch` until they are, or until a
    /// reload covers the gap. Caller holds the journal lock.
    fn record_local_epoch(&self, journal: &mut Journal, epoch: u64) {
        let applied = self.applied.load(Ordering::Acquire);
        if epoch <= applied {
            return;
        }
        journal.local_epochs.insert(epoch);
        self.advance_applied(journal, applied);
    }

    /// Sets `applied` to `floor` (if higher), then through every contiguous
    /// epoch recorded in `local_epochs`. Caller holds the journal lock.
    fn advance_applied(&self, journal: &mut Journal, floor: u64) {
        let mut applied = self.applied.load(Ordering::Acquire).max(floor);
        journal.local_epochs.retain(|&e| e > applied);
        while journal.local_epochs.remove(&(applied + 1)) {
            applied += 1;
        }
        self.applied.store(applied, Ordering::Release);
    }

    /// Reloads every control cache from storage now, on the calling thread.
    ///
    /// Used at start-up, after a snapshot install, and by the background
    /// reloader. Concurrent control writes are preserved (module docs). On
    /// error nothing is published and no epoch is recorded.
    ///
    /// # Errors
    ///
    /// The first storage or decoding error of the scan.
    pub(super) fn reload(&self) -> Result<(), IdentityError> {
        let _exclusive = lock(&self.reload_exclusive);
        let scan = self.scan_recording()?;
        let mut revoked = self.caches.revoked_jti.prepare(scan.revoked_jti);
        let mut blocked = self
            .caches
            .blocked_jkt
            .prepare(scan.blocked_jkt.into_iter().map(|jkt| (jkt, ())));
        let mut statuses = scan.realm_status;
        {
            let mut journal = lock(&self.journal);
            for op in journal.ops.drain(..) {
                match op {
                    ControlOp::RevokeJti { key, exp } => {
                        self.caches
                            .revoked_jti
                            .prepared_insert(&mut revoked, key, exp);
                    }
                    ControlOp::ForgetJti { key } => {
                        self.caches
                            .revoked_jti
                            .prepared_remove(&mut revoked, key.as_str());
                    }
                    ControlOp::BlockJkt(jkt) => {
                        self.caches
                            .blocked_jkt
                            .prepared_insert(&mut blocked, jkt, ());
                    }
                    ControlOp::UnblockJkt(jkt) => {
                        self.caches
                            .blocked_jkt
                            .prepared_remove(&mut blocked, jkt.as_str());
                    }
                    ControlOp::SetRealmStatus(realm, status) => {
                        statuses.insert(realm, status);
                    }
                    ControlOp::ForgetRealmStatus(realm) => {
                        statuses.remove(&realm);
                    }
                }
            }
            journal.recording = false;
            self.caches.revoked_jti.install(revoked);
            self.caches.blocked_jkt.install(blocked);
            self.caches.realm_status.store(Arc::new(statuses));
            self.advance_applied(&mut journal, scan.epoch);
        }
        // `lookup_session` returns a cached live session without consulting
        // storage, so a session revoked on another node stays live here until
        // the entry is dropped; and a memoized token skips the checks a
        // reload may have changed the answer to.
        self.caches.flush_sessions();
        self.caches.flush_claims();
        Ok(())
    }

    /// Reads the persisted epoch, starts recording, and scans. Stops recording
    /// again if the scan fails.
    fn scan_recording(&self) -> Result<Scan, IdentityError> {
        // Read before the scan: a control bumped after this read may be
        // missing from the scan, and must leave the persisted epoch ahead of
        // what this reload records, so that it causes another one.
        let epoch = self.read_persisted_epoch()?;
        {
            let mut journal = lock(&self.journal);
            journal.recording = true;
            journal.ops.clear();
        }
        let scanned = self.scan(epoch);
        #[cfg(test)]
        {
            let hook = lock(&self.scan_hook).clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        if scanned.is_err() {
            let mut journal = lock(&self.journal);
            journal.recording = false;
            journal.ops.clear();
        }
        scanned
    }

    fn scan(&self, epoch: u64) -> Result<Scan, IdentityError> {
        let realms = self.scan_realms()?;
        let mut realm_status = HashMap::new();
        for realm in &realms {
            if !keys::is_system_realm(realm.id()) {
                realm_status.insert(realm.id().clone(), realm.status());
            }
        }
        // The system realm's revocations and DPoP blocks are control rows too
        // (its admin and system tokens can be revoked or DPoP-bound). Include
        // it whether or not its realm record is present.
        let mut realm_ids: Vec<RealmId> = vec![keys::system_realm_id()];
        realm_ids.extend(
            realms
                .iter()
                .map(|realm| realm.id().clone())
                .filter(|id| !keys::is_system_realm(id)),
        );
        Ok(Scan {
            epoch,
            realm_status,
            revoked_jti: self.scan_revoked_jtis(&realm_ids)?,
            blocked_jkt: self.scan_blocked_jkts(&realm_ids)?,
        })
    }

    fn read_persisted_epoch(&self) -> Result<u64, IdentityError> {
        let raw = self
            .storage
            .get(&keys::system_realm_id(), &keys::encode_control_epoch())
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        crate::storage::decode_u64_counter(raw.as_deref())
            .map_err(|e| IdentityError::Storage(Box::new(e)))
    }

    /// Every realm record. Fail-closed: a corrupted record is an error, not a
    /// realm silently missing from the status cache (which reads as active).
    fn scan_realms(&self) -> Result<Vec<Realm>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        entries
            .iter()
            .map(|entry| {
                serde_json::from_slice::<Realm>(&entry.value).map_err(|e| {
                    tracing::error!(
                        key = ?entry.key,
                        err = %e,
                        "realm deserialization failed while loading the control caches"
                    );
                    IdentityError::Internal {
                        reason: format!("realm status cache population failed: {e}"),
                    }
                })
            })
            .collect()
    }

    /// `oauth:revjti:*` in every realm, minus entries already expired. Two
    /// value formats: an 8-byte little-endian expiry, or the legacy `b"1"`
    /// (no expiry; never self-evicts — the `exp` claim check catches it).
    fn scan_revoked_jtis(&self, realms: &[RealmId]) -> Result<HashMap<String, i64>, IdentityError> {
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        let prefix = keys::revoked_jti_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let mut map = HashMap::new();
        for realm in realms {
            let entries = self
                .storage
                .scan(realm, &prefix, &end)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?;
            for entry in entries {
                let exp = decode_revoked_jti_expiry(&entry.value);
                if exp != i64::MAX && now_secs >= exp {
                    continue;
                }
                let jti = String::from_utf8_lossy(entry.key.get(prefix.len()..).unwrap_or(&[]));
                map.insert(revoked_jti_cache_key(realm, &jti), exp);
            }
        }
        Ok(map)
    }

    /// `agt:dpop:block:jkt:*` in every realm.
    fn scan_blocked_jkts(&self, realms: &[RealmId]) -> Result<HashSet<String>, IdentityError> {
        let prefix = keys::blocked_dpop_jkt_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let mut set = HashSet::new();
        for realm in realms {
            let entries = self
                .storage
                .scan(realm, &prefix, &end)
                .map_err(|e| IdentityError::Storage(Box::new(e)))?;
            for entry in entries {
                let jkt = entry.key.get(prefix.len()..).unwrap_or(&[]);
                set.insert(String::from_utf8_lossy(jkt).into_owned());
            }
        }
        Ok(set)
    }

    fn reload_wanted(&self) -> bool {
        self.force.load(Ordering::Acquire)
            || self.target.load(Ordering::Acquire) > self.applied.load(Ordering::Acquire)
    }

    /// Parks until `deadline` or shutdown. Returns `false` on shutdown.
    fn pause_until(&self, deadline: Instant) -> bool {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            std::thread::park_timeout(deadline - now);
        }
    }

    /// The background reloader's loop.
    fn run(self: Arc<Self>) {
        let _runtime = self.runtime.as_ref().map(tokio::runtime::Handle::enter);
        let mut last_start: Option<Instant> = None;
        let mut backoff = RETRY_MIN;
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return;
            }
            if !self.reload_wanted() {
                std::thread::park_timeout(IDLE_RECHECK);
                continue;
            }
            let mut not_before = Instant::now() + RELOAD_SETTLE;
            if let Some(started) = last_start {
                not_before = not_before.max(started + RELOAD_MIN_SPACING);
            }
            if !self.pause_until(not_before) {
                return;
            }
            if !self.reload_wanted() {
                continue;
            }
            let forced = self.force.swap(false, Ordering::AcqRel);
            last_start = Some(Instant::now());
            let outcome = catch_unwind(AssertUnwindSafe(|| self.reload())).unwrap_or_else(|_| {
                Err(IdentityError::Internal {
                    reason: "control-cache reload panicked".to_string(),
                })
            });
            match outcome {
                Ok(()) => {
                    backoff = RETRY_MIN;
                    tracing::debug!(
                        epoch = self.applied_epoch(),
                        "control caches reloaded after a control was asserted elsewhere"
                    );
                }
                Err(err) => {
                    // Nothing was recorded, so the epoch still reads as ahead
                    // and the next pass retries. A forced reload re-arms.
                    if forced {
                        self.force.store(true, Ordering::Release);
                    }
                    tracing::warn!(
                        error = %err,
                        retry_in_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                        "control-cache reload failed; controls asserted on other nodes are \
                         not yet enforced here"
                    );
                    if !self.pause_until(Instant::now() + backoff) {
                        return;
                    }
                    backoff = (backoff * 2).min(RETRY_MAX);
                }
            }
        }
    }

    /// Holds the writer/reloader lock, for tests proving validation never
    /// takes it.
    #[cfg(test)]
    pub(super) fn lock_writers_for_test(&self) -> MutexGuard<'_, impl Sized> {
        lock(&self.journal)
    }

    /// Installs a hook every reload runs after its scan and before its swap
    /// (`None` removes it).
    #[cfg(test)]
    pub(super) fn set_scan_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.scan_hook) = hook;
    }
}

/// Decodes a revoked-JTI row's value: an 8-byte little-endian expiry, or
/// `i64::MAX` for the legacy `b"1"` format.
pub(super) fn decode_revoked_jti_expiry(value: &[u8]) -> i64 {
    <[u8; 8]>::try_from(value).map_or(i64::MAX, i64::from_le_bytes)
}

/// The revoked-JTI cache key: `{realm_uuid}:{jti}`.
pub(super) fn revoked_jti_cache_key(realm: &RealmId, jti: &str) -> String {
    format!("{}:{}", realm.as_uuid(), jti)
}
