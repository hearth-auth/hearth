//! Cluster engine: public-facing storage wrapper with single-node bypass.
//!
//! [`ClusterEngine`] routes reads and writes through Raft when cluster mode
//! is active. In single-node mode all calls go directly to the inner
//! [`EmbeddedStorageEngine`] with zero overhead.
//!
//! ## Write path (cluster mode)
//! Every mutation creates a [`RaftCommand`] carrying a `leader_timestamp`
//! stamped at proposal time, proposes it via `Raft::client_write`, and blocks
//! until quorum commit.
//!
//! On a follower the proposal is refused without entering the log, and the
//! command is **forwarded** to the leader over the peer mTLS channel (the
//! `ForwardWrite` RPC) — standard Raft client-request forwarding, as in
//! etcd and Consul. The leader restamps and proposes it and answers with the
//! committed log index and the state-machine response; the follower then
//! waits until its own state machine has applied that index, so the caller
//! reads its own write on the node it wrote to. See
//! [`ClusterEngine::propose_with_response`] for the retry rules that keep
//! conditional commands exactly-once. [`ClusterError::NotLeader`] now means
//! no leader could be reached at all.
//!
//! ## Read path (cluster mode)
//! A background task updates [`ClusterEngine::reads_allowed`] every 50 ms by
//! comparing `last_log_index` vs `last_applied` log indices. Reads check the
//! flag; if `false` the caller receives [`ClusterError::ReplicationLagExceeded`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use openraft::error::{ClientWriteError, RaftError};
use openraft::metrics::WaitError;
use openraft::raft::ClientWriteResponse;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use openraft::{Config as RaftConfig, EntryPayload, RaftMetrics, ServerState};
use tokio::task::spawn_blocking;
use tracing::{info, warn};

use crate::cluster::log_store::HearthLogStore;
use crate::cluster::network::{ForwardFailure, HearthNetworkFactory, LeaderForwarder, PeerFaults};
use crate::cluster::server::IncomingRpcDispatch;
use crate::cluster::state_machine::HearthStateMachine;
use crate::cluster::types::{
    ForwardedWriteOutcome, HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand,
};
use crate::cluster::wire::{self, MAX_COMMAND_BYTES, SNAPSHOT_CHUNK_BYTES};
use crate::cluster::ReplicatedWriteObserver;
use crate::config::ClusterConfig;
use crate::core::RealmId;
use crate::metrics::ForwardedWriteOutcomeLabel;
use crate::storage::{EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine};

// ── Error types ───────────────────────────────────────────────────────────────

/// Error produced by cluster-layer storage operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// This node is not the Raft leader; clients should redirect.
    #[error("not the leader; redirect to {leader_addr}")]
    NotLeader { leader_addr: String },

    /// Follower replication lag exceeds the configured threshold.
    #[error("replication lag exceeded; redirect to {leader_addr}")]
    ReplicationLagExceeded { leader_addr: String },

    /// Underlying storage returned an error.
    #[error("storage: {0}")]
    Storage(#[from] crate::storage::StorageError),

    /// A replicated write was accepted by this node but did not reach quorum
    /// commit within `cluster.write_timeout_ms` (task 26.58).
    ///
    /// The proposal is **not** cancelled — openraft may still commit it after
    /// this error is returned, so the caller must treat the outcome as
    /// unknown and re-read rather than assume the write was lost.
    #[error(
        "replicated write did not reach quorum commit within {timeout_ms} ms and its outcome \
         is unknown; leadership or quorum was most likely lost mid-write \
         (last known leader: {leader_addr})"
    )]
    WriteTimeout {
        timeout_ms: u64,
        leader_addr: String,
    },

    /// A write forwarded to the leader may or may not have been applied:
    /// the connection to the leader was lost after the request was sent, or
    /// the leader could not tell whether its proposal committed.
    ///
    /// Never retried — a conditional command (`PutIfAbsent`, `IncrementU64`)
    /// applied twice is a different result. The caller must re-read.
    #[error(
        "the write was forwarded to the leader at {leader_addr} and its outcome is unknown \
         ({reason}); it may or may not have been applied — re-read before retrying"
    )]
    ForwardOutcomeUnknown { leader_addr: String, reason: String },

    /// The leader refused a forwarded write without proposing it because it
    /// is serving its limit of forwarded writes. Nothing was written; retry.
    #[error("the leader at {leader_addr} is at its forwarded-write limit; retry shortly")]
    LeaderBusy { leader_addr: String },

    /// The leader refused a forwarded write without proposing it, for a reason
    /// a retry does not cure (undecodable, too large, older build).
    #[error("the leader at {leader_addr} refused the forwarded write: {reason}")]
    ForwardRejected { leader_addr: String, reason: String },

    /// A forwarded write committed, but this node had not applied it within
    /// its bound, so answering success would break read-your-writes on this
    /// node. The write is durable and becomes visible here once this node's
    /// state machine catches up.
    #[error(
        "the write committed at log index {log_index} but this node did not apply it within \
         {timeout_ms} ms; it becomes visible here once replication catches up"
    )]
    NotAppliedLocally { log_index: u64, timeout_ms: u64 },

    /// A write too large to replicate: its Raft entry would not fit a peer
    /// message. Refused before it is proposed, so nothing was written.
    #[error(
        "the write is about {size} bytes as a Raft entry, above the {limit}-byte limit for one \
         replicated write; split it"
    )]
    CommandTooLarge { size: usize, limit: usize },

    /// Raft refused to initialise the cluster because this node's Raft state
    /// is not empty: the cluster was initialised already, by this node or by
    /// the leader that replicated to it.
    #[error("the cluster is already initialised: {0}")]
    AlreadyInitialized(String),

    /// Raft or runtime error.
    #[error("raft: {0}")]
    Raft(String),
}

/// Refuses a command whose Raft entry could not fit a peer message.
fn check_command_size(cmd: &RaftCommand) -> Result<(), ClusterError> {
    let size = cmd.wire_size_estimate();
    if size > MAX_COMMAND_BYTES {
        return Err(ClusterError::CommandTooLarge {
            size,
            limit: MAX_COMMAND_BYTES,
        });
    }
    Ok(())
}

/// Why this node's own `client_write` did not produce a committed entry.
enum LocalProposal {
    /// Refused **without** entering the log: this node is not the leader.
    /// Carries the leader it knows of, if any.
    NotLeader(Option<u64>),
    /// Any other failure, including a timeout whose outcome is unknown.
    Failed(ClusterError),
}

/// What one forwarded attempt produced.
enum ForwardAttempt {
    /// Committed and applied on the leader at `log_index`.
    Committed {
        log_index: u64,
        response: HearthLogResponse,
    },
    /// Not proposed anywhere; may be sent to another leader. Carries the
    /// leader the refusing node named, if any.
    Retryable(Option<u64>),
    /// A final answer: rejected, or an unknown outcome.
    Failed(ClusterError),
}

/// Follower-to-leader write forwarding state. Absent in single-node mode.
struct Forwarding {
    client: LeaderForwarder,
    /// Bounds the forwarded writes this node serves at once as a leader.
    permits: tokio::sync::Semaphore,
}

/// Forwarded writes a leader serves concurrently. One more is refused at
/// once (not queued), so a burst cannot pin unbounded memory on the leader.
pub const MAX_CONCURRENT_FORWARDED_WRITES: usize = 256;

/// Extra time a follower gives a forwarded write beyond
/// `cluster.write_timeout_ms`, so the leader's own commit-timeout answer
/// arrives in-band instead of racing the follower's deadline.
const FORWARD_GRACE: Duration = Duration::from_secs(2);

/// How many times one write may be routed (proposed locally or forwarded)
/// before it gives up. At most two of those are forwards: the first, and one
/// retry on a new leader when the first provably did not propose it.
const MAX_ROUTING_ROUNDS: usize = 4;

/// Error produced when building a [`ClusterEngine`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ClusterBuildError {
    #[error("failed to open Raft log store: {0}")]
    LogStore(String),
    #[error("failed to read TLS material: {0}")]
    Tls(#[from] std::io::Error),
    #[error("failed to initialise Raft: {0}")]
    RaftInit(String),
}

// ── ClusterEngine ─────────────────────────────────────────────────────────────

/// Public-facing storage wrapper that makes the cluster layer invisible in
/// single-node mode and routes traffic correctly in cluster mode.
pub struct ClusterEngine {
    inner: Arc<EmbeddedStorageEngine>,
    /// `None` in single-node mode — no Raft overhead, no port allocation.
    raft: Option<openraft::Raft<HearthRaftConfig>>,
    /// Follower reads are allowed when `true`. Updated every 50 ms by the
    /// background lag-monitor task in cluster mode.
    reads_allowed: Arc<AtomicBool>,
    /// Maximum acceptable replication lag in milliseconds (default 500).
    read_lag_threshold_ms: u64,
    /// Upper bound on a single `client_write` (default 10 s). See
    /// [`ClusterError::WriteTimeout`].
    write_timeout: Duration,
    /// This node's own Raft node ID. `None` in single-node mode.
    self_node_id: Option<u64>,
    /// Initial membership derived from config at startup. Used by the
    /// bootstrap HTTP handler without requiring access to `ClusterConfig`.
    /// `None` in single-node mode.
    initial_members: Option<BTreeMap<u64, HearthNode>>,
    /// Shared slot for the state machine's projection observer (audit
    /// 2026-08-28 §4.16#5). `None` in single-node mode — there is no state
    /// machine, and the node's own API handlers keep projections coherent.
    observer_slot: Option<Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>>>,
    /// Follower write forwarding (client and leader-side limit). `None` in
    /// single-node mode, which never forwards anything.
    forwarding: Option<Forwarding>,
    /// Estimates this node's clock offset from the leader (C4). Unused in
    /// single-node mode, which receives no entries.
    clock_offset: ClockOffsetMonitor,
}

impl ClusterEngine {
    /// How long [`Self::transfer_leadership`] waits for a replacement leader.
    ///
    /// openraft will not let a follower start an election before
    /// `leader_lease + election_timeout` has elapsed, which under this node's
    /// Raft config (`election_timeout` 1500–3000 ms, `leader_lease =
    /// election_timeout_max` = 3000 ms) is 4.5–6.0 s. Add the vote round-trip
    /// and the winner's no-op commit, then leave headroom for a loaded CI
    /// runner. The old 5 s bound sat *below* openraft's own floor.
    const STEP_DOWN_WAIT: Duration = Duration::from_secs(20);

    // ── Constructors ──────────────────────────────────────────────────────────

    /// Build a single-node engine (no Raft overhead, direct storage calls).
    pub fn single_node(inner: Arc<EmbeddedStorageEngine>) -> Self {
        Self {
            inner,
            raft: None,
            reads_allowed: Arc::new(AtomicBool::new(true)),
            read_lag_threshold_ms: 500,
            write_timeout: Duration::from_millis(ClusterConfig::DEFAULT_WRITE_TIMEOUT_MS),
            self_node_id: None,
            initial_members: None,
            observer_slot: None,
            forwarding: None,
            clock_offset: ClockOffsetMonitor::default(),
        }
    }

    /// Register the node-local projection observer with the state machine
    /// (audit 2026-08-28 §4.16#5).
    ///
    /// Called by the server composition root once the identity engine exists —
    /// the state machine is consumed by `Raft::new` before that point, so the
    /// registration goes through the shared slot. No-op in single-node mode.
    /// A second call is ignored with a warning; the observer is set once at
    /// startup.
    pub fn set_replicated_write_observer(&self, observer: Arc<dyn ReplicatedWriteObserver>) {
        if let Some(slot) = &self.observer_slot {
            if slot.set(Arc::clone(&observer)).is_err() {
                warn!("replicated-write observer already set; ignoring second registration");
                return;
            }
            // The leadership watch drops a transition it sees before an
            // observer exists; a node that already leads when the observer
            // arrives is told now. Both firing costs one extra epoch bump.
            if let Some(raft) = &self.raft {
                if raft.metrics().borrow().state == ServerState::Leader {
                    observer.on_leadership_acquired();
                }
            }
        }
    }

    /// Build a full cluster-mode engine from config.
    ///
    /// Opens the Raft log store at `{storage_config.data_dir}/raft.db`,
    /// reads TLS credentials from the paths in `config`, creates a Raft
    /// instance, and spawns the background lag-monitor task.
    pub async fn build_clustered(
        inner: Arc<EmbeddedStorageEngine>,
        config: &ClusterConfig,
        storage_config: &StorageConfig,
    ) -> Result<Self, ClusterBuildError> {
        Self::build_clustered_inner(inner, config, storage_config, None).await
    }

    /// Same as [`Self::build_clustered`], but every outbound Raft RPC this
    /// node sends is routed through `faults` first.
    ///
    /// **Test-only.** It is the seam that makes a partition of a real,
    /// socket-backed cluster possible — see [`PeerFaults`] for why no other
    /// shape works. `serve` calls [`Self::build_clustered`], which installs no
    /// injector, so a production node cannot reach this path.
    pub async fn build_clustered_with_peer_faults(
        inner: Arc<EmbeddedStorageEngine>,
        config: &ClusterConfig,
        storage_config: &StorageConfig,
        faults: Arc<PeerFaults>,
    ) -> Result<Self, ClusterBuildError> {
        Self::build_clustered_inner(inner, config, storage_config, Some(faults)).await
    }

    async fn build_clustered_inner(
        inner: Arc<EmbeddedStorageEngine>,
        config: &ClusterConfig,
        storage_config: &StorageConfig,
        faults: Option<Arc<PeerFaults>>,
    ) -> Result<Self, ClusterBuildError> {
        let raft_db_path = storage_config.data_dir.join("raft.db");
        let mut log_store = HearthLogStore::open(&raft_db_path)
            .map_err(|e| ClusterBuildError::LogStore(e.to_string()))?;

        let sm_engine: Arc<dyn StorageEngine> = Arc::clone(&inner) as Arc<dyn StorageEngine>;
        // Shared observer slot: the state machine is consumed by `Raft::new`
        // below, but the projection observer (the identity engine) is built
        // later — the composition root fills the slot via
        // `set_replicated_write_observer` (audit 2026-08-28 §4.16#5).
        let observer_slot: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>> =
            Arc::new(OnceLock::new());
        // The state machine loads its persisted applied state (storage reads:
        // on the blocking pool).
        let slot = Arc::clone(&observer_slot);
        let state_machine = tokio::task::spawn_blocking(move || {
            HearthStateMachine::with_observer_slot(sm_engine, slot)
        })
        .await
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?;
        if state_machine.has_no_applied_state() {
            let log_state = openraft::storage::RaftLogStorage::get_log_state(&mut log_store)
                .await
                .map_err(|e| ClusterBuildError::LogStore(e.to_string()))?;
            refuse_restart_without_applied_state(log_state.last_purged_log_id)?;
        }

        let cert_pem = tokio::fs::read(&config.tls_cert_path).await?;
        let key_pem = tokio::fs::read(&config.tls_key_path).await?;
        let ca_pem = tokio::fs::read(&config.tls_ca_cert_path).await?;
        let network_factory = HearthNetworkFactory::new(cert_pem, key_pem, ca_pem);
        let network_factory = match faults {
            Some(f) => network_factory.with_peer_faults(f),
            None => network_factory,
        };
        let forwarding = Forwarding {
            client: network_factory.leader_forwarder(),
            permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_FORWARDED_WRITES),
        };

        let raft_config = Arc::new(
            RaftConfig {
                heartbeat_interval: 500,
                election_timeout_min: 1500,
                election_timeout_max: 3000,
                // Chunks well under the peer message limit (see
                // `cluster::wire`); openraft's default is 3 MiB.
                snapshot_max_chunk_size: SNAPSHOT_CHUNK_BYTES,
                ..RaftConfig::default()
            }
            .validate()
            .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?,
        );

        let raft = openraft::Raft::<HearthRaftConfig>::new(
            config.node_id,
            raft_config,
            network_factory,
            log_store,
            state_machine,
        )
        .await
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?;

        let threshold = config.read_lag_threshold_ms.unwrap_or(500);
        let write_timeout = Duration::from_millis(
            config
                .write_timeout_ms
                .unwrap_or(ClusterConfig::DEFAULT_WRITE_TIMEOUT_MS),
        );
        let reads_allowed = Arc::new(AtomicBool::new(true));
        let reads_flag = Arc::clone(&reads_allowed);
        let raft_for_monitor = raft.clone();

        tokio::spawn(async move {
            run_lag_monitor(raft_for_monitor, reads_flag, threshold).await;
        });
        tokio::spawn(watch_leadership(raft.clone(), Arc::clone(&observer_slot)));

        let initial_members = initial_members_of(config);
        Self::self_initialise_if_designated(&raft, config, &initial_members).await;

        info!(
            node_id = config.node_id,
            peer_address = %config.peer_address,
            read_lag_threshold_ms = threshold,
            write_timeout_ms = write_timeout.as_millis(),
            "ClusterEngine initialised in cluster mode"
        );

        Ok(Self {
            inner,
            raft: Some(raft),
            reads_allowed,
            read_lag_threshold_ms: threshold,
            write_timeout,
            self_node_id: Some(config.node_id),
            initial_members: Some(initial_members),
            observer_slot: Some(observer_slot),
            forwarding: Some(forwarding),
            clock_offset: ClockOffsetMonitor::default(),
        })
    }

    /// Cold-cluster self-initialisation (task 26.46).
    ///
    /// Extracted from `build_clustered_inner` verbatim so that function stays
    /// under the pedantic line limit; the behaviour and the reasoning below
    /// are unchanged.
    async fn self_initialise_if_designated(
        raft: &openraft::Raft<HearthRaftConfig>,
        config: &ClusterConfig,
        initial_members: &BTreeMap<u64, HearthNode>,
    ) {
        //
        // `serve` builds the identity engine over this handle, and that
        // constructor *writes* on a cold data directory (the KEK-enrolment
        // marker, the global signing key, the system-realm row). In cluster
        // mode each of those is a Raft proposal, so it needs a leader — and
        // the only way to elect one was `POST /admin/cluster/bootstrap`, which
        // is served by a router that does not exist until the identity engine
        // has been built. Every node therefore died with
        // `raft: not the leader; redirect to unknown` before the documented
        // bootstrap step could be reached.
        //
        // Exactly ONE node self-initialises: the lowest node ID in the
        // membership this node's own config names. That is the same shape as
        // the documented "call bootstrap on one designated node", with the
        // designation made deterministically from configuration instead of by
        // an HTTP call that cannot be served yet. The other nodes stay
        // pristine and adopt the membership from the first `AppendEntries`
        // they receive — exactly what they do today under manual bootstrap.
        //
        // Having *every* node initialise is the obvious alternative and is
        // worse twice over. openraft warns that concurrent `initialize()`
        // with a *different* config "will result in split brain condition",
        // so one node's `cluster.peers` typo would fork the cluster instead
        // of merely failing to join. And even with identical config it makes
        // the first election contested — three candidates, three terms — and
        // a leader elected in that churn can be deposed part-way through the
        // start-up write set it is serving. Measured: with all three
        // initialising, this test hung on two runs in five.
        //
        // Nothing is trusted here that was not already trusted: the
        // membership, the peer addresses and the mTLS material all come from
        // this node's own configuration file, and no network surface is
        // exposed to do it. `initialize_cluster` — and the
        // `POST /admin/cluster/bootstrap` handler over it — still works, and
        // is the escape hatch when the designated node is the one that is
        // down.
        //
        // Skipped when `peers` is empty: that is a degenerate cluster-mode
        // configuration with nothing to replicate to, and
        // `initialize_cluster` remains the way to form it explicitly.
        let designated_initialiser = initial_members.keys().copied().min();
        if !config.peers.is_empty() && designated_initialiser == Some(config.node_id) {
            match raft.is_initialized().await {
                Ok(false) => match raft.initialize(initial_members.clone()).await {
                    Ok(()) => info!(
                        node_id = config.node_id,
                        members = initial_members.len(),
                        "cold cluster: Raft membership initialised from cluster.peers"
                    ),
                    Err(e) => warn!(
                        node_id = config.node_id,
                        error = %e,
                        "cold cluster: self-initialisation refused; the cluster may need an \
                         explicit POST /admin/cluster/bootstrap"
                    ),
                },
                Ok(true) => {}
                Err(e) => warn!(
                    error = %e,
                    "could not read Raft initialisation state; skipping self-initialisation"
                ),
            }
        }
    }

    // ── Cluster initialisation ────────────────────────────────────────────────

    /// Bootstrap a brand-new cluster with the given membership.
    ///
    /// Call only on the designated bootstrap node. Other nodes join via the
    /// normal Raft membership protocol after the cluster is formed.
    pub async fn initialize_cluster(
        &self,
        members: BTreeMap<u64, HearthNode>,
    ) -> Result<(), ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("cannot initialise cluster on a single-node engine".to_string())
        })?;
        raft.initialize(members).await.map_err(|e| match e {
            RaftError::APIError(openraft::error::InitializeError::NotAllowed(not_allowed)) => {
                ClusterError::AlreadyInitialized(not_allowed.to_string())
            }
            other => ClusterError::Raft(other.to_string()),
        })
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    /// Returns a snapshot of the current Raft metrics (cluster mode only).
    pub fn raft_metrics(&self) -> Option<RaftMetrics<u64, HearthNode>> {
        self.raft.as_ref().map(|r| r.metrics().borrow().clone())
    }

    /// Stops the Raft core (heartbeats, elections, replication). A no-op in
    /// single-node mode.
    ///
    /// Called once on graceful shutdown, after every listener has drained
    /// (GA audit 2026-09-28 L24: the Raft side was never shut down). A failure
    /// is logged, not returned: nothing is left to recover at that point.
    pub async fn shutdown(&self) {
        if let Some(raft) = &self.raft {
            if let Err(e) = raft.shutdown().await {
                warn!(error = %e, "Raft core did not shut down cleanly");
            }
        }
    }

    /// Configured replication-lag threshold in milliseconds.
    pub fn read_lag_threshold_ms(&self) -> u64 {
        self.read_lag_threshold_ms
    }

    /// This node's own Raft node ID. `None` in single-node mode.
    pub fn node_id(&self) -> Option<u64> {
        self.self_node_id
    }

    /// Whether this node would propose a replicated write itself right now,
    /// i.e. whether it is the Raft leader.
    ///
    /// Always `true` in single-node mode. In cluster mode a follower's writes
    /// are forwarded to the leader and succeed there, so this is no longer
    /// "would a write succeed": it answers "does this node lead". Start-up
    /// uses it to run the cold-data-directory write set on exactly one node
    /// (see `EmbeddedIdentityEngine::await_cold_start_window`). Advisory
    /// only: leadership can move between this call and the write.
    pub fn accepts_writes(&self) -> bool {
        let Some(raft) = self.raft.as_ref() else {
            return true;
        };
        let metrics = raft.metrics().borrow().clone();
        metrics.current_leader == Some(metrics.id)
    }

    /// Initial cluster membership map built from config at startup.
    ///
    /// Contains self + all configured peers. Used by the bootstrap HTTP
    /// handler to call [`Self::initialize_cluster`] without needing to
    /// re-parse `hearth.yaml`. `None` in single-node mode.
    pub fn initial_members(&self) -> Option<&BTreeMap<u64, HearthNode>> {
        self.initial_members.as_ref()
    }

    /// Step this node down so that some other voter takes over leadership.
    ///
    /// This node must be the current leader; returns [`ClusterError::NotLeader`]
    /// otherwise. Returns the new leader's node ID.
    ///
    /// ## This is a step-down, not a targeted transfer
    ///
    /// openraft 0.9.25 exposes no way to hand leadership to a *chosen* peer.
    /// `Raft` has `trigger().elect()`, `heartbeat()`, `snapshot()` and
    /// `purge_log()` and nothing else; the internal "node-a elects for node-b"
    /// mechanism that would implement a targeted transfer
    /// (`vote_handler::become_leader`) has no public entry point, and
    /// `external_request` hands out an immutable `&RaftState`. A targeted
    /// `Trigger::transfer_leader` arrived in openraft 0.10.
    ///
    /// So this method takes no target. `POST /admin/cluster/transfer-leadership`
    /// refuses a body naming `target_node_id` with 422 rather than stepping
    /// down anyway and reporting success (task 26.60), and reports the node
    /// that actually won in `new_leader_id`.
    ///
    /// ## How the step-down is performed, and why it used to do nothing
    ///
    /// The previous implementation always returned "leadership transfer timed
    /// out after 5 s" on a healthy cluster, and leadership never moved. Three
    /// separate faults, each sufficient on its own (task 26.57):
    ///
    /// 1. It called `trigger().elect()`, whose own documentation reads "if
    ///    this node is already a leader, this is a no-op". Step 2 of the
    ///    documented procedure did literally nothing — and had it done
    ///    something, it would have elected *this* node, which holds the
    ///    longest log and simply re-wins.
    /// 2. Heartbeats were never stopped. A follower only elects when its
    ///    leader lease expires (`RaftCore::handle_tick_election`), and this
    ///    node kept renewing that lease every `heartbeat_interval` throughout
    ///    the wait. Leadership could not move for any reason.
    /// 3. The wait was 5 s. openraft's own floor for a follower to start an
    ///    election is `leader_lease + election_timeout`, and this node
    ///    configures `election_timeout` 1500–3000 ms with `leader_lease =
    ///    election_timeout_max`, i.e. **4.5–6.0 s** before a vote is even
    ///    cast. A 5 s bound was below the floor, so even with faults 1 and 2
    ///    fixed it would still usually report failure on a transfer that was
    ///    in fact about to succeed.
    ///
    /// What actually works, using only the pinned version's public API:
    /// stop heartbeating so the followers' leases expire, refuse to stand in
    /// the election they then hold, and wait longer than openraft's own floor.
    /// The old leader steps down when it sees the winner's higher term.
    ///
    /// Both runtime flags are restored on every exit path, including the
    /// timeout — leaving `heartbeat` disabled on a node that stayed leader
    /// would hand the cluster a rolling election.
    ///
    /// **Note on availability:** this deliberately lets the cluster go without
    /// a leader for one lease-plus-election window, so writes fail with
    /// `NoLeader`/`NotLeader` for several seconds. Do not call it during a
    /// write burst.
    pub async fn transfer_leadership(&self) -> Result<u64, ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("transfer_leadership called on single-node engine".to_string())
        })?;

        let my_id = {
            let metrics = raft.metrics().borrow().clone();
            if metrics.state != ServerState::Leader {
                return Err(ClusterError::NotLeader {
                    leader_addr: self.current_leader_addr(),
                });
            }
            metrics.id
        };

        // Stop renewing the followers' leader leases, and decline to stand in
        // the election that follows. Without the first, no follower ever times
        // out; without the second, this node re-wins on its longer log.
        raft.runtime_config().heartbeat(false);
        raft.runtime_config().elect(false);

        let result = tokio::time::timeout(Self::STEP_DOWN_WAIT, async {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let metrics = raft.metrics().borrow().clone();
                // Require both halves: some other node claims the leadership
                // AND this node has accepted that it no longer holds it.
                // Checking only `current_leader` would return as soon as a
                // candidate announced itself, while this node still served
                // writes for the old term.
                if metrics.state == ServerState::Leader {
                    continue;
                }
                if let Some(leader_id) = metrics.current_leader {
                    if leader_id != my_id {
                        return leader_id;
                    }
                }
            }
        })
        .await;

        // Restore both flags on every path, success or not.
        raft.runtime_config().elect(true);
        raft.runtime_config().heartbeat(true);

        result.map_err(|_| {
            ClusterError::Raft(format!(
                "leadership step-down did not complete within {} s: this node is still the \
                 leader and no replacement was elected. A voter must be reachable and \
                 up-to-date enough to win an election; check /admin/cluster/status for \
                 unhealthy peers",
                Self::STEP_DOWN_WAIT.as_secs()
            ))
        })
    }

    /// Builds a snapshot of everything this node has applied, then purges
    /// its Raft log up to that snapshot, and returns the snapshot's last log
    /// index.
    ///
    /// openraft does both on its own schedule (a snapshot every 5,000 applied
    /// entries, then a purge that keeps 1,000); this runs them now. A follower
    /// whose next entry was purged catches up by snapshot. Each wait is
    /// bounded by `cluster.write_timeout_ms`; openraft may delay a purge while
    /// a replication task still reads the logs, so the purge wait can expire
    /// (reported as an error) while the purge still happens later.
    ///
    /// # Errors
    ///
    /// Single-node mode, a stopped Raft core, or a bound expiring.
    pub async fn compact_log(&self) -> Result<u64, ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("compact_log called on a single-node engine".to_string())
        })?;
        let applied = raft.metrics().borrow().last_applied.map_or(0, |l| l.index);
        raft.trigger()
            .snapshot()
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?;
        let upto = raft
            .wait(Some(self.write_timeout))
            .metrics(
                |m| m.snapshot.is_some_and(|s| s.index >= applied),
                "a snapshot of every applied entry",
            )
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .snapshot
            .map_or(applied, |s| s.index);
        raft.trigger()
            .purge_log(upto)
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?;
        raft.wait(Some(self.write_timeout))
            .metrics(
                |m| m.purged.is_some_and(|p| p.index >= upto),
                "the log purged up to the snapshot",
            )
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?;
        Ok(upto)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn current_leader_addr(&self) -> String {
        let Some(raft) = &self.raft else {
            return "unknown".to_string();
        };
        let metrics = raft.metrics().borrow().clone();
        let Some(leader_id) = metrics.current_leader else {
            return "unknown".to_string();
        };
        for (id, node) in metrics.membership_config.nodes() {
            if *id == leader_id {
                return node.addr.clone();
            }
        }
        "unknown".to_string()
    }

    /// Wall-clock microseconds since UNIX epoch — embedded in write commands
    /// as `leader_timestamp` so all nodes apply the same timestamp.
    fn leader_timestamp_now() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64
    }

    /// Feeds one `AppendEntries` request to the clock-offset monitor and logs
    /// its verdict (C4). The warning never changes how the node answers.
    fn note_clock_offset(&self, req: &AppendEntriesRequest<HearthRaftConfig>) {
        let now = Self::leader_timestamp_now();
        let Some(age) = min_in_flight_age(req, now) else {
            return;
        };
        match self.clock_offset.observe(age, now) {
            Some(ClockOffset::LeaderAhead { ms }) => warn!(
                offset_ms = ms,
                "clock offset from the leader exceeds 1 s: the leader's clock is ahead of this \
                 node's — ensure NTP is configured"
            ),
            Some(ClockOffset::FollowerAhead { ms }) => warn!(
                offset_ms = ms,
                "clock offset from the leader may exceed 1 s: for 30 s no entry arrived less than \
                 offset_ms after the leader proposed it, so this node's clock may be ahead — \
                 ensure NTP is configured"
            ),
            None => {}
        }
    }

    /// Returns `true` if reads should be served.
    ///
    /// Single-node: always true. Cluster: gated by the lag-monitor flag.
    fn reads_ok(&self) -> bool {
        self.raft.is_none() || self.reads_allowed.load(Ordering::Relaxed)
    }

    /// Runs `read` against the local engine on the calling thread, behind the
    /// same replication-lag check as [`Self::get`] and [`Self::scan`].
    ///
    /// [`ClusterStorageAdapter`]'s reads use this rather than the async
    /// `get`/`scan`, which hop to the Tokio blocking pool. The adapter's
    /// caller is already off the executor, so the hop bought nothing and made
    /// every read wait for a free pool thread. A backup export reads while it
    /// holds the storage write barrier, and each write that arrives meanwhile
    /// parks a pool thread on that barrier: once they filled the pool, the
    /// export's next read waited for a thread only the export could free, and
    /// the whole server stopped for good (GA audit 3 F-7).
    fn read_inline<T>(
        &self,
        read: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Result<T, ClusterError> {
        if !self.reads_ok() {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: self.current_leader_addr(),
            });
        }
        read(&self.inner).map_err(ClusterError::Storage)
    }

    /// Propose a [`RaftCommand`] and block until quorum commit.
    async fn propose(&self, cmd: RaftCommand) -> Result<(), ClusterError> {
        self.propose_with_response(cmd).await.map(|_| ())
    }

    /// Propose a [`RaftCommand`] and return the state-machine response.
    ///
    /// Used by conditional commands (e.g. `PutIfAbsent`) that need to inspect
    /// the `success` flag of the applied response.
    ///
    /// ## Routing
    ///
    /// The command is first offered to this node's own Raft. On the leader
    /// that is the whole story. On a follower openraft refuses it **before**
    /// it enters the log (`ForwardToLeader`), and the command is forwarded to
    /// the leader instead (the `ForwardWrite` peer RPC). A committed answer is
    /// only returned once this node's own state machine has applied the
    /// entry, so a caller that reads on this node right after a write sees it.
    ///
    /// ## Exactly once
    ///
    /// A forwarded command is retried — once, on a new leader — only when it
    /// provably never entered any log: the connection to the leader could not
    /// be opened, or the leader refused it as not-the-leader without
    /// proposing. Once the request may have reached a leader that proposed it
    /// (a lost connection, the leader's commit wait timing out, Raft stopping
    /// under it) the outcome is unknown and is reported as
    /// [`ClusterError::ForwardOutcomeUnknown`], never retried: a
    /// `PutIfAbsent` retried after it committed answers `false` for the
    /// caller's own write, and an `IncrementU64` counts twice.
    ///
    /// ## Why this is bounded (task 26.58)
    ///
    /// `Raft::client_write` resolves when the entry commits, when the node
    /// learns it is no longer the leader, or **never** — a leader that lost
    /// its quorum (openraft 0.9 does not step down on a lost quorum) waits
    /// for acknowledgements that cannot arrive. Every caller above this is an
    /// HTTP handler holding a connection and, on the login path, an advisory
    /// lock, so every wait here is bounded: the local proposal by
    /// `cluster.write_timeout_ms` (default 10 s), finding a leader and the
    /// forwarded call together by that plus a 2 s grace, and the local apply
    /// wait by `cluster.write_timeout_ms` again. A timeout does **not** cancel
    /// a proposal — openraft may still commit it afterwards — so it is
    /// reported as an unknown outcome, not a failure.
    async fn propose_with_response(
        &self,
        cmd: RaftCommand,
    ) -> Result<HearthLogResponse, ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("propose called on single-node engine".to_string())
        })?;
        check_command_size(&cmd)?;
        let deadline = tokio::time::Instant::now() + self.write_timeout + FORWARD_GRACE;
        let mut forwards = 0_u8;
        // The leader that last refused the command without proposing it, and
        // the leader it named in its place.
        let mut refused_by: Option<u64> = None;
        let mut named: Option<u64> = None;

        for _ in 0..MAX_ROUTING_ROUNDS {
            let hint = match self.propose_local(raft, cmd.clone()).await {
                Ok(resp) => return Ok(resp.data),
                Err(LocalProposal::NotLeader(hint)) => hint,
                Err(LocalProposal::Failed(e)) => return Err(e),
            };
            let Some(forwarding) = self.forwarding.as_ref() else {
                return Err(ClusterError::NotLeader {
                    leader_addr: self.current_leader_addr(),
                });
            };
            let leader = match named.take().or(hint).filter(|l| Some(*l) != refused_by) {
                Some(leader) => leader,
                None => self.await_leader(raft, refused_by, deadline).await?,
            };
            if Some(leader) == self.self_node_id {
                // This node has just been elected: propose it here.
                continue;
            }
            let leader_addr = self.node_addr(leader);
            forwards += 1;
            match self
                .forward_once(forwarding, leader, &leader_addr, &cmd, deadline)
                .await
            {
                ForwardAttempt::Committed {
                    log_index,
                    response,
                } => {
                    let applied = self.await_applied(raft, log_index).await;
                    crate::metrics::metrics().record_forwarded_write(if applied.is_ok() {
                        ForwardedWriteOutcomeLabel::Committed
                    } else {
                        ForwardedWriteOutcomeLabel::NotAppliedLocally
                    });
                    applied?;
                    return Ok(response);
                }
                ForwardAttempt::Retryable(next) if forwards < 2 => {
                    refused_by = Some(leader);
                    named = next;
                }
                ForwardAttempt::Retryable(_) => {
                    return Err(ClusterError::NotLeader { leader_addr });
                }
                ForwardAttempt::Failed(e) => return Err(e),
            }
        }
        Err(ClusterError::NotLeader {
            leader_addr: self.current_leader_addr(),
        })
    }

    /// Offers `cmd` to this node's own Raft, bounded by
    /// `cluster.write_timeout_ms`.
    async fn propose_local(
        &self,
        raft: &openraft::Raft<HearthRaftConfig>,
        cmd: RaftCommand,
    ) -> Result<ClientWriteResponse<HearthRaftConfig>, LocalProposal> {
        let Ok(outcome) = tokio::time::timeout(self.write_timeout, raft.client_write(cmd)).await
        else {
            let timeout_ms = u64::try_from(self.write_timeout.as_millis()).unwrap_or(u64::MAX);
            let leader_addr = self.current_leader_addr();
            warn!(
                timeout_ms,
                leader_addr = %leader_addr,
                "replicated write did not reach quorum commit within the configured bound"
            );
            return Err(LocalProposal::Failed(ClusterError::WriteTimeout {
                timeout_ms,
                leader_addr,
            }));
        };
        outcome.map_err(|e| match e {
            RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)) => {
                LocalProposal::NotLeader(fwd.leader_id)
            }
            other => LocalProposal::Failed(ClusterError::Raft(other.to_string())),
        })
    }

    /// Waits (until `deadline`) for this node to learn of a leader other than
    /// `exclude`, and returns it — possibly this node itself.
    async fn await_leader(
        &self,
        raft: &openraft::Raft<HearthRaftConfig>,
        exclude: Option<u64>,
        deadline: tokio::time::Instant,
    ) -> Result<u64, ClusterError> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let found = raft
            .wait(Some(remaining))
            .metrics(
                |m| m.current_leader.is_some_and(|l| Some(l) != exclude),
                "a leader to forward a write to",
            )
            .await;
        match found.ok().and_then(|m| m.current_leader) {
            Some(leader) => Ok(leader),
            None => Err(ClusterError::NotLeader {
                leader_addr: self.current_leader_addr(),
            }),
        }
    }

    /// The peer address of `node` in the current membership.
    fn node_addr(&self, node: u64) -> String {
        let Some(raft) = &self.raft else {
            return "unknown".to_string();
        };
        let metrics = raft.metrics().borrow().clone();
        let addr = metrics
            .membership_config
            .nodes()
            .find(|(id, _)| **id == node)
            .map_or_else(|| "unknown".to_string(), |(_, n)| n.addr.clone());
        addr
    }

    /// Sends `cmd` to `leader` once, classifies the answer, and counts every
    /// outcome but a commit (counted once its local apply is known) in
    /// `hearth_cluster_forwarded_writes_total`.
    async fn forward_once(
        &self,
        forwarding: &Forwarding,
        leader: u64,
        leader_addr: &str,
        cmd: &RaftCommand,
        deadline: tokio::time::Instant,
    ) -> ForwardAttempt {
        let (attempt, label) = self
            .forward_once_unrecorded(forwarding, leader, leader_addr, cmd, deadline)
            .await;
        if let Some(label) = label {
            crate::metrics::metrics().record_forwarded_write(label);
        }
        attempt
    }

    async fn forward_once_unrecorded(
        &self,
        forwarding: &Forwarding,
        leader: u64,
        leader_addr: &str,
        cmd: &RaftCommand,
        deadline: tokio::time::Instant,
    ) -> (ForwardAttempt, Option<ForwardedWriteOutcomeLabel>) {
        use ForwardedWriteOutcomeLabel as L;
        let payload = match wire::encode(cmd) {
            Ok(p) => p,
            Err(e) => {
                return (
                    ForwardAttempt::Failed(ClusterError::Raft(format!(
                        "could not encode a write to forward: {e}"
                    ))),
                    Some(L::Rejected),
                )
            }
        };
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        let unknown = |reason: String| {
            ForwardAttempt::Failed(ClusterError::ForwardOutcomeUnknown {
                leader_addr: leader_addr.to_string(),
                reason,
            })
        };
        let answer = match forwarding
            .client
            .forward(leader, leader_addr, payload, timeout)
            .await
        {
            Ok(answer) => answer,
            Err(ForwardFailure::NotSent(e)) => {
                warn!(leader, leader_addr, error = %e, "could not reach the leader to forward a write");
                return (ForwardAttempt::Retryable(None), Some(L::Unreachable));
            }
            Err(ForwardFailure::Unsupported(e)) => {
                return (
                    ForwardAttempt::Failed(ClusterError::ForwardRejected {
                        leader_addr: leader_addr.to_string(),
                        reason: format!(
                            "the leader runs a Hearth build without follower write forwarding \
                             ({e}); mixed-version clusters are not supported"
                        ),
                    }),
                    Some(L::Rejected),
                );
            }
            Err(ForwardFailure::Unknown(e)) => {
                warn!(
                    leader,
                    leader_addr,
                    error = %e,
                    "lost the leader's answer to a forwarded write; its outcome is unknown"
                );
                return (unknown(e.to_string()), Some(L::OutcomeUnknown));
            }
        };
        match wire::decode::<ForwardedWriteOutcome>(&answer) {
            // Counted by the caller once the local apply is known.
            Ok(ForwardedWriteOutcome::Committed {
                log_index,
                response,
            }) => (
                ForwardAttempt::Committed {
                    log_index,
                    response,
                },
                None,
            ),
            Ok(ForwardedWriteOutcome::NotLeader { leader_id }) => {
                (ForwardAttempt::Retryable(leader_id), Some(L::NotLeader))
            }
            Ok(ForwardedWriteOutcome::Busy) => (
                ForwardAttempt::Failed(ClusterError::LeaderBusy {
                    leader_addr: leader_addr.to_string(),
                }),
                Some(L::Busy),
            ),
            Ok(ForwardedWriteOutcome::Rejected { reason }) => (
                ForwardAttempt::Failed(ClusterError::ForwardRejected {
                    leader_addr: leader_addr.to_string(),
                    reason,
                }),
                Some(L::Rejected),
            ),
            Ok(ForwardedWriteOutcome::Unknown { reason }) => {
                (unknown(reason), Some(L::OutcomeUnknown))
            }
            Err(_) => (
                unknown("the leader's answer could not be decoded".to_string()),
                Some(L::OutcomeUnknown),
            ),
        }
    }

    /// Blocks until this node's state machine has applied `log_index`,
    /// bounded by `cluster.write_timeout_ms`.
    async fn await_applied(
        &self,
        raft: &openraft::Raft<HearthRaftConfig>,
        log_index: u64,
    ) -> Result<(), ClusterError> {
        match raft
            .wait(Some(self.write_timeout))
            .applied_index_at_least(Some(log_index), "a forwarded write to apply locally")
            .await
        {
            Ok(_) => Ok(()),
            Err(WaitError::Timeout(..)) => Err(ClusterError::NotAppliedLocally {
                log_index,
                timeout_ms: u64::try_from(self.write_timeout.as_millis()).unwrap_or(u64::MAX),
            }),
            Err(WaitError::ShuttingDown) => Err(ClusterError::Raft(
                "this node's Raft core stopped while a forwarded write was being applied"
                    .to_string(),
            )),
        }
    }

    /// Serves a write a follower forwarded to this node: proposes it if this
    /// node leads and says, in every other case, whether it can have entered
    /// the log. Never forwards onward — a node that is not the leader answers
    /// [`ForwardedWriteOutcome::NotLeader`], so a forward cannot loop.
    async fn serve_forwarded_write(&self, payload: &[u8]) -> ForwardedWriteOutcome {
        let (Some(raft), Some(forwarding)) = (self.raft.as_ref(), self.forwarding.as_ref()) else {
            return ForwardedWriteOutcome::Rejected {
                reason: "this node does not run in cluster mode".to_string(),
            };
        };
        let Ok(_permit) = forwarding.permits.try_acquire() else {
            return ForwardedWriteOutcome::Busy;
        };
        // The decode error is not echoed: serde quotes input fragments.
        let Ok(cmd) = wire::decode::<RaftCommand>(payload) else {
            return ForwardedWriteOutcome::Rejected {
                reason: "the forwarded command could not be decoded (are all nodes on the same \
                         Hearth build?)"
                    .to_string(),
            };
        };
        if let Err(e) = check_command_size(&cmd) {
            return ForwardedWriteOutcome::Rejected {
                reason: e.to_string(),
            };
        }
        // A stopped Raft core cannot have proposed anything: refuse it as
        // not-the-leader so the follower may try the next leader.
        if raft.metrics().borrow().running_state.is_err() {
            return ForwardedWriteOutcome::NotLeader { leader_id: None };
        }
        let cmd = cmd.restamped(Self::leader_timestamp_now());
        match self.propose_local(raft, cmd).await {
            Ok(resp) => ForwardedWriteOutcome::Committed {
                log_index: resp.log_id.index,
                response: resp.data,
            },
            Err(LocalProposal::NotLeader(leader_id)) => ForwardedWriteOutcome::NotLeader {
                leader_id: leader_id.filter(|l| Some(*l) != self.self_node_id),
            },
            Err(LocalProposal::Failed(e)) => ForwardedWriteOutcome::Unknown {
                reason: e.to_string(),
            },
        }
    }

    // ── Async storage API ─────────────────────────────────────────────────────

    /// Retrieve a single value. Checks the lag flag in cluster mode.
    pub async fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        if !self.reads_ok() {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: self.current_leader_addr(),
            });
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        spawn_blocking(move || inner.get(&realm_id, &key))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Insert or update a key-value pair.
    ///
    /// In cluster mode the write is proposed through Raft with an embedded
    /// `leader_timestamp`. Returns `NotLeader` if this node is not the leader.
    pub async fn put(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Put {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                    value: value.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        spawn_blocking(move || inner.put(&realm_id, &key, &value))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Delete a key. In cluster mode proposes through Raft.
    pub async fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Delete {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        spawn_blocking(move || inner.delete(&realm_id, &key))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Scan a key range. Checks the lag flag in cluster mode.
    pub async fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, ClusterError> {
        if !self.reads_ok() {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: self.current_leader_addr(),
            });
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let start = start.to_vec();
        let end = end.to_vec();
        spawn_blocking(move || inner.scan(&realm_id, &start, &end))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Atomically write a batch of key-value pairs.
    ///
    /// In cluster mode the entire batch is proposed as a single `Batch` command
    /// so followers apply it atomically.
    pub async fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Batch {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    entries: entries.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let entries = entries.to_vec();
        spawn_blocking(move || inner.put_batch(&realm_id, &entries))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Atomically apply a mix of writes and removals for a single realm.
    ///
    /// In cluster mode proposes one `RaftCommand::WriteBatch`, so followers
    /// apply the puts and the deletes together. In single-node mode delegates
    /// to the inner engine's atomic `write_batch` (audit 2026-08-28 §4.9#4).
    pub async fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::WriteBatch {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    puts: puts.to_vec(),
                    deletes: deletes.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let puts = puts.to_vec();
        let deletes = deletes.to_vec();
        spawn_blocking(move || inner.write_batch(&realm_id, &puts, &deletes))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// The inner engine's backup consistency barrier.
    ///
    /// `serve` installs a [`ClusterStorageAdapter`] as the app-layer storage
    /// handle in every topology, so the barrier has to reach through both
    /// wrappers or a backup export takes no barrier at all (§4.9#4).
    pub fn backup_barrier(&self) -> Option<Arc<std::sync::RwLock<()>>> {
        self.inner.backup_barrier()
    }

    /// Conditionally insert a key-value pair only if the key is absent.
    ///
    /// In cluster mode proposes `RaftCommand::PutIfAbsent` through Raft,
    /// making the check-and-write atomic across all nodes.  Returns `true` if
    /// the write was performed (key was absent), `false` if already present.
    pub async fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, ClusterError> {
        if self.raft.is_some() {
            let resp = self
                .propose_with_response(RaftCommand::PutIfAbsent {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                    value: value.to_vec(),
                })
                .await?;
            return Ok(resp.success);
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        spawn_blocking(move || inner.put_if_absent(&realm_id, &key, &value))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Atomically increments the `u64` counter at `key` and returns the new
    /// value.
    ///
    /// In cluster mode proposes `RaftCommand::IncrementU64`, whose successor
    /// the state machine computes at apply time, so concurrent increments on
    /// any node never collide or move the counter backwards.
    pub async fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, ClusterError> {
        if self.raft.is_some() {
            let resp = self
                .propose_with_response(RaftCommand::IncrementU64 {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                })
                .await?;
            if !resp.success {
                // Defensive: the state machine repairs a counter that does not
                // decode and succeeds (every node the same way), so no current
                // state machine answers `false` here.
                return Err(ClusterError::Storage(
                    crate::storage::StorageError::DeserializationFailed {
                        reason: "the replicated counter is corrupted; the increment was refused"
                            .to_string(),
                    },
                ));
            }
            return crate::storage::decode_u64_counter(Some(&resp.payload))
                .map_err(ClusterError::Storage);
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        spawn_blocking(move || inner.increment_u64(&realm_id, &key))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Enumerates all realm IDs present in the underlying storage engine.
    ///
    /// Delegates directly to [`EmbeddedStorageEngine::list_realms`] without
    /// routing through Raft — enumeration is a local read, not a replicated
    /// write.
    pub(crate) fn list_realms(
        &self,
    ) -> Result<Vec<crate::core::RealmId>, crate::storage::StorageError> {
        self.inner.list_realms()
    }

    /// Write the snapshot-restore marker on the underlying storage engine.
    ///
    /// Delegates directly to [`EmbeddedStorageEngine::begin_snapshot_restore`]
    /// — this is a local, durable operation, not a replicated write.
    pub(crate) fn begin_snapshot_restore(
        &self,
        snapshot_id: &str,
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    /// Remove the snapshot-restore marker on the underlying storage engine.
    ///
    /// Delegates directly to
    /// [`EmbeddedStorageEngine::complete_snapshot_restore`].
    pub(crate) fn complete_snapshot_restore(&self) -> Result<(), crate::storage::StorageError> {
        self.inner.complete_snapshot_restore()
    }

    /// Flushes the underlying storage engine's memtable.
    ///
    /// Local and durable, not a replicated write — the shutdown path calls it
    /// on every node for its own data directory.
    pub(crate) fn flush_memtable(&self) -> Result<(), crate::storage::StorageError> {
        self.inner.flush_memtable()
    }
}

// ── IncomingRpcDispatch ───────────────────────────────────────────────────────

impl IncomingRpcDispatch for ClusterEngine {
    async fn append_entries(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: AppendEntriesRequest<HearthRaftConfig> = wire::decode(payload)?;
        self.note_clock_offset(&req);
        let resp = raft.append_entries(req).await.map_err(|e| e.to_string())?;
        wire::encode(&resp)
    }

    async fn vote(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: VoteRequest<u64> = wire::decode(payload)?;
        let resp = raft.vote(req).await.map_err(|e| e.to_string())?;
        wire::encode(&resp)
    }

    async fn install_snapshot(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: InstallSnapshotRequest<HearthRaftConfig> =
            wire::decode::<wire::WireInstallSnapshot>(payload)?.into();
        let resp = raft
            .install_snapshot(req)
            .await
            .map_err(|e| e.to_string())?;
        wire::encode(&resp)
    }

    async fn forward_write(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let outcome = self.serve_forwarded_write(payload).await;
        wire::encode(&outcome)
    }
}

// ── Background lag monitor ────────────────────────────────────────────────────

/// A node whose log was purged but whose data directory holds no persisted
/// applied state was written by an earlier release, which did not persist it:
/// openraft would replay from index 0, which the log no longer holds, and fail
/// deep inside `Raft::new`. Refuse with instructions instead. (A current
/// binary persists the applied state with every entry, so it cannot reach
/// this state: a log is purged only after a snapshot of applied entries.)
fn refuse_restart_without_applied_state(
    last_purged: Option<openraft::LogId<u64>>,
) -> Result<(), ClusterBuildError> {
    match last_purged {
        None => Ok(()),
        Some(purged) => Err(ClusterBuildError::RaftInit(format!(
            "this node's Raft log is purged through index {} but its data directory holds no \
             persisted applied state (it was written by an earlier Hearth release, which kept \
             its applied state and membership in memory only, or an interrupted snapshot \
             install cleared it): it cannot be restarted in place. Re-seed it if the rest of \
             the cluster still has a leader: stop it, move its data directory (including \
             raft.db) aside, and start it empty so the leader sends it a snapshot. If no node \
             can start (every node's log was purged, as in the full-cluster restart this \
             release requires), there is no leader to send one, and the older build cannot \
             restart this node either: rebuild the cluster from the backup taken before the \
             upgrade. Restore it offline with `hearth backup restore` into one empty data \
             directory and copy that directory to every node before the new cluster first \
             starts; restoring into a cluster that has already started leaves every realm \
             empty under a new id (see the upgrading guide, \"Upgrading a cluster whose Raft \
             logs were purged\")",
            purged.index
        ))),
    }
}

async fn run_lag_monitor(
    raft: openraft::Raft<HearthRaftConfig>,
    reads_allowed: Arc<AtomicBool>,
    threshold_ms: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
    loop {
        interval.tick().await;
        let metrics = raft.metrics().borrow().clone();
        let lag = compute_lag_ms(&metrics);
        let ok = reads_allowed_for_lag(lag, threshold_ms);
        reads_allowed.store(ok, Ordering::Relaxed);
        if !ok {
            warn!(
                lag_ms = lag,
                threshold_ms, "replication lag exceeds threshold — follower reads disabled"
            );
        }
    }
}

/// Read-fencing decision: follower reads are served only while replication lag
/// stays at or below the configured threshold. Extracted from `run_lag_monitor`
/// so both branches — allow when caught up, fence when lagging — are unit
/// testable without standing up a multi-node Raft cluster.
pub(crate) fn reads_allowed_for_lag(lag_ms: u64, threshold_ms: u64) -> bool {
    lag_ms <= threshold_ms
}

/// Estimate replication lag in milliseconds from Raft metrics.
///
/// Compares `last_log_index` (entries received) against `last_applied.index`
/// (entries applied to the state machine), using 5 ms per pending entry as a
/// conservative estimate.
pub(crate) fn compute_lag_ms(metrics: &RaftMetrics<u64, HearthNode>) -> u64 {
    let log_idx = metrics.last_log_index.unwrap_or(0);
    let applied_idx = metrics.last_applied.as_ref().map(|l| l.index).unwrap_or(0);
    if log_idx > applied_idx {
        (log_idx - applied_idx).saturating_mul(5)
    } else {
        0
    }
}

/// The membership `config` names: this node plus every `cluster.peers` entry.
/// Used for self-initialisation and by the bootstrap HTTP handler.
fn initial_members_of(config: &ClusterConfig) -> BTreeMap<u64, HearthNode> {
    std::iter::once((config.node_id, config.peer_address.clone()))
        .chain(config.peers.iter().map(|p| (p.id, p.address.clone())))
        .map(|(id, addr)| (id, HearthNode { addr }))
        .collect()
}

// ── Clock-offset check (§16.4, C4) ────────────────────────────────────────────

/// The clock offset from the leader above which a node warns (C4).
const CLOCK_OFFSET_LIMIT_MICROS: i64 = 1_000_000;

/// How long [`ClockOffsetMonitor`] observes before it gives a verdict.
const CLOCK_OFFSET_WINDOW_MICROS: i64 = 30_000_000;

/// A clock offset from the leader over [`CLOCK_OFFSET_LIMIT_MICROS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockOffset {
    /// The leader's clock is ahead of this node's by at least `ms`.
    LeaderAhead { ms: u64 },
    /// This node's clock is ahead of the leader's by at most `ms`.
    FollowerAhead { ms: u64 },
}

/// The age on arrival, in microseconds, of the freshest in-flight entry of an
/// `AppendEntries` request, or `None` when the request carries none.
///
/// An entry's age is `now - leader_timestamp`: this node's clock offset from
/// the leader, plus the time the entry took to arrive. Only entries above
/// `leader_commit` count. Committed entries are a catch-up after a restart or
/// a partition, and their age is mostly that delay, not an offset.
fn min_in_flight_age(req: &AppendEntriesRequest<HearthRaftConfig>, now_micros: i64) -> Option<i64> {
    let committed = req.leader_commit.map_or(0, |id| id.index);
    req.entries
        .iter()
        .filter(|entry| req.leader_commit.is_none() || entry.log_id.index > committed)
        .filter_map(|entry| match &entry.payload {
            EntryPayload::Normal(
                RaftCommand::Put {
                    leader_timestamp, ..
                }
                | RaftCommand::Delete {
                    leader_timestamp, ..
                }
                | RaftCommand::Batch {
                    leader_timestamp, ..
                }
                | RaftCommand::WriteBatch {
                    leader_timestamp, ..
                }
                | RaftCommand::PutIfAbsent {
                    leader_timestamp, ..
                }
                | RaftCommand::IncrementU64 {
                    leader_timestamp, ..
                },
            ) => Some(*leader_timestamp),
            _ => None,
        })
        .filter(|&leader_ts| leader_ts != 0)
        .map(|leader_ts| now_micros - leader_ts)
        .min()
}

/// Decodes an `AppendEntries` payload and runs [`min_in_flight_age`] on it at
/// the current time; `None` when the payload does not decode.
#[cfg(test)]
fn check_clock_skew(payload: &[u8]) -> Option<i64> {
    let req = wire::decode::<AppendEntriesRequest<HearthRaftConfig>>(payload).ok()?;
    min_in_flight_age(&req, ClusterEngine::leader_timestamp_now())
}

/// Estimates this node's clock offset from the leader and reports it once per
/// observation window (C4). NTP is a deployment prerequisite for cluster mode.
///
/// An entry's age (see [`min_in_flight_age`]) is the offset plus a delay that
/// is never negative. So the smallest age seen in a window is the best
/// estimate: a node in contact receives fresh entries, and their delay is
/// small. A negative smallest age proves the leader's clock is ahead. A
/// positive one bounds this node's lead from above.
#[derive(Debug, Default)]
struct ClockOffsetMonitor {
    window: std::sync::Mutex<Option<OffsetWindow>>,
}

/// One observation window of a [`ClockOffsetMonitor`].
#[derive(Debug, Clone, Copy)]
struct OffsetWindow {
    start_micros: i64,
    min_age_micros: i64,
}

impl ClockOffsetMonitor {
    /// Records the smallest entry age of one request. Returns a verdict when
    /// this observation closes a window whose smallest age is more than
    /// [`CLOCK_OFFSET_LIMIT_MICROS`] from zero; then a new window starts.
    fn observe(&self, min_age_micros: i64, now_micros: i64) -> Option<ClockOffset> {
        // A poisoned lock only means another observation panicked; the
        // window it left is still a valid estimate.
        let mut slot = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let window = slot.get_or_insert(OffsetWindow {
            start_micros: now_micros,
            min_age_micros,
        });
        window.min_age_micros = window.min_age_micros.min(min_age_micros);
        if now_micros - window.start_micros < CLOCK_OFFSET_WINDOW_MICROS {
            return None;
        }
        let min_age = window.min_age_micros;
        *slot = None;
        let ms = min_age.unsigned_abs() / 1_000;
        if min_age < -CLOCK_OFFSET_LIMIT_MICROS {
            Some(ClockOffset::LeaderAhead { ms })
        } else if min_age > CLOCK_OFFSET_LIMIT_MICROS {
            Some(ClockOffset::FollowerAhead { ms })
        } else {
            None
        }
    }
}

// ── ClusterStorageAdapter ─────────────────────────────────────────────────────

/// Sync bridge: exposes [`ClusterEngine`] as [`StorageEngine`].
///
/// [`StorageEngine`] is a synchronous trait; [`ClusterEngine`] is async.
/// This adapter bridges the gap using [`tokio::task::block_in_place`] +
/// [`tokio::runtime::Handle::current().block_on`], which is safe to call
/// from both async executor threads and [`tokio::task::spawn_blocking`]
/// closures. Plain `Handle::current().block_on` panics when called from
/// an async context; `block_in_place` first parks the current thread's
/// async tasks, making the nested `block_on` safe.
///
/// Reads are local in every topology, and so are writes on a single node, so
/// both skip the async layer: they run on the calling thread (inside
/// `block_in_place`) and never wait for a second blocking-pool thread. A
/// backup export depends on that — see `ClusterEngine::read_inline` and
/// `single_node_write`. Only cluster-mode writes still go through `block_on`,
/// because a Raft proposal is async.
///
/// `enqueue_batch` / `await_batch_durable` are deliberately NOT forwarded:
/// the trait defaults route through [`StorageEngine::put_batch`] (and so
/// through Raft in cluster mode). Forwarding them to the inner engine would
/// bypass replication, and would expose the split-commit barrier deadlock
/// (GA audit 3 F-1) in `serve`.
///
/// Every [`ClusterError`] is surfaced as [`StorageError::Io`] with a
/// descriptive message (see [`cluster_to_storage_err`]); [`is_not_leader`]
/// recognises the one that means no leader could be reached.
pub struct ClusterStorageAdapter {
    engine: Arc<ClusterEngine>,
}

impl ClusterStorageAdapter {
    /// Wraps a [`ClusterEngine`] for use as [`StorageEngine`].
    pub fn new(engine: Arc<ClusterEngine>) -> Self {
        Self { engine }
    }

    /// Single-node mode: runs `write` against the local engine on the calling
    /// thread and returns its result. Cluster mode: `None` — the write must be
    /// proposed through Raft.
    ///
    /// The async single-node path hopped to the blocking pool, so a writer
    /// already on a pool thread (a `spawn_blocking` handler) waited for a
    /// SECOND pool thread. Writers parked on a backup export's barrier filled
    /// the pool with such outer threads; when the export released it, their
    /// inner writes found no thread and the server stayed stopped (GA audit 3
    /// F-7). Inline, a writer holds only the thread it already has.
    fn single_node_write<T>(
        &self,
        write: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Option<Result<T, crate::storage::StorageError>> {
        self.engine
            .raft
            .is_none()
            .then(|| tokio::task::block_in_place(|| write(&self.engine.inner)))
    }
}

/// Tells the replicated-write observer each time this node wins leadership —
/// once per term it leads, however quickly the metrics change around it.
///
/// A control's durable row and its control-epoch bump are two Raft proposals.
/// When leadership moves between them the bump can be lost — including while
/// no leader is elected, when there is nowhere to forward it — so the
/// observer bumps the epoch on the new leader too (see the identity engine's
/// control plane). Exits when the Raft instance shuts down.
async fn watch_leadership(
    raft: openraft::Raft<HearthRaftConfig>,
    observer: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>>,
) {
    let mut metrics = raft.metrics();
    let mut led_term: Option<u64> = None;
    loop {
        let won = {
            let m = metrics.borrow_and_update();
            let won = m.state == ServerState::Leader && led_term != Some(m.current_term);
            if won {
                led_term = Some(m.current_term);
            }
            won
        };
        if won {
            if let Some(observer) = observer.get() {
                observer.on_leadership_acquired();
            }
        }
        if metrics.changed().await.is_err() {
            return;
        }
    }
}

/// Whether a storage error is cluster storage refusing a write because no
/// Raft leader could be reached.
///
/// A follower forwards its writes to the leader, so this is returned only
/// when there was none to forward to within the write bound (no leader
/// elected, or the known one unreachable and no other elected) — a caller
/// retrying one is waiting on an election, not on a transient fault.
pub fn is_not_leader(err: &crate::storage::StorageError) -> bool {
    matches!(
        err,
        crate::storage::StorageError::ClusterUnavailable {
            cause: crate::storage::ClusterUnavailableCause::NoLeader,
            ..
        }
    )
}

/// Maps a [`ClusterError`] onto the [`crate::storage::StorageError`] the
/// [`StorageEngine`] facade returns.
///
/// The transient ones keep their meaning in structured variants the protocol
/// layer answers as `503` / `UNAVAILABLE`:
/// [`StorageError::ClusterUnavailable`](crate::storage::StorageError::ClusterUnavailable)
/// when nothing was written, and
/// [`StorageError::ClusterWriteOutcomeUnknown`](crate::storage::StorageError::ClusterWriteOutcomeUnknown)
/// when the write may have been applied.
pub(crate) fn cluster_to_storage_err(e: ClusterError) -> crate::storage::StorageError {
    use crate::storage::{ClusterUnavailableCause as Cause, StorageError};
    let unavailable = |cause, e: &ClusterError| StorageError::ClusterUnavailable {
        cause,
        reason: format!("raft: {e}"),
    };
    match e {
        ClusterError::Storage(se) => se,
        ClusterError::NotLeader { .. } => unavailable(Cause::NoLeader, &e),
        ClusterError::LeaderBusy { .. } => unavailable(Cause::LeaderBusy, &e),
        ClusterError::ReplicationLagExceeded { .. } => unavailable(Cause::ReplicationLag, &e),
        ClusterError::WriteTimeout { .. }
        | ClusterError::ForwardOutcomeUnknown { .. }
        | ClusterError::NotAppliedLocally { .. } => StorageError::ClusterWriteOutcomeUnknown {
            reason: format!("raft: {e}"),
        },
        e @ (ClusterError::CommandTooLarge { .. }
        | ClusterError::ForwardRejected { .. }
        | ClusterError::AlreadyInitialized(_)) => {
            StorageError::Io(std::io::Error::other(format!("raft: {e}")))
        }
        ClusterError::Raft(msg) => StorageError::Io(std::io::Error::other(format!("raft: {msg}"))),
    }
}

impl StorageEngine for ClusterStorageAdapter {
    fn accepts_writes(&self) -> bool {
        self.engine.accepts_writes()
    }

    /// Bypasses Raft: the row is this node's own and must not replicate.
    ///
    /// The identity engine's rate-limit trackers are per-node by design — each
    /// node counts what it saw — so their rehydration rows have to be writable
    /// on a follower. Proposing them broke both directions silently: a
    /// follower could persist nothing, and a lockout row the leader had
    /// replicated could never be deleted by a follower that later saw the
    /// successful attempt, so the next restart rehydrated a lockout for a user
    /// who had already authenticated (task 26.49).
    fn put_node_local(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        self.engine.inner.put(realm_id, key, value)
    }

    /// Bypasses Raft; see [`Self::put_node_local`].
    fn delete_node_local(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        self.engine.inner.delete(realm_id, key)
    }

    /// Served on the calling thread, never via the blocking pool (see
    /// `ClusterEngine::read_inline`). `block_in_place` only hands a runtime
    /// worker's other tasks to another thread while this one reads.
    fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
        tokio::task::block_in_place(|| self.engine.read_inline(|inner| inner.get(realm_id, key)))
            .map_err(cluster_to_storage_err)
    }

    fn put(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| inner.put(realm_id, key, value)) {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.put(&realm_id, &key, &value).await })
        })
        .map_err(cluster_to_storage_err)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| inner.delete(realm_id, key)) {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.delete(&realm_id, &key).await })
        })
        .map_err(cluster_to_storage_err)
    }

    /// Served on the calling thread; see [`Self::get`].
    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.scan(realm_id, start, end))
        })
        .map_err(cluster_to_storage_err)
    }

    /// Forwarded so the inner engine's key-only merge runs; the trait default
    /// materialises every value through [`Self::scan`] (GA audit 3 F-4).
    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.scan_keys(realm_id, start, end))
        })
        .map_err(cluster_to_storage_err)
    }

    /// Forwarded to the inner engine; see [`Self::scan_keys`].
    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.count_prefix(realm_id, prefix, cap))
        })
        .map_err(cluster_to_storage_err)
    }

    /// Forwarded to the inner engine; see [`Self::scan_keys`].
    fn scan_prefix_paged(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        offset: u64,
        limit: u32,
        cap: u64,
    ) -> Result<(Vec<ScanEntry>, u64), crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.scan_prefix_paged(realm_id, prefix, offset, limit, cap))
        })
        .map_err(cluster_to_storage_err)
    }

    /// The inner engine's WAL write fence. `/readyz` reads it through this
    /// adapter in every `serve` topology; the trait default (`false`) kept a
    /// node that refused every write reporting ready (GA audit 3 F-4).
    fn is_write_fenced(&self) -> bool {
        self.engine.inner.is_write_fenced()
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| inner.put_batch(realm_id, entries)) {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let entries = entries.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.put_batch(&realm_id, &entries).await })
        })
        .map_err(cluster_to_storage_err)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), crate::storage::StorageError> {
        if let Some(done) =
            self.single_node_write(|inner| inner.write_batch(realm_id, puts, deletes))
        {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let puts = puts.to_vec();
        let deletes = deletes.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.write_batch(&realm_id, &puts, &deletes).await })
        })
        .map_err(cluster_to_storage_err)
    }

    fn backup_barrier(&self) -> Option<Arc<std::sync::RwLock<()>>> {
        self.engine.backup_barrier()
    }

    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, crate::storage::StorageError> {
        if let Some(done) =
            self.single_node_write(|inner| inner.put_if_absent(realm_id, key, value))
        {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.put_if_absent(&realm_id, &key, &value).await })
        })
        .map_err(cluster_to_storage_err)
    }

    fn increment_u64(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<u64, crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| inner.increment_u64(realm_id, key)) {
            return done;
        }
        let engine = Arc::clone(&self.engine);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { engine.increment_u64(&realm_id, &key).await })
        })
        .map_err(cluster_to_storage_err)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, crate::storage::StorageError> {
        self.engine.list_realms()
    }

    fn begin_snapshot_restore(
        &self,
        snapshot_id: &str,
    ) -> Result<(), crate::storage::StorageError> {
        self.engine.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), crate::storage::StorageError> {
        self.engine.complete_snapshot_restore()
    }

    fn flush_memtable(&self) -> Result<(), crate::storage::StorageError> {
        self.engine.flush_memtable()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::{CommittedLeaderId, LogId, ServerState, StoredMembership, Vote};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn make_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    /// A data directory written by an earlier release (no persisted applied
    /// state) over a purged log is refused; over an unpurged log (openraft
    /// replays it all) it starts.
    ///
    /// The instructions must work when NO node can start — the full-cluster
    /// restart this release requires, on a cluster whose logs were purged.
    /// "Start it empty and the leader sends it a snapshot" assumes a leader,
    /// so on its own it sent operators round in a circle: the refusal must
    /// also name the rebuild-from-backup procedure.
    #[test]
    fn a_purged_log_without_persisted_applied_state_is_refused_with_instructions() {
        assert!(refuse_restart_without_applied_state(None).is_ok());
        let err = refuse_restart_without_applied_state(Some(LogId::new(
            CommittedLeaderId::new(1, 1),
            5_000,
        )))
        .expect_err("refused");
        let msg = err.to_string();
        assert!(msg.contains("5000") && msg.contains("Re-seed"), "{msg}");
        assert!(
            msg.contains("no node") && msg.contains("backup") && msg.contains("upgrading guide"),
            "the refusal must give the procedure for when no node can start: {msg}"
        );
        // Realms come from hearth.yaml, so a cluster that has started has
        // already created every declared realm under a new id, and a restore
        // into it leaves the realms empty under their names. The rebuild must
        // restore OFFLINE, before the new cluster first starts.
        assert!(
            msg.contains("hearth backup restore") && msg.contains("before"),
            "the refusal must name the offline restore, before the first start: {msg}"
        );
        assert!(
            !msg.contains("start a fresh cluster with empty data directories and restore"),
            "restoring into a started cluster loses every realm's id and keys: {msg}"
        );
        // Stopping a purged node is one-way on either build.
        assert!(msg.contains("older build"), "{msg}");
    }

    fn open_engine(dir: &std::path::Path) -> Arc<EmbeddedStorageEngine> {
        let config = StorageConfig::dev(dir.to_path_buf());
        Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"))
    }

    fn make_metrics(
        log_idx: Option<u64>,
        applied_idx: Option<u64>,
    ) -> RaftMetrics<u64, HearthNode> {
        let make_log_id = |idx: u64| Some(LogId::new(CommittedLeaderId::new(1, 0), idx));

        RaftMetrics {
            running_state: Ok(()),
            id: 1,
            current_term: 1,
            vote: Vote::new(1, 1),
            last_log_index: log_idx,
            last_applied: applied_idx.and_then(|i| make_log_id(i)),
            snapshot: None,
            purged: None,
            state: ServerState::Follower,
            current_leader: None,
            millis_since_quorum_ack: None,
            membership_config: Arc::new(StoredMembership::default()),
            replication: None,
        }
    }

    // ── §4.9#4: the app-layer storage handle ──────────────────────────────────

    /// `serve` always installs a `ClusterStorageAdapter`, single-node included.
    /// The adapter answered `None` for the backup consistency barrier, so the
    /// export took no barrier and every mutating write ran straight through it.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn adapter_exposes_the_inner_backup_barrier() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let inner_barrier = inner
            .backup_barrier()
            .expect("embedded engine has a barrier");
        let adapter = ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(inner)));

        let adapter_barrier = adapter
            .backup_barrier()
            .expect("the adapter must expose the barrier, not swallow it");
        assert!(
            Arc::ptr_eq(&inner_barrier, &adapter_barrier),
            "the adapter must expose the SAME barrier the export blocks on"
        );
    }

    /// `serve` reads the WAL write fence through the adapter (`/readyz` →
    /// identity → storage). The adapter inherited the trait default `false`,
    /// so a node whose WAL refused every write kept reporting ready and kept
    /// taking write traffic (GA audit 3 F-4).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn adapter_reports_the_inner_wal_write_fence() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let adapter =
            ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(Arc::clone(&inner))));
        assert!(
            !adapter.is_write_fenced(),
            "an unfenced engine must not report a fence"
        );

        inner.engage_wal_fence_for_test();

        assert!(
            inner.is_write_fenced(),
            "precondition: the inner engine is fenced"
        );
        assert!(
            adapter.is_write_fenced(),
            "the adapter must report the inner engine's WAL write fence"
        );
    }

    /// The adapter's key-only scans (`scan_keys`, `count_prefix`,
    /// `scan_prefix_paged`) answer exactly what the inner engine answers,
    /// tombstones included — they are forwarded, not rebuilt from `scan`.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn adapter_key_only_scans_match_the_inner_engine() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let adapter =
            ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(Arc::clone(&inner))));
        let realm = make_realm();
        for k in [b"p:a".as_slice(), b"p:b", b"p:c", b"q:z"] {
            adapter.put(&realm, k, b"v").unwrap();
        }
        adapter.delete(&realm, b"p:b").unwrap();

        let keys = adapter.scan_keys(&realm, b"p:", b"p;").unwrap();
        assert_eq!(keys, vec![b"p:a".to_vec(), b"p:c".to_vec()]);
        assert_eq!(keys, inner.scan_keys(&realm, b"p:", b"p;").unwrap());
        assert_eq!(adapter.count_prefix(&realm, b"p:", 0).unwrap(), 2);
        assert_eq!(adapter.count_prefix(&realm, b"p:", 1).unwrap(), 1);
        let (window, total) = adapter.scan_prefix_paged(&realm, b"p:", 1, 5, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(
            window.iter().map(|e| e.key.clone()).collect::<Vec<_>>(),
            vec![b"p:c".to_vec()]
        );
    }

    /// The adapter inherited the default `write_batch`, which is a sequential
    /// `put`/`delete` loop with no atomicity — so the one primitive callers use
    /// when a record and its index must land together silently lost it.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn adapter_write_batch_applies_puts_and_deletes() {
        let dir = tempdir().unwrap();
        let adapter = ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(
            open_engine(dir.path().join("data").as_path()),
        )));
        let realm = make_realm();

        adapter.put(&realm, b"stale", b"v").unwrap();
        adapter
            .write_batch(
                &realm,
                &[(b"fresh".to_vec(), b"v2".to_vec())],
                &[b"stale".to_vec()],
            )
            .unwrap();

        assert_eq!(adapter.get(&realm, b"fresh").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(adapter.get(&realm, b"stale").unwrap(), None);
    }

    // ── Single-node passthrough ───────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"k", b"v").await.expect("put");
        let got = engine.get(&realm, b"k").await.expect("get");
        assert_eq!(got, Some(b"v".to_vec()));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_delete_removes_value() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"k", b"v").await.expect("put");
        engine.delete(&realm, b"k").await.expect("delete");
        assert!(engine.get(&realm, b"k").await.expect("get").is_none());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_put_batch_writes_all() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        let pairs = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
        ];
        engine.put_batch(&realm, &pairs).await.expect("put_batch");
        assert_eq!(
            engine.get(&realm, b"a").await.expect("get a"),
            Some(b"1".to_vec())
        );
        assert_eq!(
            engine.get(&realm, b"b").await.expect("get b"),
            Some(b"2".to_vec())
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_scan_returns_entries() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"a", b"1").await.expect("put a");
        engine.put(&realm, b"b", b"2").await.expect("put b");
        let results = engine.scan(&realm, b"a", &[0xFF; 4]).await.expect("scan");
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_reads_ok_always_true() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        assert!(engine.reads_ok(), "single-node never blocks reads");
    }

    // ── Read-fencing decision (both branches) ─────────────────────────────────

    #[test]
    fn reads_allowed_when_lag_at_or_below_threshold() {
        // Caught up and exactly at the threshold both keep reads flowing.
        assert!(reads_allowed_for_lag(0, 500));
        assert!(reads_allowed_for_lag(500, 500));
    }

    #[test]
    fn reads_fenced_when_lag_exceeds_threshold() {
        // The false branch the single-node test can never reach: a lagging
        // follower must have reads disabled (one ms over the line is enough).
        assert!(
            !reads_allowed_for_lag(501, 500),
            "reads must be fenced once replication lag exceeds the threshold"
        );
        assert!(!reads_allowed_for_lag(10_000, 500));
    }

    #[test]
    fn lag_monitor_decision_fences_reads_for_lagged_metrics() {
        // Compose the real monitor pipeline: metrics → compute_lag_ms → fence.
        // 100 pending entries × 5 ms = 500 ms lag; with a 200 ms threshold the
        // node must be fenced, and with a 600 ms threshold it must stay open.
        let m = make_metrics(Some(120), Some(20));
        let lag = compute_lag_ms(&m);
        assert_eq!(lag, 500);
        assert!(
            !reads_allowed_for_lag(lag, 200),
            "500 ms lag > 200 ms → fenced"
        );
        assert!(
            reads_allowed_for_lag(lag, 600),
            "500 ms lag ≤ 600 ms → open"
        );
    }

    // ── compute_lag_ms ────────────────────────────────────────────────────────

    #[test]
    fn lag_zero_when_caught_up() {
        let m = make_metrics(Some(7), Some(7));
        assert_eq!(compute_lag_ms(&m), 0);
    }

    #[test]
    fn lag_zero_when_no_log() {
        let m = make_metrics(None, None);
        assert_eq!(compute_lag_ms(&m), 0);
    }

    #[test]
    fn lag_proportional_to_pending_entries() {
        let m = make_metrics(Some(20), Some(10));
        assert_eq!(compute_lag_ms(&m), 50); // 10 entries × 5 ms
    }

    #[test]
    fn lag_zero_when_applied_ahead_of_log() {
        // Shouldn't happen in practice but must not underflow.
        let m = make_metrics(Some(5), Some(10));
        assert_eq!(compute_lag_ms(&m), 0);
    }

    // ── leader_timestamp_now ──────────────────────────────────────────────────

    #[test]
    fn leader_timestamp_is_positive_and_recent() {
        let ts = ClusterEngine::leader_timestamp_now();
        assert!(ts > 0);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        assert!((now - ts).abs() < 1_000_000, "timestamp within 1 second");
    }

    // ── Clock-skew check ──────────────────────────────────────────────────────

    #[test]
    fn check_clock_skew_returns_none_on_unparseable_payload() {
        // Malformed / empty payloads must be rejected by the parser and yield
        // None (no entry inspected) rather than panicking or reporting a skew.
        assert_eq!(check_clock_skew(b"not cbor"), None);
        assert_eq!(check_clock_skew(b"{}"), None);
        assert_eq!(check_clock_skew(b""), None);
    }

    /// An `AppendEntries` request with one `IncrementU64` entry per
    /// `(index, leader_timestamp)` pair, and the leader's commit index.
    fn append_with(
        entries: &[(u64, i64)],
        leader_commit: Option<u64>,
    ) -> AppendEntriesRequest<HearthRaftConfig> {
        let log_id = |index| LogId::new(CommittedLeaderId::new(1, 1), index);
        AppendEntriesRequest {
            vote: Vote::new_committed(1, 1),
            prev_log_id: None,
            entries: entries
                .iter()
                .map(|&(index, leader_timestamp)| openraft::Entry {
                    log_id: log_id(index),
                    payload: EntryPayload::Normal(RaftCommand::IncrementU64 {
                        leader_timestamp,
                        realm: RealmId::new(Uuid::nil()),
                        key: b"ctr".to_vec(),
                    }),
                })
                .collect(),
            leader_commit: leader_commit.map(log_id),
        }
    }

    const NOW: i64 = 1_800_000_000_000_000;
    const SEC: i64 = 1_000_000;

    /// A follower that catches up receives entries the leader committed long
    /// ago. Their age is the time it was away, not a clock offset (C4 false
    /// warning seen on a 3-node cluster sharing one clock: `skew_ms=2234`).
    #[test]
    fn a_catch_up_of_committed_entries_gives_no_clock_sample() {
        let req = append_with(&[(1, NOW - 300 * SEC), (2, NOW - 200 * SEC)], Some(2));
        assert_eq!(min_in_flight_age(&req, NOW), None);
    }

    /// Of the in-flight entries, the freshest one gives the age: its delay is
    /// the smallest, so its age is closest to the offset.
    #[test]
    fn the_freshest_in_flight_entry_gives_the_clock_sample() {
        let req = append_with(
            &[(3, NOW - 300 * SEC), (4, NOW - 5 * SEC), (5, NOW - 10_000)],
            Some(3),
        );
        assert_eq!(min_in_flight_age(&req, NOW), Some(10_000));
    }

    /// Entries without a leader timestamp give no sample.
    #[test]
    fn entries_without_a_timestamp_give_no_clock_sample() {
        assert_eq!(min_in_flight_age(&append_with(&[(1, 0)], None), NOW), None);
        assert_eq!(min_in_flight_age(&append_with(&[], None), NOW), None);
    }

    /// One late entry (queued while the leader was elected) does not warn
    /// when a fresh one arrives in the same window.
    #[test]
    fn a_late_entry_does_not_warn_when_a_fresh_one_arrives_in_the_window() {
        let m = ClockOffsetMonitor::default();
        assert_eq!(m.observe(2_234_000, NOW), None);
        assert_eq!(m.observe(12_000, NOW + SEC), None);
        assert_eq!(m.observe(2_234_000, NOW + 31 * SEC), None);
    }

    /// A follower whose clock is ahead sees every entry arrive late. It warns
    /// once, when the window closes, and starts a new window.
    #[test]
    fn a_follower_clock_ahead_warns_once_per_window() {
        let m = ClockOffsetMonitor::default();
        assert_eq!(m.observe(2_100_000, NOW), None);
        assert_eq!(m.observe(2_000_000, NOW + 10 * SEC), None);
        assert_eq!(
            m.observe(2_050_000, NOW + 30 * SEC),
            Some(ClockOffset::FollowerAhead { ms: 2_000 })
        );
        assert_eq!(m.observe(2_000_000, NOW + 31 * SEC), None, "a new window");
    }

    /// An entry that arrives before the leader proposed it proves the
    /// leader's clock is ahead.
    #[test]
    fn a_leader_clock_ahead_warns() {
        let m = ClockOffsetMonitor::default();
        assert_eq!(m.observe(-1_400_000, NOW), None);
        assert_eq!(
            m.observe(-1_500_000, NOW + 30 * SEC),
            Some(ClockOffset::LeaderAhead { ms: 1_500 })
        );
    }

    /// Offsets within 1 s either way do not warn; 1 s itself is not "exceeds".
    #[test]
    fn an_offset_within_one_second_does_not_warn() {
        for age in [-1_000_000, -400_000, 0, 900_000, 1_000_000] {
            let m = ClockOffsetMonitor::default();
            assert_eq!(m.observe(age, NOW), None);
            assert_eq!(m.observe(age, NOW + 30 * SEC), None, "age {age} µs");
        }
    }

    // ── ClusterStorageAdapter::list_realms delegation ─────────────────────────

    /// `ClusterStorageAdapter::list_realms` must report every realm stored in
    /// the underlying `EmbeddedStorageEngine`.  Without this delegation the
    /// `restore_snapshot_in_place` Phase 1 clear would silently no-op when
    /// invoked through the adapter (HEA-2133).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn adapter_list_realms_delegates_to_inner() {
        use crate::storage::StorageEngine as _;

        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let realm_a = make_realm();
        let realm_b = make_realm();

        // Write one key into each realm so they appear on disk.
        inner.put(&realm_a, b"key", b"val").expect("put realm_a");
        inner.put(&realm_b, b"key", b"val").expect("put realm_b");

        let cluster_engine = Arc::new(ClusterEngine::single_node(Arc::clone(&inner)));
        let adapter = ClusterStorageAdapter::new(cluster_engine);

        let mut realms = adapter.list_realms().expect("list_realms");
        realms.sort();
        let mut expected = vec![realm_a, realm_b];
        expected.sort();
        assert_eq!(
            realms, expected,
            "adapter must report all realms held by inner engine"
        );
    }

    // ── ClusterStorageAdapter::begin/complete_snapshot_restore delegation ──────

    /// `ClusterStorageAdapter::begin_snapshot_restore` must reach the
    /// underlying `EmbeddedStorageEngine`.  Without delegation a crash between
    /// Phase 1 (clear) and Phase 2 (replay) is undetectable because no marker
    /// file is written (HEA-2135).
    ///
    /// Proof: after `begin_snapshot_restore` via the adapter, re-opening the
    /// raw `EmbeddedStorageEngine` returns `TornSnapshotRestore`.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn adapter_begin_snapshot_restore_delegates_to_inner() {
        use crate::storage::{StorageConfig, StorageEngine as _};

        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let inner = open_engine(data_dir.as_path());
        let cluster_engine = Arc::new(ClusterEngine::single_node(Arc::clone(&inner)));
        let adapter = ClusterStorageAdapter::new(cluster_engine);

        adapter
            .begin_snapshot_restore("snap-delegate-begin")
            .expect("begin_snapshot_restore");
        drop(adapter);
        drop(inner);

        let torn = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir));
        assert!(
            matches!(
                torn,
                Err(crate::storage::StorageError::TornSnapshotRestore { .. })
            ),
            "re-open after begin_snapshot_restore via adapter must return TornSnapshotRestore; \
             got: {torn:?}"
        );
    }

    /// `ClusterStorageAdapter::complete_snapshot_restore` must reach the
    /// underlying `EmbeddedStorageEngine` and remove the marker.  Without
    /// delegation the marker persists and subsequent opens fail (HEA-2135).
    ///
    /// Proof: after `begin` + `complete` via the adapter, re-opening the
    /// engine succeeds (marker is gone).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn adapter_complete_snapshot_restore_delegates_to_inner() {
        use crate::storage::{StorageConfig, StorageEngine as _};

        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let inner = open_engine(data_dir.as_path());
        let cluster_engine = Arc::new(ClusterEngine::single_node(Arc::clone(&inner)));
        let adapter = ClusterStorageAdapter::new(cluster_engine);

        adapter
            .begin_snapshot_restore("snap-delegate-complete")
            .expect("begin_snapshot_restore");
        adapter
            .complete_snapshot_restore()
            .expect("complete_snapshot_restore");
        drop(adapter);
        drop(inner);

        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir))
            .expect("engine must open cleanly after complete_snapshot_restore via adapter");
    }
}
