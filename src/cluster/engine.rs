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
//! Reads are local, behind the read gate ([`ReadGate`]): a node serves a read
//! only while it is in contact (`cluster-consistency` R2). A follower is in
//! contact for `cluster.read_lag_threshold_ms` after each `AppendEntries` it
//! accepts from the current leader; a leader, for that long after a quorum
//! acknowledged it. A background task checks every 50 ms that applied entries do not lag
//! received ones beyond the threshold, holds the gate closed while they do,
//! and refreshes a leader's contact.
//! A refused read returns
//! [`ClusterError::ReadsFenced`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use openraft::error::{ClientWriteError, RaftError};
use openraft::metrics::WaitError;
use openraft::raft::ClientWriteResponse;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use openraft::{Config as RaftConfig, EntryPayload, RaftMetrics, ServerState};
use tokio::task::spawn_blocking;
use tracing::{info, warn};

use crate::cluster::log_store::{ClusterIdentity, HearthLogStore};
use crate::cluster::network::{ForwardFailure, HearthNetworkFactory, LeaderForwarder, PeerFaults};
use crate::cluster::peer_identity::PeerStanding;
use crate::cluster::read_gate::{leader_contact, LeaderContact, ReadGate, Refusal};
use crate::cluster::server::{IncomingRpcDispatch, LeaderRpcAnswer};
use crate::cluster::state_machine::HearthStateMachine;
use crate::cluster::types::{
    ClusterId, ForwardedWriteOutcome, HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand,
};
use crate::cluster::wire::{self, MAX_COMMAND_BYTES, SNAPSHOT_CHUNK_BYTES};
use crate::cluster::ReplicatedWriteObserver;
use crate::config::ClusterConfig;
use crate::core::RealmId;
use crate::metrics::ForwardedWriteOutcomeLabel;
use crate::storage::{
    ClusterUnavailableCause, EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine,
};

// ── Error types ───────────────────────────────────────────────────────────────

/// Error produced by cluster-layer storage operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// This node is not the Raft leader; clients should redirect.
    #[error("not the leader; redirect to {leader_addr}")]
    NotLeader { leader_addr: String },

    /// This node's reads are fenced: it is out of contact, or it lags the
    /// leader (see [`ReadGate`]).
    #[error("reads fenced ({cause}); redirect to {leader_addr}")]
    ReadsFenced {
        cause: ClusterUnavailableCause,
        leader_addr: String,
    },

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

    /// This node is not the one that may initialise the cluster: only the
    /// lowest node ID of the membership does (it does so at start-up). Each
    /// initialiser generates its own cluster ID, so two of them would form
    /// two clusters that refuse each other.
    #[error(
        "only node {designated}, the lowest node ID in cluster.peers, may initialise the \
         cluster; it does so itself at start-up. If it cannot start, remove it from \
         cluster.peers on every node before any node is initialised"
    )]
    NotTheInitialiser {
        /// The lowest node ID of the membership.
        designated: u64,
    },

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

/// Default `storage.max_writes_in_flight`: the single-node writes that may be
/// in progress at once (#596). One more is refused at once, not queued.
///
/// Each write in progress holds a thread. When the disk stops completing
/// syncs, each write that arrives waits, so without a limit the server adds a
/// thread for each one, and the blocking pool keeps them after the disk
/// recovers. 32 writes sustain 3,200 writes/s until one write takes 10 ms.
///
/// Audit batches may use twice the limit (#836). After a disk stall, the
/// server can keep about one thread per place, so a higher limit also keeps
/// more threads (the `write_stall_threads` simulation test).
pub const DEFAULT_MAX_WRITES_IN_FLIGHT: usize = 32;

/// Extra time a follower gives a forwarded write beyond
/// `cluster.write_timeout_ms`, so the leader's own commit-timeout answer
/// arrives in-band instead of racing the follower's deadline.
const FORWARD_GRACE: Duration = Duration::from_secs(2);

/// How many times one write may be routed (proposed locally or forwarded)
/// before it gives up. At most two of those are forwards: the first, and one
/// retry on a new leader when the first provably did not propose it.
const MAX_ROUTING_ROUNDS: usize = 4;

/// Upper bound of the Raft election timeout, in milliseconds. A leader that
/// no quorum has acknowledged for longer than this may already be replaced:
/// a majority elsewhere can elect a new leader after one election timeout.
const ELECTION_TIMEOUT_MAX_MS: u64 = 3000;

/// How long the leader waits for a follower to answer a snapshot chunk, in
/// milliseconds. openraft applies it to every chunk, and the answer to the
/// last one comes after the follower has checked the whole file and
/// restored it into its store: minutes at a million users
/// (`cluster-file-snapshots`, design decision 8). openraft's 200 ms default
/// timed out every large install, so the leader sent it again and again.
/// The other chunks are bounded more tightly by the peer client
/// ([`crate::cluster::network`]).
const INSTALL_SNAPSHOT_TIMEOUT_MS: u64 = 15 * 60 * 1000;

/// The Raft configuration of every clustered node (before validation).
fn raft_config() -> RaftConfig {
    RaftConfig {
        heartbeat_interval: ClusterConfig::RAFT_HEARTBEAT_INTERVAL_MS,
        election_timeout_min: 1500,
        election_timeout_max: ELECTION_TIMEOUT_MAX_MS,
        // Chunks well under the peer message limit (see `cluster::wire`);
        // openraft's default is 3 MiB.
        snapshot_max_chunk_size: SNAPSHOT_CHUNK_BYTES,
        install_snapshot_timeout: INSTALL_SNAPSHOT_TIMEOUT_MS,
        ..RaftConfig::default()
    }
}

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

/// While alive, a node's reads skip the contact check (see
/// [`ClusterEngine::start_up_reads`]).
pub struct StartUpReads {
    gate: Option<Arc<ReadGate>>,
}

impl Drop for StartUpReads {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.end_start_up();
        }
    }
}

/// Public-facing storage wrapper that makes the cluster layer invisible in
/// single-node mode and routes traffic correctly in cluster mode.
pub struct ClusterEngine {
    inner: Arc<EmbeddedStorageEngine>,
    /// `None` in single-node mode — no Raft overhead, no port allocation.
    raft: Option<openraft::Raft<HearthRaftConfig>>,
    /// Whether this node is in contact (see [`ReadGate`]). `None` in
    /// single-node mode, which always serves reads.
    read_gate: Option<Arc<ReadGate>>,
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
    /// This node's cluster ID, kept in `raft.db`. `None` in single-node mode.
    cluster_identity: Option<Arc<ClusterIdentity>>,
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
            read_gate: None,
            read_lag_threshold_ms: ClusterConfig::DEFAULT_READ_LAG_THRESHOLD_MS,
            write_timeout: Duration::from_millis(ClusterConfig::DEFAULT_WRITE_TIMEOUT_MS),
            self_node_id: None,
            initial_members: None,
            observer_slot: None,
            forwarding: None,
            clock_offset: ClockOffsetMonitor::default(),
            cluster_identity: None,
        }
    }

    /// A single-node engine with a read gate: reads behave as on a cluster
    /// node, with `gate` driven by the test. Test-only.
    #[cfg(test)]
    pub(crate) fn with_read_gate(inner: Arc<EmbeddedStorageEngine>, gate: Arc<ReadGate>) -> Self {
        Self {
            read_gate: Some(gate),
            ..Self::single_node(inner)
        }
    }

    /// Lets this node's reads skip the contact check while `serve` starts,
    /// until the returned guard drops. A no-op in single-node mode.
    ///
    /// Start-up reads build caches and serve no client, so a node that
    /// cannot reach a quorum still starts and reports why on `/readyz`.
    /// `serve` drops the guard just before its listeners start: from then
    /// on, every read needs contact (`cluster-consistency` R2).
    #[must_use = "the exemption ends when the guard drops"]
    pub fn start_up_reads(&self) -> StartUpReads {
        if let Some(gate) = &self.read_gate {
            gate.begin_start_up();
        }
        StartUpReads {
            gate: self.read_gate.clone(),
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

        let sm_engine = Arc::clone(&inner);
        // Shared observer slot: the state machine is consumed by `Raft::new`
        // below, but the projection observer (the identity engine) is built
        // later — the composition root fills the slot via
        // `set_replicated_write_observer` (audit 2026-08-28 §4.16#5).
        let observer_slot: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>> =
            Arc::new(OnceLock::new());
        // The state machine loads its persisted applied state (storage reads:
        // on the blocking pool).
        let threshold = config
            .read_lag_threshold_ms
            .unwrap_or(ClusterConfig::DEFAULT_READ_LAG_THRESHOLD_MS);
        // Closed until the first contact: a node that has just started has
        // not yet heard from any leader.
        let read_gate = Arc::new(ReadGate::new(threshold));
        let slot = Arc::clone(&observer_slot);
        let state_machine = tokio::task::spawn_blocking(move || {
            HearthStateMachine::with_observer_slot(sm_engine, slot)
        })
        .await
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?
        .with_read_gate(Arc::clone(&read_gate));
        if state_machine.has_no_applied_state() {
            let log_state = openraft::storage::RaftLogStorage::get_log_state(&mut log_store)
                .await
                .map_err(|e| ClusterBuildError::LogStore(e.to_string()))?;
            refuse_restart_without_applied_state(log_state.last_purged_log_id)?;
        }

        // Taken before `Raft::new` consumes the store; shares its database.
        let cluster_identity = log_store
            .cluster_identity()
            .map_err(|e| ClusterBuildError::LogStore(e.to_string()))?;

        let cert_pem = tokio::fs::read(&config.tls_cert_path).await?;
        let key_pem = tokio::fs::read(&config.tls_key_path).await?;
        let ca_pem = tokio::fs::read(&config.tls_ca_cert_path).await?;
        let network_factory = HearthNetworkFactory::new(
            config.node_id,
            Arc::clone(&cluster_identity),
            cert_pem,
            key_pem,
            ca_pem,
        )
        .with_read_gate(Arc::clone(&read_gate));
        let network_factory = match faults {
            Some(f) => network_factory.with_peer_faults(f),
            None => network_factory,
        };
        let forwarding = Forwarding {
            client: network_factory.leader_forwarder(),
            permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_FORWARDED_WRITES),
        };

        let raft_config = Arc::new(
            raft_config()
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

        let write_timeout = Duration::from_millis(
            config
                .write_timeout_ms
                .unwrap_or(ClusterConfig::DEFAULT_WRITE_TIMEOUT_MS),
        );

        tokio::spawn(run_lag_monitor(
            raft.clone(),
            Arc::clone(&read_gate),
            threshold,
        ));
        tokio::spawn(watch_leadership(raft.clone(), Arc::clone(&observer_slot)));

        let initial_members = initial_members_of(config);
        Self::self_initialise_if_designated(&raft, &cluster_identity, config, &initial_members)
            .await;

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
            read_gate: Some(read_gate),
            read_lag_threshold_ms: threshold,
            write_timeout,
            self_node_id: Some(config.node_id),
            initial_members: Some(initial_members),
            observer_slot: Some(observer_slot),
            forwarding: Some(forwarding),
            clock_offset: ClockOffsetMonitor::default(),
            cluster_identity: Some(cluster_identity),
        })
    }

    /// Cold-cluster self-initialisation (task 26.46).
    ///
    /// Extracted from `build_clustered_inner` verbatim so that function stays
    /// under the pedantic line limit; the behaviour and the reasoning below
    /// are unchanged.
    async fn self_initialise_if_designated(
        raft: &openraft::Raft<HearthRaftConfig>,
        cluster_identity: &ClusterIdentity,
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
        // `POST /admin/cluster/bootstrap` handler over it — accepts the same
        // node only: each initialiser generates its own cluster ID, so two
        // would refuse each other (design decision 5). When the designated
        // node is down on a cold cluster, the operator removes it from
        // `cluster.peers` on every node.
        //
        // Skipped when `peers` is empty: that is a degenerate cluster-mode
        // configuration with nothing to replicate to, and
        // `initialize_cluster` remains the way to form it explicitly.
        let designated_initialiser = initial_members.keys().copied().min();
        if !config.peers.is_empty() && designated_initialiser == Some(config.node_id) {
            match raft.is_initialized().await {
                Ok(false) => match initialize_with_cluster_id(
                    raft,
                    cluster_identity,
                    config.node_id,
                    initial_members.clone(),
                )
                .await
                {
                    Ok(cluster_id) => info!(
                        node_id = config.node_id,
                        members = initial_members.len(),
                        %cluster_id,
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
    /// Only the designated initialiser, the lowest node ID in `members`, may
    /// call it; other nodes join when the leader first reaches them. On an
    /// initialised node it writes nothing.
    ///
    /// # Errors
    ///
    /// [`ClusterError::AlreadyInitialized`] on an initialised node,
    /// [`ClusterError::NotTheInitialiser`] on any node but the lowest ID.
    pub async fn initialize_cluster(
        &self,
        members: BTreeMap<u64, HearthNode>,
    ) -> Result<(), ClusterError> {
        let (Some(raft), Some(identity), Some(node_id)) = (
            self.raft.as_ref(),
            self.cluster_identity.as_ref(),
            self.self_node_id,
        ) else {
            return Err(ClusterError::Raft(
                "cannot initialise cluster on a single-node engine".to_string(),
            ));
        };
        initialize_with_cluster_id(raft, identity, node_id, members)
            .await
            .map(|_| ())
    }

    /// This node's cluster ID: `None` in single-node mode and on a cluster
    /// node that has not yet initialised or joined a cluster.
    pub fn cluster_id(&self) -> Option<ClusterId> {
        self.cluster_identity.as_ref().and_then(|c| c.get())
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

    /// Why this node cannot take a write now, or `None` when it can.
    /// `/readyz` reports the reason as not-ready. Always `None` in
    /// single-node mode.
    ///
    /// - `"no_leader"`: no known leader (an election, or no quorum reachable).
    /// - `"no_quorum"`: this node leads, but no quorum has acknowledged it
    ///   within [`ELECTION_TIMEOUT_MAX_MS`]. openraft 0.9 never steps such a
    ///   leader down (docs/dev/CONSISTENCY.md G1), and a node restarted on a
    ///   store whose last vote was its own resumes as leader with no quorum.
    /// - `"installing_snapshot"`: a snapshot install runs (or failed); reads
    ///   answer `503` until a contact after it.
    /// - `"not_in_contact"`: the read gate is closed: no contact with a
    ///   leader within `cluster.read_lag_threshold_ms`, so reads answer `503`.
    /// - `"replication_lag"`: the read gate's lag hold is set.
    ///
    /// Local knowledge only: a follower whose leader is gone keeps it as
    /// leader until its own election timeout (1.5–3 s) passes, but its read
    /// gate closes within the threshold.
    pub fn not_ready_reason(&self) -> Option<&'static str> {
        let leader = self.raft.as_ref().and_then(|raft| {
            let metrics = raft.metrics();
            let m = metrics.borrow();
            leader_gap(
                m.id,
                m.current_leader,
                m.millis_since_quorum_ack,
                m.membership_config.membership().voter_ids().count(),
            )
        });
        leader.or_else(|| {
            let gate = self.read_gate.as_ref()?;
            gate.refusal_at(gate.now_ms()).map(|refusal| match refusal {
                Refusal::NotInContact => "not_in_contact",
                Refusal::ReplicationLag => "replication_lag",
                Refusal::InstallingSnapshot => "installing_snapshot",
            })
        })
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
    /// Single-node: always true. Cluster: the read gate. Hot path: one
    /// atomic load and a monotonic clock read, no allocation, no lock.
    pub(crate) fn reads_ok(&self) -> bool {
        self.read_gate.as_ref().is_none_or(|gate| gate.allows())
    }

    /// The error for a read that [`Self::reads_ok`] refused. Off the hot
    /// path.
    fn reads_fenced(&self) -> ClusterError {
        let refusal = self
            .read_gate
            .as_ref()
            .and_then(|gate| gate.refusal_at(gate.now_ms()));
        let cause = match refusal {
            Some(Refusal::ReplicationLag) => ClusterUnavailableCause::ReplicationLag,
            Some(Refusal::InstallingSnapshot) => ClusterUnavailableCause::InstallingSnapshot,
            // `None`: the gate opened after the read was refused.
            Some(Refusal::NotInContact) | None => ClusterUnavailableCause::NotInContact,
        };
        ClusterError::ReadsFenced {
            cause,
            leader_addr: self.current_leader_addr(),
        }
    }

    /// Runs `read` against the local engine on the calling thread, behind the
    /// same replication-lag check as [`Self::get`] and [`Self::scan`].
    ///
    /// [`ClusterStorageAdapter`]'s reads use this rather than the async
    /// `get`/`scan`, which hop to the Tokio blocking pool. The adapter's
    /// caller is already off the executor, so the hop bought nothing and made
    /// every read wait for a free pool thread. A backup export used to read
    /// while it held a storage write barrier, and each write that arrived
    /// meanwhile parked a pool thread on that barrier: once they filled the
    /// pool, the export's next read waited for a thread only the export could
    /// free, and the whole server stopped for good (GA audit 3 F-7). The
    /// export now reads a snapshot and holds no barrier (#643).
    fn read_inline<T>(
        &self,
        read: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Result<T, ClusterError> {
        if !self.reads_ok() {
            return Err(self.reads_fenced());
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
            return Err(self.reads_fenced());
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
            return Err(self.reads_fenced());
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

    /// A read-only snapshot of the inner engine (#643).
    ///
    /// `serve` installs a [`ClusterStorageAdapter`] as the app-layer storage
    /// handle in every topology, so the call has to reach through both
    /// wrappers, or a backup export reads the live engine (§4.9#4).
    ///
    /// # Errors
    ///
    /// The inner engine's error making the snapshot.
    pub fn read_snapshot(
        &self,
    ) -> Result<Option<Arc<dyn StorageEngine>>, crate::storage::StorageError> {
        self.inner.read_snapshot()
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
    fn cluster_id(&self) -> Option<ClusterId> {
        ClusterEngine::cluster_id(self)
    }

    fn peer_standing(&self, node: u64) -> PeerStanding {
        let Some(raft) = self.raft.as_ref() else {
            return PeerStanding::Pristine;
        };
        let metrics = raft.metrics();
        let metrics = metrics.borrow();
        let membership = metrics.membership_config.membership();
        if membership.nodes().next().is_none() {
            PeerStanding::Pristine
        } else if membership.get_node(&node).is_some() {
            PeerStanding::Member
        } else {
            // Retired IDs (`PeerStanding::Retired`) arrive with the
            // replicated retired-ID set (cluster-membership-changes 2.3).
            PeerStanding::NotAMember
        }
    }

    async fn adopt_cluster_id(&self, id: ClusterId) -> Result<ClusterId, String> {
        let identity = self
            .cluster_identity
            .as_ref()
            .ok_or("Raft not initialised")?;
        identity.adopt(id).await.map_err(|e| e.to_string())
    }

    async fn append_entries(
        &self,
        payload: &[u8],
        leader_quorum_ack_age_ms: Option<u64>,
    ) -> Result<LeaderRpcAnswer, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: AppendEntriesRequest<HearthRaftConfig> = wire::decode(payload)?;
        self.note_clock_offset(&req);
        // Dated from its arrival, before Raft handles it: the contact cannot
        // be later than the leader's state the request carries.
        let gate = self.read_gate.as_ref().ok_or("Raft not initialised")?;
        let received_ms = gate.now_ms();
        let reach = LogReach::of(&req);
        let resp = raft.append_entries(req).await.map_err(|e| e.to_string())?;
        note_append_entries(gate, received_ms, leader_quorum_ack_age_ms, reach, &resp);
        let accepted = matches!(
            resp,
            openraft::raft::AppendEntriesResponse::Success
                | openraft::raft::AppendEntriesResponse::PartialSuccess(_)
        );
        Ok(LeaderRpcAnswer {
            payload: wire::encode(&resp)?,
            accepted,
        })
    }

    async fn vote(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: VoteRequest<u64> = wire::decode(payload)?;
        let resp = raft.vote(req).await.map_err(|e| e.to_string())?;
        wire::encode(&resp)
    }

    async fn install_snapshot(&self, payload: &[u8]) -> Result<LeaderRpcAnswer, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: InstallSnapshotRequest<HearthRaftConfig> =
            wire::decode::<wire::WireInstallSnapshot>(payload)?.into();
        let sender_vote = req.vote;
        let resp = raft
            .install_snapshot(req)
            .await
            .map_err(|e| e.to_string())?;
        // openraft answers a chunk with its own vote, and refuses one whose
        // sender's vote is below it.
        let accepted = sender_vote >= resp.vote;
        Ok(LeaderRpcAnswer {
            payload: wire::encode(&resp)?,
            accepted,
        })
    }

    async fn forward_write(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let outcome = self.serve_forwarded_write(payload).await;
        wire::encode(&outcome)
    }
}

/// Initialises a cluster with `members` under this node's cluster ID. A node
/// without one generates it and writes it to `raft.db` first, so no node
/// ever leads a cluster whose ID it could lose in a crash
/// (`cluster-membership-changes` design decision 5). Returns the ID.
///
/// Writes nothing on a node that is initialised already (a node of a
/// cluster an older release formed holds no cluster ID, and its leader sends
/// none: an ID written now would make it refuse its leader), nor on a node
/// other than `members`' lowest ID. openraft lets several nodes initialise
/// the same membership, and they used to converge; under cluster IDs each
/// would hold its own and refuse the others for ever.
async fn initialize_with_cluster_id(
    raft: &openraft::Raft<HearthRaftConfig>,
    identity: &ClusterIdentity,
    node_id: u64,
    members: BTreeMap<u64, HearthNode>,
) -> Result<ClusterId, ClusterError> {
    let initialised = raft
        .is_initialized()
        .await
        .map_err(|e| ClusterError::Raft(e.to_string()))?;
    if initialised {
        return Err(ClusterError::AlreadyInitialized(
            "this node already holds a Raft log or vote".to_string(),
        ));
    }
    if let Some(&designated) = members.keys().next() {
        if designated != node_id {
            return Err(ClusterError::NotTheInitialiser { designated });
        }
    }
    let cluster_id = identity
        .adopt(ClusterId::random())
        .await
        .map_err(|e| ClusterError::Raft(format!("cannot persist the cluster ID: {e}")))?;
    raft.initialize(members).await.map_err(|e| match e {
        RaftError::APIError(openraft::error::InitializeError::NotAllowed(not_allowed)) => {
            ClusterError::AlreadyInitialized(not_allowed.to_string())
        }
        other => ClusterError::Raft(other.to_string()),
    })?;
    Ok(cluster_id)
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
             install cleared it): it cannot be restarted in place, and the older build cannot \
             restart it either. Do not move its data directory aside to bring the node back \
             with an empty one under the same node id: raft.db holds this node's Raft vote, \
             and a node that forgets its vote can help elect a second leader in one term \
             (docs/dev/CONSISTENCY.md G9). Rebuild the cluster from the backup taken before \
             the upgrade, which also works when no node can start (every node's log was \
             purged, as in the full-cluster restart this release requires). Restore it \
             offline with `hearth backup restore` into one empty data \
             directory and copy that directory to every node before the new cluster first \
             starts; restoring into a cluster that has already started leaves every realm \
             empty under a new id (see the upgrading guide, \"Upgrading a cluster whose Raft \
             logs were purged\")",
            purged.index
        ))),
    }
}

/// Every 50 ms: sets the read gate's lag hold, and refreshes a leader's
/// contact, from the Raft metrics. Exits when the Raft instance shuts down.
async fn run_lag_monitor(
    raft: openraft::Raft<HearthRaftConfig>,
    gate: Arc<ReadGate>,
    threshold_ms: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
    let mut metrics = raft.metrics();
    // When the previous poll began. Every report seen as new now was made
    // after it.
    let mut previous_poll_ms: Option<u64> = None;
    let mut was_lagging = false;
    loop {
        interval.tick().await;
        // Read before the metrics, so it is a lower bound for any report the
        // next poll sees as new.
        let poll_ms = gate.now_ms();
        let Ok(fresh) = metrics.has_changed() else {
            return;
        };
        let (tick, lagging) = {
            let m = metrics.borrow_and_update();
            let tick = MonitorTick {
                lag_ms: compute_lag_ms(&m),
                contact: leader_contact(
                    m.id,
                    m.current_leader,
                    m.millis_since_quorum_ack,
                    m.membership_config.membership().voter_ids().count(),
                    threshold_ms,
                ),
                quorum_ack_ago_ms: m.millis_since_quorum_ack,
                reported_after_ms: previous_poll_ms.filter(|_| fresh),
                now_ms: poll_ms,
            };
            let lagging = apply_monitor_tick(&gate, &tick, threshold_ms);
            (tick, lagging)
        };
        previous_poll_ms = Some(poll_ms);
        if lagging && !was_lagging {
            warn!(
                lag_ms = tick.lag_ms,
                threshold_ms, "replication lag exceeds threshold — reads refused on this node"
            );
        }
        was_lagging = lagging;
    }
}

/// The oldest leader quorum acknowledgement for which a follower still counts
/// an `AppendEntries` as contact (see [`note_append_entries`]): the leader
/// lease (openraft's `leader_lease`, equal to [`ELECTION_TIMEOUT_MAX_MS`])
/// less 1 s for the network delay between the leader's clock and this node's.
///
/// A voter that acknowledged a leader refuses to vote for another until the
/// lease runs out, so no other leader can acknowledge a write before the
/// deposed one's last quorum acknowledgement plus the lease. A follower that
/// stops counting it earlier serves no state older than that.
const MAX_LEADER_ACK_AGE_MS: u64 = ELECTION_TIMEOUT_MAX_MS - 1_000;

/// Records a follower's contact when it accepted an `AppendEntries` that
/// arrived at `received_ms` ([`accepted_through_commit`]), from a leader a
/// quorum acknowledged `leader_quorum_ack_age_ms` before it sent the request.
///
/// The highest term this node knows can be stale: a leader cut off from its
/// quorum together with this node goes on sending heartbeats while the
/// majority elects another leader and acknowledges writes. So a request
/// counts only when its leader had a quorum acknowledgement less than
/// [`MAX_LEADER_ACK_AGE_MS`] before it sent it. A request with no age (no
/// acknowledgement on record, or an older build) is no contact.
fn note_append_entries(
    gate: &ReadGate,
    received_ms: u64,
    leader_quorum_ack_age_ms: Option<u64>,
    reach: LogReach,
    resp: &openraft::raft::AppendEntriesResponse<u64>,
) {
    let leader_acked = leader_quorum_ack_age_ms.is_some_and(|age| age < MAX_LEADER_ACK_AGE_MS);
    if leader_acked && accepted_through_commit(reach, resp) {
        gate.record_contact_once_applied(received_ms, reach.leader_commit);
    }
}

/// How far an `AppendEntries` request reaches, by log index.
#[derive(Debug, Clone, Copy)]
struct LogReach {
    /// The leader's commit index when it sent the request.
    leader_commit: Option<u64>,
    /// The request's last log id: its last entry, or `prev_log_id` when it
    /// carries none.
    last: Option<u64>,
}

impl LogReach {
    fn of(req: &AppendEntriesRequest<HearthRaftConfig>) -> Self {
        Self {
            leader_commit: req.leader_commit.map(|id| id.index),
            last: req
                .entries
                .last()
                .map(|entry| entry.log_id.index)
                .or(req.prev_log_id.map(|id| id.index)),
        }
    }
}

/// Whether a follower that answered `resp` to a request of `reach` now holds
/// every entry the leader had committed when it sent it.
///
/// openraft answers `Success` or `PartialSuccess` only to the leader of the
/// highest term this node knows, and only when the request's log matched. A
/// `Conflict` (log mismatch) or a `HigherVote` (a stale leader) is no
/// contact. A matching log is not the leader's whole log either: a heartbeat
/// to a follower that is behind, or one catch-up batch, ends before the
/// leader's commit index, so it is no contact. In steady state every request
/// ends at the leader's last log, so this costs nothing.
fn accepted_through_commit(
    reach: LogReach,
    resp: &openraft::raft::AppendEntriesResponse<u64>,
) -> bool {
    use openraft::raft::AppendEntriesResponse as R;
    let accepted_last = match resp {
        R::Success => reach.last,
        R::PartialSuccess(matching) => matching.map(|id| id.index),
        R::Conflict | R::HigherVote(_) => return false,
    };
    match (reach.leader_commit, accepted_last) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(commit), Some(last)) => last >= commit,
    }
}

/// What one lag-monitor poll read from the Raft metrics.
#[derive(Debug, Clone, Copy)]
struct MonitorTick {
    /// [`compute_lag_ms`] of the metrics.
    lag_ms: u64,
    /// The node's contact as a leader.
    contact: LeaderContact,
    /// `millis_since_quorum_ack` of the metrics, threshold or not.
    quorum_ack_ago_ms: Option<u64>,
    /// A time before the metrics were reported, in read-gate milliseconds,
    /// or `None` when that is not known (the metrics did not change since
    /// the previous poll, or this is the first). openraft computes
    /// `millis_since_quorum_ack` when it reports, so the age is measured
    /// from the report, not from the poll.
    reported_after_ms: Option<u64>,
    /// When the poll began, in read-gate milliseconds.
    now_ms: u64,
}

/// Applies one lag-monitor poll to the read gate. Returns whether the apply
/// lag holds reads.
///
/// A leader's quorum acknowledgement is dated from `reported_after_ms`, which
/// is never later than the report, so the deadline is never later than the
/// acknowledgement plus the threshold. A poll that cannot date the report
/// leaves the deadline as it is. The same date is recorded as the leader's
/// quorum acknowledgement, which its heartbeats carry to its followers; a
/// node that does not lead has none.
fn apply_monitor_tick(gate: &ReadGate, tick: &MonitorTick, threshold_ms: u64) -> bool {
    let lagging = !reads_allowed_for_lag(tick.lag_ms, threshold_ms);
    gate.set_lag_hold(lagging);
    match tick.contact {
        LeaderContact::SoleVoter => {
            gate.record_contact_at(tick.now_ms);
            gate.record_quorum_ack_at(tick.now_ms);
        }
        LeaderContact::AckedAgo { ms } => {
            if let Some(reported_after) = tick.reported_after_ms {
                gate.record_contact_at(reported_after.saturating_sub(ms));
            }
        }
        LeaderContact::NotLeader => gate.clear_quorum_ack(),
        LeaderContact::OutOfContact => {}
    }
    if matches!(
        tick.contact,
        LeaderContact::AckedAgo { .. } | LeaderContact::OutOfContact
    ) {
        if let (Some(ago), Some(reported_after)) = (tick.quorum_ack_ago_ms, tick.reported_after_ms)
        {
            gate.record_quorum_ack_at(reported_after.saturating_sub(ago));
        }
    }
    lagging
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

/// The decision of [`ClusterEngine::not_ready_reason`], from the Raft
/// metrics of node `id`. A sole voter is its own quorum.
fn leader_gap(
    id: u64,
    current_leader: Option<u64>,
    millis_since_quorum_ack: Option<u64>,
    voters: usize,
) -> Option<&'static str> {
    match current_leader {
        None => Some("no_leader"),
        Some(leader) if leader == id && voters > 1 => match millis_since_quorum_ack {
            Some(ms) if ms <= ELECTION_TIMEOUT_MAX_MS => None,
            _ => Some("no_quorum"),
        },
        Some(_) => None,
    }
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
///
/// On a single node, at most `max_writes_in_flight` writes are in progress
/// at once (#596). A write over the limit is refused before it starts with
/// [`ClusterUnavailableCause::WriteLimit`](crate::storage::ClusterUnavailableCause::WriteLimit),
/// a `503` with `Retry-After` at the HTTP layer. A wait for a write that is
/// already queued ([`StorageEngine::await_batch_durable`]) counts toward the
/// limit but is never refused. An audit-only batch
/// ([`StorageEngine::enqueue_audit_batch`]) is admitted up to twice the limit
/// (#836).
pub struct ClusterStorageAdapter {
    engine: Arc<ClusterEngine>,
    /// Single-node writes in progress, and waits for queued writes.
    writes_in_flight: AtomicUsize,
    /// The most single-node writes that may be in progress at once.
    max_writes_in_flight: usize,
}

impl ClusterStorageAdapter {
    /// Wraps a [`ClusterEngine`] for use as [`StorageEngine`], with the
    /// default write limit ([`DEFAULT_MAX_WRITES_IN_FLIGHT`]).
    pub fn new(engine: Arc<ClusterEngine>) -> Self {
        Self::with_max_writes_in_flight(engine, DEFAULT_MAX_WRITES_IN_FLIGHT)
    }

    /// Wraps a [`ClusterEngine`] with a single-node write limit of `max`
    /// (`storage.max_writes_in_flight`) and publishes it to
    /// `hearth_storage_write_permits`. A `max` of `0` is clamped to `1`: a
    /// limit that admits nothing would refuse every write.
    pub fn with_max_writes_in_flight(engine: Arc<ClusterEngine>, max: usize) -> Self {
        let max = max.max(1);
        #[allow(clippy::cast_precision_loss)]
        crate::metrics::metrics()
            .storage_write_permits
            .set(max as f64);
        Self {
            engine,
            writes_in_flight: AtomicUsize::new(0),
            max_writes_in_flight: max,
        }
    }

    /// Takes a place while fewer than `ceiling` writes are in progress, or
    /// `None` when `ceiling` writes are in progress.
    fn try_start_write(&self, ceiling: usize) -> Option<WriteInFlight<'_>> {
        // Rust 1.99 renamed `fetch_update` to `try_update`; the MSRV (1.88)
        // has only the old name.
        #[allow(deprecated)]
        self.writes_in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < ceiling).then_some(n + 1)
            })
            .ok()?;
        Some(WriteInFlight::counted(&self.writes_in_flight))
    }

    /// The most single-node writes in progress at which an audit batch is
    /// still admitted: twice the write limit (#836). See
    /// [`StorageEngine::enqueue_audit_batch`].
    fn audit_write_ceiling(&self) -> usize {
        self.max_writes_in_flight.saturating_mul(2)
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
    ///
    /// A write over the write limit is refused before `block_in_place`: it
    /// takes no thread and writes nothing (#596).
    fn single_node_write<T>(
        &self,
        write: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Option<Result<T, crate::storage::StorageError>> {
        self.single_node_write_below(self.max_writes_in_flight, write)
    }

    /// [`Self::single_node_write`], admitted while fewer than `ceiling`
    /// writes are in progress.
    fn single_node_write_below<T>(
        &self,
        ceiling: usize,
        write: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Option<Result<T, crate::storage::StorageError>> {
        if self.engine.raft.is_some() {
            return None;
        }
        let Some(_in_flight) = self.try_start_write(ceiling) else {
            crate::metrics::metrics().storage_writes_shed_total.inc();
            return Some(Err(crate::storage::StorageError::ClusterUnavailable {
                cause: crate::storage::ClusterUnavailableCause::WriteLimit,
                reason: format!(
                    "{ceiling} single-node writes already in progress (storage.max_writes_in_flight)"
                ),
            }));
        };
        Some(tokio::task::block_in_place(|| write(&self.engine.inner)))
    }

    /// A point read of the local engine (see `ClusterEngine::read_inline`).
    ///
    /// Single node: on the calling thread, without `block_in_place` (#581). A
    /// point read is a lookup in memory or in a mapped SST and takes no lock.
    /// On a runtime worker, each `block_in_place` hands the worker's other
    /// tasks to a blocking-pool thread, and point reads are most of the
    /// adapter's calls: the hand-offs kept the pool's threads in use, so the
    /// pool did not shrink after a burst. Cluster: inside `block_in_place`, as
    /// before.
    fn point_read<T>(
        &self,
        read: impl FnOnce(&EmbeddedStorageEngine) -> Result<T, crate::storage::StorageError>,
    ) -> Result<T, crate::storage::StorageError> {
        if self.engine.raft.is_none() {
            return self
                .engine
                .read_inline(read)
                .map_err(cluster_to_storage_err);
        }
        tokio::task::block_in_place(|| self.engine.read_inline(read))
            .map_err(cluster_to_storage_err)
    }
}

/// One write counted in [`ClusterStorageAdapter`]'s write limit; the count
/// goes down when it drops, also on an error or a panic.
struct WriteInFlight<'a>(&'a AtomicUsize);

impl<'a> WriteInFlight<'a> {
    /// Wraps a count that the caller already took.
    fn counted(count: &'a AtomicUsize) -> Self {
        crate::metrics::metrics().storage_writes_in_flight.inc();
        Self(count)
    }
}

impl Drop for WriteInFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
        crate::metrics::metrics().storage_writes_in_flight.dec();
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
        ClusterError::ReadsFenced { cause, .. } => unavailable(cause, &e),
        ClusterError::WriteTimeout { .. }
        | ClusterError::ForwardOutcomeUnknown { .. }
        | ClusterError::NotAppliedLocally { .. } => StorageError::ClusterWriteOutcomeUnknown {
            reason: format!("raft: {e}"),
        },
        e @ (ClusterError::CommandTooLarge { .. }
        | ClusterError::ForwardRejected { .. }
        | ClusterError::AlreadyInitialized(_)
        | ClusterError::NotTheInitialiser { .. }) => {
            StorageError::Io(std::io::Error::other(format!("raft: {e}")))
        }
        ClusterError::Raft(msg) => StorageError::Io(std::io::Error::other(format!("raft: {msg}"))),
    }
}

impl StorageEngine for ClusterStorageAdapter {
    fn accepts_writes(&self) -> bool {
        self.engine.accepts_writes()
    }

    /// The read gate's answer: one atomic load and a monotonic clock read.
    fn serves_reads(&self) -> Result<(), crate::storage::StorageError> {
        if self.engine.reads_ok() {
            Ok(())
        } else {
            Err(cluster_to_storage_err(self.engine.reads_fenced()))
        }
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
    /// [`Self::point_read`]).
    fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
        self.point_read(|inner| inner.get(realm_id, key))
    }

    /// Forwarded so the inner engine's non-caching read runs; the trait
    /// default is a caching `get` (#445).
    fn get_uncached(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
        self.point_read(|inner| inner.get_uncached(realm_id, key))
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

    /// Forwarded so the inner engine's streaming key merge runs; the trait
    /// default collects the range through [`Self::scan_keys`] first (#447).
    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> std::ops::ControlFlow<()>,
    ) -> Result<(), crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.visit_keys(realm_id, start, end, visit))
        })
        .map_err(cluster_to_storage_err)
    }

    /// Forwarded so the inner engine's streaming entry merge runs; the trait
    /// default collects the range through [`Self::scan`] first (#445).
    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut crate::storage::EntryVisitor<'_>,
    ) -> Result<(), crate::storage::StorageError> {
        tokio::task::block_in_place(|| {
            self.engine
                .read_inline(|inner| inner.visit_entries(realm_id, start, end, visit))
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

    /// Forwarded in single-node mode so the inner engine's WAL group commit
    /// runs: the caller (the audit engine, under its realm chain lock) gets a
    /// pending handle back and waits for the fsync after it drops the lock,
    /// so concurrent audited writes share one fsync. The trait default is a
    /// full `put_batch`, fsync included, inside the caller's lock. In cluster
    /// mode a write is a Raft proposal, durable when it returns, so the
    /// default is right there.
    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<crate::storage::StorageDurabilityHandle, crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| inner.enqueue_batch(realm_id, entries)) {
            return done;
        }
        self.put_batch(realm_id, entries)?;
        Ok(crate::storage::StorageDurabilityHandle(
            crate::storage::StorageDurabilityHandleKind::Immediate,
        ))
    }

    /// [`Self::enqueue_batch`] for an audit-only batch. Single node: admitted
    /// while fewer than twice `max_writes_in_flight` writes are in progress
    /// (#836). Cluster mode: the same Raft proposal as `enqueue_batch`.
    fn enqueue_audit_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<crate::storage::StorageDurabilityHandle, crate::storage::StorageError> {
        if let Some(done) = self.single_node_write_below(self.audit_write_ceiling(), |inner| {
            inner.enqueue_batch(realm_id, entries)
        }) {
            return done;
        }
        self.enqueue_batch(realm_id, entries)
    }

    /// Forwarded to the inner engine, which issued the handle; see
    /// [`Self::enqueue_batch`]. A cluster-mode handle is `Immediate`, a no-op.
    ///
    /// Single node: the wait counts toward the write limit, so the writes
    /// that wait for one fsync cannot pass it, but it is never refused: the
    /// batch is already queued, and only a wait commits it (#596).
    fn await_batch_durable(
        &self,
        handle: crate::storage::StorageDurabilityHandle,
    ) -> Result<(), crate::storage::StorageError> {
        let _in_flight = self.engine.raft.is_none().then(|| {
            self.writes_in_flight.fetch_add(1, Ordering::SeqCst);
            WriteInFlight::counted(&self.writes_in_flight)
        });
        tokio::task::block_in_place(|| self.engine.inner.await_batch_durable(handle))
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

    fn read_snapshot(
        &self,
    ) -> Result<Option<Arc<dyn StorageEngine>>, crate::storage::StorageError> {
        self.engine.read_snapshot()
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

    /// Single node: one atomic WAL record of the local engine, admitted under
    /// the write limit like [`Self::enqueue_batch`]: a refused call writes
    /// nothing, neither the guard nor `entries` (#890). Cluster mode: the
    /// trait default's two proposals, a `PutIfAbsent` of the guard and then a
    /// `Batch` of `entries`.
    fn enqueue_batch_if_absent(
        &self,
        realm_id: &RealmId,
        guard_key: &[u8],
        guard_value: &[u8],
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Option<crate::storage::StorageDurabilityHandle>, crate::storage::StorageError> {
        if let Some(done) = self.single_node_write(|inner| {
            inner.enqueue_batch_if_absent(realm_id, guard_key, guard_value, entries)
        }) {
            return done;
        }
        if !self.put_if_absent(realm_id, guard_key, guard_value)? {
            return Ok(None);
        }
        self.enqueue_batch(realm_id, entries).map(Some)
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
    /// openraft's 200 ms default bounds the answer to a snapshot's last
    /// chunk, which comes after the follower checked and restored it, so a
    /// large install always timed out (`cluster-file-snapshots`).
    #[test]
    fn a_snapshot_install_may_take_minutes() {
        let config = super::raft_config().validate().expect("valid config");
        assert_eq!(
            config.install_snapshot_timeout(),
            std::time::Duration::from_secs(15 * 60)
        );
        assert_eq!(config.snapshot_max_chunk_size, super::SNAPSHOT_CHUNK_BYTES);
    }

    use super::*;

    use openraft::{CommittedLeaderId, LogId, ServerState, StoredMembership, Vote};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn make_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    /// `/readyz` readiness from the Raft metrics: a follower needs a known
    /// leader; a leader needs a quorum acknowledgement within the election
    /// timeout, unless it is the only voter.
    #[test]
    fn leader_gap_requires_a_leader_and_a_leader_requires_a_recent_quorum() {
        // Follower.
        assert_eq!(leader_gap(2, Some(1), None, 3), None);
        assert_eq!(leader_gap(2, None, None, 3), Some("no_leader"));
        // Leader with a fresh, a borderline and a stale quorum ack.
        assert_eq!(leader_gap(1, Some(1), Some(0), 3), None);
        assert_eq!(
            leader_gap(1, Some(1), Some(ELECTION_TIMEOUT_MAX_MS), 3),
            None
        );
        assert_eq!(
            leader_gap(1, Some(1), Some(ELECTION_TIMEOUT_MAX_MS + 1), 3),
            Some("no_quorum")
        );
        // Leader never acknowledged (restarted on its own committed vote).
        assert_eq!(leader_gap(1, Some(1), None, 3), Some("no_quorum"));
        // A sole voter is its own quorum.
        assert_eq!(leader_gap(1, Some(1), None, 1), None);
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
        assert!(msg.contains("5000"), "{msg}");
        // `raft.db` holds the node's Raft vote: a node started empty under its
        // old id forgets it, which Raft's safety proof does not allow
        // (docs/dev/CONSISTENCY.md G9). The refusal used to tell the operator
        // to do exactly that (#670).
        assert!(
            !msg.contains("start it empty") && !msg.contains("Re-seed"),
            "the refusal must not tell the operator to start the node empty: {msg}"
        );
        assert!(
            msg.contains("raft.db") && msg.contains("vote") && msg.contains("G9"),
            "the refusal must say why the node must not start empty: {msg}"
        );
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

    // ── The read gate (cluster-read-fencing 1.1) ──────────────────────────────

    /// Task 2.1: `StorageEngine::serves_reads` is the gate the identity
    /// engine checks before it serves a credential from a cache. It never
    /// refuses on single-node storage, and follows the gate on a cluster node.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn serves_reads_follows_the_read_gate_only_on_a_cluster_node() {
        let dir = tempdir().unwrap();
        let local = open_engine(dir.path());
        let ok = |s: &dyn StorageEngine| s.serves_reads().map_err(|e| e.to_string());
        assert_eq!(ok(local.as_ref()), Ok(()));
        let single =
            ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(Arc::clone(&local))));
        assert_eq!(ok(&single), Ok(()));

        let gate = Arc::new(ReadGate::new(60_000));
        let clustered = ClusterStorageAdapter::new(Arc::new(ClusterEngine::with_read_gate(
            local,
            Arc::clone(&gate),
        )));
        let refused = clustered.serves_reads().unwrap_err();
        assert!(
            matches!(
                refused,
                crate::storage::StorageError::ClusterUnavailable {
                    cause: ClusterUnavailableCause::NotInContact,
                    ..
                }
            ),
            "{refused:?}"
        );
        gate.record_contact_at(gate.now_ms());
        assert_eq!(ok(&clustered), Ok(()));
    }

    /// `/readyz` reports a node whose read gate is closed as not ready, with
    /// the gate's reason (task 4.1).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_closed_read_gate_makes_the_node_not_ready() {
        let dir = tempdir().unwrap();
        let gate = Arc::new(ReadGate::new(60_000));
        let engine = ClusterEngine::with_read_gate(open_engine(dir.path()), Arc::clone(&gate));
        assert_eq!(engine.not_ready_reason(), Some("not_in_contact"));
        gate.record_contact_at(gate.now_ms());
        assert_eq!(engine.not_ready_reason(), None);
        gate.set_lag_hold(true);
        assert_eq!(engine.not_ready_reason(), Some("replication_lag"));
        gate.begin_install();
        assert_eq!(engine.not_ready_reason(), Some("installing_snapshot"));
    }

    /// A node whose gate is closed refuses a read with `NotInContact`, and a
    /// contact opens it again. The refusal reaches the storage facade as
    /// `ClusterUnavailable`, which the protocol layer answers `503`.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_closed_read_gate_refuses_reads_as_not_in_contact() {
        let dir = tempdir().unwrap();
        let gate = Arc::new(ReadGate::new(60_000));
        let engine = Arc::new(ClusterEngine::with_read_gate(
            open_engine(dir.path()),
            Arc::clone(&gate),
        ));
        let adapter = ClusterStorageAdapter::new(Arc::clone(&engine));
        let realm = make_realm();

        let refused = adapter.get(&realm, b"k").unwrap_err();
        assert!(
            matches!(
                refused,
                crate::storage::StorageError::ClusterUnavailable {
                    cause: ClusterUnavailableCause::NotInContact,
                    ..
                }
            ),
            "{refused:?}"
        );

        gate.record_contact_at(gate.now_ms());
        assert_eq!(adapter.get(&realm, b"k").unwrap(), None);

        gate.close();
        assert!(adapter.get(&realm, b"k").is_err_and(|e| matches!(
            e,
            crate::storage::StorageError::ClusterUnavailable {
                cause: ClusterUnavailableCause::NotInContact,
                ..
            }
        )));

        gate.begin_install();
        assert!(adapter.get(&realm, b"k").is_err_and(|e| matches!(
            e,
            crate::storage::StorageError::ClusterUnavailable {
                cause: ClusterUnavailableCause::InstallingSnapshot,
                ..
            }
        )));
    }

    /// Task 1.2: an apply lag above `read_lag_threshold_ms` closes the gate
    /// at once, although the node is in contact; a lag at or below it
    /// leaves the gate to the contact.
    #[test]
    fn an_apply_lag_above_the_threshold_closes_the_gate() {
        let gate = ReadGate::new(500);
        gate.record_contact_at(1_000);

        let tick = |lag_ms| MonitorTick {
            lag_ms,
            contact: LeaderContact::NotLeader,
            quorum_ack_ago_ms: None,
            reported_after_ms: None,
            now_ms: 1_001,
        };

        // 101 unapplied entries × 5 ms = 505 ms > 500 ms.
        let lagging = compute_lag_ms(&make_metrics(Some(101), Some(0)));
        assert!(apply_monitor_tick(&gate, &tick(lagging), 500), "lagging");
        assert!(!gate.allows_at(1_001));

        // 100 × 5 ms = 500 ms: at the threshold, not above it.
        let caught_up = compute_lag_ms(&make_metrics(Some(100), Some(0)));
        assert!(
            !apply_monitor_tick(&gate, &tick(caught_up), 500),
            "not lagging"
        );
        assert!(gate.allows_at(1_001), "the contact was kept");
    }

    /// Task 1.3: a leader's quorum acknowledgement keeps the gate open for
    /// the threshold, dated no later than the metrics report that carried it.
    #[test]
    fn a_leader_acked_within_the_threshold_extends_the_deadline() {
        let gate = ReadGate::new(500);
        let tick = MonitorTick {
            lag_ms: 0,
            contact: LeaderContact::AckedAgo { ms: 100 },
            quorum_ack_ago_ms: Some(100),
            reported_after_ms: Some(1_000),
            now_ms: 1_050,
        };
        assert!(!apply_monitor_tick(&gate, &tick, 500));
        // Acknowledged at or after 1_000 - 100 = 900: open until 1_400.
        assert!(gate.allows_at(1_399));
        assert!(!gate.allows_at(1_400));
    }

    /// A report the monitor cannot date (unchanged since the previous poll,
    /// or the first poll) leaves the deadline as it is: openraft computes
    /// `millis_since_quorum_ack` when it reports, so an old report's age
    /// understates the real one.
    #[test]
    fn an_undated_leader_report_moves_no_deadline() {
        let gate = ReadGate::new(500);
        let tick = MonitorTick {
            lag_ms: 0,
            contact: LeaderContact::AckedAgo { ms: 0 },
            quorum_ack_ago_ms: Some(0),
            reported_after_ms: None,
            now_ms: 1_000,
        };
        apply_monitor_tick(&gate, &tick, 500);
        assert!(!gate.allows_at(1_000));
    }

    /// A leader no quorum acknowledged within the threshold is out of
    /// contact: its deadline runs out. A sole voter is always in contact.
    #[test]
    fn a_leader_out_of_contact_lets_its_deadline_run_out_and_a_sole_voter_never_does() {
        let gate = ReadGate::new(500);
        gate.record_contact_at(1_000);
        let out = MonitorTick {
            lag_ms: 0,
            contact: LeaderContact::OutOfContact,
            quorum_ack_ago_ms: None,
            reported_after_ms: Some(1_400),
            now_ms: 1_450,
        };
        apply_monitor_tick(&gate, &out, 500);
        assert!(!gate.allows_at(1_500));

        let sole = MonitorTick {
            lag_ms: 0,
            contact: LeaderContact::SoleVoter,
            quorum_ack_ago_ms: None,
            reported_after_ms: None,
            now_ms: 2_000,
        };
        apply_monitor_tick(&gate, &sole, 500);
        assert!(gate.allows_at(2_000));
    }

    /// Task 1.4: an `AppendEntries` that openraft accepted (`Success`, or
    /// `PartialSuccess`) came from the leader of the highest term this node
    /// knows, and its log matched: contact from its arrival. A refused one
    /// (`Conflict`: log mismatch; `HigherVote`: a stale leader) is none.
    #[test]
    fn an_accepted_append_entries_is_contact_and_a_refused_one_is_not() {
        use openraft::raft::AppendEntriesResponse as R;

        let gate = ReadGate::new(500);
        gate.note_applied(7);
        let reach = LogReach::of(&append_request(Some(7), &[], Some(7)));
        let age = Some(100);
        note_append_entries(&gate, 1_000, age, reach, &R::Conflict);
        note_append_entries(&gate, 1_000, age, reach, &R::HigherVote(Vote::new(9, 9)));
        assert!(!gate.allows_at(1_000), "refused requests are no contact");

        note_append_entries(&gate, 1_000, age, reach, &R::Success);
        assert!(gate.allows_at(1_499));
        assert!(!gate.allows_at(1_500), "dated from its arrival");

        note_append_entries(
            &gate,
            2_000,
            age,
            reach,
            &R::PartialSuccess(Some(log_id(7))),
        );
        assert!(gate.allows_at(2_499));
    }

    fn log_id(index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 1), index)
    }

    fn append_request(
        prev: Option<u64>,
        entries: &[u64],
        commit: Option<u64>,
    ) -> AppendEntriesRequest<HearthRaftConfig> {
        AppendEntriesRequest {
            vote: Vote::new_committed(1, 1),
            prev_log_id: prev.map(log_id),
            entries: entries
                .iter()
                .map(|&i| openraft::Entry {
                    log_id: log_id(i),
                    payload: EntryPayload::Blank,
                })
                .collect(),
            leader_commit: commit.map(log_id),
        }
    }

    /// Task 1.4: a follower that accepts a heartbeat or a catch-up batch
    /// that ends before the leader's commit index holds only a prefix of
    /// what the leader committed (Jepsen `staleness` on the 2026-10-07
    /// branch): that is no contact, whatever its apply lag.
    #[test]
    fn an_accepted_append_entries_counts_only_when_it_reaches_the_leader_commit() {
        use openraft::raft::AppendEntriesResponse as R;
        let ok = |prev, entries: &[u64], commit, resp: &R<u64>| {
            accepted_through_commit(LogReach::of(&append_request(prev, entries, commit)), resp)
        };
        assert!(
            ok(Some(10), &[], Some(10), &R::Success),
            "a heartbeat at the commit"
        );
        assert!(ok(Some(10), &[11, 12], Some(11), &R::Success));
        assert!(ok(None, &[], None, &R::Success), "nothing committed yet");
        assert!(
            !ok(Some(10), &[], Some(11), &R::Success),
            "a heartbeat behind the commit"
        );
        assert!(
            !ok(Some(10), &[11, 12], Some(20), &R::Success),
            "a batch short of the commit"
        );
        assert!(!ok(None, &[], Some(1), &R::Success));
        assert!(
            ok(
                Some(10),
                &[11, 12],
                Some(11),
                &R::PartialSuccess(Some(log_id(11)))
            ),
            "accepted through the commit"
        );
        assert!(
            !ok(
                Some(10),
                &[11, 12],
                Some(12),
                &R::PartialSuccess(Some(log_id(11)))
            ),
            "accepted short of the commit"
        );
        assert!(!ok(Some(10), &[], Some(10), &R::Conflict));
        assert!(!ok(
            Some(10),
            &[],
            Some(10),
            &R::HigherVote(Vote::new(9, 9))
        ));
    }

    /// Task 1.7: an accepted `AppendEntries` counts only once this node has
    /// applied the leader's commit index, dated from its arrival.
    #[test]
    fn an_append_entries_counts_once_its_commit_index_is_applied() {
        use openraft::raft::AppendEntriesResponse as R;
        let gate = ReadGate::new(500);
        gate.note_applied(5);
        let reach = LogReach::of(&append_request(Some(7), &[], Some(7)));
        note_append_entries(&gate, 1_000, Some(100), reach, &R::Success);
        assert!(!gate.allows_at(1_000), "index 7 is not applied yet");
        gate.note_applied(7);
        assert!(gate.allows_at(1_000));
        assert!(!gate.allows_at(1_500), "dated from the arrival");
    }

    /// Task 1.6: a deposed leader cut off with this follower. Its heartbeats
    /// are accepted (the follower knows no higher term), but no quorum has
    /// acknowledged it for longer than the lease allows.
    #[test]
    fn an_append_entries_from_a_leader_without_a_recent_quorum_is_no_contact() {
        use openraft::raft::AppendEntriesResponse as R;
        let gate = ReadGate::new(500);
        gate.note_applied(7);
        let reach = LogReach::of(&append_request(Some(7), &[], Some(7)));
        note_append_entries(
            &gate,
            1_000,
            Some(MAX_LEADER_ACK_AGE_MS),
            reach,
            &R::Success,
        );
        assert!(!gate.allows_at(1_000), "an acknowledgement too old");
        note_append_entries(&gate, 1_000, None, reach, &R::Success);
        assert!(!gate.allows_at(1_000), "no acknowledgement on record");
        note_append_entries(
            &gate,
            1_000,
            Some(MAX_LEADER_ACK_AGE_MS - 1),
            reach,
            &R::Success,
        );
        assert!(gate.allows_at(1_000), "an acknowledgement within the lease");
        assert_eq!(MAX_LEADER_ACK_AGE_MS, 2_000);
    }

    /// A leader records its quorum acknowledgement for its heartbeats to
    /// carry, also above the read threshold; a node that does not lead
    /// forgets it.
    #[test]
    fn a_leader_records_its_quorum_ack_and_a_follower_forgets_it() {
        let gate = ReadGate::new(500);
        let tick = |contact, quorum_ack_ago_ms, reported_after| MonitorTick {
            lag_ms: 0,
            contact,
            quorum_ack_ago_ms,
            reported_after_ms: Some(reported_after),
            now_ms: reported_after + 50,
        };
        apply_monitor_tick(
            &gate,
            &tick(LeaderContact::AckedAgo { ms: 100 }, Some(100), 9_950),
            500,
        );
        assert_eq!(gate.quorum_ack_age_at(10_000), Some(150));
        apply_monitor_tick(
            &gate,
            &tick(LeaderContact::OutOfContact, Some(900), 10_950),
            500,
        );
        assert_eq!(gate.quorum_ack_age_at(11_000), Some(950));
        apply_monitor_tick(&gate, &tick(LeaderContact::NotLeader, None, 11_950), 500);
        assert_eq!(gate.quorum_ack_age_at(12_000), None);
    }

    /// While `serve` starts, reads skip the contact check; once the guard
    /// drops, a read needs contact again.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn start_up_reads_skip_the_contact_check_until_the_guard_drops() {
        let dir = tempdir().unwrap();
        let gate = Arc::new(ReadGate::new(60_000));
        let engine = Arc::new(ClusterEngine::with_read_gate(
            open_engine(dir.path()),
            Arc::clone(&gate),
        ));
        let adapter = ClusterStorageAdapter::new(Arc::clone(&engine));
        let realm = make_realm();

        let guard = engine.start_up_reads();
        assert_eq!(adapter.get(&realm, b"k").unwrap(), None);
        drop(guard);
        assert!(adapter.get(&realm, b"k").is_err());
    }

    /// Single-node mode has no gate: reads never need contact.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_single_node_engine_always_serves_reads() {
        let dir = tempdir().unwrap();
        let engine = Arc::new(ClusterEngine::single_node(open_engine(dir.path())));
        assert!(engine.reads_ok());
        let _guard = engine.start_up_reads();
        assert!(engine.reads_ok());
    }

    // ── §4.9#4: the app-layer storage handle ──────────────────────────────────

    /// #581: a single-node point read runs on the calling thread, without
    /// `block_in_place`. On a runtime worker, each `block_in_place` hands the
    /// worker's other tasks to a blocking-pool thread. `block_in_place` panics
    /// on a current-thread runtime, so this test fails while a point read
    /// still calls it.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::unwrap_used)]
    async fn a_single_node_point_read_does_not_use_block_in_place() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let realm = RealmId::generate();
        inner.put(&realm, b"k", b"v").unwrap();
        let adapter = ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(inner)));

        assert_eq!(adapter.get(&realm, b"k").unwrap(), Some(b"v".to_vec()));
        assert_eq!(
            adapter.get_uncached(&realm, b"k").unwrap(),
            Some(b"v".to_vec())
        );
    }

    /// Waits until `count` single-node writes are in progress on `adapter`.
    fn wait_for_writes_in_flight(adapter: &ClusterStorageAdapter, count: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while adapter.writes_in_flight.load(Ordering::SeqCst) < count {
            assert!(
                std::time::Instant::now() < deadline,
                "{count} writes never parked"
            );
            std::thread::yield_now();
        }
    }

    /// Holds every write that reaches `inner`'s WAL until it is dropped.
    struct ParkedWrites(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

    impl ParkedWrites {
        fn install(inner: &EmbeddedStorageEngine) -> Self {
            let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let hook_gate = Arc::clone(&gate);
            inner.set_pre_wal_hook(Arc::new(move || {
                let (open, cv) = &*hook_gate;
                let mut open = open
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*open {
                    open = cv
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }));
            Self(gate)
        }
    }

    impl Drop for ParkedWrites {
        fn drop(&mut self) {
            let (open, cv) = &*self.0;
            *open
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            cv.notify_all();
        }
    }

    /// #596: on a single node, a write over the write limit is refused before
    /// it starts, so it takes no thread and writes nothing. The writes that
    /// hold the limit (here: parked before the WAL) finish, and then a write
    /// succeeds again.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_single_node_write_over_the_limit_is_refused_before_it_starts() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let parked_writes = ParkedWrites::install(&inner);
        let adapter = Arc::new(ClusterStorageAdapter::with_max_writes_in_flight(
            Arc::new(ClusterEngine::single_node(inner)),
            2,
        ));
        let realm = RealmId::generate();

        let parked: Vec<_> = (0..2u8)
            .map(|i| {
                let (adapter, realm) = (Arc::clone(&adapter), realm.clone());
                std::thread::spawn(move || adapter.put(&realm, &[b'p', i], b"v"))
            })
            .collect();
        wait_for_writes_in_flight(&adapter, 2);

        let refused = adapter.put(&realm, b"over", b"v");
        assert!(
            matches!(
                refused,
                Err(crate::storage::StorageError::ClusterUnavailable {
                    cause: crate::storage::ClusterUnavailableCause::WriteLimit,
                    ..
                })
            ),
            "a third write over a limit of 2 must be refused: {refused:?}"
        );
        assert_eq!(
            crate::storage::StorageError::retry_class_of(&refused.unwrap_err()),
            Some(crate::storage::RetryClass::Unavailable),
            "a refused write is a 503: nothing was written"
        );

        drop(parked_writes);
        for writer in parked {
            writer.join().unwrap().expect("a parked write completes");
        }
        assert_eq!(adapter.writes_in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.get(&realm, b"over").unwrap(), None);
        adapter
            .put(&realm, b"after", b"v")
            .expect("the limit is free again");
        assert_eq!(adapter.get(&realm, b"after").unwrap(), Some(b"v".to_vec()));
    }

    /// #890: a conditional batch over the write limit is refused before it
    /// starts, so neither its guard nor its entries are written: a refresh
    /// refused this way leaves its token unspent. Below the limit, the guard
    /// and the entries are written together.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_conditional_batch_over_the_limit_writes_neither_the_guard_nor_the_entries() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let parked_writes = ParkedWrites::install(&inner);
        let adapter = Arc::new(ClusterStorageAdapter::with_max_writes_in_flight(
            Arc::new(ClusterEngine::single_node(inner)),
            2,
        ));
        let realm = RealmId::generate();
        let entries = [(b"family".to_vec(), b"rotated".to_vec())];

        let parked: Vec<_> = (0..2u8)
            .map(|i| {
                let (adapter, realm) = (Arc::clone(&adapter), realm.clone());
                std::thread::spawn(move || adapter.put(&realm, &[b'p', i], b"v"))
            })
            .collect();
        wait_for_writes_in_flight(&adapter, 2);

        let refused = adapter.enqueue_batch_if_absent(&realm, b"claim", b"1", &entries);
        assert!(
            matches!(
                refused,
                Err(crate::storage::StorageError::ClusterUnavailable {
                    cause: crate::storage::ClusterUnavailableCause::WriteLimit,
                    ..
                })
            ),
            "a conditional batch over a limit of 2 must be refused: {:?}",
            refused.map(|handle| handle.is_some())
        );
        drop(parked_writes);
        for writer in parked {
            writer.join().unwrap().expect("a parked write completes");
        }
        assert_eq!(adapter.get(&realm, b"claim").unwrap(), None);
        assert_eq!(adapter.get(&realm, b"family").unwrap(), None);

        let handle = adapter
            .enqueue_batch_if_absent(&realm, b"claim", b"1", &entries)
            .expect("below the limit")
            .expect("the guard is still absent");
        adapter.await_batch_durable(handle).expect("durable");
        assert_eq!(adapter.get(&realm, b"claim").unwrap(), Some(b"1".to_vec()));
        assert_eq!(
            adapter.get(&realm, b"family").unwrap(),
            Some(b"rotated".to_vec())
        );
        assert!(
            adapter
                .enqueue_batch_if_absent(&realm, b"claim", b"2", &entries)
                .expect("a present guard is not an error")
                .is_none(),
            "a second claim loses"
        );
    }

    /// #836: an audit batch is admitted above the write limit, up to twice
    /// the limit. An audit event usually follows a write that the operation
    /// already made, so a refused audit batch lets the operation succeed
    /// without its event. Above the audit ceiling, an audit batch is refused
    /// too: the thread count stays bounded when the disk stops.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn an_audit_batch_is_admitted_above_the_write_limit_up_to_twice_the_limit() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let parked_writes = ParkedWrites::install(&inner);
        let adapter = Arc::new(ClusterStorageAdapter::with_max_writes_in_flight(
            Arc::new(ClusterEngine::single_node(inner)),
            2,
        ));
        let realm = RealmId::generate();

        let parked: Vec<_> = (0..2u8)
            .map(|i| {
                let (adapter, realm) = (Arc::clone(&adapter), realm.clone());
                std::thread::spawn(move || adapter.put(&realm, &[b'p', i], b"v"))
            })
            .collect();
        wait_for_writes_in_flight(&adapter, 2);
        assert!(
            adapter.put(&realm, b"over", b"v").is_err(),
            "the write limit of 2 is full"
        );

        let admitted = adapter
            .enqueue_audit_batch(&realm, &[(b"audit".to_vec(), b"v".to_vec())])
            .expect("an audit batch at a full write limit must be admitted");
        adapter
            .await_batch_durable(admitted)
            .expect("the admitted audit batch is durable");
        assert_eq!(adapter.get(&realm, b"audit").unwrap(), Some(b"v".to_vec()));

        // Two more audit writes in progress: 4 in all, twice the limit.
        let audit_places: Vec<_> = (0..2)
            .map(|_| {
                adapter
                    .try_start_write(adapter.audit_write_ceiling())
                    .expect("an audit place below twice the limit")
            })
            .collect();
        let refused = adapter.enqueue_audit_batch(&realm, &[(b"a-over".to_vec(), b"v".to_vec())]);
        assert!(
            matches!(
                refused,
                Err(crate::storage::StorageError::ClusterUnavailable {
                    cause: crate::storage::ClusterUnavailableCause::WriteLimit,
                    ..
                })
            ),
            "an audit batch at twice the limit must be refused: {:?}",
            refused.err()
        );

        drop(audit_places);
        drop(parked_writes);
        for writer in parked {
            writer.join().unwrap().expect("a parked write completes");
        }
        assert_eq!(adapter.writes_in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.get(&realm, b"a-over").unwrap(), None);
    }

    /// #596: a wait for a write that is already queued is never refused, also
    /// when the write limit is full: only a wait commits the queued batch.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_wait_for_a_queued_write_is_not_refused_at_the_limit() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let inner_handle = Arc::clone(&inner);
        let adapter = Arc::new(ClusterStorageAdapter::with_max_writes_in_flight(
            Arc::new(ClusterEngine::single_node(inner)),
            1,
        ));
        let realm = RealmId::generate();
        let queued = adapter
            .enqueue_batch(&realm, &[(b"queued".to_vec(), b"v".to_vec())])
            .unwrap();

        let parked_writes = ParkedWrites::install(&inner_handle);
        let parked = {
            let (adapter, realm) = (Arc::clone(&adapter), realm.clone());
            std::thread::spawn(move || adapter.put(&realm, b"parked", b"v"))
        };
        wait_for_writes_in_flight(&adapter, 1);

        adapter
            .await_batch_durable(queued)
            .expect("a wait for a queued write must not be refused");

        drop(parked_writes);
        parked.join().unwrap().expect("the parked write completes");
        assert_eq!(adapter.writes_in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.get(&realm, b"queued").unwrap(), Some(b"v".to_vec()));
    }

    /// `serve` always installs a `ClusterStorageAdapter`, single-node included.
    /// If the adapter answered `None` for a snapshot, a backup export would
    /// read the live engine, and a write during the export could tear the
    /// archive (#643, §4.9#4).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn adapter_forwards_the_inner_read_snapshot() {
        let dir = tempdir().unwrap();
        let inner = open_engine(dir.path().join("data").as_path());
        let realm = RealmId::generate();
        inner.put(&realm, b"before", b"v").unwrap();
        let adapter =
            ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(Arc::clone(&inner))));

        let snapshot = adapter
            .read_snapshot()
            .unwrap()
            .expect("the adapter must forward the snapshot, not swallow it");
        inner.put(&realm, b"after", b"v").unwrap();

        assert_eq!(
            snapshot.get(&realm, b"before").unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(snapshot.get(&realm, b"after").unwrap(), None);
    }

    /// `serve` always installs a `ClusterStorageAdapter`, and the audit engine
    /// appends through `enqueue_batch` under its realm chain lock, waiting for
    /// the fsync only after it drops the lock. The adapter inherited the trait
    /// default, a full `put_batch` with its fsync, so the fsync ran inside the
    /// chain lock and every audited write in a realm waited for the one before
    /// it (2026-10-08 stress run: ~168 user creates/s, CPU ~15%, disk-bound).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn adapter_hands_back_the_inner_group_commit_handle() {
        let dir = tempdir().unwrap();
        let mut config = StorageConfig::dev(dir.path().join("data"));
        config.wal_config.sync_mode = crate::storage::wal::SyncMode::EveryWrite;
        let inner = Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        let adapter =
            ClusterStorageAdapter::new(Arc::new(ClusterEngine::single_node(Arc::clone(&inner))));
        let realm = RealmId::generate();

        let handle = adapter
            .enqueue_batch(&realm, &[(b"k".to_vec(), b"v".to_vec())])
            .expect("enqueue");
        assert!(
            matches!(
                handle.0,
                crate::storage::StorageDurabilityHandleKind::Pending(_)
            ),
            "the adapter must return the inner engine's group-commit handle, \
             so the caller waits for the fsync outside its own lock"
        );
        adapter.await_batch_durable(handle).expect("durable");
        assert!(
            inner.wal_sync_count() >= 1,
            "awaiting the handle must leave the batch fsynced"
        );
        assert_eq!(adapter.get(&realm, b"k").unwrap(), Some(b"v".to_vec()));
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

    /// The adapter's streaming and key-only reads (`scan_keys`, `visit_keys`,
    /// `visit_entries`, `get_uncached`, `count_prefix`, `scan_prefix_paged`)
    /// answer exactly what the inner engine answers, tombstones included —
    /// they are forwarded, not rebuilt from `scan` or `get`.
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
        let mut visited = Vec::new();
        adapter
            .visit_keys(&realm, b"p:", b"p;", &mut |key| {
                visited.push(key.to_vec());
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(visited, keys);
        let mut entries = Vec::new();
        adapter
            .visit_entries(&realm, b"p:", b"p;", &mut |key, value| {
                entries.push((key.to_vec(), value.to_vec()));
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(
            entries,
            vec![
                (b"p:a".to_vec(), b"v".to_vec()),
                (b"p:c".to_vec(), b"v".to_vec())
            ]
        );
        assert_eq!(
            adapter.get_uncached(&realm, b"p:a").unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(adapter.get_uncached(&realm, b"p:b").unwrap(), None);
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

    // ── Bootstrap and the cluster ID (design decision 5) ─────────────────────

    use crate::cluster::peer_identity::test_pki::TestCa;

    /// A cluster node `node_id` whose `cluster.peers` names `peers` (nobody
    /// listens at their addresses). Its gRPC server is not started.
    #[allow(clippy::unwrap_used)]
    async fn clustered_node(dir: &std::path::Path, node_id: u64, peers: &[u64]) -> ClusterEngine {
        clustered_node_of(&TestCa::new(), dir, node_id, peers).await
    }

    /// [`clustered_node`] with a certificate `ca` signed.
    #[allow(clippy::unwrap_used)]
    async fn clustered_node_of(
        ca: &TestCa,
        dir: &std::path::Path,
        node_id: u64,
        peers: &[u64],
    ) -> ClusterEngine {
        use crate::config::PeerConfig;

        let leaf = ca.leaf_for_node(node_id);
        let ca_path = dir.join("ca.pem");
        let cert_path = dir.join("node.pem");
        let key_path = dir.join("node.key");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        std::fs::write(&cert_path, &leaf.cert_pem).unwrap();
        std::fs::write(&key_path, &leaf.key_pem).unwrap();
        let data_dir = dir.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let storage_cfg = StorageConfig::dev(data_dir);
        let inner = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
        let config = ClusterConfig {
            node_id,
            peer_address: format!("127.0.0.1:{}", 40_000 + node_id),
            peers: peers
                .iter()
                .map(|&id| PeerConfig {
                    id,
                    address: format!("127.0.0.1:{}", 40_000 + id),
                })
                .collect(),
            tls_cert_path: cert_path,
            tls_key_path: key_path,
            tls_ca_cert_path: ca_path,
            read_lag_threshold_ms: None,
            write_timeout_ms: None,
            experimental_opt_in: true,
        };
        ClusterEngine::build_clustered(inner, &config, &storage_cfg)
            .await
            .unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn persisted_cluster_id(engine: &ClusterEngine) -> Option<ClusterId> {
        engine
            .cluster_identity
            .as_ref()
            .unwrap()
            .persisted()
            .unwrap()
    }

    /// Finding 1, scenario A: a node of a cluster formed by an older release
    /// (initialised, no cluster ID) answers a repeated bootstrap with
    /// `AlreadyInitialized` and writes no cluster ID, so it keeps accepting
    /// its leader's RPCs, which carry none.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn bootstrap_on_an_initialised_node_writes_no_cluster_id() {
        let dir = tempdir().unwrap();
        let engine = clustered_node(dir.path(), 1, &[]).await;
        let members = engine.initial_members().cloned().unwrap();
        // What an older release did: initialise with no cluster ID.
        engine
            .raft
            .as_ref()
            .unwrap()
            .initialize(members.clone())
            .await
            .unwrap();

        let refused = engine.initialize_cluster(members).await;

        assert!(
            matches!(refused, Err(ClusterError::AlreadyInitialized(_))),
            "{refused:?}"
        );
        assert_eq!(engine.cluster_id(), None);
        assert_eq!(persisted_cluster_id(&engine), None);
    }

    /// Finding 1, scenario B: only the designated initialiser (the lowest
    /// node ID of the membership) may initialise. Two nodes that both
    /// initialised the same membership would each hold their own random
    /// cluster ID and refuse each other for ever; before cluster IDs they
    /// converged.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn bootstrap_on_a_node_that_is_not_the_designated_initialiser_is_refused() {
        let dir = tempdir().unwrap();
        let engine = clustered_node(dir.path(), 2, &[1, 3]).await;
        let members = engine.initial_members().cloned().unwrap();

        let refused = engine.initialize_cluster(members).await;

        assert!(
            matches!(
                refused,
                Err(ClusterError::NotTheInitialiser { designated: 1 })
            ),
            "{refused:?}"
        );
        assert_eq!(engine.cluster_id(), None);
        assert_eq!(persisted_cluster_id(&engine), None);
        assert!(!engine
            .raft
            .as_ref()
            .unwrap()
            .is_initialized()
            .await
            .unwrap());
    }

    /// Finding 2 on #955: a pristine node adopts a leader's cluster ID only
    /// once Raft has accepted the `AppendEntries`. An undecodable request or
    /// one Raft rejects, even from a peer the cluster CA signed, leaves it
    /// pristine, so a node of another cluster sharing the CA cannot claim a
    /// replacement node with one bad RPC.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn a_pristine_node_adopts_a_cluster_id_only_from_an_append_entries_raft_accepts() {
        use crate::cluster::peer_identity::PeerClaim;
        use crate::cluster::rpc::AppendEntriesRequest as WireAppendEntries;
        use crate::cluster::server::RaftRpcHandler;
        use openraft::raft::AppendEntriesRequest;
        use tokio_rustls::rustls::pki_types::CertificateDer;
        use tonic::metadata::MetadataMap;

        const A: ClusterId = ClusterId::new(Uuid::from_u128(0xA));
        let ca = TestCa::new();
        let dir = tempdir().unwrap();
        let engine = Arc::new(clustered_node_of(&ca, dir.path(), 2, &[1, 3]).await);
        let handler = RaftRpcHandler::new(2, Arc::clone(&engine));
        let mut md = MetadataMap::new();
        PeerClaim {
            cluster_id: Some(A),
            source: 1,
            target: 2,
        }
        .stamp(&mut md);
        let certs = vec![CertificateDer::from(ca.leaf_for_node(1).der)];
        let aer = |prev_log_id: Option<LogId<u64>>| {
            let req: AppendEntriesRequest<HearthRaftConfig> = AppendEntriesRequest {
                vote: Vote::new_committed(1, 1),
                prev_log_id,
                entries: vec![],
                leader_commit: None,
            };
            WireAppendEntries {
                payload: wire::encode(&req).unwrap(),
                leader_quorum_ack_age_ms: Some(1),
            }
        };

        let garbage = WireAppendEntries {
            payload: b"not an AppendEntries".to_vec(),
            leader_quorum_ack_age_ms: Some(1),
        };
        let undecodable = handler
            .serve_append_entries(&md, Some(&certs), garbage)
            .await;
        assert!(
            undecodable.is_err(),
            "garbage was answered: {undecodable:?}"
        );
        assert_eq!(engine.cluster_id(), None, "adopted from an undecodable RPC");
        assert_eq!(persisted_cluster_id(&engine), None);

        // Raft answers Conflict: this node holds no entry at index 5.
        let unknown_prev = Some(LogId::new(CommittedLeaderId::new(1, 1), 5));
        let conflict = handler
            .serve_append_entries(&md, Some(&certs), aer(unknown_prev))
            .await
            .expect("answered");
        let conflict: openraft::raft::AppendEntriesResponse<u64> =
            wire::decode(&conflict.payload).unwrap();
        assert!(conflict.is_conflict(), "{conflict:?}");
        assert_eq!(engine.cluster_id(), None, "adopted from a rejected RPC");
        assert_eq!(persisted_cluster_id(&engine), None);

        let accepted = handler
            .serve_append_entries(&md, Some(&certs), aer(None))
            .await
            .expect("answered");
        let accepted: openraft::raft::AppendEntriesResponse<u64> =
            wire::decode(&accepted.payload).unwrap();
        assert!(accepted.is_success(), "{accepted:?}");
        assert_eq!(engine.cluster_id(), Some(A));
        assert_eq!(persisted_cluster_id(&engine), Some(A));
    }
}
