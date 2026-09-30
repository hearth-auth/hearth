//! Cluster layer: Raft consensus via `openraft`.
//!
//! Handles log replication, leader election, membership changes, and snapshots.
//! Invisible in single-node mode — the module is compiled unconditionally but
//! the engine is only started when `config.cluster` is `Some`.
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────┐
//!  │  ClusterEngine (public-facing wrapper)               │
//!  │    • single-node bypass (zero Raft overhead)         │
//!  │    • leader write routing via client_write           │
//!  │    • follower writes forwarded to the leader, then   │
//!  │      awaited locally (read-your-writes)              │
//!  │    • follower read staleness via reads_allowed flag  │
//!  └──────────────────────────────────────────────────────┘
//!  ┌──────────────────────────────────────────────────────┐
//!  │  HearthNetworkFactory (outgoing RPCs)                │
//!  │    └─ HearthPeerNetwork per peer                     │
//!  │         • lazy mTLS gRPC channel                     │
//!  │         • CBOR encode/decode openraft payloads       │
//!  │           (size limits: see `wire`)                  │
//!  └──────────────────────────────────────────────────────┘
//!  ┌──────────────────────────────────────────────────────┐
//!  │  RaftRpcHandler / serve() (incoming RPCs)            │
//!  │    • tonic Server with ServerTlsConfig (mTLS)        │
//!  │    • delegates to IncomingRpcDispatch                │
//!  │      (Raft RPCs + ForwardWrite from followers)       │
//!  └──────────────────────────────────────────────────────┘
//! ```

pub mod engine;
pub(crate) mod error;
pub mod log_store;
pub mod network;
pub(crate) mod rpc;
pub mod server;
pub mod state_machine;
pub mod types;
pub mod wire;

/// Observes storage writes applied outside the node's own API surface —
/// today, Raft state-machine applies on a follower.
///
/// Node-local projections (hot-path caches derived from storage, such as the
/// revoked-JTI blocklist) are updated synchronously by the API handler that
/// performs a write. A write applied by the replication layer bypasses those
/// handlers, so a revocation committed on the leader never reached a
/// follower's projection until that follower restarted (audit 2026-08-28
/// §4.16#5). Implementors project the applied write into their caches here.
///
/// Callbacks run on the state-machine apply path: they MUST be fast,
/// non-blocking and infallible. Mirrors the `SvBumper` pattern — the lower
/// layer defines the trait, the layer above implements it, and the server
/// composition root wires the two together.
pub trait ReplicatedWriteObserver: Send + Sync {
    /// A `put` — or one entry of a batch — was applied for `realm_id`.
    fn on_replicated_put(&self, realm_id: &crate::core::RealmId, key: &[u8], value: &[u8]);
    /// A `delete` was applied for `realm_id`.
    fn on_replicated_delete(&self, realm_id: &crate::core::RealmId, key: &[u8]);
    /// The whole key-space was replaced (snapshot install). Implementors
    /// MUST rebuild their projections from storage.
    fn on_replicated_reset(&self);
    /// This node has just become the Raft leader (once per term it wins).
    ///
    /// Called from the cluster engine's leadership watch, and when the
    /// observer is registered on a node that already leads. Like the other
    /// callbacks it MUST be fast, non-blocking and infallible: an implementor
    /// records the event and acts on it elsewhere.
    fn on_leadership_acquired(&self);
}

pub use engine::{
    is_not_leader, ClusterBuildError, ClusterEngine, ClusterError, ClusterStorageAdapter,
};
pub use log_store::{HearthLogReader, HearthLogStore};
pub use network::{HearthNetworkFactory, PeerFaults};
pub use server::{serve, serve_with_shutdown, IncomingRpcDispatch, NoopDispatch, RaftRpcHandler};
pub use state_machine::HearthStateMachine;
pub use types::{
    ForwardedWriteOutcome, HearthLogData, HearthLogResponse, HearthNode, HearthRaftConfig,
    RaftCommand,
};
pub use wire::{
    APPEND_BATCH_BYTES, MAX_COMMAND_BYTES, MAX_PEER_MESSAGE_BYTES, SNAPSHOT_CHUNK_BYTES,
};
