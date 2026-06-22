//! Raft type configuration and application-layer command types.

use serde::{Deserialize, Serialize};

use crate::core::RealmId;

/// Information stored alongside each node in the Raft membership config.
///
/// Automatically satisfies `openraft::Node` via the blanket impl, which
/// requires `Debug + Clone + Default + PartialEq + Eq + Serialize + Deserialize`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HearthNode {
    /// gRPC peer address for this node, e.g. `"10.0.0.1:8421"`.
    pub addr: String,
}

/// Commands replicated through Raft and applied to the storage engine.
///
/// Every variant carries `leader_timestamp` — the wall-clock microseconds
/// stamped by the leader at the time the command was proposed.  Followers
/// MUST NOT substitute a local clock reading; they use this field verbatim
/// so time-ordered reads are consistent across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftCommand {
    /// Insert or update a single key-value pair.
    Put {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Delete a single key.
    Delete {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
    },
    /// Atomically write multiple key-value pairs for a single realm.
    Batch {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        /// `(key, value)` pairs to write atomically.
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Insert a key-value pair only if the key is currently absent.
    ///
    /// The check and write are performed atomically inside the state machine —
    /// Raft serializes all log entries, so no concurrent apply can interleave
    /// between the existence check and the write.  This closes the TOCTOU
    /// window that the per-node advisory lock cannot prevent across nodes.
    PutIfAbsent {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    },
}

/// Openraft `D` type alias — keeps the `declare_raft_types!` binding stable.
pub type HearthLogData = RaftCommand;

/// Response returned by the state machine after each applied log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HearthLogResponse {
    /// `true` when the command succeeded or was unconditional; `false` when a
    /// conditional command (e.g. `PutIfAbsent`) found the key already present.
    pub success: bool,
    /// Optional result bytes returned to the caller.
    pub payload: Vec<u8>,
}

impl Default for HearthLogResponse {
    fn default() -> Self {
        Self {
            success: true,
            payload: Vec::new(),
        }
    }
}

openraft::declare_raft_types!(
    /// Type configuration for Hearth's Raft consensus engine.
    pub HearthRaftConfig:
        D             = HearthLogData,
        R             = HearthLogResponse,
        NodeId        = u64,
        Node          = HearthNode,
        Entry         = openraft::Entry<HearthRaftConfig>,
        SnapshotData  = std::io::Cursor<Vec<u8>>,
        AsyncRuntime  = openraft::TokioRuntime,
);
