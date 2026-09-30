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
    /// Atomically apply a mix of writes and removals for a single realm.
    ///
    /// The counterpart to [`Self::Batch`] for callers that must land a record
    /// and remove its old index in one durable step. Applied as one
    /// `write_batch` on the node's storage engine, so a crash mid-apply leaves
    /// either the whole batch or none of it (audit 2026-08-28 §4.9#4).
    ///
    /// Added after `Batch`, so a node running an older build cannot decode it.
    /// Cluster mode is experimental and requires a full-cluster restart to
    /// change membership, so a mixed-version cluster is already unsupported.
    WriteBatch {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        /// `(key, value)` pairs to write.
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        /// Keys to remove.
        deletes: Vec<Vec<u8>>,
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
    /// Atomically increment the little-endian `u64` counter at `key` (absent
    /// counts as `0`) and return the new value in the response payload.
    ///
    /// The successor is computed by the state machine at apply time, not by
    /// the proposer: Raft applies entries one at a time, so two concurrent
    /// proposals always produce two distinct, increasing values. A proposer
    /// that read the counter and proposed a `Put` of its successor could be
    /// overtaken and move the counter backwards — the control-epoch defect
    /// this exists to close.
    ///
    /// Added after `PutIfAbsent`, so a node running an older build cannot
    /// decode it; as with `WriteBatch`, a mixed-version cluster is already
    /// unsupported (membership changes need a full-cluster restart).
    IncrementU64 {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
    },
}

impl RaftCommand {
    /// Replaces the command's `leader_timestamp` with `now` (microseconds
    /// since the UNIX epoch).
    ///
    /// A follower that forwards a write stamped it with its own clock; the
    /// leader restamps it on receipt, so every command in the log carries the
    /// clock of the node that proposed it, as the field's contract requires.
    #[must_use]
    pub fn restamped(mut self, now: i64) -> Self {
        match &mut self {
            Self::Put {
                leader_timestamp, ..
            }
            | Self::Delete {
                leader_timestamp, ..
            }
            | Self::Batch {
                leader_timestamp, ..
            }
            | Self::WriteBatch {
                leader_timestamp, ..
            }
            | Self::PutIfAbsent {
                leader_timestamp, ..
            }
            | Self::IncrementU64 {
                leader_timestamp, ..
            } => *leader_timestamp = now,
        }
        self
    }
}

/// The leader's answer to a write a follower forwarded to it (the
/// `ForwardWrite` peer RPC).
///
/// Each variant says whether the command can have entered the Raft log,
/// because that decides whether the follower may retry it: a conditional
/// command (`PutIfAbsent`, `IncrementU64`) applied twice is a different
/// result, not a repeated one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardedWriteOutcome {
    /// Committed and applied on the leader at `log_index`. The follower waits
    /// until its own state machine has applied that index before it answers.
    Committed {
        /// Index of the log entry that carried the command.
        log_index: u64,
        /// The state machine's response (the `PutIfAbsent` / `IncrementU64`
        /// outcome).
        response: HearthLogResponse,
    },
    /// Refused **without proposing**: the receiving node is not the leader.
    /// `leader_id` is the leader it knows of, if any. Safe to retry.
    NotLeader {
        /// The leader the refusing node knows of, if any.
        leader_id: Option<u64>,
    },
    /// Refused **without proposing** for a reason a retry does not cure (the
    /// payload is too large, undecodable, or the leader is at its forwarding
    /// concurrency limit).
    Rejected {
        /// Operator-facing reason; carries no key or value bytes.
        reason: String,
    },
    /// Proposed, but the leader cannot say whether it committed (its commit
    /// wait timed out, or Raft stopped under it). MUST NOT be retried.
    Unknown {
        /// Operator-facing reason; carries no key or value bytes.
        reason: String,
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
