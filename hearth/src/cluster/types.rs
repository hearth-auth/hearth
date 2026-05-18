use std::io::Cursor;
use openraft::BasicNode;

pub type NodeId = u64;

openraft::declare_raft_types!(
    pub TypeConfig:
        D = KVCommand,
        R = KVResponse,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KVCommand {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KVResponse {
    pub applied_log_index: u64,
}
