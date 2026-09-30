//! Peer wire encoding and message-size limits for the cluster transport.
//!
//! Every peer RPC payload (`AppendEntries`, `Vote`, `InstallSnapshot`,
//! `ForwardWrite`, and their answers) is CBOR. Byte strings — keys, values,
//! snapshot chunks — are written as CBOR byte strings, one byte per byte.
//!
//! The transport used to be JSON, where serde writes a `Vec<u8>` as an array
//! of decimal numbers (about 3.6 bytes per byte), under tonic's default 4 MiB
//! decode limit. A follower that fell a few MiB behind, a single write over
//! ~1 MiB, or any snapshot over ~1 MiB produced a message the receiver
//! refused on every retry, and replication to it stalled for good.
//!
//! The limits below fit together so that no message the transport builds can
//! exceed what the receiver accepts:
//!
//! * a single command is at most [`MAX_COMMAND_BYTES`] (checked when it is
//!   proposed, on the leader or on a forwarding follower);
//! * `AppendEntries` batches are cut to [`APPEND_BATCH_BYTES`] (openraft's
//!   `PartialSuccess`), but always carry at least one entry;
//! * snapshot chunks are [`SNAPSHOT_CHUNK_BYTES`];
//! * the peer server and client accept messages up to [`MAX_PEER_MESSAGE_BYTES`],
//!   which exceeds each of the above plus its envelope.
//!
//! Raft log entries persisted in `raft.db` stay JSON: the byte-string helpers
//! below write exactly the number arrays the derived encoding wrote, and read
//! both forms.

use std::fmt;

use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Largest gRPC message a node sends to or accepts from a peer (16 MiB).
pub const MAX_PEER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Largest single replicated command, estimated by
/// [`RaftCommand::wire_size_estimate`](crate::cluster::RaftCommand::wire_size_estimate)
/// (4 MiB). A larger write is refused before it is proposed, on the leader
/// and on a forwarding follower alike, instead of stalling replication.
pub const MAX_COMMAND_BYTES: usize = 4 * 1024 * 1024;

/// Target size of one `AppendEntries` message (2 MiB). A batch openraft
/// hands the transport is cut to fit and reported as a partial success, so
/// openraft sends the rest next; an entry larger than this travels alone.
pub const APPEND_BATCH_BYTES: usize = 2 * 1024 * 1024;

/// Snapshot chunk size configured into openraft (4 MiB).
pub const SNAPSHOT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

/// Encodes a peer payload as CBOR.
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Decodes a CBOR peer payload.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

/// The CBOR-encoded size of `value`, without building the encoding.
pub(crate) fn encoded_len<T: Serialize>(value: &T) -> Result<usize, String> {
    let mut counter = ByteCounter(0);
    ciborium::into_writer(value, &mut counter).map_err(|e| e.to_string())?;
    Ok(counter.0)
}

/// An `io::Write` that only counts.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A borrowed byte string, serialised as one (not as a sequence of numbers).
struct ByteStr<'a>(&'a [u8]);

impl Serialize for ByteStr<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

/// An owned byte string read from either a byte string or a sequence of
/// numbers (the pre-CBOR JSON form).
struct ByteBuf(Vec<u8>);

impl<'de> Deserialize<'de> for ByteBuf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_byte_buf(ByteBufVisitor).map(ByteBuf)
    }
}

struct ByteBufVisitor;

impl<'de> Visitor<'de> for ByteBufVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64 * 1024));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

/// `#[serde(with = "…")]` for a `Vec<u8>` field.
pub(crate) mod bytes {
    use super::{ByteBuf, ByteStr};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialises the field as a byte string.
    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        ByteStr(v).serialize(s)
    }

    /// Reads a byte string or a sequence of numbers.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        ByteBuf::deserialize(d).map(|b| b.0)
    }
}

/// `#[serde(with = "…")]` for a `Vec<Vec<u8>>` field.
pub(crate) mod byte_list {
    use super::{ByteBuf, ByteStr};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialises each element as a byte string.
    pub(crate) fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&ByteStr(item))?;
        }
        seq.end()
    }

    /// Reads each element as a byte string or a sequence of numbers.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<ByteBuf>::deserialize(d).map(|v| v.into_iter().map(|b| b.0).collect())
    }
}

/// Key/value pairs as the replicated commands carry them.
type BytePairs = Vec<(Vec<u8>, Vec<u8>)>;

/// `#[serde(with = "…")]` for a `Vec<(Vec<u8>, Vec<u8>)>` field.
pub(crate) mod byte_pairs {
    use super::{ByteBuf, ByteStr};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialises each pair as a two-element sequence of byte strings.
    pub(crate) fn serialize<S: Serializer>(
        v: &[(Vec<u8>, Vec<u8>)],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for (k, val) in v {
            seq.serialize_element(&(ByteStr(k), ByteStr(val)))?;
        }
        seq.end()
    }

    /// Reads each pair's halves as byte strings or sequences of numbers.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<super::BytePairs, D::Error> {
        Vec::<(ByteBuf, ByteBuf)>::deserialize(d)
            .map(|v| v.into_iter().map(|(k, val)| (k.0, val.0)).collect())
    }
}

/// `InstallSnapshotRequest` as it travels between peers: openraft's struct
/// with the chunk written as one byte string (openraft derives it as a
/// sequence of numbers).
#[derive(Serialize, Deserialize)]
pub(crate) struct WireInstallSnapshot {
    vote: openraft::Vote<u64>,
    meta: openraft::SnapshotMeta<u64, crate::cluster::types::HearthNode>,
    offset: u64,
    #[serde(with = "bytes")]
    data: Vec<u8>,
    done: bool,
}

type InstallSnapshotReq =
    openraft::raft::InstallSnapshotRequest<crate::cluster::types::HearthRaftConfig>;

impl From<InstallSnapshotReq> for WireInstallSnapshot {
    fn from(r: InstallSnapshotReq) -> Self {
        Self {
            vote: r.vote,
            meta: r.meta,
            offset: r.offset,
            data: r.data,
            done: r.done,
        }
    }
}

impl From<WireInstallSnapshot> for InstallSnapshotReq {
    fn from(w: WireInstallSnapshot) -> Self {
        Self {
            vote: w.vote,
            meta: w.meta,
            offset: w.offset,
            data: w.data,
            done: w.done,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cluster::types::{HearthLogResponse, RaftCommand};
    use crate::core::RealmId;

    fn sample() -> RaftCommand {
        RaftCommand::WriteBatch {
            leader_timestamp: 42,
            realm: RealmId::new(uuid::Uuid::nil()),
            puts: vec![
                (b"k1".to_vec(), vec![0xFF; 300]),
                (b"k2".to_vec(), Vec::new()),
            ],
            deletes: vec![b"gone".to_vec()],
        }
    }

    /// Byte strings cost one byte per byte on the wire: a 1 MiB value is
    /// ~1 MiB of CBOR, where the old JSON encoding made it ~3.6 MiB.
    #[test]
    fn cbor_encodes_byte_fields_as_byte_strings() {
        let cmd = RaftCommand::Put {
            leader_timestamp: 1,
            realm: RealmId::new(uuid::Uuid::nil()),
            key: b"k".to_vec(),
            value: vec![200; 1024 * 1024],
        };
        let wire = encode(&cmd).unwrap();
        assert!(
            wire.len() < 1024 * 1024 + 256,
            "a 1 MiB value took {} bytes on the wire",
            wire.len()
        );
        assert!(serde_json::to_vec(&cmd).unwrap().len() > 3 * 1024 * 1024);
        assert!(cmd.wire_size_estimate() >= wire.len());
    }

    #[test]
    fn cbor_round_trips_every_byte_field_shape() {
        let cmd = sample();
        let back: RaftCommand = decode(&encode(&cmd).unwrap()).unwrap();
        assert_eq!(format!("{back:?}"), format!("{cmd:?}"));
        assert!(cmd.wire_size_estimate() >= encode(&cmd).unwrap().len());
        let resp = HearthLogResponse {
            success: false,
            payload: vec![1, 2, 3],
        };
        let back: HearthLogResponse = decode(&encode(&resp).unwrap()).unwrap();
        assert_eq!((back.success, back.payload), (false, vec![1, 2, 3]));
    }

    /// `raft.db` keeps log entries as JSON. The byte helpers must write the
    /// same number arrays the derived encoding wrote, and read them back, so
    /// a log written before this change still replays.
    #[test]
    fn json_log_entries_keep_their_encoding_and_still_decode() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(
            json.contains("[[[107,49],[255,255")
                && json.contains(r#""deletes":[[103,111,110,101]]"#),
            "the JSON encoding of byte fields changed: {json}"
        );
        let back: RaftCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{back:?}"), format!("{:?}", sample()));
    }
}
