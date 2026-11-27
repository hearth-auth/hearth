//! The Raft snapshot record stream (`cluster-file-snapshots`, design decision 2).
//!
//! This is what openraft sends between nodes, so it is the same on every
//! node. Each node keeps it on disk inside a sealed file
//! ([`crate::storage::SealedFiles`]).
//!
//! ```text
//! magic   (8 bytes, "HRSNAP01")
//! zstd frame of records:
//!   0x01 META   u32 length, JSON SnapshotMeta          exactly once, first
//!   0x02 REALM  16-byte realm UUID
//!   0x03 ROW    u32 key length, key, u32 value length, value    only after a REALM
//!   0x04 END    u64 realms, u64 rows, SHA-256 of every record byte before END
//! ```
//!
//! Integers are little-endian. The reader holds one row at a time and
//! refuses anything else: an unknown tag, a ROW before a REALM, a key or
//! value over [`MAX_ROW_PART`], a second META, an END whose counts or digest
//! do not match, and any byte after END. Error messages never carry key or
//! value bytes.

// Used by the state machine from task 3.2 of `cluster-file-snapshots` on;
// until then only its tests use it.
#![cfg_attr(not(test), allow(dead_code))]

use std::io::{self, BufReader, Read, Write};

use openraft::SnapshotMeta;
use sha2::{Digest, Sha256};

use crate::cluster::types::HearthNode;
use crate::core::RealmId;

/// The first bytes of every snapshot stream.
const MAGIC: &[u8; 8] = b"HRSNAP01";

const TAG_META: u8 = 0x01;
const TAG_REALM: u8 = 0x02;
const TAG_ROW: u8 = 0x03;
const TAG_END: u8 = 0x04;

/// The longest key or value a snapshot carries (16 MiB, the peer message
/// limit). The builder refuses a longer one, so every snapshot it writes can
/// be read back.
pub(crate) const MAX_ROW_PART: usize = crate::cluster::wire::MAX_PEER_MESSAGE_BYTES;

/// Longest META record body accepted.
const MAX_META: usize = 1024 * 1024;

/// zstd level: speed first, because a build holds its storage read snapshot
/// until it ends.
const ZSTD_LEVEL: i32 = 1;

/// The snapshot's metadata as openraft knows it.
pub(crate) type Meta = SnapshotMeta<u64, HearthNode>;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn len_u32(len: usize) -> io::Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| invalid("snapshot record field is too long"))
}

// ── Writer ───────────────────────────────────────────────────────────────────

/// Writes a snapshot stream into `W`.
pub(crate) struct StreamWriter<W: Write> {
    zstd: zstd::stream::write::Encoder<'static, W>,
    digest: Sha256,
    realms: u64,
    rows: u64,
    in_realm: bool,
}

impl<W: Write> StreamWriter<W> {
    /// Writes the magic and the META record for `meta`.
    ///
    /// # Errors
    ///
    /// Any error of `inner`, or a META that does not encode.
    pub(crate) fn new(mut inner: W, meta: &Meta) -> io::Result<Self> {
        inner.write_all(MAGIC)?;
        let mut writer = Self {
            zstd: zstd::stream::write::Encoder::new(inner, ZSTD_LEVEL)?,
            digest: Sha256::new(),
            realms: 0,
            rows: 0,
            in_realm: false,
        };
        let json = serde_json::to_vec(meta).map_err(io::Error::other)?;
        writer.record(&[&[TAG_META], &len_u32(json.len())?, &json])?;
        Ok(writer)
    }

    /// Starts the rows of `realm`.
    ///
    /// # Errors
    ///
    /// Any error of the inner writer.
    pub(crate) fn begin_realm(&mut self, realm: &RealmId) -> io::Result<()> {
        self.record(&[&[TAG_REALM], realm.as_uuid().as_bytes()])?;
        self.realms += 1;
        self.in_realm = true;
        Ok(())
    }

    /// Writes one row of the current realm.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for a row before any realm or a key or
    /// value over [`MAX_ROW_PART`], and any error of the inner writer.
    pub(crate) fn row(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
        if !self.in_realm {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot row written before its realm",
            ));
        }
        if key.len() > MAX_ROW_PART || value.len() > MAX_ROW_PART {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot row key or value is over the size limit",
            ));
        }
        self.record(&[
            &[TAG_ROW],
            &len_u32(key.len())?,
            key,
            &len_u32(value.len())?,
            value,
        ])?;
        self.rows += 1;
        Ok(())
    }

    /// Writes the END record and the end of the zstd frame, and returns the
    /// inner writer.
    ///
    /// # Errors
    ///
    /// Any error of the inner writer.
    pub(crate) fn finish(mut self) -> io::Result<W> {
        let digest: [u8; 32] = self.digest.clone().finalize().into();
        self.zstd.write_all(&[TAG_END])?;
        self.zstd.write_all(&self.realms.to_le_bytes())?;
        self.zstd.write_all(&self.rows.to_le_bytes())?;
        self.zstd.write_all(&digest)?;
        self.zstd.finish()
    }

    fn record(&mut self, parts: &[&[u8]]) -> io::Result<()> {
        for part in parts {
            self.digest.update(part);
            self.zstd.write_all(part)?;
        }
        Ok(())
    }
}

// ── Reader ───────────────────────────────────────────────────────────────────

/// One record of a snapshot stream after META.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// The rows that follow belong to this realm.
    Realm(RealmId),
    /// One row of the current realm.
    Row(Vec<u8>, Vec<u8>),
}

/// What [`verify`] found in a whole stream.
#[derive(Debug)]
pub(crate) struct Summary {
    /// The stream's META.
    pub(crate) meta: Meta,
    /// Realms in the stream.
    pub(crate) realms: u64,
    /// Rows in the stream.
    pub(crate) rows: u64,
}

/// Reads a snapshot stream from `R`, one record at a time.
pub(crate) struct StreamReader<R: Read> {
    zstd: zstd::stream::read::Decoder<'static, BufReader<R>>,
    digest: Sha256,
    meta: Meta,
    realms: u64,
    rows: u64,
    in_realm: bool,
    ended: bool,
}

impl<R: Read> StreamReader<R> {
    /// Reads the magic and the META record.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] for a stream that is not a snapshot or
    /// does not start with META, and any error of `inner`.
    pub(crate) fn new(mut inner: R) -> io::Result<Self> {
        let mut magic = [0u8; MAGIC.len()];
        inner
            .read_exact(&mut magic)
            .map_err(|_| invalid("not a snapshot stream (too short)"))?;
        if &magic != MAGIC {
            return Err(invalid("not a snapshot stream (bad magic)"));
        }
        let mut zstd = zstd::stream::read::Decoder::new(inner)?;
        let mut digest = Sha256::new();
        let tag = read_tag(&mut zstd)?;
        digest.update([tag]);
        if tag != TAG_META {
            return Err(invalid("snapshot stream does not start with META"));
        }
        let len = read_len(&mut zstd, &mut digest, MAX_META)?;
        let json = read_bytes(&mut zstd, &mut digest, len)?;
        let meta =
            serde_json::from_slice(&json).map_err(|_| invalid("snapshot META does not decode"))?;
        Ok(Self {
            zstd,
            digest,
            meta,
            realms: 0,
            rows: 0,
            in_realm: false,
            ended: false,
        })
    }

    /// The stream's META.
    pub(crate) fn meta(&self) -> &Meta {
        &self.meta
    }

    /// The next record, or `None` after a valid END with nothing after it.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] for anything the module docs list as
    /// refused, and any error of the inner reader (a sealed file's chunk that
    /// fails its tag comes back as one).
    pub(crate) fn next_record(&mut self) -> io::Result<Option<Record>> {
        if self.ended {
            return Ok(None);
        }
        let tag =
            read_tag(&mut self.zstd).map_err(|e| eof_as(e, "snapshot stream ends without END"))?;
        // The digest covers every record byte before END, so END's own tag
        // is left out of it.
        if tag != TAG_END {
            self.digest.update([tag]);
        }
        match tag {
            TAG_REALM => {
                let mut uuid = [0u8; 16];
                read_into(&mut self.zstd, &mut self.digest, &mut uuid)?;
                self.realms += 1;
                self.in_realm = true;
                Ok(Some(Record::Realm(RealmId::new(uuid::Uuid::from_bytes(
                    uuid,
                )))))
            }
            TAG_ROW => {
                if !self.in_realm {
                    return Err(invalid("snapshot ROW before any REALM"));
                }
                let klen = read_len(&mut self.zstd, &mut self.digest, MAX_ROW_PART)?;
                let key = read_bytes(&mut self.zstd, &mut self.digest, klen)?;
                let vlen = read_len(&mut self.zstd, &mut self.digest, MAX_ROW_PART)?;
                let value = read_bytes(&mut self.zstd, &mut self.digest, vlen)?;
                self.rows += 1;
                Ok(Some(Record::Row(key, value)))
            }
            TAG_END => {
                let expected: [u8; 32] = self.digest.clone().finalize().into();
                let mut body = [0u8; 8 + 8 + 32];
                self.zstd
                    .read_exact(&mut body)
                    .map_err(|e| eof_as(e, "snapshot END record is cut short"))?;
                let realms = u64::from_le_bytes(body[..8].try_into().map_err(io::Error::other)?);
                let rows = u64::from_le_bytes(body[8..16].try_into().map_err(io::Error::other)?);
                if realms != self.realms || rows != self.rows {
                    return Err(invalid("snapshot END counts do not match the stream"));
                }
                if body[16..] != expected {
                    return Err(invalid("snapshot digest does not match the stream"));
                }
                let mut after = [0u8; 1];
                if self.zstd.read(&mut after)? != 0 {
                    return Err(invalid("snapshot stream has bytes after END"));
                }
                self.ended = true;
                Ok(None)
            }
            TAG_META => Err(invalid("snapshot stream has a second META")),
            _ => Err(invalid("snapshot stream has an unknown record tag")),
        }
    }
}

/// Reads a whole stream and checks it (design decision 5).
///
/// # Errors
///
/// As [`StreamReader::new`] and [`StreamReader::next_record`].
pub(crate) fn verify<R: Read>(inner: R) -> io::Result<Summary> {
    let mut reader = StreamReader::new(inner)?;
    while reader.next_record()?.is_some() {}
    Ok(Summary {
        realms: reader.realms,
        rows: reader.rows,
        meta: reader.meta,
    })
}

fn eof_as(e: io::Error, reason: &'static str) -> io::Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        invalid(reason)
    } else {
        e
    }
}

fn read_into(r: &mut impl Read, digest: &mut Sha256, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf)
        .map_err(|e| eof_as(e, "snapshot record is cut short"))?;
    digest.update(&*buf);
    Ok(())
}

fn read_tag(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_len(r: &mut impl Read, digest: &mut Sha256, max: usize) -> io::Result<usize> {
    let mut b = [0u8; 4];
    read_into(r, digest, &mut b)?;
    let len = usize::try_from(u32::from_le_bytes(b)).map_err(io::Error::other)?;
    if len > max {
        return Err(invalid("snapshot record field is over the size limit"));
    }
    Ok(len)
}

fn read_bytes(r: &mut impl Read, digest: &mut Sha256, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    read_into(r, digest, &mut buf)?;
    Ok(buf)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use openraft::{CommittedLeaderId, LogId, StoredMembership};

    fn meta(index: u64) -> Meta {
        SnapshotMeta {
            last_log_id: Some(LogId::new(CommittedLeaderId::new(3, 1), index)),
            last_membership: StoredMembership::default(),
            snapshot_id: format!("snap-{index}-test"),
        }
    }

    fn realm(n: u128) -> RealmId {
        RealmId::new(uuid::Uuid::from_u128(n))
    }

    /// A stream with two realms: three rows, then one.
    fn sample() -> Vec<u8> {
        let mut w = StreamWriter::new(Vec::new(), &meta(42)).unwrap();
        w.begin_realm(&realm(1)).unwrap();
        w.row(b"a", b"1").unwrap();
        w.row(b"b", &[]).unwrap();
        w.row(b"c", &vec![7u8; 100_000]).unwrap();
        w.begin_realm(&realm(2)).unwrap();
        w.row(b"z", b"26").unwrap();
        w.finish().unwrap()
    }

    fn records(bytes: &[u8]) -> io::Result<(Meta, Vec<Record>)> {
        let mut r = StreamReader::new(bytes)?;
        let mut out = Vec::new();
        while let Some(rec) = r.next_record()? {
            out.push(rec);
        }
        Ok((r.meta().clone(), out))
    }

    /// The plaintext record bytes (magic stripped, zstd undone).
    fn plain(bytes: &[u8]) -> Vec<u8> {
        zstd::decode_all(&bytes[MAGIC.len()..]).unwrap()
    }

    /// `records` as a stream again, with the same magic and compression.
    fn repack(records: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(zstd::encode_all(records, 1).unwrap());
        out
    }

    fn assert_invalid(bytes: &[u8], what: &str) {
        let err = verify(bytes).expect_err(what);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{what}: {err}");
    }

    #[test]
    fn a_stream_round_trips() {
        let (m, recs) = records(&sample()).unwrap();
        assert_eq!(m, meta(42));
        assert_eq!(
            recs,
            vec![
                Record::Realm(realm(1)),
                Record::Row(b"a".to_vec(), b"1".to_vec()),
                Record::Row(b"b".to_vec(), Vec::new()),
                Record::Row(b"c".to_vec(), vec![7u8; 100_000]),
                Record::Realm(realm(2)),
                Record::Row(b"z".to_vec(), b"26".to_vec()),
            ]
        );
        let summary = verify(&sample()[..]).unwrap();
        assert_eq!((summary.realms, summary.rows), (2, 4));
        assert_eq!(summary.meta, meta(42));
    }

    #[test]
    fn an_empty_snapshot_round_trips() {
        let bytes = StreamWriter::new(Vec::new(), &meta(1))
            .unwrap()
            .finish()
            .unwrap();
        let summary = verify(&bytes[..]).unwrap();
        assert_eq!((summary.realms, summary.rows), (0, 0));
    }

    #[test]
    fn a_wrong_magic_or_a_cut_stream_is_refused() {
        let good = sample();
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_invalid(&bad, "bad magic");
        assert_invalid(&good[..4], "cut inside the magic");
        // Cut the plaintext at every record boundary class: inside META,
        // inside a row, just before END, inside END.
        let p = plain(&good);
        for cut in [3, 40, p.len() - 49, p.len() - 1] {
            assert!(
                verify(&repack(&p[..cut])[..]).is_err(),
                "a stream cut at {cut} of {} must be refused",
                p.len()
            );
        }
    }

    #[test]
    fn a_changed_byte_fails_the_digest() {
        let p = plain(&sample());
        // A byte inside the 100 KB value: the structure still parses.
        let at = p.len() / 2;
        let mut bad = p.clone();
        bad[at] ^= 0x01;
        assert_invalid(&repack(&bad), "a flipped value byte");
    }

    #[test]
    fn wrong_end_counts_are_refused() {
        let p = plain(&sample());
        let end = p.len() - 48;
        let mut bad = p.clone();
        bad[end] = 9; // realm count
        assert_invalid(&repack(&bad), "a wrong realm count");
        let mut bad = p.clone();
        bad[end + 8] = 9; // row count
        assert_invalid(&repack(&bad), "a wrong row count");
    }

    #[test]
    fn bytes_after_end_are_refused() {
        let mut p = plain(&sample());
        p.push(TAG_REALM);
        assert_invalid(&repack(&p), "a record after END");
        let mut two_frames = sample();
        two_frames.extend(zstd::encode_all(&[1u8, 2, 3][..], 1).unwrap());
        assert_invalid(&two_frames, "a second zstd frame after END");
    }

    /// Replaces the records after META in `sample()`'s plaintext with `body`.
    fn with_body(body: &[u8]) -> Vec<u8> {
        let p = plain(&sample());
        let meta_len =
            1 + 4 + usize::try_from(u32::from_le_bytes(p[1..5].try_into().unwrap())).unwrap();
        let mut out = p[..meta_len].to_vec();
        out.extend_from_slice(body);
        repack(&out)
    }

    #[test]
    fn malformed_records_are_refused() {
        let mut row_first = vec![TAG_ROW];
        row_first.extend(1u32.to_le_bytes());
        row_first.push(b'k');
        row_first.extend(0u32.to_le_bytes());
        assert_invalid(&with_body(&row_first), "a ROW before any REALM");

        assert_invalid(&with_body(&[0x7F]), "an unknown tag");

        let mut second_meta = vec![TAG_META];
        second_meta.extend(2u32.to_le_bytes());
        second_meta.extend(b"{}");
        assert_invalid(&with_body(&second_meta), "a second META");

        let mut huge = vec![TAG_REALM];
        huge.extend([0u8; 16]);
        huge.push(TAG_ROW);
        huge.extend(u32::MAX.to_le_bytes());
        assert_invalid(&with_body(&huge), "a key over the size limit");

        assert_invalid(&with_body(&[]), "no END");
    }

    #[test]
    fn a_stream_must_start_with_meta() {
        let mut p = vec![TAG_REALM];
        p.extend([0u8; 16]);
        assert_invalid(&repack(&p), "no META");
    }

    #[test]
    fn the_writer_refuses_rows_it_could_not_read_back() {
        let mut w = StreamWriter::new(Vec::new(), &meta(1)).unwrap();
        let err = w.row(b"k", b"v").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "row before realm");
        w.begin_realm(&realm(1)).unwrap();
        let big = vec![0u8; MAX_ROW_PART + 1];
        let err = w.row(&big, b"v").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "oversized key");
        let err = w.row(b"k", &big).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "oversized value");
    }
}
