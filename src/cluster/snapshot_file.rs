//! The Raft `SnapshotData` type: a sealed snapshot file behind tokio's async
//! I/O traits (`cluster-file-snapshots`, design decision 1).
//!
//! openraft reads a snapshot to send it (`seek`, `read_buf`) and writes one it
//! receives (`seek`, `write_all`, `shutdown`). Each call runs the sealed
//! file's synchronous I/O on the blocking pool, as `tokio::fs::File` does,
//! with at most [`MAX_IO`] bytes in memory:
//!
//! - a write returns once its bytes are copied; an error is reported by the
//!   next call (write-behind);
//! - `shutdown` of a received file seals its last chunk, syncs it and reads it
//!   all back through the stream reader ([`snapshot_stream::verify`]), so a
//!   bad transfer fails the transfer, before the state machine sees it.

// Used by the state machine from task 3.2 of `cluster-file-snapshots` on;
// until then only its tests use it.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::cluster::snapshot_stream::{self, Summary};
use crate::storage::{SealedFiles, SealedReader, SealedWriter, SEALED_CHUNK_LEN};

/// Most bytes one read or write moves through memory: the transfer chunk,
/// [`SNAPSHOT_CHUNK_BYTES`](crate::cluster::wire::SNAPSHOT_CHUNK_BYTES).
pub(crate) const MAX_IO: usize = 4 * 1024 * 1024;

/// A snapshot file being written or read.
enum Mode {
    /// A received snapshot, being written.
    Write(SealedWriter),
    /// A finished snapshot, open for reading.
    Read(SealedReader),
    /// A received snapshot, sealed and checked.
    Verified(Summary),
    /// A write failed or the file was closed.
    Closed,
}

/// The state the blocking pool works on.
struct Inner {
    mode: Mode,
    /// Bytes read ahead and not yet returned (read mode), or waiting to be
    /// written (write mode).
    buf: Vec<u8>,
    /// Bytes of `buf` already returned (read mode).
    buf_pos: usize,
}

enum State {
    Idle(Option<Box<Inner>>),
    Busy(JoinHandle<(Box<Inner>, io::Result<()>)>),
}

/// A Raft snapshot on disk: openraft's `SnapshotData`.
pub struct SnapshotFile {
    files: SealedFiles,
    path: PathBuf,
    state: State,
    /// A seek asked for with `start_seek`, not yet done.
    seek: Option<SeekFrom>,
    /// A read is on the blocking pool; its bytes go to the next `poll_read`.
    reading: bool,
}

impl fmt::Debug for SnapshotFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SnapshotFile {
    /// Creates an empty sealed file at `path` to receive a snapshot into.
    ///
    /// # Errors
    ///
    /// Any error creating the file.
    pub(crate) fn create(files: &SealedFiles, path: &Path) -> io::Result<Self> {
        let writer = files.create(path).map_err(io::Error::other)?;
        Ok(Self::new(files, path, Mode::Write(writer)))
    }

    /// Opens the finished sealed file at `path` to send it.
    ///
    /// # Errors
    ///
    /// Any error opening the file (see [`SealedFiles::open`]).
    pub(crate) fn open(files: &SealedFiles, path: &Path) -> io::Result<Self> {
        let reader = files.open(path).map_err(io::Error::other)?;
        Ok(Self::new(files, path, Mode::Read(reader)))
    }

    fn new(files: &SealedFiles, path: &Path, mode: Mode) -> Self {
        Self {
            files: files.clone(),
            path: path.to_path_buf(),
            state: State::Idle(Some(Box::new(Inner {
                mode,
                buf: Vec::new(),
                buf_pos: 0,
            }))),
            seek: None,
            reading: false,
        }
    }

    /// The check of a received file that `shutdown` made: its META, realms
    /// and rows. `None` before `shutdown` completed, or for a file opened
    /// to send.
    pub(crate) fn verified(&self) -> Option<&Summary> {
        match &self.state {
            State::Idle(Some(inner)) => match &inner.mode {
                Mode::Verified(summary) => Some(summary),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Waits for the blocking-pool call in flight, if any, and returns its
/// result.
fn poll_idle(state: &mut State, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if let State::Busy(handle) = state {
        let (inner, result) = ready!(Pin::new(handle).poll(cx)).map_err(io::Error::other)?;
        *state = State::Idle(Some(inner));
        return Poll::Ready(result);
    }
    Poll::Ready(Ok(()))
}

fn busy() -> io::Error {
    io::Error::other("snapshot file is busy")
}

/// The idle state. Call after [`poll_idle`] returned ready.
fn idle(state: &mut State) -> io::Result<&mut Inner> {
    match state {
        State::Idle(Some(inner)) => Ok(inner),
        _ => Err(busy()),
    }
}

/// Runs `op` on the blocking pool.
fn spawn<F>(state: &mut State, op: F) -> io::Result<()>
where
    F: FnOnce(&mut Inner) -> io::Result<()> + Send + 'static,
{
    let State::Idle(slot) = state else {
        return Err(busy());
    };
    let mut inner = slot.take().ok_or_else(busy)?;
    *state = State::Busy(tokio::task::spawn_blocking(move || {
        let result = op(&mut inner);
        if result.is_err() && matches!(inner.mode, Mode::Write(_)) {
            // A partly written file stays partial: refuse later calls.
            inner.mode = Mode::Closed;
        }
        (inner, result)
    }));
    Ok(())
}

fn wrong_mode(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, what)
}

/// Fills `inner.buf` with up to `want` bytes from the reader.
fn read_ahead(inner: &mut Inner, want: usize) -> io::Result<()> {
    inner.buf.clear();
    inner.buf.resize(want, 0);
    inner.buf_pos = 0;
    let Mode::Read(reader) = &mut inner.mode else {
        return Err(wrong_mode("snapshot file is not open for reading"));
    };
    let mut filled = 0;
    while filled < want {
        match reader.read(&mut inner.buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                inner.buf.clear();
                return Err(e);
            }
        }
    }
    inner.buf.truncate(filled);
    Ok(())
}

/// Seals a received file, syncs it and checks it from its first byte.
fn finish_and_verify(inner: &mut Inner, files: &SealedFiles) -> io::Result<()> {
    let Mode::Write(writer) = std::mem::replace(&mut inner.mode, Mode::Closed) else {
        return Err(wrong_mode("snapshot file is not open for writing"));
    };
    let path = writer.finish()?;
    let reader = files.open(&path).map_err(io::Error::other)?;
    let summary = snapshot_stream::verify(io::BufReader::with_capacity(SEALED_CHUNK_LEN, reader))?;
    inner.mode = Mode::Verified(summary);
    Ok(())
}

impl AsyncRead for SnapshotFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = ready!(poll_idle(&mut this.state, cx));
        let reading = std::mem::take(&mut this.reading);
        result?;
        let inner = idle(&mut this.state)?;
        if inner.buf_pos < inner.buf.len() {
            let take = out.remaining().min(inner.buf.len() - inner.buf_pos);
            out.put_slice(&inner.buf[inner.buf_pos..inner.buf_pos + take]);
            inner.buf_pos += take;
            return Poll::Ready(Ok(()));
        }
        if reading || out.remaining() == 0 {
            // A read just finished with no bytes: the end of the file.
            return Poll::Ready(Ok(()));
        }
        if !matches!(inner.mode, Mode::Read(_)) {
            return Poll::Ready(Err(wrong_mode("snapshot file is not open for reading")));
        }
        let want = out.remaining().min(MAX_IO);
        spawn(&mut this.state, move |inner| read_ahead(inner, want))?;
        this.reading = true;
        // Poll the task now so the waker is registered.
        Pin::new(this).poll_read(cx, out)
    }
}

impl AsyncWrite for SnapshotFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(poll_idle(&mut this.state, cx))?;
        let inner = idle(&mut this.state)?;
        if !matches!(inner.mode, Mode::Write(_)) {
            return Poll::Ready(Err(wrong_mode("snapshot file is not open for writing")));
        }
        let take = data.len().min(MAX_IO);
        inner.buf.clear();
        inner.buf.extend_from_slice(&data[..take]);
        spawn(&mut this.state, |inner| {
            let Mode::Write(writer) = &mut inner.mode else {
                return Err(wrong_mode("snapshot file is not open for writing"));
            };
            let result = writer.write_all(&inner.buf);
            inner.buf.clear();
            result
        })?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_idle(&mut self.get_mut().state, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(poll_idle(&mut this.state, cx))?;
        match idle(&mut this.state)?.mode {
            Mode::Write(_) => {}
            Mode::Read(_) | Mode::Verified(_) => return Poll::Ready(Ok(())),
            Mode::Closed => {
                return Poll::Ready(Err(io::Error::other("snapshot file write failed earlier")))
            }
        }
        let files = this.files.clone();
        spawn(&mut this.state, move |inner| {
            finish_and_verify(inner, &files)
        })?;
        Pin::new(this).poll_shutdown(cx)
    }
}

impl AsyncSeek for SnapshotFile {
    fn start_seek(self: Pin<&mut Self>, pos: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.seek.is_some() {
            return Err(io::Error::other(
                "a snapshot file seek is already in progress",
            ));
        }
        this.seek = Some(pos);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        ready!(poll_idle(&mut this.state, cx))?;
        let seek = this.seek.take();
        let inner = idle(&mut this.state)?;
        let target = match &mut inner.mode {
            Mode::Read(reader) => {
                // Bytes read ahead are not returned yet: the logical position
                // is behind the reader's by that much.
                let ahead = (inner.buf.len() - inner.buf_pos) as u64;
                let logical = reader.stream_position()? - ahead;
                let target = match seek {
                    None => return Poll::Ready(Ok(logical)),
                    Some(SeekFrom::Current(d)) => {
                        SeekFrom::Start(logical.checked_add_signed(d).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "seek before the start")
                        })?)
                    }
                    Some(other) => other,
                };
                inner.buf.clear();
                inner.buf_pos = 0;
                this.reading = false;
                return Poll::Ready(reader.seek(target));
            }
            Mode::Write(writer) => {
                let here = writer.position();
                match seek {
                    None | Some(SeekFrom::Current(0) | SeekFrom::End(0)) => {
                        return Poll::Ready(Ok(here))
                    }
                    Some(SeekFrom::Start(p)) if p == here => return Poll::Ready(Ok(here)),
                    Some(SeekFrom::Start(p)) => p,
                    Some(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "a received snapshot seeks only to an offset from its start",
                        )))
                    }
                }
            }
            Mode::Verified(_) | Mode::Closed => {
                return Poll::Ready(Err(wrong_mode("snapshot file is closed")))
            }
        };
        spawn(&mut this.state, move |inner| match &mut inner.mode {
            Mode::Write(writer) => writer.seek_to(target),
            _ => Err(wrong_mode("snapshot file is not open for writing")),
        })?;
        // `seek` is now empty: the next poll reports the new position.
        Pin::new(this).poll_complete(cx)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cluster::snapshot_stream::{Record, StreamReader, StreamWriter};
    use crate::core::RealmId;
    use openraft::{CommittedLeaderId, LogId, SnapshotMeta, StoredMembership};
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    fn files_in(dir: &Path) -> SealedFiles {
        SealedFiles::for_tests(dir)
    }

    fn meta(index: u64) -> snapshot_stream::Meta {
        SnapshotMeta {
            last_log_id: Some(LogId::new(CommittedLeaderId::new(2, 1), index)),
            last_membership: StoredMembership::default(),
            snapshot_id: format!("s-{index}"),
        }
    }

    /// A snapshot stream of `rows` rows in one realm, each with a 5,000-byte
    /// value that does not compress, so the stream crosses chunks.
    fn stream(rows: u32) -> Vec<u8> {
        let mut w = StreamWriter::new(Vec::new(), &meta(9)).unwrap();
        w.begin_realm(&RealmId::new(uuid::Uuid::from_u128(5)))
            .unwrap();
        let mut x = 0x9E37_79B9_7F4A_7C15_u64;
        for i in 0..rows {
            let value: Vec<u8> = (0..5_000)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x.to_le_bytes()[0]
                })
                .collect();
            w.row(format!("key-{i:06}").as_bytes(), &value).unwrap();
        }
        w.finish().unwrap()
    }

    /// Sends `bytes` the way openraft's receiver writes them: `chunk` bytes
    /// per request, each after a seek to its offset when it differs.
    async fn receive(file: &mut SnapshotFile, bytes: &[u8], chunk: usize) {
        let mut offset = 0u64;
        for part in bytes.chunks(chunk) {
            let at = file.stream_position().await.unwrap();
            if at != offset {
                file.seek(SeekFrom::Start(offset)).await.unwrap();
            }
            file.write_all(part).await.unwrap();
            offset += part.len() as u64;
        }
    }

    #[test]
    fn max_io_is_the_transfer_chunk() {
        assert_eq!(MAX_IO as u64, crate::cluster::wire::SNAPSHOT_CHUNK_BYTES);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_received_file_is_checked_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let bytes = stream(600);
        assert!(bytes.len() > 2 << 20, "the stream crosses transfer chunks");
        let path = dir.path().join("recv.part");
        let mut file = SnapshotFile::create(&files, &path).unwrap();
        receive(&mut file, &bytes, 1 << 20).await;
        assert!(file.verified().is_none(), "not checked before shutdown");
        file.shutdown().await.unwrap();
        let summary = file.verified().expect("checked at shutdown");
        assert_eq!(summary.meta, meta(9));
        assert_eq!(summary.rows, 600);

        // Sent back the way openraft's sender reads it.
        let mut sent = SnapshotFile::open(&files, &path).unwrap();
        let end = sent.seek(SeekFrom::End(0)).await.unwrap();
        assert_eq!(end, bytes.len() as u64);
        let mut got = Vec::new();
        let mut offset = 0u64;
        while offset < end {
            sent.seek(SeekFrom::Start(offset)).await.unwrap();
            let mut buf = Vec::with_capacity(1 << 20);
            while buf.capacity() > buf.len() {
                if sent.read_buf(&mut buf).await.unwrap() == 0 {
                    break;
                }
            }
            offset += buf.len() as u64;
            got.extend(buf);
        }
        assert_eq!(got, bytes);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resent_chunk_after_a_seek_back_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let bytes = stream(1_000);
        let path = dir.path().join("recv.part");
        let mut file = SnapshotFile::create(&files, &path).unwrap();
        let half = bytes.len() / 2;
        file.write_all(&bytes[..half]).await.unwrap();
        // The leader lost the answer and sends from an earlier offset again.
        let back = (half / 3) as u64;
        file.seek(SeekFrom::Start(back)).await.unwrap();
        file.write_all(&bytes[half / 3..]).await.unwrap();
        file.shutdown().await.unwrap();
        assert_eq!(file.verified().unwrap().rows, 1_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bad_transfer_fails_at_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let mut bytes = stream(200);
        let at = bytes.len() / 2;
        bytes[at] ^= 0x10;
        let path = dir.path().join("recv.part");
        let mut file = SnapshotFile::create(&files, &path).unwrap();
        receive(&mut file, &bytes, 64 * 1024).await;
        assert!(
            file.shutdown().await.is_err(),
            "a corrupt stream is refused"
        );
        assert!(file.verified().is_none());

        let mut cut = SnapshotFile::create(&files, &path).unwrap();
        let good = stream(200);
        cut.write_all(&good[..good.len() - 10]).await.unwrap();
        assert!(cut.shutdown().await.is_err(), "a cut stream is refused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_seek_past_the_written_end_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let mut file = SnapshotFile::create(&files, &dir.path().join("p")).unwrap();
        file.write_all(b"abc").await.unwrap();
        let err = file.seek(SeekFrom::Start(100)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // The file is closed after a failed call; shutdown says so.
        assert!(file.shutdown().await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_received_file_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("recv.part");
        let mut file = SnapshotFile::create(&files, &path).unwrap();
        let bytes = stream(50);
        file.write_all(&bytes).await.unwrap();
        file.shutdown().await.unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(8).any(|w| w == b"HRSNAP01"),
            "stream magic is sealed"
        );
        assert!(
            !raw.windows(10).any(|w| w == b"key-000001"),
            "keys are sealed"
        );

        // And it still decodes through the stream reader.
        let reader = files.open(&path).unwrap();
        let mut r = StreamReader::new(reader).unwrap();
        assert!(matches!(r.next_record().unwrap(), Some(Record::Realm(_))));
    }
}
