//! Encrypted node-local files with random access (`cluster-file-snapshots`).
//!
//! A sealed file holds bytes that only this node needs to read back, such as
//! a Raft snapshot. It is encrypted the way SST and WAL files are: a random
//! data key per file, wrapped by the system realm's KEK.
//!
//! # Layout
//!
//! ```text
//! magic          ( 8 bytes, "HSEALF01")
//! key header     (76 bytes, the SST/WAL encryption header: KEK id, nonce, wrapped key, tag)
//! chunk*         (one or more)
//! ```
//!
//! Each chunk is a 12-byte random nonce, the AES-256-GCM ciphertext of
//! [`CHUNK_LEN`] plaintext bytes (the last chunk: 0 to [`CHUNK_LEN`]), and a
//! 16-byte tag. The additional authenticated data of chunk `i` is the file
//! header, `i` as a big-endian `u64` and a last-chunk flag:
//!
//! - a changed chunk fails its tag;
//! - a moved, dropped or repeated chunk has another index in its AAD;
//! - a file cut after a chunk that is not the last has no chunk sealed as
//!   last, so its final chunk fails its tag;
//! - a chunk from another file has another header in its AAD.
//!
//! Every chunk but the last has the same size, so plaintext offset `p` is in
//! chunk `p / CHUNK_LEN` and a seek needs no index. The nonce is random per
//! chunk, so a chunk written again after a backward seek never reuses one.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::core::RealmId;
use crate::storage::encryption::{
    self, EncryptionHeader, ENCRYPTION_HEADER_SIZE, NONCE_SIZE, TAG_SIZE,
};
use crate::storage::fs::{Fs, FsFile};
use crate::storage::key_registry::KeyRegistry;
use crate::storage::StorageError;

/// Plaintext bytes in each chunk except the last one.
pub const CHUNK_LEN: usize = 64 * 1024;

/// The first bytes of every sealed file.
const MAGIC: &[u8; 8] = b"HSEALF01";
/// Bytes of the file header: magic and the wrapped-key header.
const HEADER_LEN: usize = MAGIC.len() + ENCRYPTION_HEADER_SIZE;
/// Bytes a chunk adds to its plaintext: nonce and tag.
const CHUNK_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;
/// Bytes of a full chunk on disk.
const FULL_CHUNK: u64 = (CHUNK_LEN + CHUNK_OVERHEAD) as u64;
/// Bytes of a chunk's additional authenticated data.
const AAD_LEN: usize = HEADER_LEN + 8 + 1;

/// Opens and creates sealed files under the node's system KEK.
///
/// Obtained from [`EmbeddedStorageEngine::sealed_files`](crate::storage::EmbeddedStorageEngine::sealed_files).
/// File I/O goes through the engine's [`Fs`], so fault-injection tests cover it.
#[derive(Clone)]
pub struct SealedFiles {
    fs: Arc<dyn Fs>,
    key_registry: Arc<KeyRegistry>,
    system_realm: RealmId,
}

impl SealedFiles {
    /// Sealed files keyed by `system_realm`'s KEK in `key_registry`.
    pub(crate) fn new(
        fs: Arc<dyn Fs>,
        key_registry: Arc<KeyRegistry>,
        system_realm: RealmId,
    ) -> Self {
        Self {
            fs,
            key_registry,
            system_realm,
        }
    }

    /// Sealed files over a fresh dev key registry in `dir`, for tests.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn for_tests(dir: &Path) -> Self {
        Self::for_tests_with(dir, Arc::new(crate::storage::fs::RealFs))
    }

    /// Sealed files for tests over `fs`, keyed by a fresh system KEK kept in
    /// `dir`.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn for_tests_with(dir: &Path, fs: Arc<dyn Fs>) -> Self {
        let registry = Arc::new(KeyRegistry::load_with_fs(dir, Arc::clone(&fs), true).unwrap());
        let realm = RealmId::new(uuid::Uuid::from_u128(1));
        registry.ensure_kek_for_realm(&realm).unwrap();
        Self::new(fs, registry, realm)
    }

    /// The filesystem the files live on (for renames, listings and directory
    /// syncs).
    #[must_use]
    pub fn fs(&self) -> &Arc<dyn Fs> {
        &self.fs
    }

    /// Creates (or truncates) the sealed file at `path` with a new data key.
    ///
    /// # Errors
    ///
    /// [`StorageError::Crypto`] when no system KEK is registered or a key
    /// cannot be made, and [`StorageError::Io`] when the file cannot be
    /// created or its header written.
    pub fn create(&self, path: &Path) -> Result<SealedWriter, StorageError> {
        let kek = self
            .key_registry
            .get_kek_for_realm(&self.system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "system KEK not found for a sealed file".to_string(),
            })?;
        let kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
        let dek = encryption::generate_dek()?;
        let wrapped = encryption::wrap_dek(&dek, &kek, kek_id)?;
        let header = file_header(&wrapped);
        let mut file = self.fs.create(path)?;
        file.write_all(&header)?;
        Ok(SealedWriter {
            fs: Arc::clone(&self.fs),
            path: path.to_path_buf(),
            file,
            key: aead_key(dek.as_bytes())?,
            header,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_LEN + CHUNK_OVERHEAD)),
        })
    }

    /// Opens the finished sealed file at `path` for reading.
    ///
    /// Checks the magic, unwraps the data key and the file's length. Chunk
    /// tags are checked as chunks are read.
    ///
    /// # Errors
    ///
    /// [`StorageError::DeserializationFailed`] for a file that is not a sealed file or is
    /// cut inside its header, [`StorageError::Crypto`] when its KEK is not
    /// registered or its key does not unwrap, and [`StorageError::Io`].
    pub fn open(&self, path: &Path) -> Result<SealedReader, StorageError> {
        let mut file = self.fs.open_read(path)?;
        let mut header = [0u8; HEADER_LEN];
        read_exact(&mut *file, &mut header).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => corrupted("sealed file is shorter than its header"),
            _ => StorageError::Io(e),
        })?;
        if &header[..MAGIC.len()] != MAGIC {
            return Err(corrupted("not a sealed file (bad magic)"));
        }
        let mut key_header = [0u8; ENCRYPTION_HEADER_SIZE];
        key_header.copy_from_slice(&header[MAGIC.len()..]);
        let wrapped = EncryptionHeader::from_bytes(&key_header);
        let kek_realm = RealmId::new(uuid::Uuid::from_bytes(wrapped.kek_id));
        let kek = self
            .key_registry
            .get_kek_for_realm(&kek_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "the KEK of a sealed file is not registered".to_string(),
            })?;
        let dek = encryption::unwrap_dek(&wrapped, &kek)?;

        let file_len = file.seek(SeekFrom::End(0))?;
        let body = file_len
            .checked_sub(HEADER_LEN as u64)
            .ok_or_else(|| corrupted("sealed file is shorter than its header"))?;
        if body < CHUNK_OVERHEAD as u64 {
            return Err(corrupted("sealed file has no last chunk"));
        }
        let chunks = body.div_ceil(FULL_CHUNK);
        let last_chunk = body - (chunks - 1) * FULL_CHUNK;
        if last_chunk < CHUNK_OVERHEAD as u64 {
            return Err(corrupted("sealed file ends inside a chunk"));
        }
        let len = (chunks - 1) * CHUNK_LEN as u64 + (last_chunk - CHUNK_OVERHEAD as u64);
        Ok(SealedReader {
            file,
            key: aead_key(dek.as_bytes())?,
            header,
            chunks,
            last_chunk,
            len,
            pos: 0,
            cached: None,
        })
    }
}

/// Writes a sealed file in order, one chunk of plaintext in memory.
///
/// Call [`finish`](Self::finish): a file dropped without it has no last
/// chunk, and [`SealedFiles::open`] or the first read past its end refuses it.
pub struct SealedWriter {
    fs: Arc<dyn Fs>,
    path: PathBuf,
    file: Box<dyn FsFile>,
    key: LessSafeKey,
    header: [u8; HEADER_LEN],
    /// Index of the chunk whose plaintext is in `buf`.
    index: u64,
    /// Plaintext of chunk `index` (at most [`CHUNK_LEN`] bytes).
    buf: Zeroizing<Vec<u8>>,
}

impl SealedWriter {
    /// The plaintext bytes written so far (the next write's offset).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.index * CHUNK_LEN as u64 + self.buf.len() as u64
    }

    /// The file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves the write position back to `pos`; the bytes after it are
    /// dropped and the next write replaces them.
    ///
    /// openraft seeks back when the leader sends a chunk again after a lost
    /// answer. A seek forward, past the bytes written, is refused.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for a seek past the written end, and
    /// any error reading back or truncating the file.
    pub fn seek_to(&mut self, pos: u64) -> io::Result<()> {
        let end = self.position();
        if pos == end {
            return Ok(());
        }
        if pos > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a sealed file cannot seek past the bytes written",
            ));
        }
        let chunk = pos / CHUNK_LEN as u64;
        let within = usize::try_from(pos % CHUNK_LEN as u64)
            .map_err(|_| io::Error::other("chunk offset does not fit in usize"))?;
        if chunk == self.index {
            self.buf.truncate(within);
            return Ok(());
        }
        // `chunk` is sealed: read its plaintext back, then cut the file at it.
        let start = chunk_start(chunk);
        let mut sealed = Zeroizing::new(vec![
            0u8;
            usize::try_from(FULL_CHUNK)
                .map_err(io::Error::other)?
        ]);
        {
            let mut reader = self.fs.open_read(&self.path)?;
            reader.seek(SeekFrom::Start(start))?;
            read_exact(&mut *reader, &mut sealed)?;
        }
        let plain = open_chunk(&self.key, &self.header, chunk, false, &mut sealed)?;
        self.buf.clear();
        self.buf.extend_from_slice(&plain[..within]);
        self.file.set_len(start)?;
        self.file.seek(SeekFrom::Start(start))?;
        self.index = chunk;
        Ok(())
    }

    /// Seals the last chunk and syncs the file to disk.
    ///
    /// # Errors
    ///
    /// Any error writing or syncing the file.
    pub fn finish(mut self) -> io::Result<PathBuf> {
        self.seal(true)?;
        self.file.sync_all()?;
        Ok(self.path)
    }

    /// Seals `buf` as chunk `index` and appends it to the file.
    fn seal(&mut self, last: bool) -> io::Result<()> {
        let mut nonce = [0u8; NONCE_SIZE];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("nonce generation failed"))?;
        let aad = chunk_aad(&self.header, self.index, last);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..]),
                &mut *self.buf,
            )
            .map_err(|_| io::Error::other("chunk encryption failed"))?;
        self.file.write_all(&nonce)?;
        self.file.write_all(&self.buf)?;
        self.buf.clear();
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("sealed file has too many chunks"))?;
        Ok(())
    }
}

impl Write for SealedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            // A full chunk is sealed only once more data arrives: until then
            // it may be the last one.
            if self.buf.len() == CHUNK_LEN {
                self.seal(false)?;
            }
            let take = rest.len().min(CHUNK_LEN - self.buf.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads a finished sealed file, with random access by plaintext offset.
///
/// Holds one decrypted chunk in memory. Each chunk's tag is checked when it
/// is read; a chunk that fails is reported as [`io::ErrorKind::InvalidData`].
pub struct SealedReader {
    file: Box<dyn FsFile>,
    key: LessSafeKey,
    header: [u8; HEADER_LEN],
    /// Number of chunks in the file.
    chunks: u64,
    /// Bytes of the last chunk on disk (nonce, ciphertext, tag).
    last_chunk: u64,
    /// Plaintext length of the file.
    len: u64,
    /// Plaintext offset of the next read.
    pos: u64,
    /// The last chunk decrypted: its index and plaintext.
    cached: Option<(u64, Zeroizing<Vec<u8>>)>,
}

impl SealedReader {
    /// The plaintext length of the file.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the file holds no plaintext.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Decrypts chunk `index` into the cache unless it is there already.
    fn load(&mut self, index: u64) -> io::Result<&[u8]> {
        if self.cached.as_ref().is_none_or(|(i, _)| *i != index) {
            let last = index + 1 == self.chunks;
            let on_disk = if last { self.last_chunk } else { FULL_CHUNK };
            let mut sealed = Zeroizing::new(vec![
                0u8;
                usize::try_from(on_disk)
                    .map_err(io::Error::other)?
            ]);
            self.file.seek(SeekFrom::Start(chunk_start(index)))?;
            read_exact(&mut *self.file, &mut sealed)?;
            let plain = open_chunk(&self.key, &self.header, index, last, &mut sealed)?.to_vec();
            self.cached = Some((index, Zeroizing::new(plain)));
        }
        // The branch above filled the cache with chunk `index`.
        Ok(self.cached.as_ref().map_or(&[][..], |(_, p)| p.as_slice()))
    }
}

impl Read for SealedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.pos >= self.len {
            // A file whose last chunk was never read has not been checked to
            // the end: check it on the read that reports the end.
            if self.pos >= self.len && !out.is_empty() {
                self.load(self.chunks - 1)?;
            }
            return Ok(0);
        }
        let mut written = 0;
        while written < out.len() && self.pos < self.len {
            let index = self.pos / CHUNK_LEN as u64;
            let within = usize::try_from(self.pos % CHUNK_LEN as u64).map_err(io::Error::other)?;
            let chunk = self.load(index)?;
            let take = (chunk.len() - within).min(out.len() - written);
            out[written..written + take].copy_from_slice(&chunk[within..within + take]);
            written += take;
            self.pos += take as u64;
        }
        Ok(written)
    }
}

impl Seek for SealedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = target
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn corrupted(reason: &str) -> StorageError {
    StorageError::DeserializationFailed {
        reason: reason.to_string(),
    }
}

fn file_header(wrapped: &EncryptionHeader) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()..].copy_from_slice(&wrapped.to_bytes());
    header
}

fn aead_key(dek: &[u8; 32]) -> io::Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|_| io::Error::other("sealed file key initialisation failed"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Byte offset of chunk `index` in the file.
fn chunk_start(index: u64) -> u64 {
    HEADER_LEN as u64 + index * FULL_CHUNK
}

fn chunk_aad(header: &[u8; HEADER_LEN], index: u64, last: bool) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header);
    aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_be_bytes());
    aad[AAD_LEN - 1] = u8::from(last);
    aad
}

/// Checks and decrypts one sealed chunk (nonce, ciphertext, tag) in place and
/// returns its plaintext.
fn open_chunk<'a>(
    key: &LessSafeKey,
    header: &[u8; HEADER_LEN],
    index: u64,
    last: bool,
    sealed: &'a mut [u8],
) -> io::Result<&'a [u8]> {
    if sealed.len() < CHUNK_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed chunk is too short",
        ));
    }
    let (nonce, body) = sealed.split_at_mut(NONCE_SIZE);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(nonce);
    let aad = chunk_aad(header, index, last);
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad[..]),
            body,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed chunk failed its authentication check",
            )
        })?;
    Ok(plain)
}

/// Fills `buf` from `file`, or fails with [`io::ErrorKind::UnexpectedEof`].
fn read_exact(file: &mut dyn FsFile, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sealed file ends early",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn files_in(dir: &Path) -> SealedFiles {
        SealedFiles::for_tests(dir)
    }

    /// Deterministic, non-repeating test bytes.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap())
            .collect()
    }

    fn write_file(files: &SealedFiles, path: &Path, data: &[u8], piece: usize) {
        let mut w = files.create(path).unwrap();
        for part in data.chunks(piece.max(1)) {
            w.write_all(part).unwrap();
        }
        if data.is_empty() {
            w.write_all(&[]).unwrap();
        }
        w.finish().unwrap();
    }

    fn read_all(files: &SealedFiles, path: &Path) -> io::Result<Vec<u8>> {
        let mut r = files.open(path).map_err(io::Error::other)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn round_trips_every_length_class() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 17,
        ] {
            let path = dir.path().join(format!("f-{len}"));
            let data = pattern(len);
            write_file(&files, &path, &data, 10_000);
            let reader = files.open(&path).unwrap();
            assert_eq!(reader.len(), len as u64, "length of a {len}-byte file");
            assert_eq!(read_all(&files, &path).unwrap(), data, "{len}-byte file");
        }
    }

    #[test]
    fn a_seek_reads_from_any_offset() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let data = pattern(5 * CHUNK_LEN + 123);
        write_file(&files, &path, &data, 4096);
        let mut r = files.open(&path).unwrap();
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), data.len() as u64);
        for start in [
            0,
            1,
            CHUNK_LEN - 3,
            CHUNK_LEN,
            2 * CHUNK_LEN + 999,
            data.len() - 5,
        ] {
            r.seek(SeekFrom::Start(start as u64)).unwrap();
            let mut got = vec![0u8; (CHUNK_LEN + 10).min(data.len() - start)];
            r.read_exact(&mut got).unwrap();
            assert_eq!(got, data[start..start + got.len()], "read at {start}");
        }
        r.seek(SeekFrom::Start(data.len() as u64 + 10)).unwrap();
        let mut one = [0u8; 1];
        assert_eq!(r.read(&mut one).unwrap(), 0, "a read past the end is empty");
    }

    #[test]
    fn a_backward_seek_while_writing_replaces_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let data = pattern(4 * CHUNK_LEN + 50);
        let mut w = files.create(&path).unwrap();
        w.write_all(&data).unwrap();
        // Back into a sealed chunk, mid-chunk, then into the open chunk, then
        // to a chunk boundary, writing the original bytes again each time.
        for back in [CHUNK_LEN + 77, 4 * CHUNK_LEN + 10, 2 * CHUNK_LEN] {
            w.seek_to(back as u64).unwrap();
            assert_eq!(w.position(), back as u64);
            w.write_all(&data[back..]).unwrap();
        }
        let ahead = w.position() + 1;
        let err = w.seek_to(ahead).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        w.finish().unwrap();
        assert_eq!(read_all(&files, &path).unwrap(), data);
    }

    #[test]
    fn the_file_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let marker = b"plaintext-marker-6c1f";
        let data: Vec<u8> = marker.iter().copied().cycle().take(3 * CHUNK_LEN).collect();
        write_file(&files, &path, &data, 1000);
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker),
            "a sealed file must not hold its plaintext"
        );
    }

    /// Writes a three-chunk file and returns its raw bytes.
    fn three_chunks(files: &SealedFiles, path: &Path) -> (Vec<u8>, Vec<u8>) {
        let data = pattern(2 * CHUNK_LEN + 100);
        write_file(files, path, &data, 50_000);
        (data, std::fs::read(path).unwrap())
    }

    fn assert_refused(files: &SealedFiles, path: &Path, what: &str) {
        let result = read_all(files, path);
        assert!(result.is_err(), "{what} must be refused, got {result:?}");
    }

    #[test]
    fn a_changed_byte_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let (_, raw) = three_chunks(&files, &path);
        for at in [HEADER_LEN + 3, HEADER_LEN + 20, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[at] ^= 0x01;
            std::fs::write(&path, &bad).unwrap();
            assert_refused(&files, &path, &format!("a flipped byte at {at}"));
        }
    }

    #[test]
    fn a_dropped_swapped_or_appended_chunk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let (_, raw) = three_chunks(&files, &path);
        let full = usize::try_from(FULL_CHUNK).unwrap();
        let (head, body) = raw.split_at(HEADER_LEN);
        let c0 = &body[..full];
        let c1 = &body[full..2 * full];
        let c2 = &body[2 * full..];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("chunk 1 dropped", [head, c0, c2].concat()),
            ("chunks 0 and 1 swapped", [head, c1, c0, c2].concat()),
            ("cut after a full chunk", [head, c0, c1].concat()),
            ("a chunk appended", [head, c0, c1, c2, c2].concat()),
            ("cut inside a chunk", [head, c0, &c1[..100]].concat()),
            ("no chunk", head.to_vec()),
        ];
        for (what, bytes) in cases {
            std::fs::write(&path, &bytes).unwrap();
            assert_refused(&files, &path, what);
        }
    }

    #[test]
    fn a_file_without_finish_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        let mut w = files.create(&path).unwrap();
        w.write_all(&pattern(2 * CHUNK_LEN + 5)).unwrap();
        drop(w);
        assert_refused(&files, &path, "a file never finished");
    }

    #[test]
    fn a_file_from_another_node_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        write_file(&files, &path, &pattern(1000), 1000);
        let theirs = files_in(other.path());
        assert!(
            theirs.open(&path).is_err(),
            "another node's KEK must not open this file"
        );
    }

    #[test]
    fn a_chunk_from_another_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        let (_, raw_a) = three_chunks(&files, &a);
        let (_, raw_b) = three_chunks(&files, &b);
        let full = usize::try_from(FULL_CHUNK).unwrap();
        let mut mixed = raw_a.clone();
        mixed[HEADER_LEN..HEADER_LEN + full].copy_from_slice(&raw_b[HEADER_LEN..HEADER_LEN + full]);
        std::fs::write(&a, &mixed).unwrap();
        assert_refused(&files, &a, "a chunk taken from another file");
    }

    #[test]
    fn a_file_that_is_not_sealed_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let files = files_in(dir.path());
        let path = dir.path().join("f");
        std::fs::write(&path, vec![0u8; 500]).unwrap();
        assert!(matches!(
            files.open(&path),
            Err(StorageError::DeserializationFailed { .. })
        ));
        std::fs::write(&path, b"HSEALF01").unwrap();
        assert!(matches!(
            files.open(&path),
            Err(StorageError::DeserializationFailed { .. })
        ));
    }
}
