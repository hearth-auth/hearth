//! Chunked AEAD encryption for archive members (#866).
//!
//! An archive member is encrypted as a stream of chunks, so that neither the
//! export nor the restore holds a whole member in memory.
//!
//! # Member layout
//!
//! ```text
//! magic         ( 8 bytes, "HBKSTRM1")
//! nonce prefix  ( 7 bytes, random, one per member)
//! chunk*        (one or more)
//! ```
//!
//! Each chunk is:
//!
//! ```text
//! last flag     ( 1 byte, 0 or 1)
//! length        ( 4 bytes, little-endian u32: the length of the sealed bytes)
//! sealed bytes  (AES-256-GCM ciphertext of at most CHUNK_LEN bytes + 16-byte tag)
//! ```
//!
//! The nonce of chunk `i` is `prefix (7) || i as big-endian u32 (4) || last
//! flag (1)`, and the additional authenticated data is the member's archive
//! path. This is the STREAM construction of Hoang, Reyhanitabar, Rogaway and
//! Vizár ("Online authenticated-encryption and its nonce-reuse
//! misuse-resistance", CRYPTO 2015), as `aead::stream::StreamBE32` uses it.
//!
//! - A changed chunk fails its tag.
//! - A reordered, repeated or removed chunk has a different index in its
//!   nonce, so it fails its tag.
//! - A member cut after a chunk that is not the last ends without a chunk that
//!   was sealed as last, and the reader refuses it. Bytes after the last chunk
//!   are refused too.
//! - A changed last flag gives a different nonce, so the chunk fails its tag.
//! - A member moved to another path fails the tag of its first chunk, because
//!   the path is the additional authenticated data.
//!
//! Every chunk except the last holds exactly [`CHUNK_LEN`] plaintext bytes.
//! The last chunk holds 0 to [`CHUNK_LEN`] bytes, so an empty member is one
//! empty last chunk.

use std::io::{self, BufRead, Read, Write};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use super::BackupError;

/// Plaintext bytes in each chunk except the last one.
pub const CHUNK_LEN: usize = 64 * 1024;

/// The first bytes of every encrypted member.
const MAGIC: &[u8; 8] = b"HBKSTRM1";
/// Bytes of the random nonce prefix of a member.
const PREFIX_LEN: usize = 7;
/// Bytes of the AES-GCM tag of each chunk.
const TAG_LEN: usize = 16;
/// Bytes of the frame header before each chunk (last flag + length).
const FRAME_LEN: usize = 5;

/// Makes the AES-256-GCM key for `dek`.
fn aead_key(dek: &[u8; 32]) -> Result<LessSafeKey, BackupError> {
    let unbound = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|_| BackupError::Crypto("key initialisation failed".into()))?;
    Ok(LessSafeKey::new(unbound))
}

/// The nonce of chunk `index` of the member with nonce prefix `prefix`.
fn chunk_nonce(prefix: [u8; PREFIX_LEN], index: u32, last: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..PREFIX_LEN].copy_from_slice(&prefix);
    nonce[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

/// A [`Write`] that encrypts what it gets into chunks and writes them to an
/// inner writer.
///
/// It holds one chunk of plaintext at a time. Call
/// [`finish`](Self::finish) to seal the last chunk: a member that is dropped
/// without `finish` has no last chunk, and a restore refuses it.
pub struct EncryptWriter<W: Write> {
    inner: W,
    key: LessSafeKey,
    aad: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
    index: u32,
    /// The plaintext of the current chunk, then its ciphertext and tag.
    buf: Zeroizing<Vec<u8>>,
}

impl<W: Write> EncryptWriter<W> {
    /// Writes the member header to `inner` and returns a writer that encrypts
    /// with `dek` for the member at `archive_path`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Crypto`] when the random nonce prefix cannot be made,
    /// and [`BackupError::Io`] when `inner` refuses the header.
    pub fn new(mut inner: W, dek: &[u8; 32], archive_path: &str) -> Result<Self, BackupError> {
        let mut prefix = [0u8; PREFIX_LEN];
        SystemRandom::new()
            .fill(&mut prefix)
            .map_err(|_| BackupError::Crypto("nonce generation failed".into()))?;
        inner.write_all(MAGIC)?;
        inner.write_all(&prefix)?;
        Ok(Self {
            inner,
            key: aead_key(dek)?,
            aad: archive_path.as_bytes().to_vec(),
            prefix,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_LEN + TAG_LEN)),
        })
    }

    /// Seals the bytes in `buf` as chunk `index` and writes the chunk.
    fn seal_chunk(&mut self, last: bool) -> io::Result<()> {
        let nonce = chunk_nonce(self.prefix, self.index, last);
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(self.aad.as_slice()), &mut *self.buf)
            .map_err(|_| io::Error::other("chunk encryption failed"))?;
        let len = u32::try_from(self.buf.len())
            .map_err(|_| io::Error::other("chunk length does not fit in u32"))?;
        self.inner.write_all(&[u8::from(last)])?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(&self.buf)?;
        // The buffer now holds ciphertext, but clear it the same way as
        // plaintext: the next chunk starts empty.
        self.buf.zeroize();
        self.buf.clear();
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("member has too many chunks"))?;
        Ok(())
    }

    /// Seals the last chunk and returns the inner writer, flushed.
    ///
    /// # Errors
    ///
    /// [`BackupError::Io`] when the chunk cannot be sealed or written.
    pub fn finish(mut self) -> Result<W, BackupError> {
        self.seal_chunk(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full chunk is sealed only when more bytes follow it, so that the
        // chunk `finish` seals is never an extra empty one after a full one
        // unless the member is empty.
        if self.buf.len() == CHUNK_LEN {
            self.seal_chunk(false)?;
        }
        let take = data.len().min(CHUNK_LEN - self.buf.len());
        self.buf.extend_from_slice(&data[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        // A chunk is sealed only when it is full or the member ends, so a
        // flush cannot write the partial chunk.
        self.inner.flush()
    }
}

/// A [`Read`] that decrypts a member written by [`EncryptWriter`].
///
/// It holds one chunk at a time. It returns an error, and no more bytes, for
/// a chunk that fails its tag, a member that ends before its last chunk, and
/// bytes after the last chunk. Bytes of earlier chunks were already returned
/// when such an error comes, so a caller that acts on the bytes must not keep
/// the result of a read that ended in an error.
pub struct DecryptReader<R: Read> {
    inner: R,
    key: LessSafeKey,
    aad: Vec<u8>,
    prefix: [u8; PREFIX_LEN],
    index: u32,
    /// The plaintext of the current chunk.
    buf: Zeroizing<Vec<u8>>,
    /// The next byte of `buf` to return.
    pos: usize,
    /// The last chunk was read and checked.
    done: bool,
    /// A chunk was refused: every later read is an error.
    failed: bool,
}

impl<R: Read> DecryptReader<R> {
    /// Reads the member header from `inner` and returns a reader that
    /// decrypts with `dek` the member at `archive_path`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Crypto`] when the header is absent or is not the header
    /// of a chunked member (an archive from an older Hearth).
    pub fn new(mut inner: R, dek: &[u8; 32], archive_path: &str) -> Result<Self, BackupError> {
        let mut header = [0u8; MAGIC.len() + PREFIX_LEN];
        read_exact_or(&mut inner, &mut header, || {
            BackupError::Crypto(format!(
                "member {archive_path} is too short to be an encrypted member"
            ))
        })?;
        if &header[..MAGIC.len()] != MAGIC {
            return Err(BackupError::Crypto(format!(
                "member {archive_path} is not in the chunked encryption format of this \
                 Hearth version"
            )));
        }
        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(&header[MAGIC.len()..]);
        Ok(Self {
            inner,
            key: aead_key(dek)?,
            aad: archive_path.as_bytes().to_vec(),
            prefix,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_LEN + TAG_LEN)),
            pos: 0,
            done: false,
            failed: false,
        })
    }

    /// The archive path, for error messages.
    fn path(&self) -> String {
        String::from_utf8_lossy(&self.aad).into_owned()
    }

    /// Reads, checks and decrypts the next chunk into `buf`.
    fn next_chunk(&mut self) -> Result<(), BackupError> {
        let truncated = || {
            BackupError::Crypto(format!(
                "member {} ends before its last chunk: the archive is truncated or changed",
                String::from_utf8_lossy(&self.aad)
            ))
        };
        let mut frame = [0u8; FRAME_LEN];
        read_exact_or(&mut self.inner, &mut frame, truncated)?;
        let last = match frame[0] {
            0 => false,
            1 => true,
            _ => {
                return Err(BackupError::Crypto(format!(
                    "member {} has a chunk with a bad frame",
                    self.path()
                )))
            }
        };
        let len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        if !(TAG_LEN..=CHUNK_LEN + TAG_LEN).contains(&len) {
            return Err(BackupError::Crypto(format!(
                "member {} has a chunk with a bad length",
                self.path()
            )));
        }
        self.buf.zeroize();
        self.buf.clear();
        self.buf.resize(len, 0);
        read_exact_or(&mut self.inner, self.buf.as_mut_slice(), truncated)?;
        let nonce = chunk_nonce(self.prefix, self.index, last);
        let opened = self
            .key
            .open_in_place(
                nonce,
                Aad::from(self.aad.as_slice()),
                self.buf.as_mut_slice(),
            )
            .map(|plain| plain.len());
        let Ok(plain_len) = opened else {
            return Err(BackupError::Crypto(format!(
                "decryption of member {} failed: wrong DEK, or the archive is changed \
                 (a chunk is changed, reordered or missing)",
                self.path()
            )));
        };
        if !last && plain_len != CHUNK_LEN {
            return Err(BackupError::Crypto(format!(
                "member {} has a short chunk before its last chunk",
                self.path()
            )));
        }
        self.buf.truncate(plain_len);
        self.pos = 0;
        self.index = self.index.checked_add(1).ok_or_else(|| {
            BackupError::Crypto(format!("member {} has too many chunks", self.path()))
        })?;
        if last {
            let mut extra = [0u8; 1];
            if read_some(&mut self.inner, &mut extra)? != 0 {
                return Err(BackupError::Crypto(format!(
                    "member {} has bytes after its last chunk",
                    self.path()
                )));
            }
            self.done = true;
        }
        Ok(())
    }

    /// Reads the whole member into memory.
    ///
    /// For small members only (keys, `realm.json`): the result grows with the
    /// member.
    ///
    /// # Errors
    ///
    /// As [`next_chunk`](Self::next_chunk), with the [`BackupError::Crypto`]
    /// variant kept.
    pub fn read_all(mut self) -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let mut out = Zeroizing::new(Vec::new());
        while !self.done {
            self.next_chunk()?;
            out.extend_from_slice(&self.buf);
        }
        Ok(out)
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = out.len().min(available.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

/// Reads lines straight from the chunk buffer, which is zeroed after each
/// chunk: a `BufReader` around the reader would keep a copy of the plaintext
/// in a buffer that is not zeroed.
impl<R: Read> BufRead for DecryptReader<R> {
    /// The error of a refused chunk is an [`io::ErrorKind::InvalidData`]
    /// error that carries the [`BackupError`]; [`BackupError::from_read`]
    /// takes it back out.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos == self.buf.len() {
            if self.failed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    BackupError::Crypto(format!(
                        "member {} was refused at an earlier chunk",
                        self.path()
                    )),
                ));
            }
            if self.done {
                return Ok(&[]);
            }
            if let Err(e) = self.next_chunk() {
                // Drop the refused chunk: no byte of it is returned later.
                self.failed = true;
                self.buf.zeroize();
                self.buf.clear();
                self.pos = 0;
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.buf.len());
    }
}

/// Reads `buf.len()` bytes, or returns `short()` when the input ends first.
fn read_exact_or(
    inner: &mut impl Read,
    buf: &mut [u8],
    short: impl FnOnce() -> BackupError,
) -> Result<(), BackupError> {
    match inner.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(short()),
        Err(e) => Err(BackupError::Io(e)),
    }
}

/// Reads into `buf` once, retrying on interruption.
fn read_some(inner: &mut impl Read, buf: &mut [u8]) -> Result<usize, BackupError> {
    loop {
        match inner.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(BackupError::Io(e)),
        }
    }
}

/// Encrypts `plaintext` as the member at `archive_path` and returns the
/// whole encrypted member.
///
/// For small members and tests: the result grows with `plaintext`.
///
/// # Errors
///
/// As [`EncryptWriter::new`] and [`EncryptWriter::finish`].
pub fn encrypt_member(
    archive_path: &str,
    plaintext: &[u8],
    dek: &[u8; 32],
) -> Result<Vec<u8>, BackupError> {
    let mut writer = EncryptWriter::new(Vec::new(), dek, archive_path)?;
    writer.write_all(plaintext)?;
    writer.finish()
}

/// Decrypts the whole member at `archive_path`, written by
/// [`EncryptWriter`] or [`encrypt_member`].
///
/// Returns a [`Zeroizing`] buffer, because members carry key material and
/// credentials. For small members only: the result grows with the member.
///
/// # Errors
///
/// [`BackupError::Crypto`] when the member is not a chunked member, a chunk
/// fails its tag, or the member is truncated or has extra bytes.
pub fn decrypt_member(
    archive_path: &str,
    encrypted: &[u8],
    dek: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    DecryptReader::new(encrypted, dek, archive_path)?.read_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "realms/acme/users.ndjson";

    fn dek() -> [u8; 32] {
        let mut dek = [0u8; 32];
        SystemRandom::new().fill(&mut dek).expect("random DEK");
        dek
    }

    /// Deterministic plaintext of `len` bytes.
    fn plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The byte ranges of each chunk (frame included) of an encrypted member.
    fn chunk_ranges(member: &[u8]) -> Vec<std::ops::Range<usize>> {
        let mut ranges = Vec::new();
        let mut at = MAGIC.len() + PREFIX_LEN;
        while at < member.len() {
            let len = u32::from_le_bytes(member[at + 1..at + 5].try_into().expect("4 bytes"));
            let end = at + FRAME_LEN + len as usize;
            ranges.push(at..end);
            at = end;
        }
        ranges
    }

    /// Rebuilds a member from its header and the chunks at `order`.
    fn reassemble(member: &[u8], order: &[usize]) -> Vec<u8> {
        let ranges = chunk_ranges(member);
        let mut out = member[..MAGIC.len() + PREFIX_LEN].to_vec();
        for &i in order {
            out.extend_from_slice(&member[ranges[i].clone()]);
        }
        out
    }

    fn crypto_message(err: &BackupError) -> String {
        match err {
            BackupError::Crypto(msg) => msg.clone(),
            other => panic!("expected a Crypto error, got {other:?}"),
        }
    }

    #[test]
    fn members_of_every_size_round_trip() {
        let dek = dek();
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 17,
        ] {
            let plain = plaintext(len);
            let member = encrypt_member(PATH, &plain, &dek).expect("encrypt");
            let chunks = len.div_ceil(CHUNK_LEN).max(1);
            assert_eq!(chunk_ranges(&member).len(), chunks, "chunks of {len} bytes");
            let back = decrypt_member(PATH, &member, &dek).expect("decrypt");
            assert_eq!(&*back, &plain, "a member of {len} bytes round-trips");

            // The streaming reader returns the same bytes in small reads.
            let mut reader = DecryptReader::new(member.as_slice(), &dek, PATH).expect("reader");
            let mut streamed = Vec::new();
            let mut piece = [0u8; 1000];
            loop {
                let n = reader.read(&mut piece).expect("read");
                if n == 0 {
                    break;
                }
                streamed.extend_from_slice(&piece[..n]);
            }
            assert_eq!(
                streamed, plain,
                "a streamed member of {len} bytes round-trips"
            );
        }
    }

    #[test]
    fn lines_are_read_from_the_chunk_buffer() {
        let dek = dek();
        // Lines that cross chunk boundaries.
        let lines: Vec<String> = (0..20_000).map(|i| format!("{{\"n\":{i}}}")).collect();
        let plain = lines.join("\n") + "\n";
        assert!(plain.len() > 2 * CHUNK_LEN, "the member has several chunks");
        let member = encrypt_member(PATH, plain.as_bytes(), &dek).expect("encrypt");
        let reader = DecryptReader::new(member.as_slice(), &dek, PATH).expect("reader");
        let back: Vec<String> = reader.lines().map(|l| l.expect("line")).collect();
        assert_eq!(back, lines);
    }

    #[test]
    fn the_writer_holds_one_chunk_at_a_time() {
        let dek = dek();
        let mut writer = EncryptWriter::new(Vec::new(), &dek, PATH).expect("writer");
        let piece = plaintext(10_000);
        for _ in 0..100 {
            writer.write_all(&piece).expect("write");
            assert!(
                writer.buf.capacity() <= CHUNK_LEN + TAG_LEN,
                "the chunk buffer grew to {} bytes",
                writer.buf.capacity()
            );
        }
        let member = writer.finish().expect("finish");
        let back = decrypt_member(PATH, &member, &dek).expect("decrypt");
        assert_eq!(back.len(), 100 * piece.len());
    }

    #[test]
    fn reordered_chunks_are_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(3 * CHUNK_LEN + 5), &dek).expect("encrypt");
        let swapped = reassemble(&member, &[1, 0, 2, 3]);
        let err = decrypt_member(PATH, &swapped, &dek).expect_err("reordered chunks");
        assert!(crypto_message(&err).contains("decryption"), "got: {err}");
    }

    #[test]
    fn a_member_cut_after_a_whole_chunk_is_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(3 * CHUNK_LEN + 5), &dek).expect("encrypt");
        // Drop the last chunk: every chunk left is whole and authentic.
        let cut = reassemble(&member, &[0, 1, 2]);
        let err = decrypt_member(PATH, &cut, &dek).expect_err("truncated member");
        assert!(crypto_message(&err).contains("ends before"), "got: {err}");

        // The streaming reader refuses it too, after the authentic chunks,
        // and the error still says why.
        let mut reader = DecryptReader::new(cut.as_slice(), &dek, PATH).expect("reader");
        let mut sink = Vec::new();
        let err = reader.read_to_end(&mut sink).expect_err("truncated member");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = BackupError::from_read(err);
        assert!(crypto_message(&err).contains("ends before"), "got: {err}");
    }

    #[test]
    fn a_member_cut_inside_a_chunk_is_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(2 * CHUNK_LEN), &dek).expect("encrypt");
        let err =
            decrypt_member(PATH, &member[..member.len() - 3], &dek).expect_err("truncated member");
        assert!(crypto_message(&err).contains("ends before"), "got: {err}");
    }

    #[test]
    fn a_removed_middle_chunk_is_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(3 * CHUNK_LEN + 5), &dek).expect("encrypt");
        let gap = reassemble(&member, &[0, 2, 3]);
        let err = decrypt_member(PATH, &gap, &dek).expect_err("missing chunk");
        assert!(crypto_message(&err).contains("decryption"), "got: {err}");
    }

    #[test]
    fn a_chunk_marked_last_too_early_is_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(2 * CHUNK_LEN + 5), &dek).expect("encrypt");
        // Set the last flag of the first chunk and drop the rest.
        let first = chunk_ranges(&member)[0].clone();
        let mut early = reassemble(&member, &[0]);
        early[first.start] = 1;
        let err = decrypt_member(PATH, &early, &dek).expect_err("flag changed");
        assert!(crypto_message(&err).contains("decryption"), "got: {err}");
    }

    #[test]
    fn bytes_after_the_last_chunk_are_refused() {
        let dek = dek();
        let mut member = encrypt_member(PATH, &plaintext(100), &dek).expect("encrypt");
        member.push(0);
        let err = decrypt_member(PATH, &member, &dek).expect_err("trailing byte");
        assert!(
            crypto_message(&err).contains("after its last"),
            "got: {err}"
        );
    }

    #[test]
    fn a_changed_byte_is_refused() {
        let dek = dek();
        let mut member = encrypt_member(PATH, &plaintext(CHUNK_LEN + 9), &dek).expect("encrypt");
        let at = chunk_ranges(&member)[1].start + FRAME_LEN + 3;
        member[at] ^= 0x01;
        decrypt_member(PATH, &member, &dek).expect_err("changed byte");
    }

    /// After a refused chunk, every later read is an error too: it returns
    /// no bytes of the refused chunk and does not panic.
    #[test]
    fn a_read_after_a_refused_chunk_is_an_error() {
        let dek = dek();
        let mut member = encrypt_member(PATH, &plaintext(CHUNK_LEN + 9), &dek).expect("encrypt");
        let at = chunk_ranges(&member)[1].start + FRAME_LEN + 3;
        member[at] ^= 0x01;
        let mut reader = DecryptReader::new(member.as_slice(), &dek, PATH).expect("header");

        assert_eq!(reader.fill_buf().expect("first chunk").len(), CHUNK_LEN);
        reader.consume(CHUNK_LEN);
        reader.fill_buf().expect_err("the changed chunk is refused");
        for _ in 0..2 {
            assert!(
                reader.fill_buf().is_err(),
                "a read after a refused chunk must be an error"
            );
        }
    }

    #[test]
    fn a_member_moved_to_another_path_is_refused() {
        let dek = dek();
        let member = encrypt_member(PATH, &plaintext(100), &dek).expect("encrypt");
        let err = decrypt_member("realms/acme/credentials.ndjson", &member, &dek)
            .expect_err("moved member");
        assert!(crypto_message(&err).contains("decryption"), "got: {err}");
    }

    #[test]
    fn the_wrong_dek_is_refused() {
        let member = encrypt_member(PATH, &plaintext(100), &dek()).expect("encrypt");
        decrypt_member(PATH, &member, &dek()).expect_err("wrong DEK");
    }

    #[test]
    fn a_member_from_an_older_format_is_refused_with_a_clear_error() {
        let old = br#"{"nonce_b64":"AAAAAAAAAAAAAAAA","ciphertext_b64":"AAAA"}"#;
        let err = decrypt_member(PATH, old, &dek()).expect_err("old format");
        assert!(
            crypto_message(&err).contains("chunked encryption format"),
            "got: {err}"
        );
    }

    #[test]
    fn two_members_use_different_nonce_prefixes() {
        let dek = dek();
        let a = encrypt_member(PATH, b"same", &dek).expect("encrypt a");
        let b = encrypt_member(PATH, b"same", &dek).expect("encrypt b");
        assert_ne!(
            a[MAGIC.len()..MAGIC.len() + PREFIX_LEN],
            b[MAGIC.len()..MAGIC.len() + PREFIX_LEN]
        );
        assert_ne!(a, b);
    }
}
