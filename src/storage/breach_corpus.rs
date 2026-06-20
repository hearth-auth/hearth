//! Offline breached-password corpus checker for air-gapped deployments.
//!
//! The corpus file is a flat binary array of 20-byte raw SHA-1 hashes, sorted
//! lexicographically, with no separators. A password is checked by computing
//! its SHA-1 hash and running a standard binary search over the mmap'd file.
//!
//! # Corpus format
//!
//! ```text
//! [sha1_hash_0: 20 bytes][sha1_hash_1: 20 bytes]...[sha1_hash_N: 20 bytes]
//! ```
//!
//! Hashes are in network byte order (big-endian), matching the sort order used
//! by the HIBP Pwned Passwords sorted-SHA1 download.
//!
//! # Building the corpus
//!
//! ```text
//! # Download from https://haveibeenpwned.com/Passwords (sorted SHA-1 export)
//! # Then strip the ":COUNT" suffix and convert hex → binary:
//! awk -F: '{print $1}' pwned-passwords-sha1-sorted.txt \
//!   | xxd -r -p > breach_corpus.bin
//! ```
//!
//! The file should be refreshed at least every 90 days (configured via
//! `max_corpus_age_days` in the realm's breach-check config).
//!
//! # False-positive behaviour
//!
//! Binary search on a sorted exact-match file produces **zero false positives**:
//! a password is flagged only when its SHA-1 appears verbatim in the corpus.
//!
//! # SIGBUS caveat
//!
//! If the corpus file is truncated while the mmap is live (e.g. via a
//! concurrent `truncate(1)`), accessing a page past the new end of file will
//! deliver `SIGBUS` on Linux and macOS. Hearth does not support hot-replacing
//! corpus files; a full server restart is required to pick up a new corpus.

use std::path::Path;
use std::time::SystemTime;

use memmap2::Mmap;
use ring::digest;
use thiserror::Error;

/// Size of one SHA-1 hash entry in the corpus (bytes).
const HASH_LEN: usize = 20;

/// Error returned when loading or validating an offline breach corpus.
#[derive(Debug, Error)]
pub enum CorpusError {
    /// The corpus file could not be opened or memory-mapped.
    #[error("could not open corpus at {path}: {reason}")]
    Io { path: String, reason: String },

    /// The file size is not a multiple of 20 bytes.
    #[error(
        "corpus at {path} has size {size} which is not a multiple of {HASH_LEN} — file is corrupt or truncated"
    )]
    InvalidSize { path: String, size: u64 },
}

/// Memory-mapped offline breach corpus.
///
/// Holds an OS-managed mmap of a sorted 20-byte SHA-1 hash file.
/// Thread-safe: `Mmap` is `Send + Sync` and binary search is read-only.
pub(crate) struct OfflineBreachCorpus {
    mmap: Mmap,
    /// Number of hash entries in the corpus.
    entry_count: usize,
}

impl std::fmt::Debug for OfflineBreachCorpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineBreachCorpus")
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

impl OfflineBreachCorpus {
    /// Opens and validates the corpus at `path`.
    ///
    /// Emits a [`tracing::warn`] when `max_corpus_age_days > 0` and the file's
    /// modification time is older than that threshold.
    ///
    /// # Errors
    ///
    /// Returns [`CorpusError::Io`] if the file cannot be opened, or
    /// [`CorpusError::InvalidSize`] if the file size is not a multiple of 20.
    pub(crate) fn load(path: &Path, max_corpus_age_days: u32) -> Result<Self, CorpusError> {
        let path_str = path.display().to_string();

        let file = std::fs::File::open(path).map_err(|e| CorpusError::Io {
            path: path_str.clone(),
            reason: e.to_string(),
        })?;

        let metadata = file.metadata().map_err(|e| CorpusError::Io {
            path: path_str.clone(),
            reason: e.to_string(),
        })?;
        let size = metadata.len();

        if size % (HASH_LEN as u64) != 0 {
            return Err(CorpusError::InvalidSize {
                path: path_str,
                size,
            });
        }

        if max_corpus_age_days > 0 {
            if let Ok(mtime) = metadata.modified() {
                let age_secs = SystemTime::now()
                    .duration_since(mtime)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let max_age_secs = u64::from(max_corpus_age_days) * 86_400;
                if age_secs > max_age_secs {
                    tracing::warn!(
                        corpus_path = %path_str,
                        age_days = age_secs / 86_400,
                        max_corpus_age_days,
                        "offline breach corpus is stale; refresh recommended"
                    );
                }
            }
        }

        // SAFETY: The file is opened read-only and is never mutated while the
        // mmap is live. Hearth does not support hot-replacing corpus files at
        // runtime; a server restart is required to pick up a new corpus.
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .map(&file)
                .map_err(|e| CorpusError::Io {
                    path: path_str.clone(),
                    reason: e.to_string(),
                })?
        };

        let entry_count = (size as usize) / HASH_LEN;

        tracing::info!(
            corpus_path = %path_str,
            entry_count,
            size_bytes = size,
            "offline breach corpus loaded"
        );

        Ok(Self { mmap, entry_count })
    }

    /// Returns `true` if `password` appears in the corpus.
    ///
    /// Computes the SHA-1 of `password` and binary-searches the sorted corpus.
    /// This is a pure read with no heap allocation on the hot path.
    pub(crate) fn is_pwned(&self, password: &[u8]) -> bool {
        let hash = sha1(password);
        self.binary_search(&hash)
    }

    /// Binary search for `target` in the sorted mmap'd hash array.
    fn binary_search(&self, target: &[u8; HASH_LEN]) -> bool {
        if self.entry_count == 0 {
            return false;
        }
        let mut lo: usize = 0;
        let mut hi: usize = self.entry_count - 1;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry_at(mid);
            match entry.cmp(target) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => {
                    if mid == 0 {
                        break;
                    }
                    hi = mid - 1;
                }
            }
        }
        false
    }

    /// Returns a reference to the hash at index `i`.
    fn entry_at(&self, i: usize) -> &[u8; HASH_LEN] {
        let offset = i * HASH_LEN;
        // SAFETY: `entry_count` is computed from `mmap.len() / HASH_LEN`, so
        // any index in `0..entry_count` always produces a valid 20-byte slice.
        #[allow(clippy::unwrap_used)]
        self.mmap[offset..offset + HASH_LEN].try_into().unwrap()
    }

    /// Number of entries in the corpus.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entry_count
    }
}

fn sha1(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    // SAFETY: SHA-1 always produces exactly 20 bytes.
    #[allow(clippy::unwrap_used)]
    digest.as_ref().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn write_corpus(hashes: &[[u8; HASH_LEN]]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        let mut sorted = hashes.to_vec();
        sorted.sort_unstable();
        for h in &sorted {
            f.write_all(h.as_slice()).expect("write hash");
        }
        f.flush().expect("flush");
        f
    }

    fn sha1_of(data: &[u8]) -> [u8; HASH_LEN] {
        sha1(data)
    }

    // ── load validation ───────────────────────────────────────────────────────

    #[test]
    fn rejects_invalid_file_size() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(&[0u8; 19]).expect("write"); // 19 is not divisible by 20
        let err = OfflineBreachCorpus::load(f.path(), 0).expect_err("should reject invalid size");
        assert!(matches!(err, CorpusError::InvalidSize { .. }), "{err}");
    }

    #[test]
    fn rejects_missing_file() {
        let err =
            OfflineBreachCorpus::load(std::path::Path::new("/nonexistent/breach_corpus.bin"), 0)
                .expect_err("should reject missing file");
        assert!(matches!(err, CorpusError::Io { .. }), "{err}");
    }

    #[test]
    fn empty_corpus_loads_ok() {
        let f = write_corpus(&[]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert_eq!(corpus.entry_count(), 0);
    }

    // ── is_pwned ──────────────────────────────────────────────────────────────

    #[test]
    fn is_pwned_detects_known_password() {
        let hash = sha1_of(b"password");
        let f = write_corpus(&[hash]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert!(corpus.is_pwned(b"password"));
    }

    #[test]
    fn is_pwned_returns_false_for_absent_password() {
        let hash = sha1_of(b"in_corpus");
        let f = write_corpus(&[hash]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert!(!corpus.is_pwned(b"not_in_corpus"));
    }

    #[test]
    fn is_pwned_false_on_empty_corpus() {
        let f = write_corpus(&[]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert!(!corpus.is_pwned(b"anything"));
    }

    #[test]
    fn is_pwned_finds_entry_at_beginning_of_corpus() {
        // Smallest hash ends up at index 0 after sort.
        let low_hash = [0x00u8; HASH_LEN];
        let high_hash = [0xFFu8; HASH_LEN];
        let f = write_corpus(&[low_hash, high_hash]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        // Create a password whose SHA-1 happens to equal low_hash would be
        // infeasible; instead we test via binary_search directly.
        assert!(corpus.binary_search(&low_hash));
    }

    #[test]
    fn is_pwned_finds_entry_at_end_of_corpus() {
        let low_hash = [0x00u8; HASH_LEN];
        let high_hash = [0xFFu8; HASH_LEN];
        let f = write_corpus(&[low_hash, high_hash]);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert!(corpus.binary_search(&high_hash));
    }

    #[test]
    fn is_pwned_not_found_in_multi_entry_corpus() {
        let hashes: Vec<[u8; HASH_LEN]> = (0u8..10).map(|i| [i; HASH_LEN]).collect();
        let f = write_corpus(&hashes);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        // 0x0A (10) is not in 0x00..0x09
        assert!(!corpus.binary_search(&[0x0Au8; HASH_LEN]));
    }

    #[test]
    fn entry_count_matches_hashes_written() {
        let hashes: Vec<[u8; HASH_LEN]> = (0u8..5).map(|i| [i; HASH_LEN]).collect();
        let f = write_corpus(&hashes);
        let corpus = OfflineBreachCorpus::load(f.path(), 0).expect("load corpus");
        assert_eq!(corpus.entry_count(), 5);
    }

    // ── SHA-1 correctness ─────────────────────────────────────────────────────

    #[test]
    fn sha1_of_password_matches_known_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let hash = sha1_of(b"password");
        let hex = hex::encode(hash);
        assert_eq!(
            hex.to_uppercase(),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }
}
