//! Filesystem abstraction for testable storage I/O.
//!
//! The [`Fs`] trait abstracts synchronous filesystem operations used by WAL
//! and SST layers. Production code uses [`RealFs`], which delegates directly
//! to `std::fs`. The simulation crate provides a `FaultFs` implementation
//! that can inject I/O failures at controlled points for crash-recovery
//! testing.

use std::io;
use std::ops::Deref;
use std::path::Path;

/// Read-only byte backing for an SST file.
///
/// Production ([`RealFs`]) memory-maps the file so ciphertext pages are backed
/// by the OS page cache and evictable under memory pressure — the block-based
/// v3 reader (HEA-1914) slices decryptable blocks straight out of it without
/// ever pulling the whole file into a heap `Vec`. Test and simulation
/// filesystems that have no real on-disk file fall back to a heap buffer via
/// the default [`Fs::map_readonly`]; correctness is identical, only the
/// residency characteristics differ.
pub enum FileBacking {
    /// Whole-file contents read into the heap (test/simulation fallback).
    Heap(Vec<u8>),
    /// A read-only memory map of the file (production).
    #[cfg(unix)]
    Mmap(memmap2::Mmap),
}

impl Deref for FileBacking {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            FileBacking::Heap(v) => v,
            #[cfg(unix)]
            FileBacking::Mmap(m) => m,
        }
    }
}

/// A file handle returned by [`Fs::open`] or [`Fs::create`].
///
/// Mirrors the subset of `std::fs::File` operations used by the storage engine.
pub trait FsFile: Send + Sync {
    /// Writes the entire buffer to the file.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Reads the entire file contents into a buffer.
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize>;

    /// Flushes and syncs the file to durable storage.
    fn sync_all(&self) -> io::Result<()>;

    /// Syncs file *data* to durable storage, skipping non-essential metadata.
    ///
    /// Maps to `fdatasync(2)`. The kernel still persists any metadata required
    /// to read the written bytes back after a crash — critically, the file
    /// length — but skips the journal commit for fields the WAL does not
    /// depend on (`mtime`, `ctime`). For an append-only, pre-created WAL
    /// segment this is the same durability guarantee as [`Self::sync_all`] at
    /// roughly half the device round-trips (HEA-1959).
    ///
    /// The default implementation delegates to `sync_all`, so alternate
    /// filesystems (simulation, fault injection) remain correct without
    /// change — they simply give up the optimisation.
    fn sync_data(&self) -> io::Result<()> {
        self.sync_all()
    }

    /// Seeks to a position in the file.
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64>;

    /// Sets the length of the file (truncate or extend).
    fn set_len(&self, size: u64) -> io::Result<()>;
}

/// Filesystem abstraction for dependency injection.
///
/// All synchronous filesystem operations used by the storage engine go
/// through this trait. Production uses [`RealFs`]; simulation tests use
/// `FaultFs` for deterministic fault injection.
pub trait Fs: Send + Sync {
    /// Opens an existing file for reading and appending.
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Creates a new file (or truncates an existing one) for writing.
    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Opens an existing file for reading only.
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Reads the entire contents of a file into a byte vector.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Maps a file read-only for random access without decrypting it eagerly.
    ///
    /// The default implementation reads the whole file into a heap buffer,
    /// which is correct for any filesystem but keeps the ciphertext resident.
    /// [`RealFs`] overrides this to `mmap(2)` the file so pages stay in the OS
    /// page cache and are evictable under pressure — the mechanism by which the
    /// v3 SST reader keeps resident RAM independent of corpus size (HEA-1914).
    fn map_readonly(&self, path: &Path) -> io::Result<FileBacking> {
        Ok(FileBacking::Heap(self.read(path)?))
    }

    /// Writes data to a file, creating it if needed, truncating if it exists.
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;

    /// Creates a directory and all parent directories.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Lists entries in a directory.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<std::path::PathBuf>>;

    /// Removes a file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Renames a file.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Fsyncs a directory so that file creations, renames, and deletions within
    /// it become durable — i.e. their directory entries are committed.
    ///
    /// A `create` or `rename` is not crash-durable until the containing
    /// directory's metadata is itself synced. Without this, a power loss after
    /// the file's data was `fsync`'d can still lose the directory entry, leaving
    /// the restart to resolve the *old* inode (HEA-1855). Callers MUST invoke
    /// this on the parent directory after creating a new WAL/SST segment and
    /// after any rename that finalizes one.
    ///
    /// Implementations MAY treat this as a no-op on platforms where directory
    /// fsync is unsupported or meaningless (e.g. non-unix).
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// Production filesystem implementation delegating to `std::fs`.
#[derive(Debug, Clone)]
pub struct RealFs;

/// Wrapper around `std::fs::File` implementing [`FsFile`].
pub struct RealFsFile(std::fs::File);

impl FsFile for RealFsFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(&mut self.0, buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        io::Read::read_to_end(&mut self.0, buf)
    }

    fn sync_all(&self) -> io::Result<()> {
        self.0.sync_all()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }

    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.0, pos)
    }

    fn set_len(&self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }
}

impl Fs for RealFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        Ok(Box::new(RealFsFile(file)))
    }

    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::File::create(path)?; // lgtm[rust/path-injection]
        Ok(Box::new(RealFsFile(file)))
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::File::open(path)?;
        Ok(Box::new(RealFsFile(file)))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    #[cfg(unix)]
    fn map_readonly(&self, path: &Path) -> io::Result<FileBacking> {
        let file = std::fs::File::open(path)?;
        // SAFETY: `Mmap::map` is unsafe because the mapping's bytes may change
        // if another process truncates or writes the file concurrently. Hearth
        // SST files are write-once: created via a temp file + atomic rename,
        // fsync'd, and never modified in place afterward — the compaction path
        // writes a *new* file number and unlinks the old one, and an unlinked
        // file's pages remain valid for the lifetime of this mapping. No other
        // writer ever mutates a live SST, so the mapped range is stable for as
        // long as this `FileBacking` (and the `SstReader` owning it) lives.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Ok(FileBacking::Mmap(mmap))
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        std::fs::write(path, data)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<std::path::PathBuf>> {
        let entries = std::fs::read_dir(path)? // lgtm[rust/path-injection]
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .collect();
        Ok(entries)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    #[cfg(unix)]
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        // Opening a directory read-only and calling fsync commits its metadata
        // (the entries for files created/renamed/removed within it). This is the
        // POSIX-portable way to make a rename durable.
        let handle = std::fs::File::open(dir)?;
        handle.sync_all()
    }

    #[cfg(not(unix))]
    fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
        // Directory fsync is not portable outside unix; the durability contract
        // there is provided by other platform mechanisms. Treat as a no-op.
        Ok(())
    }
}
