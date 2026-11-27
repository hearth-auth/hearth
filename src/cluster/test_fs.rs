//! A test [`Fs`] over the real file system that can run out of space and
//! records which thread removed a file and which directories were synced.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use crate::storage::{Fs, FsFile, RealFs};

/// See the module documentation.
pub(crate) struct TestFs {
    /// Bytes file writes may still write before they fail with
    /// [`io::ErrorKind::StorageFull`].
    space: Arc<AtomicU64>,
    /// Writes refused for lack of space.
    full: Arc<AtomicU64>,
    /// Every removed path and the thread that removed it.
    pub(crate) removed: Mutex<Vec<(PathBuf, ThreadId)>>,
    /// Every directory synced.
    pub(crate) synced_dirs: Mutex<Vec<PathBuf>>,
}

impl TestFs {
    /// A file system with no space limit.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            space: Arc::new(AtomicU64::new(u64::MAX)),
            full: Arc::new(AtomicU64::new(0)),
            removed: Mutex::new(Vec::new()),
            synced_dirs: Mutex::new(Vec::new()),
        })
    }

    /// Lets file writes write `bytes` more bytes, then fail.
    pub(crate) fn set_space(&self, bytes: u64) {
        self.space.store(bytes, Ordering::SeqCst);
    }

    /// How many writes were refused for lack of space.
    pub(crate) fn refused_writes(&self) -> u64 {
        self.full.load(Ordering::SeqCst)
    }

    /// The threads that removed `path`.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn removers_of(&self, path: &Path) -> Vec<ThreadId> {
        self.removed
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, t)| *t)
            .collect()
    }
}

struct TestFile {
    inner: Box<dyn FsFile>,
    space: Arc<AtomicU64>,
    full: Arc<AtomicU64>,
}

impl FsFile for TestFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let len = buf.len() as u64;
        // A compare-exchange loop: `fetch_update` is deprecated on newer
        // toolchains and its replacement is newer than the MSRV.
        let mut left = self.space.load(Ordering::SeqCst);
        let fits = loop {
            let Some(after) = left.checked_sub(len) else {
                break false;
            };
            match self
                .space
                .compare_exchange(left, after, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break true,
                Err(now) => left = now,
            }
        };
        if !fits {
            self.full.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "test: disk full",
            ));
        }
        self.inner.write_all(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.inner.read_to_end(buf)
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }

    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }

    fn set_len(&self, size: u64) -> io::Result<()> {
        self.inner.set_len(size)
    }
}

impl TestFs {
    fn wrap(&self, inner: Box<dyn FsFile>) -> Box<dyn FsFile> {
        Box::new(TestFile {
            inner,
            space: Arc::clone(&self.space),
            full: Arc::clone(&self.full),
        })
    }
}

impl Fs for TestFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(self.wrap(RealFs.open_append(path)?))
    }

    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(self.wrap(RealFs.create(path)?))
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(self.wrap(RealFs.open_read(path)?))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        RealFs.read(path)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        RealFs.write(path, data)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        RealFs.create_dir_all(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        RealFs.read_dir(path)
    }

    #[allow(clippy::unwrap_used)]
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.removed
            .lock()
            .unwrap()
            .push((path.to_path_buf(), std::thread::current().id()));
        RealFs.remove_file(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        RealFs.rename(from, to)
    }

    #[allow(clippy::unwrap_used)]
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.synced_dirs.lock().unwrap().push(dir.to_path_buf());
        RealFs.sync_dir(dir)
    }
}

/// Waits up to 5 s for `done`.
pub(crate) async fn eventually(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if done() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    done()
}
