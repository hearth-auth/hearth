//! A file writer that keeps at most one window of its data unsynced (#891).
//!
//! A backup writes its files (the spool of each member, then the archive) at
//! the speed of the page cache. The kernel writes the dirty pages back later,
//! in bursts of up to its dirty limit: gigabytes on a large server. On the
//! same disk, a WAL `fdatasync` issued during such a burst waits behind it.
//! At 10M users on a 125 MB/s volume, WAL syncs took seconds, and the write
//! limit (`storage.max_writes_in_flight`) refused the writes of other
//! requests with `503`.
//!
//! [`SyncedWriter`] syncs its file each time [`SYNC_WINDOW`] bytes have been
//! written since the last sync. A WAL sync then waits behind at most one
//! window of backup data, and the backup goes at the speed of the disk, not
//! of the page cache.

use std::io::{self, Write};

/// Bytes a [`SyncedWriter`] writes between two syncs.
///
/// 1 MiB takes about 8 ms on a 125 MB/s volume (the AWS gp3 default): about
/// the longest a WAL sync waits behind the backup. Measured on a 3M-user
/// store with the disk capped at 125 MB/s (#891), the refresh p99 during the
/// backup was 3.2 times the p99 without one with 4 MiB, 1.8 to 2.2 times
/// with 1 MiB, and 1.5 times with 256 KiB, which made the backup 2.5 times
/// slower.
pub(crate) const SYNC_WINDOW: u64 = 1024 * 1024;

/// A file that can make its written data durable, as
/// [`std::fs::File::sync_data`] does.
pub(crate) trait SyncData {
    /// Writes the file's data to the device and waits for it.
    ///
    /// # Errors
    ///
    /// The I/O error of the sync.
    fn sync_data(&self) -> io::Result<()>;
}

impl SyncData for std::fs::File {
    fn sync_data(&self) -> io::Result<()> {
        std::fs::File::sync_data(self)
    }
}

/// A writer that syncs `inner` after each [`SYNC_WINDOW`] bytes (module
/// docs). A write never crosses a window: it is cut at the window's end, so
/// no more than one window is ever unsynced.
pub(crate) struct SyncedWriter<F> {
    inner: F,
    window: u64,
    unsynced: u64,
}

impl SyncedWriter<std::fs::File> {
    /// Wraps `file` with a window of [`SYNC_WINDOW`] bytes.
    ///
    /// Only a regular file is synced. Anything else (a pipe, a character
    /// device such as `/dev/stdout`) has no page cache to write back, and
    /// `fdatasync` refuses it with `EINVAL`: it is written unsynced.
    ///
    /// # Errors
    ///
    /// The I/O error of reading the file's type.
    pub(crate) fn for_file(file: std::fs::File) -> io::Result<Self> {
        Self::for_file_with_window(file, SYNC_WINDOW)
    }

    /// As [`for_file`](Self::for_file), with a window of `window` bytes.
    fn for_file_with_window(file: std::fs::File, window: u64) -> io::Result<Self> {
        let window = if file.metadata()?.is_file() {
            window.max(1)
        } else {
            u64::MAX
        };
        Ok(Self {
            inner: file,
            window,
            unsynced: 0,
        })
    }
}

impl<F: Write + SyncData> SyncedWriter<F> {
    /// Wraps `inner` with a window of `window` bytes (at least 1).
    #[cfg(test)]
    pub(crate) fn with_window(inner: F, window: u64) -> Self {
        Self {
            inner,
            window: window.max(1),
            unsynced: 0,
        }
    }

    /// Bytes written since the last sync.
    #[cfg(test)]
    pub(crate) fn unsynced(&self) -> u64 {
        self.unsynced
    }

    /// The wrapped file.
    #[cfg(test)]
    pub(crate) fn get_ref(&self) -> &F {
        &self.inner
    }

    /// The wrapped file. The bytes written since the last sync stay unsynced.
    pub(crate) fn into_inner(self) -> F {
        self.inner
    }
}

impl<F: Write + SyncData> Write for SyncedWriter<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Never past the window's end. `room` is at least 1: the window is
        // synced as soon as it is full.
        let room = self.window - self.unsynced;
        let take = usize::try_from(room).map_or(buf.len(), |room| buf.len().min(room));
        let n = self.inner.write(&buf[..take])?;
        self.unsynced += n as u64;
        if self.unsynced >= self.window {
            self.inner.flush()?;
            self.inner.sync_data()?;
            self.unsynced = 0;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A file in memory that records the bytes written between two syncs.
    #[derive(Default)]
    struct Recording {
        data: Vec<u8>,
        /// Bytes written since the last sync.
        since_sync: Cell<u64>,
        /// The bytes written before each sync.
        syncs: RefCell<Vec<u64>>,
    }

    impl Write for Recording {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(buf);
            self.since_sync
                .set(self.since_sync.get() + buf.len() as u64);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SyncData for Recording {
        fn sync_data(&self) -> io::Result<()> {
            self.syncs.borrow_mut().push(self.since_sync.replace(0));
            Ok(())
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // #891: a backup that leaves its writes to the kernel's writeback puts
    // gigabytes in front of every WAL sync. No more than one window may be
    // written without a sync.
    #[test]
    fn no_more_than_one_window_is_written_without_a_sync() {
        let data = pattern(10_000);
        let mut w = SyncedWriter::with_window(Recording::default(), 1_000);
        // Pieces of odd sizes, some larger than the window.
        for piece in data.chunks(1_337) {
            w.write_all(piece).expect("write");
            assert!(w.unsynced() < 1_000, "unsynced {} >= window", w.unsynced());
        }
        let inner = w.into_inner();
        assert_eq!(
            inner.data, data,
            "the bytes are written unchanged, in order"
        );
        let syncs = inner.syncs.borrow();
        assert_eq!(
            *syncs,
            vec![1_000; 10],
            "one sync after each whole window of 1,000 bytes"
        );
    }

    #[test]
    fn a_write_smaller_than_the_window_is_not_synced_alone() {
        let mut w = SyncedWriter::with_window(Recording::default(), 1_000);
        w.write_all(&pattern(999)).expect("write");
        assert_eq!(w.unsynced(), 999);
        assert!(
            w.get_ref().syncs.borrow().is_empty(),
            "no sync before the window is full"
        );
        w.write_all(&pattern(1)).expect("write");
        assert_eq!(w.unsynced(), 0);
        assert_eq!(*w.get_ref().syncs.borrow(), vec![1_000]);
    }

    #[test]
    fn a_failed_sync_fails_the_write() {
        struct FailingSync(Vec<u8>);
        impl Write for FailingSync {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl SyncData for FailingSync {
            fn sync_data(&self) -> io::Result<()> {
                Err(io::Error::other("device gone"))
            }
        }
        let mut w = SyncedWriter::with_window(FailingSync(Vec::new()), 10);
        let err = w.write_all(&pattern(25)).expect_err("the sync fails");
        assert_eq!(err.to_string(), "device gone");
    }

    #[test]
    fn a_real_file_gets_every_byte() {
        let file = tempfile::tempfile().expect("tempfile");
        let data = pattern(3 * 4096 + 17);
        let mut w = SyncedWriter::with_window(file, 4096);
        w.write_all(&data).expect("write");
        let mut file = w.into_inner();
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).expect("seek");
        let mut back = Vec::new();
        file.read_to_end(&mut back).expect("read");
        assert_eq!(back, data);
    }

    // An archive can be written to a pipe, which `fdatasync` refuses with
    // `EINVAL`. A pipe has no page cache to write back, so it is not synced.
    #[test]
    fn a_pipe_is_written_without_a_sync() {
        use std::io::Read;
        let (mut rx, tx) = std::io::pipe().expect("pipe");
        let tx = std::fs::File::from(std::os::fd::OwnedFd::from(tx));
        let data = pattern(3 * 4096 + 17);
        let reader = std::thread::spawn(move || {
            let mut back = Vec::new();
            rx.read_to_end(&mut back).expect("read the pipe");
            back
        });
        let mut w = SyncedWriter::for_file_with_window(tx, 4096).expect("wrap the pipe");
        w.write_all(&data).expect("a pipe takes every byte");
        drop(w);
        assert_eq!(reader.join().expect("reader"), data);
    }

    #[test]
    fn a_regular_file_is_synced() {
        let file = tempfile::tempfile().expect("tempfile");
        let mut w = SyncedWriter::for_file_with_window(file, 4096).expect("wrap");
        w.write_all(&pattern(4096 + 10)).expect("write");
        assert_eq!(w.unsynced(), 10, "the first window was synced");
    }
}
